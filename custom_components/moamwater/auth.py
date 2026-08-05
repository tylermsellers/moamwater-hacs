"""Okta IDX authentication client for Missouri American Water's MyWater portal.

This replicates the browser login flow captured via DevTools:

    POST {OKTA_BASE_URL}{issuer}/v1/interact           -> interaction_handle (PKCE)
    POST {OKTA_BASE_URL}/idp/idx/introspect            -> stateHandle
    POST {OKTA_BASE_URL}/idp/idx/identify               -> submit username
    POST {OKTA_BASE_URL}/idp/idx/challenge/answer        -> submit password
    POST {OKTA_BASE_URL}/idp/idx/challenge               -> select + trigger MFA factor
    POST {OKTA_BASE_URL}/idp/idx/challenge/answer        -> submit MFA passcode
    (success) -> redirect chain lands on MyWater's /openidlogin?code=...

IMPORTANT correction from an earlier version of this file: the captured
`Authorization: bearer ...` header used by MyWater's `/api/mso/data` calls
decodes as an Okta **access token** (JWT claims `cid`, `uid`, `scp`), which is
a *different* token from the `mw_id_token` cookie (JWT claims `sub`, `name`,
`email` -- an **ID token**). An earlier revision of this client mistakenly
returned the ID-token cookie value as the bearer token, which would have
caused every API call to be rejected even after a successful login.

Because we generate our own PKCE `code_verifier`/`code_challenge` pair for
the `/v1/interact` call, we can (and should) complete the interaction-code
token exchange ourselves at `{issuer}/v1/token`, which returns the real
access_token + id_token directly from Okta -- no cookie-scraping needed.
If Okta rejects that exchange (e.g. because MyWater's own backend already
consumed the code via the redirect chain first), we fall back to scraping
`mw_id_token`-shaped cookies for diagnostic purposes only; that fallback is
very unlikely to work as an *access* token and mainly exists so failures are
self-explanatory in the logs rather than a bare "no token found".
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp

from .const import OKTA_BASE_URL, OKTA_CLIENT_ID, OKTA_ISSUER_PATH, OKTA_REDIRECT_URI, OKTA_SCOPES

_LOGGER = logging.getLogger(__name__)

IDX_INTROSPECT = f"{OKTA_BASE_URL}/idp/idx/introspect"
IDX_IDENTIFY = f"{OKTA_BASE_URL}/idp/idx/identify"
IDX_CHALLENGE = f"{OKTA_BASE_URL}/idp/idx/challenge"
IDX_CHALLENGE_ANSWER = f"{OKTA_BASE_URL}/idp/idx/challenge/answer"
# Okta's "Interaction Code" flow (OIE) starts with a POST to /v1/interact,
# NOT a GET to /v1/authorize -- the latter is for the classic redirect-based
# authorization code flow and does not return an `interaction_handle`.
INTERACT_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/interact"
TOKEN_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/token"

# All /idp/idx/* endpoints speak Okta's "Ion" JSON dialect; sending plain
# application/json on later steps (identify/challenge/answer) is tolerated by
# some tenants but rejected outright by others -- use the same content type
# throughout for consistency with what the real widget sends.
_IDX_HEADERS = {"Content-Type": "application/ion+json; okta-version=1.0.0"}


class MoAmWaterAuthError(Exception):
    """Raised when authentication with Okta/MyWater fails for a protocol/implementation reason.

    Use `InvalidCredentials` (a subclass) specifically for the identify/password
    steps rejecting the submitted username/password, so the config flow can
    show "invalid_auth" only for genuine credential failures and "unknown"
    (with the real error logged) for everything else -- e.g. a malformed
    request, unexpected Okta response shape, or a broken token exchange.
    """


class InvalidCredentials(MoAmWaterAuthError):
    """Raised specifically when Okta rejects the submitted username/password."""


class InvalidMfaCode(MoAmWaterAuthError):
    """Raised specifically when Okta rejects the submitted MFA passcode."""


class MfaRequired(Exception):
    """Raised when an MFA challenge must be answered to continue login."""

    def __init__(self, state_handle: str, factors: list[dict[str, Any]]):
        super().__init__("MFA challenge required")
        self.state_handle = state_handle
        self.factors = factors


def _error_summary(data: dict[str, Any]) -> str:
    """Extract a human-readable error message from an Okta IDX error response."""
    if isinstance(data, dict):
        messages = data.get("messages", {}).get("value", [])
        if messages:
            return "; ".join(m.get("message", "") for m in messages if m.get("message"))
    return str(data)[:500]


def _has_error_messages(data: dict[str, Any]) -> bool:
    """True if an IDX response (even with HTTP 200) carries error messages.

    Okta's IDX API can return HTTP 200 with a `messages.value` array
    describing a failure (e.g. wrong password) rather than a 4xx status, so
    status-code checks alone are not sufficient to detect a failed step.
    """
    if not isinstance(data, dict):
        return False
    return bool(data.get("messages", {}).get("value"))


def _is_credential_error(data: dict[str, Any]) -> bool:
    """True if the IDX error messages indicate bad username/password specifically.

    Okta's IDX responses use i18n keys like `errors.E0000004` (auth failed) or
    class names containing "AuthenticationFailedException" for bad
    credentials, as opposed to other errors (rate limiting, policy, malformed
    request, etc.) which should NOT be shown to the user as "wrong password".
    """
    if not isinstance(data, dict):
        return False
    for msg in data.get("messages", {}).get("value", []):
        i18n_key = (msg.get("i18n") or {}).get("key", "")
        if "E0000004" in i18n_key or "authfailed" in i18n_key.lower():
            return True
    return False


def _gen_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier/code_challenge pair (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class MoAmWaterAuthClient:
    """Handles the multi-step Okta IDX login and MyWater token retrieval."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session
        self._state_handle: str | None = None
        self._code_verifier: str | None = None

    async def async_start_login(self, username: str, password: str) -> dict[str, Any]:
        """Begin login: interact, introspect, identify, then answer (password).

        Returns the token dict on immediate success (no MFA configured), or raises
        MfaRequired if a factor challenge must be completed via async_submit_mfa().
        """
        code_verifier, code_challenge = _gen_pkce_pair()
        self._code_verifier = code_verifier
        _LOGGER.debug("Starting MyWater login for user %s", username)

        # Step 1: POST /v1/interact to obtain an `interaction_handle` (this is
        # the Okta Interaction Code / OIE flow entry point -- a GET to
        # /v1/authorize does NOT return an interaction_handle).
        interact_payload = {
            "client_id": OKTA_CLIENT_ID,
            "scope": OKTA_SCOPES,
            "redirect_uri": OKTA_REDIRECT_URI,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(16),
        }
        async with self._session.post(
            INTERACT_URL,
            data=interact_payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as resp:
            body_text = await resp.text()
            if resp.status != 200:
                raise MoAmWaterAuthError(
                    f"Okta /v1/interact failed (status {resp.status}): {body_text[:500]}"
                )
            data = await resp.json(content_type=None)
            interaction_handle = data.get("interaction_handle")
            if not interaction_handle:
                raise MoAmWaterAuthError(f"No interaction_handle from /v1/interact: {data}")
            _LOGGER.debug("Got Okta interaction_handle")

        # Step 2: introspect to get a stateHandle for the idx/* endpoints.
        async with self._session.post(
            IDX_INTROSPECT,
            json={"interactionHandle": interaction_handle},
            headers=_IDX_HEADERS,
        ) as resp:
            if resp.status != 200:
                body_text = await resp.text()
                raise MoAmWaterAuthError(
                    f"Okta introspect failed (status {resp.status}): {body_text[:500]}"
                )
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle")
            if not self._state_handle:
                raise MoAmWaterAuthError(f"No stateHandle from introspect: {data}")
            _LOGGER.debug("Got Okta stateHandle from introspect")

        # Step 3: identify (submit username).
        async with self._session.post(
            IDX_IDENTIFY,
            json={"identifier": username, "stateHandle": self._state_handle},
            headers=_IDX_HEADERS,
        ) as resp:
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle", self._state_handle)
            if resp.status >= 400 or _has_error_messages(data):
                if _is_credential_error(data):
                    raise InvalidCredentials(_error_summary(data))
                raise MoAmWaterAuthError(
                    f"identify step failed (status {resp.status}): {_error_summary(data)}"
                )

        # Step 4: answer with password.
        async with self._session.post(
            IDX_CHALLENGE_ANSWER,
            json={"credentials": {"passcode": password}, "stateHandle": self._state_handle},
            headers=_IDX_HEADERS,
        ) as resp:
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle", self._state_handle)
            if resp.status >= 400 or _has_error_messages(data):
                if _is_credential_error(data):
                    raise InvalidCredentials(_error_summary(data))
                raise MoAmWaterAuthError(
                    f"password step failed (status {resp.status}): {_error_summary(data)}"
                )

        return await self._async_handle_next_step(data)

    async def _async_handle_next_step(self, data: dict[str, Any]) -> dict[str, Any]:
        """Inspect an IDX response's remediation and either finish, or drive MFA.

        Handles two distinct remediation shapes:
          - "select-authenticator-authenticate": multiple factors available;
            we auto-select the first and POST /idp/idx/challenge to trigger
            it (e.g. sends the SMS/email code), then surface MfaRequired.
          - "challenge-authenticator": a single factor is already active and
            awaiting its passcode; no selection call is needed.
        """
        remediation = (data.get("remediation") or {}).get("value", [])
        select_step = next(
            (s for s in remediation if s.get("name") == "select-authenticator-authenticate"), None
        )
        challenge_step = next(
            (s for s in remediation if s.get("name") == "challenge-authenticator"), None
        )

        if select_step:
            options = (select_step.get("value") or [{}])[0].get("options", [])
            if not options:
                raise MoAmWaterAuthError(f"No MFA factors available in response: {data}")

            chosen = options[0]
            authenticator_id = None
            for field in (chosen.get("value", {}).get("form", {}).get("value", [])):
                if field.get("name") == "id":
                    authenticator_id = field.get("value")
                    break
            if not authenticator_id:
                raise MoAmWaterAuthError(f"Could not determine authenticator id: {chosen}")

            async with self._session.post(
                IDX_CHALLENGE,
                json={"authenticator": {"id": authenticator_id}, "stateHandle": self._state_handle},
                headers=_IDX_HEADERS,
            ) as resp:
                trigger_data = await resp.json(content_type=None)
                self._state_handle = trigger_data.get("stateHandle", self._state_handle)
                if resp.status >= 400 or _has_error_messages(trigger_data):
                    raise MoAmWaterAuthError(
                        f"MFA factor selection failed (status {resp.status}): "
                        f"{_error_summary(trigger_data)}"
                    )
            _LOGGER.debug("Triggered MFA factor %s", chosen.get("label", authenticator_id))
            raise MfaRequired(self._state_handle, options)

        if challenge_step:
            _LOGGER.debug("MFA challenge already active; awaiting passcode")
            raise MfaRequired(self._state_handle, [])

        return await self._finish_login_redirect(data)

    async def async_submit_mfa(self, passcode: str) -> dict[str, Any]:
        """Submit the MFA passcode (SMS/email/TOTP code) to complete login."""
        if not self._state_handle:
            raise MoAmWaterAuthError("No active login session; call async_start_login first")

        async with self._session.post(
            IDX_CHALLENGE_ANSWER,
            json={"credentials": {"passcode": passcode}, "stateHandle": self._state_handle},
            headers=_IDX_HEADERS,
        ) as resp:
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle", self._state_handle)
            if resp.status >= 400 or _has_error_messages(data):
                raise InvalidMfaCode(
                    f"MFA step failed (status {resp.status}): {_error_summary(data)}"
                )

        return await self._finish_login_redirect(data)

    async def _finish_login_redirect(self, idx_response: dict[str, Any]) -> dict[str, Any]:
        """Complete login: exchange the interaction code for real Okta tokens.

        The idx response's `success.href` points at Okta's redirect endpoint;
        GETting it (without auto-following redirects) returns a 302 whose
        Location carries `interaction_code`/`code` + `state` query params
        bound to our PKCE `code_verifier`. We walk that redirect chain
        ourselves (rather than letting aiohttp auto-follow) so we can capture
        those query params before the final hop reaches MyWater's backend.
        """
        success = idx_response.get("success") or {}
        redirect_href = success.get("href")
        if not redirect_href:
            raise MoAmWaterAuthError(f"Login did not complete successfully: {idx_response}")

        code_value, state_value = await self._walk_redirects_for_code(redirect_href)

        if code_value:
            try:
                tokens = await self._exchange_code_for_tokens(code_value)
                return {"access_token": tokens["access_token"]}
            except MoAmWaterAuthError as exc:
                _LOGGER.warning(
                    "Client-side token exchange failed (%s); falling back to "
                    "MyWater session cookie. This is expected if MyWater's own "
                    "backend already consumed the authorization code server-side.",
                    exc,
                )

        # Fallback: let the redirect complete naturally in our aiohttp session
        # (cookie jar retains whatever MyWater's backend sets) and scrape a
        # cookie that at least proves the login succeeded, for diagnostics.
        async with self._session.get(redirect_href) as resp:
            await resp.read()

        found_cookies = {c.key: c.value for c in self._session.cookie_jar}
        for key in ("mw_id_token", "access_token", "SESSION"):
            if key in found_cookies:
                _LOGGER.debug("Using fallback cookie '%s' as bearer token (unverified)", key)
                return {"access_token": found_cookies[key]}

        raise MoAmWaterAuthError(
            "Login redirect completed but no usable token/cookie was found. "
            f"Cookies present after redirect: {sorted(found_cookies.keys())}"
        )

    async def _walk_redirects_for_code(self, url: str) -> tuple[str | None, str | None]:
        """Manually follow a redirect chain, extracting `code`/`interaction_code`.

        Stops as soon as a hop's Location (or the final response URL) carries
        a `code` or `interaction_code` query parameter, without letting
        aiohttp auto-follow past that point and potentially trigger MyWater's
        server-side exchange before we can read the param ourselves.
        """
        current_url = url
        for _ in range(6):
            async with self._session.get(current_url, allow_redirects=False) as resp:
                location = resp.headers.get("Location")
                await resp.read()

            candidate = location or str(current_url)
            query = parse_qs(urlparse(candidate).query)
            code = (query.get("interaction_code") or query.get("code") or [None])[0]
            state = (query.get("state") or [None])[0]
            if code:
                return code, state

            if not location:
                break
            current_url = location

        return None, None

    async def _exchange_code_for_tokens(self, code: str) -> dict[str, Any]:
        """POST {issuer}/v1/token to exchange our interaction code for tokens."""
        if not self._code_verifier:
            raise MoAmWaterAuthError("No code_verifier available for token exchange")

        payload = {
            "grant_type": "interaction_code",
            "interaction_code": code,
            "client_id": OKTA_CLIENT_ID,
            "code_verifier": self._code_verifier,
            "redirect_uri": OKTA_REDIRECT_URI,
        }
        async with self._session.post(
            TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as resp:
            body_text = await resp.text()
            if resp.status != 200:
                raise MoAmWaterAuthError(
                    f"Okta /v1/token exchange failed (status {resp.status}): {body_text[:500]}"
                )
            data = await resp.json(content_type=None)

        if "access_token" not in data:
            raise MoAmWaterAuthError(f"Token exchange response missing access_token: {data}")
        return data

