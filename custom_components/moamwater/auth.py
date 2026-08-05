"""Okta authentication client for Missouri American Water's MyWater portal.

Login flow used by this client (classic Okta AuthN API + authorization_code):

    POST {OKTA_BASE_URL}/api/v1/authn                          -> primary auth
      (username/password). Returns status "SUCCESS" with a `sessionToken`,
      or status "MFA_REQUIRED" with a list of enrolled `factors` plus a
      `stateToken` used to drive the MFA step.
    POST {OKTA_BASE_URL}/api/v1/authn/factors/{id}/verify        -> submit the
      passcode for the chosen factor; on success also returns a
      `sessionToken`.
    GET  {OKTA_BASE_URL}{issuer}/v1/authorize?...&sessionToken=...&
         code_challenge=...&response_type=code                    -> redirects
      (302) straight to our `redirect_uri` with a `code` query param, because
      passing `sessionToken` short-circuits the interactive login UI.
    POST {OKTA_BASE_URL}{issuer}/v1/token (grant_type=authorization_code)
      -> exchanges that `code` (+ our PKCE `code_verifier`) for the real
      `access_token` used as the Bearer credential for `/api/mso/data`.

IMPORTANT: an earlier version of this file attempted Okta's newer Identity
Engine "Interaction Code" flow (`POST /v1/interact`), but this Okta app
registration only has `authorization_code`, `password`, and `refresh_token`
grants enabled -- `/v1/interact` reliably fails with
`unauthorized_client: The client is not authorized to use the provided grant
type`. Hence the classic AuthN-API-driven authorization_code flow above.

Also important: the captured `Authorization: bearer ...` header used by
MyWater's `/api/mso/data` calls decodes as an Okta **access token** (JWT
claims `cid`, `uid`, `scp`), which is a *different* token from the
`mw_id_token` cookie (JWT claims `sub`, `name`, `email` -- an **ID token**).
This client requests the access_token directly from the `/v1/token`
exchange rather than scraping cookies.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from .const import (
    OKTA_AUTHN_FACTORS_VERIFY_URL,
    OKTA_AUTHN_URL,
    OKTA_BASE_URL,
    OKTA_CLIENT_ID,
    OKTA_ISSUER_PATH,
    OKTA_REDIRECT_URI,
    OKTA_SCOPES,
)

_LOGGER = logging.getLogger(__name__)

AUTHORIZE_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/authorize"
TOKEN_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/token"

_JSON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


class MoAmWaterAuthError(Exception):
    """Raised when authentication with Okta/MyWater fails for a protocol/implementation reason.

    Use `InvalidCredentials` (a subclass) specifically for the primary-auth
    step rejecting the submitted username/password, so the config flow can
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

    def __init__(self, factors: list[dict[str, Any]]):
        super().__init__("MFA challenge required")
        self.factors = factors


def _gen_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier/code_challenge pair (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class MoAmWaterAuthClient:
    """Handles the multi-step Okta AuthN login and authorization_code exchange."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session
        self._code_verifier: str | None = None
        self._state_token: str | None = None
        self._factors: list[dict[str, Any]] = []

    async def async_start_login(self, username: str, password: str) -> dict[str, Any]:
        """Begin login via the classic Okta AuthN API (/api/v1/authn).

        Returns the token dict on immediate success (no MFA configured), or
        raises MfaRequired if a factor challenge must be completed via
        async_submit_mfa().
        """
        self._code_verifier, _ = _gen_pkce_pair()
        _LOGGER.debug("Starting MyWater login for user %s", username)

        async with self._session.post(
            OKTA_AUTHN_URL,
            json={"username": username, "password": password, "options": {"warnBeforePasswordExpired": False}},
            headers=_JSON_HEADERS,
        ) as resp:
            data = await resp.json(content_type=None)
            status = data.get("status")

            if resp.status >= 400 or status == "LOCKED_OUT":
                if resp.status == 401 or _is_credential_error(data):
                    raise InvalidCredentials(_error_summary(data))
                raise MoAmWaterAuthError(
                    f"Okta primary auth failed (status {resp.status}): {_error_summary(data)}"
                )

        if status == "SUCCESS":
            session_token = data.get("sessionToken")
            if not session_token:
                raise MoAmWaterAuthError(f"Okta auth reported SUCCESS but no sessionToken: {data}")
            return await self._async_finish_with_session_token(session_token)

        if status == "MFA_REQUIRED" or status == "MFA_ENROLL":
            self._state_token = data.get("stateToken")
            self._factors = (data.get("_embedded") or {}).get("factors", [])
            if not self._factors:
                raise MoAmWaterAuthError(f"MFA required but no factors listed: {data}")
            _LOGGER.debug("MFA required; %d factor(s) available", len(self._factors))
            raise MfaRequired(self._factors)

        raise MoAmWaterAuthError(f"Unexpected Okta primary-auth status '{status}': {data}")

    async def async_submit_mfa(self, passcode: str) -> dict[str, Any]:
        """Submit the MFA passcode (SMS/email/TOTP code) to complete login."""
        if not self._state_token or not self._factors:
            raise MoAmWaterAuthError("No active login session; call async_start_login first")

        factor_id = self._factors[0].get("id")
        if not factor_id:
            raise MoAmWaterAuthError(f"Could not determine factor id from: {self._factors}")

        verify_url = OKTA_AUTHN_FACTORS_VERIFY_URL.format(factor_id=factor_id)
        async with self._session.post(
            verify_url,
            json={"stateToken": self._state_token, "passCode": passcode},
            headers=_JSON_HEADERS,
        ) as resp:
            data = await resp.json(content_type=None)
            status = data.get("status")

            if resp.status >= 400 or status not in ("SUCCESS", "MFA_CHALLENGE"):
                raise InvalidMfaCode(
                    f"MFA verification failed (status {resp.status}): {_error_summary(data)}"
                )
            if status == "MFA_CHALLENGE" and (data.get("factorResult") == "WAITING"):
                # Push-notification-style factor not yet approved; surface as
                # an invalid/incomplete code so the UI lets the user retry.
                raise InvalidMfaCode("MFA challenge still pending (factor not yet approved)")

        session_token = data.get("sessionToken")
        if not session_token:
            raise MoAmWaterAuthError(f"MFA verify reported success but no sessionToken: {data}")

        return await self._async_finish_with_session_token(session_token)

    async def _async_finish_with_session_token(self, session_token: str) -> dict[str, Any]:
        """Redeem an Okta `sessionToken` for an authorization `code`, then tokens.

        Passing `sessionToken` to `/v1/authorize` short-circuits Okta's
        interactive sign-in widget and redirects (302) straight to our
        `redirect_uri` with a `code` query parameter, since we're already
        authenticated for this session token.
        """
        if not self._code_verifier:
            raise MoAmWaterAuthError("No code_verifier available; login was not started correctly")

        digest = hashlib.sha256(self._code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        authorize_params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "scope": OKTA_SCOPES,
            "redirect_uri": OKTA_REDIRECT_URI,
            "state": secrets.token_urlsafe(16),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "sessionToken": session_token,
        }
        authorize_url = f"{AUTHORIZE_URL}?{urlencode(authorize_params)}"

        code_value = await self._walk_redirects_for_code(authorize_url)
        if not code_value:
            raise MoAmWaterAuthError(
                "Authorization redirect did not yield a 'code' query parameter"
            )

        tokens = await self._exchange_code_for_tokens(code_value)
        return {"access_token": tokens["access_token"]}

    async def _walk_redirects_for_code(self, url: str) -> str | None:
        """Manually follow a redirect chain, extracting the `code` query param.

        Stops as soon as a hop's Location carries a `code` param, without
        letting aiohttp auto-follow past that point (MyWater's backend would
        otherwise consume the code server-side before we can read it).
        """
        current_url = url
        for _ in range(6):
            async with self._session.get(current_url, allow_redirects=False) as resp:
                location = resp.headers.get("Location")
                body_text = await resp.text()
                if resp.status not in (301, 302, 303, 307, 308) and not location:
                    raise MoAmWaterAuthError(
                        f"Expected a redirect from Okta /v1/authorize, got "
                        f"status {resp.status}: {body_text[:500]}"
                    )

            candidate = location or str(current_url)
            query = parse_qs(urlparse(candidate).query)
            code = (query.get("code") or [None])[0]
            error = (query.get("error") or [None])[0]
            if error:
                error_desc = (query.get("error_description") or [error])[0]
                raise MoAmWaterAuthError(f"Okta /v1/authorize returned error: {error_desc}")
            if code:
                return code

            if not location:
                break
            current_url = location

        return None

    async def _exchange_code_for_tokens(self, code: str) -> dict[str, Any]:
        """POST {issuer}/v1/token to exchange our authorization code for tokens."""
        if not self._code_verifier:
            raise MoAmWaterAuthError("No code_verifier available for token exchange")

        payload = {
            "grant_type": "authorization_code",
            "code": code,
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


def _error_summary(data: dict[str, Any]) -> str:
    """Extract a human-readable error message from an Okta AuthN error response."""
    if isinstance(data, dict):
        if data.get("errorSummary"):
            return data["errorSummary"]
        causes = data.get("errorCauses") or []
        if causes:
            return "; ".join(c.get("errorSummary", "") for c in causes if c.get("errorSummary"))
    return str(data)[:500]


def _is_credential_error(data: dict[str, Any]) -> bool:
    """True if the AuthN error indicates bad username/password specifically.

    Okta's classic AuthN API returns `errorCode: "E0000004"` for
    "Authentication failed" (bad credentials), as opposed to other
    errorCodes (locked out, policy violation, rate limiting, etc.) which
    should NOT be shown to the user as "wrong password".
    """
    if not isinstance(data, dict):
        return False
    return data.get("errorCode") == "E0000004"
