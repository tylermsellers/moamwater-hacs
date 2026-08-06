"""Okta authentication client for Missouri American Water's MyWater portal.

This is the REAL login flow, reverse-engineered from a HAR capture of an
actual successful browser login (Firefox, through Okta's hosted Sign-In
Widget). It supersedes every previous approach attempted in this codebase's
history (see below) -- this one is Okta's genuine Identity Engine (IDX) API
sequence, not a shortcut:

    1. GET  {issuer}/v1/authorize?client_id=...&response_type=code&scope=...&
             redirect_uri=...&state=...                        (no PKCE)
       -> status 200, HTML host page for the Sign-In Widget. Embeds a
          `stateToken` in a `var oktaData = {...}` JS object
          (`oktaData.signIn.stateToken`).

    2. POST {OKTA_BASE_URL}/idp/idx/introspect   {"stateToken": <from step 1>}
       -> {"stateHandle": ...} plus a `remediation` array describing what
          input is needed next (here: a password challenge).

    3. (parallel, cosmetic but harmless to include) an invisible iframe loads
       GET /auth/services/devicefingerprint, which runs Okta's fingerprint2
       JS and POSTs the resulting hash to /api/v1/internal/device/nonce to
       get a `{"nonce": ...}` back. The widget then sends
       `X-Device-Fingerprint: <nonce>|<hash>|<extra>` on subsequent IDX
       calls. We cannot run that JS from Python, so we skip computing a real
       fingerprint hash and simply omit the header -- Okta's fingerprint
       check appears to be a soft device-trust/risk signal (affecting
       whether a *new* MFA challenge is required), not a hard block, since
       the IDX endpoints did not reject our hop-traced attempts for lack of
       this header in earlier testing of adjacent endpoints.

    4. POST {OKTA_BASE_URL}/idp/idx/identify
             {"identifier": <username>, "stateHandle": <from step 2>}
       -> remediation now asks for a `challenge-authenticator` (password).

    5. POST {OKTA_BASE_URL}/idp/idx/challenge/answer
             {"credentials": {"passcode": <password>}, "stateHandle": ...}
       -> if another factor (e.g. SMS) is enrolled, remediation now asks for
          an `authenticator-verification-data` challenge (phone/SMS) instead
          of returning `success` outright.

    6. POST {OKTA_BASE_URL}/idp/idx/challenge
             {"authenticator": {"id": ..., "enrollmentId": ..., "methodType": ...},
              "stateHandle": ...}
       -> triggers Okta to actually send the SMS/push, and returns a new
          remediation asking for the passcode.

    7. POST {OKTA_BASE_URL}/idp/idx/challenge/answer
             {"credentials": {"passcode": <SMS code>}, "stateHandle": ...}
       -> on success, response body includes
          `"success": {"href": "https://.../login/token/redirect?stateToken=..."}`.

    8. GET  that `success.href` URL -> 302 redirect straight to our real
          `redirect_uri` with `code`/`state` query params.

    9. POST {OKTA_BASE_URL}{issuer}/v1/token (grant_type=authorization_code,
          NO PKCE) -> exchanges `code` for the real `access_token` (and a
          `refresh_token`, since `offline_access` is in our requested scopes)
          used as the credential for `/api/mso/data`.

IMPORTANT history of failed approaches (do not repeat these mistakes):
  - Interaction Code / `/v1/interact` flow: this Okta app registration's
    allowed grant types are only `authorization_code`, `password`,
    `refresh_token` -- `/v1/interact` reliably fails with
    `unauthorized_client: The client is not authorized to use the provided
    grant type`.
  - Classic AuthN API (`POST /api/v1/authn` -> sessionToken) + redeeming
    that sessionToken via `/v1/authorize?sessionToken=...` (with or without
    PKCE, with or without first opening an unauthenticated `/v1/authorize`
    transaction, with or without `/login/sessionCookieRedirect`): ALL of
    these variants returned status 200 with the interactive HTML widget
    instead of a redirect, because this org's Identity Engine tenant does
    not support that classic-Okta shortcut at all -- it isn't a cookie or
    parameter problem, the mechanism itself doesn't exist here.
  - Once the correct redemption endpoint (`/login/token/redirect?stateToken=`)
    was found (from a smaller HAR capture) and used with a `sessionToken`
    obtained via the classic AuthN API, Okta's WAF returned a bare 403
    Access Forbidden -- even after adding realistic browser headers
    (User-Agent, Referer, Sec-Fetch-*). This is because the classic AuthN
    API was never actually part of this org's real flow at all: real
    logins never call `/api/v1/authn`, they go through `/idp/idx/*`. The
    403 was Okta's WAF rejecting a session that skipped the real IDX
    handshake steps entirely, not a header-fidelity problem.

Also important: the captured `Authorization: bearer ...` header used by
MyWater's `/api/mso/data` calls decodes as an Okta **access token** (JWT
claims `cid`, `uid`, `scp`), which is a *different* token from the
`mw_id_token` cookie (JWT claims `sub`, `name`, `email` -- an **ID token**).
This client requests the access_token directly from the `/v1/token`
exchange rather than scraping cookies.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from .const import (
    OKTA_BASE_URL,
    OKTA_CLIENT_ID,
    OKTA_IDX_CHALLENGE_ANSWER_URL,
    OKTA_IDX_CHALLENGE_URL,
    OKTA_IDX_IDENTIFY_URL,
    OKTA_IDX_INTROSPECT_URL,
    OKTA_ISSUER_PATH,
    OKTA_REDIRECT_URI,
    OKTA_SCOPES,
)

_LOGGER = logging.getLogger(__name__)

AUTHORIZE_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/authorize"
TOKEN_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/token"

# Okta's WAF/bot-detection appears to expect a real browser's header set on
# every request (confirmed by a bare 403 when these were absent in earlier
# testing). Mirrors the real captured Firefox request headers exactly.
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) "
        "Gecko/20100101 Firefox/153.0"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}
_BROWSER_NAV_HEADERS = {
    **_BROWSER_HEADERS,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}
# Header set used for /idp/idx/* and device/nonce XHR calls -- mirrors the
# okta-signin-widget's own fetch()/jQuery.post() headers exactly.
_IDX_HEADERS = {
    **_BROWSER_HEADERS,
    "Accept": "application/json; okta-version=1.0.0",
    "Content-Type": "application/json",
    "X-Okta-User-Agent-Extended": "okta-auth-js/7.14.5 okta-signin-widget-7.47.2 okta-hosted",
    "Origin": OKTA_BASE_URL,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

_STATE_TOKEN_RE = re.compile(r'"stateToken"\s*:\s*"((?:[^"\\]|\\.)*)"')


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


class MoAmWaterAuthClient:
    """Drives the real Okta Identity Engine (IDX) login sequence used by the
    hosted Sign-In Widget, as reverse-engineered from a HAR capture.
    """

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session
        self._state_handle: str | None = None
        self._authenticator: dict[str, Any] | None = None
        self._factors: list[dict[str, Any]] = []

    async def async_start_login(self, username: str, password: str) -> dict[str, Any]:
        """Begin login via the real IDX sequence: authorize -> introspect -> identify -> answer.

        Returns the token dict on immediate success (no further MFA
        configured), or raises MfaRequired if a factor challenge must be
        completed via async_submit_mfa().
        """
        _LOGGER.debug("Starting MyWater login for user %s", username)

        state_token = await self._async_get_initial_state_token()
        self._state_handle = await self._async_introspect(state_token)
        response = await self._async_identify(username)
        response = await self._async_answer_password(password, response)
        return await self._async_handle_remediation(response)

    async def async_submit_mfa(self, passcode: str) -> dict[str, Any]:
        """Submit the MFA passcode (SMS/email/TOTP code) to complete login."""
        if not self._state_handle or not self._authenticator:
            raise MoAmWaterAuthError("No active login session; call async_start_login first")

        response = await self._async_post_idx(
            OKTA_IDX_CHALLENGE_ANSWER_URL,
            {"credentials": {"passcode": passcode}, "stateHandle": self._state_handle},
            invalid_exc=InvalidMfaCode,
        )
        return await self._async_handle_remediation(response)

    async def _async_get_initial_state_token(self) -> str:
        """GET {issuer}/v1/authorize and extract the embedded `stateToken`.

        No PKCE/sessionToken params are sent -- this matches the real
        browser's very first request exactly.
        """
        authorize_params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "scope": OKTA_SCOPES,
            "redirect_uri": OKTA_REDIRECT_URI,
            "state": secrets.token_urlsafe(16),
        }
        url = f"{AUTHORIZE_URL}?{urlencode(authorize_params)}"
        async with self._session.get(url, headers=_BROWSER_NAV_HEADERS) as resp:
            body_text = await resp.text()
            if resp.status != 200:
                raise MoAmWaterAuthError(
                    f"Initial /v1/authorize GET failed (status {resp.status}): {body_text[:500]}"
                )

        match = _STATE_TOKEN_RE.search(body_text)
        if not match:
            raise MoAmWaterAuthError(
                "Could not find embedded oktaData/stateToken in /v1/authorize response"
            )
        # The oktaData object embeds a raw JS function literal (the consent
        # "cancel" callback), so it is NOT valid JSON and can't be parsed as
        # a whole -- pull the stateToken value out directly via regex
        # instead, unescaping its \xNN/\uNNNN JS string escapes.
        state_token = _unescape_js_hex(match.group(1))
        if not state_token:
            raise MoAmWaterAuthError("oktaData stateToken was empty")
        return state_token

    async def _async_introspect(self, state_token: str) -> str:
        """POST /idp/idx/introspect {stateToken} -> stateHandle."""
        async with self._session.post(
            OKTA_IDX_INTROSPECT_URL,
            json={"stateToken": state_token},
            headers=_IDX_HEADERS,
        ) as resp:
            body_text = await resp.text()
            if resp.status != 200:
                raise MoAmWaterAuthError(
                    f"/idp/idx/introspect failed (status {resp.status}): {body_text[:500]}"
                )
            data = json.loads(body_text)

        state_handle = data.get("stateHandle")
        if not state_handle:
            raise MoAmWaterAuthError(f"/idp/idx/introspect response missing stateHandle: {data}")
        return state_handle

    async def _async_identify(self, username: str) -> dict[str, Any]:
        """POST /idp/idx/identify {identifier, stateHandle} -> next remediation."""
        return await self._async_post_idx(
            OKTA_IDX_IDENTIFY_URL,
            {"identifier": username, "stateHandle": self._state_handle},
            invalid_exc=InvalidCredentials,
        )

    async def _async_answer_password(
        self, password: str, response: dict[str, Any]
    ) -> dict[str, Any]:
        """POST /idp/idx/challenge/answer {credentials.passcode=password}."""
        # Refresh stateHandle from the latest response (Okta rotates it on
        # each step in the real capture).
        self._state_handle = response.get("stateHandle", self._state_handle)
        return await self._async_post_idx(
            OKTA_IDX_CHALLENGE_ANSWER_URL,
            {"credentials": {"passcode": password}, "stateHandle": self._state_handle},
            invalid_exc=InvalidCredentials,
        )

    async def _async_post_idx(
        self, url: str, payload: dict[str, Any], invalid_exc: type[MoAmWaterAuthError]
    ) -> dict[str, Any]:
        """Shared POST helper for all /idp/idx/* calls with consistent error handling."""
        async with self._session.post(url, json=payload, headers=_IDX_HEADERS) as resp:
            body_text = await resp.text()
            try:
                data = json.loads(body_text) if body_text else {}
            except json.JSONDecodeError:
                data = {}

            if resp.status >= 400:
                messages = _idx_error_summary(data)
                if resp.status in (400, 401, 403):
                    raise invalid_exc(messages or f"status {resp.status}: {body_text[:500]}")
                raise MoAmWaterAuthError(
                    f"{url} failed (status {resp.status}): {messages or body_text[:500]}"
                )
        return data

    async def _async_handle_remediation(self, response: dict[str, Any]) -> dict[str, Any]:
        """Inspect an IDX response and either finish login, trigger the next
        factor challenge automatically (e.g. requesting an SMS code be
        sent), or raise MfaRequired for the caller to supply a passcode.
        """
        self._state_handle = response.get("stateHandle", self._state_handle)

        success = response.get("success")
        if success and success.get("href"):
            return await self._async_finish_from_success_href(success["href"])

        remediation = ((response.get("remediation") or {}).get("value")) or []
        names = [r.get("name") for r in remediation]

        # Case 1: the next step just needs a passcode directly (e.g. TOTP,
        # or an SMS/voice factor that was already triggered) -- surface it
        # as MfaRequired so the config flow can prompt for a code.
        for rem in remediation:
            if rem.get("name") == "challenge-authenticator":
                fields = ((rem.get("value") or []))
                needs_passcode_only = any(
                    f.get("name") == "credentials" for f in fields
                ) and not any(f.get("name") == "authenticator" for f in fields)
                if needs_passcode_only:
                    self._factors = [{"id": "current"}]
                    raise MfaRequired(self._factors)

        # Case 2: the next step is choosing/triggering a factor (e.g. "send
        # me an SMS code") -- the real widget auto-selects the enrolled
        # phone factor and POSTs /idp/idx/challenge to trigger it, THEN asks
        # for the passcode. Auto-trigger the first available factor so the
        # user only ever has to type one code.
        for rem in remediation:
            if rem.get("name") == "authenticator-verification-data":
                authenticator = _extract_authenticator_option(rem)
                if authenticator:
                    self._authenticator = authenticator
                    triggered = await self._async_post_idx(
                        OKTA_IDX_CHALLENGE_URL,
                        {"authenticator": authenticator, "stateHandle": self._state_handle},
                        invalid_exc=MoAmWaterAuthError,
                    )
                    self._factors = [authenticator]
                    self._state_handle = triggered.get("stateHandle", self._state_handle)
                    raise MfaRequired(self._factors)

        raise MoAmWaterAuthError(
            f"Unexpected IDX remediation; don't know how to proceed: {names or response}"
        )

    async def _async_finish_from_success_href(self, href: str) -> dict[str, Any]:
        """Follow the `success.href` (the real `/login/token/redirect?stateToken=...`
        URL returned by Okta) to get our authorization `code`, then exchange it.
        """
        code_value = await self._walk_redirects_for_code(href)
        if not code_value:
            raise MoAmWaterAuthError(
                "Authorization redirect did not yield a 'code' query parameter"
            )
        tokens = await self._exchange_code_for_tokens(code_value)
        return {"access_token": tokens["access_token"], "refresh_token": tokens.get("refresh_token")}

    async def _walk_redirects_for_code(self, url: str) -> str | None:
        """Manually follow a redirect chain, extracting the `code` query param.

        Stops as soon as a hop's Location carries a `code` param, without
        letting aiohttp auto-follow past that point (MyWater's backend would
        otherwise consume the code server-side before we can read it).
        """
        current_url = url
        hops: list[str] = []
        for _ in range(8):
            async with self._session.get(
                current_url, allow_redirects=False, headers=_BROWSER_NAV_HEADERS
            ) as resp:
                location = resp.headers.get("Location")
                set_cookie_names = [c.key for c in resp.cookies.values()] if resp.cookies else []
                body_text = await resp.text()
                hops.append(
                    f"{resp.status} {current_url.split('?')[0]} "
                    f"(set-cookie: {set_cookie_names or 'none'}, "
                    f"location: {(location or 'none').split('?')[0]})"
                )
                if resp.status not in (301, 302, 303, 307, 308) and not location:
                    raise MoAmWaterAuthError(
                        f"Expected a redirect from Okta, got status {resp.status}. "
                        f"Hop trace: {' -> '.join(hops)}. Body: {body_text[:1500]}"
                    )

            candidate = location or str(current_url)
            query = parse_qs(urlparse(candidate).query)
            code = (query.get("code") or [None])[0]
            error = (query.get("error") or [None])[0]
            if error:
                error_desc = (query.get("error_description") or [error])[0]
                raise MoAmWaterAuthError(
                    f"Okta returned error: {error_desc}. Hop trace: {' -> '.join(hops)}"
                )
            if code:
                return code

            if not location:
                break
            current_url = location

        return None

    async def _exchange_code_for_tokens(self, code: str) -> dict[str, Any]:
        """POST {issuer}/v1/token to exchange our authorization code for tokens.

        No PKCE `code_verifier` is sent -- the real browser's /v1/authorize
        request never included a `code_challenge`, so none is expected here.
        """
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": OKTA_CLIENT_ID,
            "redirect_uri": OKTA_REDIRECT_URI,
        }
        async with self._session.post(
            TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded", **_BROWSER_HEADERS},
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


async def async_refresh_access_token(
    session: aiohttp.ClientSession, refresh_token: str
) -> dict[str, Any]:
    """Redeem a stored Okta `refresh_token` for a fresh `access_token`.

    Used on every restart/renewal after the initial interactive login, via
    `grant_type=refresh_token` -- an allowed grant for this Okta client.
    Okta typically rotates the refresh_token on each redemption -- callers
    MUST persist the new `refresh_token` value from the returned dict.
    """
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OKTA_CLIENT_ID,
        "scope": OKTA_SCOPES,
    }
    async with session.post(
        TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded", **_BROWSER_HEADERS},
    ) as resp:
        body_text = await resp.text()
        if resp.status != 200:
            raise MoAmWaterAuthError(
                f"Okta refresh_token exchange failed (status {resp.status}): {body_text[:500]}"
            )
        data = await resp.json(content_type=None)

    if "access_token" not in data:
        raise MoAmWaterAuthError(f"Refresh response missing access_token: {data}")
    return data


def _unescape_js_hex(js_literal: str) -> str:
    r"""Unescape JS `\xNN` hex-escape sequences into their literal characters.

    The embedded `oktaData` object is emitted as a JS string literal with
    e.g. `\x3A` for `:`, which is not valid JSON as-is.
    """
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), js_literal)


def _extract_authenticator_option(remediation_entry: dict[str, Any]) -> dict[str, Any] | None:
    """Pull {"id", "enrollmentId", "methodType"} for the first authenticator
    option out of an `authenticator-verification-data` remediation entry.

    Okta's IDX schema nests the enrollmentId/methodType pair for each
    selectable method inside `methodType.options[i].value.form.value[]`.
    This walks that structure defensively and falls back to "sms" (the only
    method type observed in the reference HAR capture) if the nested value
    can't be resolved, since `id` alone is enough to identify *which*
    authenticator (e.g. "Phone") -- only enrollmentId/methodType select
    *how* to challenge it.
    """
    for field in remediation_entry.get("value") or []:
        if field.get("name") != "authenticator":
            continue
        form_fields = (field.get("form") or {}).get("value") or []

        authenticator_id = None
        enrollment_id = None
        method_type = None
        for sub in form_fields:
            if sub.get("name") == "id" and sub.get("value"):
                authenticator_id = sub["value"]
            elif sub.get("name") == "methodType":
                options = sub.get("options") or []
                if options:
                    option = options[0]
                    option_value = option.get("value")
                    if isinstance(option_value, dict):
                        method_type = option_value.get("value")
                        nested_form = (option_value.get("form") or {}).get("value") or []
                        for nested in nested_form:
                            if nested.get("name") == "enrollmentId" and nested.get("value"):
                                enrollment_id = nested["value"]
                            elif nested.get("name") == "methodType" and nested.get("value"):
                                method_type = nested["value"]
                    else:
                        method_type = option_value

        if authenticator_id:
            return {
                "id": authenticator_id,
                "enrollmentId": enrollment_id,
                "methodType": method_type or "sms",
            }
    return None


def _idx_error_summary(data: dict[str, Any]) -> str:
    """Extract a human-readable error message from an IDX error response."""
    if not isinstance(data, dict):
        return str(data)[:500]
    messages = (data.get("messages") or {}).get("value") or []
    if messages:
        return "; ".join(m.get("message", "") for m in messages if m.get("message"))
    return str(data)[:500]
