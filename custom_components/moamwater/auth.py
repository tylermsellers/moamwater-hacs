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
          `redirect_uri` (https://mywaterv2.amwater.com/openidlogin?code=...
          &state=...).

    9. GET  that `openidlogin?code=...` URL. **Critically, the browser never
          calls Okta's `/v1/token` directly at all** -- confirmed by a full
          HAR capture containing zero requests to `/v1/token`. Instead,
          MyWater's own backend (mywaterv2.amwater.com) receives the `code`
          on this GET, does the authorization_code exchange with Okta
          server-side, and returns a 302 to `/#/enhancedportal` with the
          real session established via cookies on ITS OWN response:
            - `mw-authenticationToken` -- this is the exact bearer token
              value sent as `Authorization: bearer <this>` on every
              `/api/mso/data` call (verified byte-for-byte equal in the HAR).
            - `mw_refresh_token` -- an opaque ~43-char MyWater-issued
              refresh token (NOT an Okta refresh_token), scoped to
              Domain=amwater.com.
            - `mw_id_token`, `JSESSIONID`, `ATMOSPHEREID`, `SESSION` -- also
              set, but not needed for our API calls.
          So this client follows the redirect chain all the way through to
          THIS response (rather than stopping at the `code` query param) and
          reads `mw-authenticationToken`/`mw_refresh_token` straight out of
          its Set-Cookie headers.

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
  - After correctly implementing the full IDX handshake through step 8, this
    client tried POSTing `code` to Okta's own `{issuer}/v1/token` directly
    (matching the OAuth2 authorization_code spec) -- Okta rejected this with
    `401 invalid_client: Client authentication failed`. This is because the
    MyWater Okta app is registered as a CONFIDENTIAL client (needs a client
    secret we don't have and never will, since the SPA itself never calls
    this endpoint) -- the token exchange is done server-side by MyWater's
    own backend when the code is redeemed at `/openidlogin?code=...`, not by
    the browser/SPA. Confirmed via HAR: zero `/v1/token` requests appear
    anywhere in a full captured login session.

Also important: the captured `Authorization: bearer ...` header used by
MyWater's `/api/mso/data` calls is IDENTICAL to the `mw-authenticationToken`
cookie value set by MyWater's backend on the `/openidlogin?code=...`
response (verified byte-for-byte in the HAR) -- NOT an Okta access_token
obtained via `/v1/token` (that endpoint is never called by this client).

Avoiding reauth on every HA restart
-----------------------------------
A real browser never re-types a password/SMS code on every visit either --
it relies on two layers of persistence, both of which this integration now
mirrors:
  1. The `mw-authenticationToken` JWT itself is valid for ~10 hours (`exp` -
     `iat` in its payload). Most HA restarts are far shorter than that, so
     simply persisting the token + its `exp` claim into the config entry and
     skipping login entirely while it's still valid (see api.py's
     `async_login()`) avoids essentially all normal-restart reauths.
  2. For restarts (or outages) that DO outlast that ~10hr window, Okta's own
     `/v1/authorize` endpoint recognizes an existing, still-valid Okta
     session (via its own session cookies, e.g. `sid`) and redirects
     straight through to a fresh `code` WITHOUT showing the interactive
     widget at all -- this is the same SSO mechanism that lets a real user
     revisit the site without re-entering credentials. Because this
     integration uses a dedicated, persisted `aiohttp.ClientSession`
     (its cookie jar saved to disk in HA's storage dir on unload/shutdown
     and reloaded on setup -- see `__init__.py`), those Okta session cookies
     survive HA restarts too, so `async_try_silent_sso()` can often succeed
     even after the access_token has expired. Only when Okta's own session
     has ALSO expired (i.e. its cookie's server-side TTL, observed to be
     considerably longer than the ~10hr JWT, has lapsed) does this
     integration fall back to a full interactive login requiring a new SMS
     code -- and even then, only genuinely necessary.
"""
from __future__ import annotations

import base64
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

# Cookies Okta sets on the initial `/v1/authorize` GET that represent its own
# authenticated browser session (distinct from MyWater's own session
# cookies). If these are still valid on a later `/v1/authorize` GET, Okta
# recognizes the existing session and redirects straight through to a `code`
# without showing the interactive widget (standard OIDC/SSO "remember this
# browser" behavior) -- letting us skip password + SMS entirely.
OKTA_SESSION_COOKIE_NAMES = ("sid", "JSESSIONID", "t", "DT", "xids")


def decode_jwt_exp(token: str) -> float | None:
    """Return the `exp` (epoch seconds) claim from a JWT, or None if undecodable.

    Used to know how much longer a stored `mw-authenticationToken` is valid
    for, without needing to verify its signature (we don't have Okta's
    public key and don't need to -- MyWater's own API will reject it if it's
    actually invalid).
    """
    try:
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return None


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

    async def async_try_silent_sso(self) -> dict[str, Any] | None:
        """Attempt to obtain fresh tokens without any user interaction, by
        replaying `/v1/authorize` and hoping Okta's own session cookies
        (persisted in `self._session.cookie_jar` from a prior login) are
        still valid.

        If Okta still recognizes the browser session, `/v1/authorize`
        redirects straight through to our `redirect_uri` with a `code`
        (skipping the interactive widget entirely) -- in that case we walk
        the redirect chain the same way as a normal login's `success.href`
        and return a fresh token dict. Returns None (never raises, except on
        genuine network errors) if Okta's session has actually expired and
        the widget HTML is shown instead, so the caller can fall back to a
        full interactive login.
        """
        authorize_params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "scope": OKTA_SCOPES,
            "redirect_uri": OKTA_REDIRECT_URI,
            "state": secrets.token_urlsafe(16),
        }
        url = f"{AUTHORIZE_URL}?{urlencode(authorize_params)}"
        try:
            async with self._session.get(
                url, headers=_BROWSER_NAV_HEADERS, allow_redirects=False
            ) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        return None
                    _LOGGER.debug("Silent SSO: /v1/authorize redirected immediately, following chain")
                    return await self._walk_redirects_for_mywater_tokens(location)

                # A 200 here means Okta didn't recognize the session and
                # served the interactive Sign-In Widget HTML instead --
                # session expired, must fall back to full interactive login.
                _LOGGER.debug(
                    "Silent SSO: /v1/authorize returned status %s (no redirect); "
                    "Okta session has expired",
                    resp.status,
                )
                return None
        except (MoAmWaterAuthError, aiohttp.ClientError) as exc:
            _LOGGER.debug("Silent SSO attempt failed: %s", exc)
            return None

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
        _LOGGER.warning("IDX remediation step names: %s", names)
        if not any(n in ("authenticator-verification-data", "challenge-authenticator") for n in names):
            _LOGGER.warning("IDX full response (unrecognized remediation): %s", response)

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
                _LOGGER.warning("IDX chosen authenticator to trigger: %s (raw remediation: %s)", authenticator, rem)
                if authenticator:
                    self._authenticator = authenticator
                    triggered = await self._async_post_idx(
                        OKTA_IDX_CHALLENGE_URL,
                        {"authenticator": authenticator, "stateHandle": self._state_handle},
                        invalid_exc=MoAmWaterAuthError,
                    )
                    _LOGGER.warning("IDX challenge-trigger response: %s", triggered)
                    self._factors = [authenticator]
                    self._state_handle = triggered.get("stateHandle", self._state_handle)
                    raise MfaRequired(self._factors)

        raise MoAmWaterAuthError(
            f"Unexpected IDX remediation; don't know how to proceed: {names or response}"
        )

    async def _async_finish_from_success_href(self, href: str) -> dict[str, Any]:
        """Follow the `success.href` redirect chain all the way through
        MyWater's own `/openidlogin?code=...` redemption, then read the real
        session tokens straight out of the Set-Cookie headers on that final
        response (see module docstring step 9 -- Okta's `/v1/token` is never
        called at all in the real flow).
        """
        return await self._walk_redirects_for_mywater_tokens(href)

    async def _walk_redirects_for_mywater_tokens(self, url: str) -> dict[str, Any]:
        """Manually follow the full redirect chain from Okta's success href
        through to MyWater's own `/openidlogin?code=...&state=...` request,
        and return the `mw-authenticationToken`/`mw_refresh_token` cookies
        MyWater's backend sets on that response.

        We must follow every hop ourselves (not let aiohttp auto-follow)
        since the final hop's tokens live in Set-Cookie headers on a 302
        response, which aiohttp would otherwise swallow while chasing the
        Location header further.
        """
        current_url = url
        hops: list[str] = []
        for _ in range(8):
            async with self._session.get(
                current_url, allow_redirects=False, headers=_BROWSER_NAV_HEADERS
            ) as resp:
                location = resp.headers.get("Location")
                cookies = {c.key: c.value for c in resp.cookies.values()} if resp.cookies else {}
                body_text = await resp.text()
                hops.append(
                    f"{resp.status} {current_url.split('?')[0]} "
                    f"(set-cookie: {list(cookies) or 'none'}, "
                    f"location: {(location or 'none').split('?')[0]})"
                )

                if "mw-authenticationToken" in cookies:
                    return {
                        "access_token": cookies["mw-authenticationToken"],
                        "refresh_token": cookies.get("mw_refresh_token"),
                    }

                if resp.status not in (301, 302, 303, 307, 308) and not location:
                    raise MoAmWaterAuthError(
                        f"Expected a redirect, got status {resp.status} without the "
                        f"mw-authenticationToken cookie. Hop trace: {' -> '.join(hops)}. "
                        f"Body: {body_text[:1500]}"
                    )

            candidate = location or str(current_url)
            query = parse_qs(urlparse(candidate).query)
            error = (query.get("error") or [None])[0]
            if error:
                error_desc = (query.get("error_description") or [error])[0]
                raise MoAmWaterAuthError(
                    f"Okta returned error: {error_desc}. Hop trace: {' -> '.join(hops)}"
                )

            if not location:
                break
            current_url = location

        raise MoAmWaterAuthError(
            f"Redirect chain never yielded the mw-authenticationToken cookie. "
            f"Hop trace: {' -> '.join(hops)}"
        )


def async_refresh_access_token(*_args: Any, **_kwargs: Any) -> Any:
    """Removed: MyWater's Okta app is a confidential OAuth client (needs a
    client secret we don't have), so `grant_type=refresh_token` against
    Okta's `/v1/token` fails with the same `401 invalid_client` error as the
    `authorization_code` exchange did (see module docstring). There is also
    no MyWater-side endpoint for redeeming `mw_refresh_token` captured in
    any HAR so far. Kept as a stub (rather than deleting outright) so any
    stale imports fail loudly instead of silently; callers should always
    fall back to a full interactive login via `MoAmWaterAuthClient` instead.
    """
    raise MoAmWaterAuthError(
        "Token refresh is not supported for this Okta app (confidential client); "
        "perform a full interactive login instead"
    )


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
            elif sub.get("name") == "enrollmentId" and sub.get("value"):
                enrollment_id = sub["value"]
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
