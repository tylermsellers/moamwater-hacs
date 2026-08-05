"""Okta authentication client for Missouri American Water's MyWater portal.

Login flow used by this client (classic Okta AuthN API + authorization_code,
WITHOUT PKCE -- confirmed against a real captured browser trace):

    GET  {OKTA_BASE_URL}{issuer}/v1/authorize?client_id=...&response_type=code&
         scope=...&redirect_uri=...&state=...                      -> the real
      MyWater SPA hits this FIRST, before any credentials are submitted. It
      returns status 200 with the Okta Sign-In Widget's HTML host page (not a
      redirect), and -- critically -- establishes an Okta transaction/session
      tied to this exact `state` value via response cookies. We must issue
      this GET (and keep its cookies in our aiohttp session) before doing
      anything else, or the later sessionToken redemption has no transaction
      to attach to and Okta just re-serves the same HTML widget page again.
    POST {OKTA_BASE_URL}/api/v1/authn                          -> primary auth
      (username/password), reusing the cookie jar from the GET above. Returns
      status "SUCCESS" with a `sessionToken`, or status "MFA_REQUIRED" with a
      list of enrolled `factors` plus a `stateToken` used to drive the MFA
      step.
    POST {OKTA_BASE_URL}/api/v1/authn/factors/{id}/verify        -> submit the
      passcode for the chosen factor; on success also returns a
      `sessionToken`.
    GET  {OKTA_BASE_URL}/login/token/redirect?stateToken=<sessionToken>  -> a
         Firefox HAR capture of a REAL live login proved this is the actual
      redemption endpoint (NOT `/v1/authorize?sessionToken=...`, which this
      org's Identity Engine tenant does not support -- it just re-serves the
      HTML widget with status 200, confirmed twice in prior live tests). This
      endpoint immediately 302-redirects straight to our real `redirect_uri`
      with `code` and `state` query params, e.g.
      `Location: https://mywaterv2.amwater.com/openidlogin?code=...&state=...`.
      Despite the query param being named `stateToken`, the value passed here
      is the same `sessionToken` string returned by `/api/v1/authn` (classic
      AuthN API terminology reuses "state"/"session" loosely) -- confirmed
      against the HAR, whose request cookies included the same `JSESSIONID`
      established earlier in the browser session (no separate /v1/authorize
      GET was present in that capture at all).
    POST {OKTA_BASE_URL}{issuer}/v1/token (grant_type=authorization_code, NO
         code_verifier/PKCE -- the real browser's flow never used PKCE)
      -> exchanges that `code` for the real `access_token` used as the
      credential for `/api/mso/data`.

IMPORTANT history of failed approaches (do not repeat these mistakes):
  - An earlier version attempted Okta's newer Identity Engine "Interaction
    Code" flow (`POST /v1/interact`), but this Okta app registration only has
    `authorization_code`, `password`, and `refresh_token` grants enabled --
    `/v1/interact` reliably fails with `unauthorized_client: The client is
    not authorized to use the provided grant type`.
  - A later version added PKCE and generated a brand-new `/v1/authorize` URL
    (new `state`, new code_challenge) only AFTER obtaining the sessionToken,
    without ever having done an initial unauthenticated GET first. This
    always returned status 200 with the interactive HTML widget instead of a
    302, because there was no prior transaction for the sessionToken to
    redeem against.
  - A subsequent version tried pre-opening an unauthenticated `/v1/authorize`
    GET first (to open a transaction/cookies), then re-hitting that exact
    same URL with `&sessionToken=...` appended. This STILL returned status
    200 with the widget HTML even though the session cookies (JSESSIONID,
    sid, xids) were present -- proving `/v1/authorize?sessionToken=...` is
    simply not a supported redemption mechanism for this Identity Engine
    org, no matter how the transaction/cookies are set up. The correct
    mechanism (`/login/token/redirect?stateToken=...`) was only discovered
    from a HAR capture of a real successful login.

Also important: the captured `Authorization: bearer ...` header used by
MyWater's `/api/mso/data` calls decodes as an Okta **access token** (JWT
claims `cid`, `uid`, `scp`), which is a *different* token from the
`mw_id_token` cookie (JWT claims `sub`, `name`, `email` -- an **ID token**).
This client requests the access_token directly from the `/v1/token`
exchange rather than scraping cookies.
"""
from __future__ import annotations

import logging
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
    MYWATER_BASE_URL,
)

_LOGGER = logging.getLogger(__name__)

TOKEN_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/token"

# Okta's WAF/bot-detection returns a bare 403 for requests that don't look
# like a real browser (missing User-Agent/Referer/Sec-Fetch-* etc). A real
# Firefox login was captured returning a clean 302 with these headers
# present, so we send a realistic browser header set on every request in
# this flow rather than aiohttp's default (near-empty) headers.
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
    "Referer": f"{MYWATER_BASE_URL}/",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

_JSON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    **_BROWSER_HEADERS,
}


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
    """Handles the multi-step Okta AuthN login and authorization_code exchange."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session
        self._state_token: str | None = None
        self._factors: list[dict[str, Any]] = []

    async def async_start_login(self, username: str, password: str) -> dict[str, Any]:
        """Begin login via the classic Okta AuthN API (/api/v1/authn).

        Returns the token dict on immediate success (no MFA configured), or
        raises MfaRequired if a factor challenge must be completed via
        async_submit_mfa().
        """
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

    def _build_token_redirect_url(self, session_token: str) -> str:
        """Build the `/login/token/redirect?stateToken=...` redemption URL.

        Confirmed via a HAR capture of a real successful login: despite the
        param being named `stateToken`, the value is the `sessionToken`
        string returned by `/api/v1/authn` (or its MFA-verify equivalent).
        This single GET 302-redirects straight to our real `redirect_uri`
        with `code`/`state` query params -- no prior `/v1/authorize` call
        or PKCE is involved at all.
        """
        return f"{OKTA_BASE_URL}/login/token/redirect?{urlencode({'stateToken': session_token})}"

    async def _async_finish_with_session_token(self, session_token: str) -> dict[str, Any]:
        """Redeem an Okta `sessionToken` via `/login/token/redirect`, then get tokens."""
        redeem_url = self._build_token_redirect_url(session_token)

        code_value = await self._walk_redirects_for_code(redeem_url)
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
