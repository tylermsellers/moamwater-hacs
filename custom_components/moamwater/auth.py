"""Okta IDX authentication client for Missouri American Water's MyWater portal.

This replicates the browser login flow captured via DevTools:

    POST {OKTA_BASE_URL}/idp/idx/introspect          -> stateHandle
    POST {OKTA_BASE_URL}/idp/idx/identify             -> submit username
    POST {OKTA_BASE_URL}/idp/idx/challenge/answer      -> submit password
    POST {OKTA_BASE_URL}/idp/idx/challenge             -> select MFA factor (if needed)
    POST {OKTA_BASE_URL}/idp/idx/challenge/answer      -> submit MFA passcode
    GET  {OKTA_BASE_URL}{authorize redirect}/redirect  -> 302 with Okta session
    GET  {MYWATER_BASE_URL}/openidlogin?code=...       -> 302, MyWater exchanges code,
                                                           sets JSESSIONID/mw_id_token/SESSION cookies

Because MyWater's backend performs the final code exchange itself (rather than the
SPA calling Okta's /token endpoint directly), we let the redirect chain play out and
recover the bearer token from the `mw_id_token` cookie that MyWater sets, mirroring
what the browser does. If MyWater ever changes to a client-side token exchange, only
`_finish_login_redirect` needs to change.
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
AUTHORIZE_URL = f"{OKTA_BASE_URL}{OKTA_ISSUER_PATH}/v1/authorize"


class MoAmWaterAuthError(Exception):
    """Raised when authentication with Okta/MyWater fails."""


class MfaRequired(Exception):
    """Raised when an MFA challenge must be answered to continue login."""

    def __init__(self, state_handle: str, factors: list[dict[str, Any]]):
        super().__init__("MFA challenge required")
        self.state_handle = state_handle
        self.factors = factors


def _gen_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier/code_challenge pair (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class MoAmWaterAuthClient:
    """Handles the multi-step Okta IDX login and MyWater session/token retrieval."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session
        self._state_handle: str | None = None
        self._code_verifier: str | None = None

    async def async_start_login(self, username: str, password: str) -> dict[str, Any] | MfaRequired:
        """Begin login: introspect, identify (username), then answer (password).

        Returns the token dict on immediate success (no MFA configured), or raises
        MfaRequired if a factor challenge must be completed via async_submit_mfa().
        """
        code_verifier, code_challenge = _gen_pkce_pair()
        self._code_verifier = code_verifier

        # Step 1: kick off the authorize request to obtain an interaction/state handle.
        # Okta's IDX flow is normally fronted by a GET to /v1/authorize with PKCE params;
        # the SPA then introspects the resulting `stateToken`/`interactionHandle`.
        params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "response_mode": "fragment" if False else "query",
            "scope": OKTA_SCOPES,
            "redirect_uri": OKTA_REDIRECT_URI,
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        async with self._session.get(AUTHORIZE_URL, params=params, allow_redirects=False) as resp:
            # Okta responds with a redirect into the interaction handle / signin widget;
            # extract the state handle it embeds for use in idx calls.
            location = resp.headers.get("Location", "")
            interaction_code = None
            if location:
                q = parse_qs(urlparse(location).query)
                interaction_code = q.get("interaction_code", [None])[0]

        # Step 2: introspect to get a stateHandle for the idx/* endpoints.
        async with self._session.post(
            IDX_INTROSPECT,
            json={"interactionHandle": interaction_code} if interaction_code else {},
            headers={"Content-Type": "application/ion+json; okta-version=1.0.0"},
        ) as resp:
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle")
            if not self._state_handle:
                raise MoAmWaterAuthError(f"No stateHandle from introspect: {data}")

        # Step 3: identify (submit username).
        async with self._session.post(
            IDX_IDENTIFY,
            json={"identifier": username, "stateHandle": self._state_handle},
            headers={"Content-Type": "application/json"},
        ) as resp:
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle", self._state_handle)

        # Step 4: answer with password.
        async with self._session.post(
            IDX_CHALLENGE_ANSWER,
            json={"credentials": {"passcode": password}, "stateHandle": self._state_handle},
            headers={"Content-Type": "application/json"},
        ) as resp:
            data = await resp.json(content_type=None)
            self._state_handle = data.get("stateHandle", self._state_handle)

        # Determine whether MFA is required by inspecting `remediation.value` for a
        # `select-authenticator-authenticate` or `challenge-authenticator` step.
        remediation = (data.get("remediation") or {}).get("value", [])
        for step in remediation:
            if step.get("name") in ("select-authenticator-authenticate", "challenge-authenticator"):
                factors = (
                    step.get("value", [{}])[0]
                    .get("options", [])
                )
                raise MfaRequired(self._state_handle, factors)

        return await self._finish_login_redirect(data)

    async def async_submit_mfa(self, passcode: str) -> dict[str, Any]:
        """Submit the MFA passcode (SMS/email/TOTP code) to complete login."""
        if not self._state_handle:
            raise MoAmWaterAuthError("No active login session; call async_start_login first")

        async with self._session.post(
            IDX_CHALLENGE_ANSWER,
            json={"credentials": {"passcode": passcode}, "stateHandle": self._state_handle},
            headers={"Content-Type": "application/json"},
        ) as resp:
            data = await resp.json(content_type=None)

        return await self._finish_login_redirect(data)

    async def _finish_login_redirect(self, idx_response: dict[str, Any]) -> dict[str, Any]:
        """Follow the success redirect chain to MyWater and recover session/tokens.

        On success, the idx response contains a `success` remediation with a `href`
        pointing at an Okta authorize/redirect URL. Following it (and the subsequent
        redirect into MyWater's /openidlogin) causes MyWater's backend to set the
        session cookies (JSESSIONID, mw_id_token, SESSION) that authenticate all
        subsequent /api/mso/data calls.
        """
        success = (idx_response.get("success") or {})
        redirect_href = success.get("href")
        if not redirect_href:
            raise MoAmWaterAuthError(f"Login did not complete successfully: {idx_response}")

        # Follow the redirect chain fully (Okta -> MyWater /openidlogin -> MyWater home).
        # aiohttp follows redirects by default when allow_redirects=True (the default),
        # and the ClientSession's cookie jar will retain the cookies MyWater sets.
        async with self._session.get(redirect_href) as resp:
            await resp.read()

        cookies = self._session.cookie_jar.filter_cookies(OKTA_REDIRECT_URI)
        mw_id_token = cookies.get("mw_id_token")
        if not mw_id_token:
            # Some deployments store it under a different cookie domain; fall back to
            # scanning the whole jar.
            for cookie in self._session.cookie_jar:
                if cookie.key == "mw_id_token":
                    mw_id_token = cookie
                    break

        if not mw_id_token:
            raise MoAmWaterAuthError(
                "Login redirect completed but no mw_id_token cookie was found; "
                "MyWater may require the SPA's client-side token exchange instead."
            )

        return {"mw_id_token": mw_id_token.value}
