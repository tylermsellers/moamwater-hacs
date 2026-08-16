"""API client for the Missouri American Water MyWater portal.

Wraps the `/api/mso/data` MSO ("Model-Service-Object") endpoint discovered via
DevTools network capture. Every call POSTs a `UIRequestParameters`-shaped
payload identifying the account (businessPartnerNumber / connectionContractNumber
/ premiseId) and the specific chart/report ("microApplicationId") being requested.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import aiohttp

from .auth import MoAmWaterAuthClient, MfaRequired, decode_jwt_exp
from .const import (
    APPLICATION_ID,
    MICRO_APP_DAILY,
    MICRO_APP_HOURLY,
    MICRO_APP_MONTHLY_12,
    MYWATER_BASE_URL,
    MYWATER_DATA_ENDPOINT,
    MYWATER_MICROAPP_ENDPOINT,
    SOLUTION_ID,
    SOLUTION_PAGE_ID,
)

_LOGGER = logging.getLogger(__name__)

DATA_URL = f"{MYWATER_BASE_URL}{MYWATER_DATA_ENDPOINT}"
MICROAPP_URL = f"{MYWATER_BASE_URL}{MYWATER_MICROAPP_ENDPOINT}"
PIPELINE_ACCOUNT_SUMMARY = "com::apporchid::cloudseer::mso::myaccountsummarypipeline"
PIPELINE_CUSTOMER_PROFILE = "com::apporchid::cloudseer::mso::customer_profile_pipeline"


class MoAmWaterApiError(Exception):
    """Raised for any non-auth API failure (network error, unexpected shape)."""


class _Unauthorized(Exception):
    """Internal sentinel: the MSO endpoint returned 401 for the current access_token."""

    def __init__(self, access_token: str) -> None:
        super().__init__("MyWater rejected the current access token")
        self.access_token = access_token


class MoAmWaterApiClient:
    """Thin async client for MyWater's usage/account MSO endpoints."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        refresh_token: str | None = None,
        access_token: str | None = None,
        access_token_expires_at: float | None = None,
    ) -> None:
        self._session = session
        self._username = username
        self._password = password
        self._auth = MoAmWaterAuthClient(session)
        self._access_token: str | None = access_token
        self._access_token_expires_at: float | None = access_token_expires_at
        self.refresh_token: str | None = refresh_token

        self.business_partner_number: str | None = None
        self.connection_contract_number: str | None = None
        self.premise_id: str | None = None
        self.state_code: str = "MO"

        # Last time we successfully confirmed Okta's own session is alive
        # (via a real login OR a silent SSO replay) -- see
        # async_maintain_okta_session()'s docstring for why this exists.
        self._last_okta_touch: float | None = None
        self._login_lock = asyncio.Lock()

    @property
    def access_token(self) -> str | None:
        return self._access_token

    @property
    def access_token_expires_at(self) -> float | None:
        return self._access_token_expires_at

    def _store_tokens(self, result: dict[str, Any]) -> None:
        self._access_token = result["access_token"]
        self.refresh_token = result.get("refresh_token") or self.refresh_token
        self._access_token_expires_at = decode_jwt_exp(self._access_token)
        self._last_okta_touch = time.time()
        # Diagnostic only (never log the value itself): confirms on every
        # successful login/silent-SSO whether `mw_refresh_token` was
        # actually captured, so a future manual browser test of whether
        # MyWater redeems it anywhere can at least confirm this client
        # captures the same cookie a real browser session would have had
        # available to it.
        _LOGGER.debug(
            "Tokens stored: access_token expires at %s; mw_refresh_token present: %s (len %s)",
            self._access_token_expires_at,
            bool(self.refresh_token),
            len(self.refresh_token) if self.refresh_token else 0,
        )

    def _has_valid_access_token(self) -> bool:
        """Return whether the current token is safe to use for a poll."""
        return bool(
            self._access_token
            and self._access_token_expires_at
            and self._access_token_expires_at - time.time() > 300
        )

    async def _async_reauthenticate(
        self,
        *,
        allow_otp_send: bool,
        stale_access_token: str | None = None,
    ) -> None:
        """Serialize token recovery and optionally try a guarded password login."""
        async with self._login_lock:
            # Another concurrent request may already have refreshed the token
            # while this caller waited for the lock.
            if stale_access_token is not None:
                if self._access_token != stale_access_token:
                    return
            elif self._has_valid_access_token():
                return

            sso_result = await self._auth.async_try_silent_sso()
            if sso_result is not None:
                _LOGGER.debug(
                    "MyWater login completed via silent Okta SSO replay "
                    "(no reauth needed)"
                )
                self._store_tokens(sso_result)
                return

            if not allow_otp_send:
                # Confirmed (2026-08-15 logs): Okta rejects an unattended
                # password+DT login for this account outright, returning an
                # `authenticator-verification-data` remediation that demands
                # a fresh MFA challenge even with the persisted DT
                # device-trust cookie presented. So this background path
                # never actually succeeds -- it only wastes a password
                # submission (with real account-lockout/anomaly-detection
                # exposure) on every access_token expiry that outlasts the
                # `sid` cookie. Go straight to reauth instead of attempting
                # it; a real interactive login (with allow_otp_send=True,
                # from the config flow) is the only path that can ever
                # succeed once silent SSO has failed.
                raise MfaRequired([])

            _LOGGER.info("Silent SSO failed; attempting interactive password login")
            result = await self._auth.async_start_login(
                self._username,
                self._password,
                allow_otp_send=allow_otp_send,
            )
            self._store_tokens(result)

    async def async_login(self, *, allow_interactive: bool = True) -> None:
        """Log in, avoiding a full interactive (password + SMS) login whenever possible.

        Three-tier strategy, in order of preference:
          1. If we already hold an access_token that hasn't expired yet
             (with a safety margin), skip login entirely and keep using it.
             This is what makes most HA restarts (which are far shorter than
             the ~10hr token lifetime) require no reauth at all.
          2. Otherwise, try a silent SSO replay of `/v1/authorize`: if Okta's
             own session cookies (persisted in the shared aiohttp session's
             cookie jar) are still valid, Okta redirects straight through to
             a fresh `code` without showing the interactive widget, letting
             us mint a new access_token with zero user interaction even
             after the access_token itself has expired.
          3. If both token paths fail, submit the stored password with the
             persisted DT device-trust cookie. Background callers set
             `allow_interactive=False`, which allows an immediate success
             when Okta remembers the device but blocks this client's
             explicit `/idp/idx/challenge` request if MFA is still required.
             The config flow uses `allow_interactive=True`, so a user who is
             present can request and enter the OTP normally.
        """
        if self._has_valid_access_token():
            _LOGGER.debug("Reusing stored MyWater access_token (not yet expired)")
            return

        await self._async_reauthenticate(allow_otp_send=allow_interactive)

    async def async_submit_mfa(self, passcode: str) -> None:
        """Complete login after an MFA challenge was raised by async_login()."""
        result = await self._auth.async_submit_mfa(passcode)
        self._store_tokens(result)

    async def async_maintain_okta_session(self, *, min_interval_seconds: float = 3600) -> None:
        """Proactively replay `/v1/authorize` to keep Okta's own session alive,
        instead of only doing so when the ~10hr MyWater access_token expires.

        Why this exists: `async_login()`'s tier 2 (silent SSO) only ever gets
        exercised when the access_token has already expired -- roughly every
        10 hours. If MoAmWater's Okta tenant enforces an *idle* timeout
        shorter than that gap (common for utility SSO tenants, e.g. 1-2hrs
        of no activity), Okta's session cookie is already dead by the time
        we go to use it, forcing an unnecessary full interactive reauth even
        though the session would have stayed alive with more frequent
        activity. Calling this once an hour (piggybacked on the regular
        coordinator poll, well inside a plausible idle-timeout window) resets
        Okta's idle timer far more often, so only a tenant-enforced *absolute*
        session lifetime (which no amount of activity can extend) would still
        force a reauth.

        This is best-effort and never raises: a failure here just means the
        next `async_login()` call will discover the dead session itself (and
        fall back to reauth) the normal way.
        """
        now = time.time()
        if self._last_okta_touch is not None and now - self._last_okta_touch < min_interval_seconds:
            return

        elapsed = None if self._last_okta_touch is None else now - self._last_okta_touch
        try:
            sso_result = await self._auth.async_try_silent_sso()
        except Exception:  # noqa: BLE001 - keep-alive must never break a poll
            _LOGGER.debug("Okta session keep-alive ping raised unexpectedly", exc_info=True)
            return

        if sso_result is not None:
            self._store_tokens(sso_result)
            _LOGGER.debug(
                "Okta session keep-alive succeeded (%.0f min since last touch); "
                "idle timer reset",
                (elapsed or 0) / 60,
            )
        else:
            # Promoted to WARNING (from INFO): the `%.0f min` figure is a
            # direct measurement of how much idle time Okta's tenant
            # actually tolerates before `sid` dies, which is exactly what's
            # needed to tell whether `min_interval_seconds` (currently 1hr)
            # is too infrequent to ever catch the session while still alive.
            # An INFO line here would be silently dropped on instances with
            # file logging disabled, same reasoning as the WARNING promotion
            # in auth.py's async_try_silent_sso() (v1.1.4).
            _LOGGER.warning(
                "Okta session keep-alive found the session already expired "
                "(%.0f min since last confirmed-alive touch). This suggests "
                "MoAmWater's Okta tenant enforces a session lifetime shorter "
                "than that, which cannot be extended by activity alone; a "
                "full reauth will be required next.",
                (elapsed or 0) / 60,
            )

    async def _post(self, payload: dict[str, Any], *, url: str = DATA_URL) -> dict[str, Any]:
        try:
            return await self._post_once(payload, url=url)
        except _Unauthorized as unauthorized:
            # The access_token expired mid-session (poll interval can span
            # hours). Try a silent Okta SSO replay before giving up -- this
            # avoids surfacing MfaRequired for something that's often
            # recoverable with zero user interaction (see async_login()).
            _LOGGER.debug("MyWater request got 401; attempting guarded relogin")
            await self._async_reauthenticate(
                allow_otp_send=False,
                stale_access_token=unauthorized.access_token,
            )
            try:
                return await self._post_once(payload, url=url)
            except _Unauthorized as exc:
                raise MfaRequired([]) from exc

    async def _post_once(self, payload: dict[str, Any], *, url: str = DATA_URL) -> dict[str, Any]:
        access_token = self._access_token
        if not access_token:
            raise MoAmWaterApiError("Not authenticated; call async_login() first")
        headers = {
            "Authorization": f"bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
        }
        try:
            async with self._session.post(url, json=payload, headers=headers) as resp:
                if resp.status == 401:
                    raise _Unauthorized(access_token)
                if resp.status >= 400:
                    body = await resp.text()
                    request_name = payload.get("microApplicationId") or payload.get("pipelineId")
                    raise MoAmWaterApiError(
                        f"MyWater API HTTP {resp.status} for {request_name} ({url}): "
                        f"{body[:500] or '(empty body)'}"
                    )
                return await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise MoAmWaterApiError(f"Request to MyWater failed: {exc}") from exc

    @staticmethod
    def _pipeline_payload(pipeline_id: str, key_value_map: dict[str, Any]) -> dict[str, Any]:
        """Build the PipelineServiceModel request shape expected by /api/mso/data."""
        return {
            "pipelineId": pipeline_id,
            "requestParameters": {
                "@class": "com.apporchid.common.UIRequestParameters",
                "keyValueMap": key_value_map,
            },
        }

    async def async_discover_account(self) -> None:
        """Fetch the customer profile pipeline to learn account identifiers.

        Mirrors the `customer_profile_pipeline` MSO call captured on page load,
        which returns the businessPartnerNumber / connectionContractNumber /
        premiseId needed for every subsequent usage request.
        """
        summary = await self._post(
            self._pipeline_payload(PIPELINE_ACCOUNT_SUMMARY, {"queryParams": None})
        )
        summary_rows = summary.get("data") or []
        if not summary_rows:
            raise MoAmWaterApiError("Account summary lookup returned no records")

        first = summary_rows[0]
        info = (first.get("additionalInformation") or {}).get("IntermediaryPageDetails") or []
        details = info[0] if info else {}
        self.business_partner_number = details.get("businessPartnerNumber")
        # API expects this field name, but the account-summary payload calls it
        # contractAccountNumber.
        self.connection_contract_number = details.get("contractAccountNumber")
        # API expects premiseId; account summary returns premiseNumber.
        self.premise_id = details.get("premiseNumber")
        self.state_code = details.get("state") or "MO"

        if not all([self.business_partner_number, self.connection_contract_number, self.premise_id]):
            raise MoAmWaterApiError(
                "Could not determine account identifiers from account summary response"
            )

        # Validate identifiers against the profile pipeline used by the portal.
        profile = await self._post(
            self._pipeline_payload(
                PIPELINE_CUSTOMER_PROFILE,
                {
                    "queryParams": {
                        "businessPartnerNumber": self.business_partner_number,
                        "connectionContractNumber": self.connection_contract_number,
                        "premiseId": self.premise_id,
                    }
                },
            )
        )
        profile_rows = profile.get("data") or []
        if profile_rows:
            rec = profile_rows[0]
            self.business_partner_number = rec.get("businessPartnerNumber") or self.business_partner_number
            self.connection_contract_number = (
                rec.get("connectionContractNumber") or self.connection_contract_number
            )
            self.premise_id = rec.get("premiseId") or self.premise_id
            self.state_code = rec.get("stateCode") or rec.get("premiseStateCode") or self.state_code

    def _usage_payload(self, micro_app_id: str, days: str = "") -> dict[str, Any]:
        selected_val = ""
        if micro_app_id != MICRO_APP_HOURLY and days:
            selected_val = days

        return {
            "solutionId": SOLUTION_ID,
            "applicationId": APPLICATION_ID,
            "microApplicationId": micro_app_id,
            "solutionPageId": SOLUTION_PAGE_ID,
            "renderType": "CONFIG_AND_DATA",
            "userOptions": {
                "@class": "com.apporchid.vulcanux.common.ui.data.UserOptions",
                "locale": "en-US",
                "timeZone": "America/Chicago",
                "screenWidth": 1920,
                "screenHeight": 1080,
                "orientation": 0,
                "orientationType": "Portrait",
            },
            "keyValueMap": {
                "queryParams": {
                    "businessPartnerNumber": self.business_partner_number,
                    "connectionContractNumber": self.connection_contract_number,
                    "premiseId": self.premise_id,
                    "billMonth": "",
                    "limitRecords": 2,
                    "regionName": self.state_code,
                    "startDate": "",
                    "endDate": "",
                    "source": "",
                    "premiseStateCode": self.state_code,
                    "stateCode": self.state_code,
                    "serviceUrl": "",
                    "accountType": "",
                    "days": days,
                    "selectedVal": selected_val,
                }
            },
            "@class": "com.apporchid.common.UIRequestParameters",
            "isDebug": False,
        }

    @staticmethod
    def _extract_series(chart_response: dict[str, Any]) -> dict[str, list]:
        """Pull the Highcharts `series`/`categories` payload out of a chart MSO response.

        Returns {"categories": [...], "series": {name: [values...]}}.
        """
        component = chart_response.get("component", {})
        categories = (component.get("xAxis") or {}).get("categories", [])
        series_out: dict[str, list] = {}
        for series in component.get("series", []):
            name = series.get("name", series.get("id", "series"))
            # Each data point is [index, value, {tooltip/meta}] per captured payload.
            values = [point[1] if isinstance(point, list) and len(point) > 1 else point
                      for point in series.get("data", [])]
            series_out[name] = values
        return {"categories": categories, "series": series_out}

    async def async_get_hourly_usage(self) -> dict[str, list]:
        """Return today's hourly usage (gallons) — 'Actual Usage' series, 24 entries."""
        data = await self._post(self._usage_payload(MICRO_APP_HOURLY, days="1"), url=MICROAPP_URL)
        return self._extract_series(data)

    async def async_get_daily_usage(self, days: int = 30) -> dict[str, list]:
        """Return daily usage (gallons) for the last `days` days."""
        data = await self._post(self._usage_payload(MICRO_APP_DAILY, days=str(days)), url=MICROAPP_URL)
        return self._extract_series(data)

    async def async_get_monthly_usage(self) -> dict[str, list]:
        """Return the last 12 months of usage (gallons)."""
        data = await self._post(self._usage_payload(MICRO_APP_MONTHLY_12, days="12"), url=MICROAPP_URL)
        return self._extract_series(data)
