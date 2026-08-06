"""API client for the Missouri American Water MyWater portal.

Wraps the `/api/mso/data` MSO ("Model-Service-Object") endpoint discovered via
DevTools network capture. Every call POSTs a `UIRequestParameters`-shaped
payload identifying the account (businessPartnerNumber / connectionContractNumber
/ premiseId) and the specific chart/report ("microApplicationId") being requested.
"""
from __future__ import annotations

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
    SOLUTION_ID,
    SOLUTION_PAGE_ID,
)

_LOGGER = logging.getLogger(__name__)

DATA_URL = f"{MYWATER_BASE_URL}{MYWATER_DATA_ENDPOINT}"
PIPELINE_ACCOUNT_SUMMARY = "com::apporchid::cloudseer::mso::myaccountsummarypipeline"
PIPELINE_CUSTOMER_PROFILE = "com::apporchid::cloudseer::mso::customer_profile_pipeline"


class MoAmWaterApiError(Exception):
    """Raised for any non-auth API failure (network error, unexpected shape)."""


class _Unauthorized(Exception):
    """Internal sentinel: the MSO endpoint returned 401 for the current access_token."""


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

    async def async_login(self) -> None:
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
          3. Only if both of those fail (Okta's own session has *also*
             expired) do we fall back to a full interactive login, which
             raises MfaRequired so the caller can prompt for a new SMS code.
        """
        if self._access_token and self._access_token_expires_at:
            # 5 minute safety margin so we don't start a poll cycle with a
            # token that expires mid-request.
            if self._access_token_expires_at - time.time() > 300:
                _LOGGER.debug("Reusing stored MyWater access_token (not yet expired)")
                return

        sso_result = await self._auth.async_try_silent_sso()
        if sso_result is not None:
            _LOGGER.debug("MyWater login completed via silent Okta SSO replay (no reauth needed)")
            self._store_tokens(sso_result)
            return

        result = await self._auth.async_start_login(self._username, self._password)
        self._store_tokens(result)

    async def async_submit_mfa(self, passcode: str) -> None:
        """Complete login after an MFA challenge was raised by async_login()."""
        result = await self._auth.async_submit_mfa(passcode)
        self._store_tokens(result)

    def _headers(self) -> dict[str, str]:
        if not self._access_token:
            raise MoAmWaterApiError("Not authenticated; call async_login() first")
        return {
            "Authorization": f"bearer {self._access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
        }

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return await self._post_once(payload)
        except _Unauthorized:
            # The access_token expired mid-session (poll interval can span
            # hours). Try a silent Okta SSO replay before giving up -- this
            # avoids surfacing MfaRequired for something that's often
            # recoverable with zero user interaction (see async_login()).
            _LOGGER.debug("MyWater request got 401; attempting silent SSO relogin")
            sso_result = await self._auth.async_try_silent_sso()
            if sso_result is None:
                raise MoAmWaterApiError(
                    "MyWater session expired; re-authentication (with a new SMS code) is required"
                )
            self._store_tokens(sso_result)
            try:
                return await self._post_once(payload)
            except _Unauthorized as exc:
                raise MoAmWaterApiError(
                    "MyWater session expired; re-authentication (with a new SMS code) is required"
                ) from exc

    async def _post_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with self._session.post(DATA_URL, json=payload, headers=self._headers()) as resp:
                if resp.status == 401:
                    raise _Unauthorized()
                if resp.status >= 400:
                    body = await resp.text()
                    request_name = payload.get("microApplicationId") or payload.get("pipelineId")
                    raise MoAmWaterApiError(
                        f"MyWater API HTTP {resp.status} for {request_name}: "
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
        return {
            "applicationId": APPLICATION_ID,
            "solutionId": SOLUTION_ID,
            "solutionPageId": SOLUTION_PAGE_ID,
            "microApplicationId": micro_app_id,
            "renderType": "CONFIG_AND_DATA",
            "businessPartnerNumber": self.business_partner_number,
            "connectionContractNumber": self.connection_contract_number,
            "premiseId": self.premise_id,
            "premiseStateCode": self.state_code,
            "stateCode": self.state_code,
            "regionName": self.state_code,
            "accountType": "",
            "billMonth": "",
            "days": days,
            "endDate": "",
            "startDate": "",
            "limitRecords": 2,
            "serviceUrl": "",
            "source": "",
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
        data = await self._post(self._usage_payload(MICRO_APP_HOURLY, days="1"))
        return self._extract_series(data)

    async def async_get_daily_usage(self, days: int = 30) -> dict[str, list]:
        """Return daily usage (gallons) for the last `days` days."""
        data = await self._post(self._usage_payload(MICRO_APP_DAILY, days=str(days)))
        return self._extract_series(data)

    async def async_get_monthly_usage(self) -> dict[str, list]:
        """Return the last 12 months of usage (gallons)."""
        data = await self._post(self._usage_payload(MICRO_APP_MONTHLY_12))
        return self._extract_series(data)
