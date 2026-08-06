"""API client for the Missouri American Water MyWater portal.

Wraps the `/api/mso/data` MSO ("Model-Service-Object") endpoint discovered via
DevTools network capture. Every call POSTs a `UIRequestParameters`-shaped
payload identifying the account (businessPartnerNumber / connectionContractNumber
/ premiseId) and the specific chart/report ("microApplicationId") being requested.
"""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .auth import MoAmWaterAuthClient, MfaRequired, async_refresh_access_token
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


class MoAmWaterApiError(Exception):
    """Raised for any non-auth API failure (network error, unexpected shape)."""


class MoAmWaterApiClient:
    """Thin async client for MyWater's usage/account MSO endpoints."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        refresh_token: str | None = None,
    ) -> None:
        self._session = session
        self._username = username
        self._password = password
        self._auth = MoAmWaterAuthClient(session)
        self._access_token: str | None = None
        self.refresh_token: str | None = refresh_token

        self.business_partner_number: str | None = None
        self.connection_contract_number: str | None = None
        self.premise_id: str | None = None
        self.state_code: str = "MO"

    async def async_login(self) -> None:
        """Log in, preferring a stored `refresh_token` over interactive login.

        A stored refresh_token (obtained once via a real browser login) is
        the ONLY reliable path -- see auth.py's module docstring for why
        automating the interactive Okta Sign-In Widget login from scratch
        does not work (WAF blocks). Falls back to the interactive IDX flow
        (which may raise MfaRequired) only if no refresh_token is stored yet.
        """
        if self.refresh_token:
            result = await async_refresh_access_token(self._session, self.refresh_token)
            self._access_token = result["access_token"]
            self.refresh_token = result.get("refresh_token", self.refresh_token)
            return

        result = await self._auth.async_start_login(self._username, self._password)
        self._access_token = result["access_token"]
        self.refresh_token = result.get("refresh_token") or self.refresh_token

    async def async_submit_mfa(self, passcode: str) -> None:
        """Complete login after an MFA challenge was raised by async_login()."""
        result = await self._auth.async_submit_mfa(passcode)
        self._access_token = result["access_token"]
        self.refresh_token = result.get("refresh_token") or self.refresh_token

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
            async with self._session.post(DATA_URL, json=payload, headers=self._headers()) as resp:
                if resp.status == 401:
                    # Access tokens are short-lived; re-derive a fresh one
                    # from our stored refresh_token and retry once before
                    # giving up (avoids forcing reauth every polling cycle).
                    if not self.refresh_token:
                        raise MoAmWaterApiError("Session expired; re-authentication required")
                    await self.async_login()
                    async with self._session.post(
                        DATA_URL, json=payload, headers=self._headers()
                    ) as retry_resp:
                        retry_resp.raise_for_status()
                        return await retry_resp.json(content_type=None)
                resp.raise_for_status()
                return await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise MoAmWaterApiError(f"Request to MyWater failed: {exc}") from exc

    async def async_discover_account(self) -> None:
        """Fetch the customer profile pipeline to learn account identifiers.

        Mirrors the `customer_profile_pipeline` MSO call captured on page load,
        which returns the businessPartnerNumber / connectionContractNumber /
        premiseId needed for every subsequent usage request.
        """
        payload = {
            "applicationId": "com::amwater::enhancedportal::customerprofile",
            "solutionId": SOLUTION_ID,
            "solutionPageId": SOLUTION_PAGE_ID,
            "microApplicationId": "customer_profile_pipeline",
            "renderType": "DATA",
        }
        data = await self._post(payload)
        records = data.get("data") or []
        if not records:
            raise MoAmWaterApiError("Customer profile lookup returned no records")
        record = records[0]
        self.business_partner_number = record.get("businessPartnerNumber") or record.get(
            "BusinessPartnerNumber"
        )
        self.connection_contract_number = record.get("connectionContractNumber") or record.get(
            "ConnectionContractNumber"
        )
        self.premise_id = record.get("premiseId") or record.get("PremiseId")
        self.state_code = record.get("stateCode") or record.get("premiseStateCode") or "MO"

        if not all([self.business_partner_number, self.connection_contract_number, self.premise_id]):
            raise MoAmWaterApiError(
                f"Could not determine account identifiers from profile response: {record}"
            )

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
