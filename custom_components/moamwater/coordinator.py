"""DataUpdateCoordinator for a Missouri American Water (MyWater) account."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import MoAmWaterAuthError
from .const import DEFAULT_SCAN_INTERVAL_MINUTES, DOMAIN

_LOGGER = logging.getLogger(__name__)


class MoAmWaterCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Polls MyWater for hourly + daily usage on a fixed interval.

    ``coordinator.data`` is a dict with:
      - "hourly": {"categories": [...], "series": {"Actual Usage": [...gallons...]}}
      - "daily":  {"categories": [...], "series": {"Actual Usage": [...], "Allocated Usage": [...]}}
    """

    def __init__(self, hass: HomeAssistant, client: MoAmWaterApiClient, entry_id: str) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry_id}",
            update_interval=timedelta(minutes=DEFAULT_SCAN_INTERVAL_MINUTES),
            always_update=False,
        )
        self.client = client
        self.entry_id = entry_id

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.client.connection_contract_number or self.entry_id)},
            name="MyWater Account",
            manufacturer="Missouri American Water",
            model="MyWater Portal",
        )

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            hourly = await self.client.async_get_hourly_usage()
            daily = await self.client.async_get_daily_usage(days=30)
        except MoAmWaterAuthError as exc:
            raise UpdateFailed(f"Authentication error: {exc}") from exc
        except MoAmWaterApiError as exc:
            raise UpdateFailed(f"MyWater API error: {exc}") from exc

        return {"hourly": hourly, "daily": daily}
