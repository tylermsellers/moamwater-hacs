"""DataUpdateCoordinator for a Missouri American Water (MyWater) account."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import MfaRequired, MoAmWaterAuthError
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
        # Best-effort: reset Okta's idle session timer every poll cycle so a
        # short idle timeout (rather than a hard session-lifetime cap) can't
        # sneak in between the ~10hr access-token expiries. See
        # api.py's async_maintain_okta_session() docstring for details.
        await self.client.async_maintain_okta_session()

        try:
            hourly = await self.client.async_get_hourly_usage()
            daily = await self.client.async_get_daily_usage(days=30)
        except MfaRequired as exc:
            # A mid-poll 401 survived even a silent SSO replay -- Okta's own
            # session is dead, not just the access_token, so only a fresh
            # password+SMS login can recover. Raise ConfigEntryAuthFailed
            # (instead of UpdateFailed) so HA actually starts the reauth
            # flow and surfaces a notification, rather than leaving the
            # entities silently unavailable indefinitely.
            raise ConfigEntryAuthFailed("MyWater requires a new MFA challenge") from exc
        except MoAmWaterAuthError as exc:
            raise ConfigEntryAuthFailed(f"MyWater authentication error: {exc}") from exc
        except MoAmWaterApiError as exc:
            raise UpdateFailed(f"MyWater API error: {exc}") from exc

        self._async_persist_tokens_if_changed()
        return {"hourly": hourly, "daily": daily}

    def _async_persist_tokens_if_changed(self) -> None:
        """Persist the client's current access_token/expiry/refresh_token into
        the config entry if any of them changed since the last poll.

        Silent SSO replays (both the hourly keepalive and a mid-poll 401
        recovery) mint a fresh access_token -- and Okta rotates the
        refresh_token on every redemption -- entirely in-memory. Previously
        only a rotated refresh_token got persisted here, so an abrupt
        restart (crash, forced container restart, power loss -- anything
        that skips the clean `async_unload_entry` path) would silently
        discard an hours-old, still-valid access_token and fall back to
        entry.data's original (older, possibly already-expired) one,
        forcing an avoidable reauth. Persisting after every poll (not just
        at setup/unload) closes that gap. Deferred import avoids a circular
        import with `__init__.py` (which imports this coordinator).
        """
        from . import _async_persist_tokens_if_changed

        entry = self.hass.config_entries.async_get_entry(self.entry_id)
        if entry is None:
            return
        _async_persist_tokens_if_changed(self.hass, entry, self.client)
