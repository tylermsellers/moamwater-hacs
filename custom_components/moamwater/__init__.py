"""Missouri American Water (MyWater) — Home Assistant integration.

Architecture
------------
One config entry covers one MyWater account (username + password, with the
account/premise identifiers discovered during setup). On setup, the entry:
  1. Creates a shared ``MoAmWaterApiClient`` (handles Okta IDX login + MFA
     that was already completed once during the config flow, plus MSO data
     calls against ``/api/mso/data``).
  2. Re-authenticates on startup (Okta sessions/cookies do not survive HA
     restarts) using the stored username/password. If Okta requires a fresh
     MFA challenge (e.g. session risk scoring), ``ConfigEntryAuthFailed`` is
     raised so HA prompts the user to reauthenticate via the config flow.
  3. Creates one ``MoAmWaterCoordinator`` that polls hourly/daily usage.
  4. Pushes daily usage into Home Assistant's long-term statistics via
     ``statistics.py`` so it can be added to the Energy dashboard exactly
     like the Spire gas integration.
  5. Stores everything in ``entry.runtime_data`` (HA 2026 typed pattern).
  6. Forwards to the sensor platform.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import MfaRequired, MoAmWaterAuthError
from .const import (
    CONF_BUSINESS_PARTNER_NUMBER,
    CONF_CONNECTION_CONTRACT_NUMBER,
    CONF_PASSWORD,
    CONF_PREMISE_ID,
    CONF_REFRESH_TOKEN,
    CONF_STATE_CODE,
    CONF_USERNAME,
    DOMAIN,
)
from .coordinator import MoAmWaterCoordinator
from .statistics import async_import_daily_statistics

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


@dataclass
class MoAmWaterRuntimeData:
    """All runtime objects stored on the config entry."""

    client: MoAmWaterApiClient
    coordinator: MoAmWaterCoordinator


type MoAmWaterConfigEntry = ConfigEntry[MoAmWaterRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> bool:
    """Set up MyWater for this account config entry."""
    session = async_get_clientsession(hass)
    client = MoAmWaterApiClient(
        session=session,
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        refresh_token=entry.data.get(CONF_REFRESH_TOKEN),
    )
    # Reuse identifiers discovered during config flow rather than re-fetching
    # the profile pipeline on every restart.
    client.business_partner_number = entry.data.get(CONF_BUSINESS_PARTNER_NUMBER)
    client.connection_contract_number = entry.data.get(CONF_CONNECTION_CONTRACT_NUMBER)
    client.premise_id = entry.data.get(CONF_PREMISE_ID)
    client.state_code = entry.data.get(CONF_STATE_CODE, "MO")

    try:
        await client.async_login()
    except MfaRequired as exc:
        # Okta decided a fresh MFA challenge is required (e.g. new IP/device
        # risk scoring). We cannot prompt for a one-time code from here, so
        # ask HA to trigger the reauth flow instead.
        raise ConfigEntryAuthFailed("MyWater requires a new MFA challenge") from exc
    except MoAmWaterAuthError as exc:
        raise ConfigEntryAuthFailed(f"Invalid MyWater credentials: {exc}") from exc
    except MoAmWaterApiError as exc:
        raise ConfigEntryNotReady(f"Could not reach MyWater: {exc}") from exc

    # Okta rotates the refresh_token on every redemption -- persist the new
    # value immediately so the NEXT restart/renewal doesn't try to reuse a
    # refresh_token Okta has already invalidated.
    if client.refresh_token and client.refresh_token != entry.data.get(CONF_REFRESH_TOKEN):
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, CONF_REFRESH_TOKEN: client.refresh_token}
        )

    coordinator = MoAmWaterCoordinator(hass, client, entry.entry_id)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = MoAmWaterRuntimeData(client=client, coordinator=coordinator)

    async def _async_push_statistics() -> None:
        try:
            daily = await client.async_get_daily_usage(days=90)
            await async_import_daily_statistics(hass, daily)
        except MoAmWaterApiError as exc:
            _LOGGER.warning("Could not import MyWater statistics: %s", exc)

    entry.async_on_unload(
        coordinator.async_add_listener(lambda: hass.async_create_task(_async_push_statistics()))
    )
    # Push once immediately so the Energy dashboard has data right away.
    await _async_push_statistics()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> bool:
    """Unload all platforms for this config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_update_listener(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> None:
    """Reload the entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)
