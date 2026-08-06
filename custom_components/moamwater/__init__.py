"""Missouri American Water (MyWater) — Home Assistant integration.

Architecture
------------
One config entry covers one MyWater account (username + password, with the
account/premise identifiers discovered during setup). On setup, the entry:
  1. Creates a shared ``MoAmWaterApiClient`` over Home Assistant's managed
     HTTP session (connector/SSL/proxy behavior consistent with HA core).
  2. Calls ``client.async_login()``, which first attempts to reuse a still-
     valid stored access token (persisted in the config entry). This avoids
     interactive reauth across typical HA restarts while token lifetime
     remains valid.
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
    CONF_ACCESS_TOKEN,
    CONF_ACCESS_TOKEN_EXPIRES_AT,
    CONF_BUSINESS_PARTNER_NUMBER,
    CONF_CONNECTION_CONTRACT_NUMBER,
    CONF_HOME_USAGE_ENTITY_ID,
    CONF_PASSWORD,
    CONF_PREMISE_ID,
    CONF_REFRESH_TOKEN,
    CONF_STATE_CODE,
    CONF_USERNAME,
    DOMAIN,
)
from .coordinator import MoAmWaterCoordinator
from .statistics import async_import_daily_statistics, async_import_irrigation_statistics

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
        access_token=entry.data.get(CONF_ACCESS_TOKEN),
        access_token_expires_at=entry.data.get(CONF_ACCESS_TOKEN_EXPIRES_AT),
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
        # Stored-token/silent-login fallback failed; ask HA to trigger reauth.
        raise ConfigEntryAuthFailed("MyWater requires a new MFA challenge") from exc
    except MoAmWaterAuthError as exc:
        raise ConfigEntryAuthFailed(f"Invalid MyWater credentials: {exc}") from exc
    except MoAmWaterApiError as exc:
        raise ConfigEntryNotReady(f"Could not reach MyWater: {exc}") from exc

    _async_persist_tokens_if_changed(hass, entry, client)

    coordinator = MoAmWaterCoordinator(hass, client, entry.entry_id)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = MoAmWaterRuntimeData(client=client, coordinator=coordinator)

    async def _async_push_statistics() -> None:
        try:
            daily = await client.async_get_daily_usage(days=90)
            await async_import_daily_statistics(hass, daily)
            home_entity_id = entry.options.get(CONF_HOME_USAGE_ENTITY_ID)
            if home_entity_id:
                await async_import_irrigation_statistics(hass, daily, home_entity_id)
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


def _async_persist_tokens_if_changed(
    hass: HomeAssistant, entry: MoAmWaterConfigEntry, client: MoAmWaterApiClient
) -> None:
    """Persist the current access_token/expiry/refresh_token into entry.data if they changed.

    This is what lets the NEXT restart potentially skip login entirely (tier
    1 of the strategy in auth.py) instead of always needing at least a
    silent SSO replay.
    """
    updates: dict = {}
    if client.access_token and client.access_token != entry.data.get(CONF_ACCESS_TOKEN):
        updates[CONF_ACCESS_TOKEN] = client.access_token
        updates[CONF_ACCESS_TOKEN_EXPIRES_AT] = client.access_token_expires_at
    if client.refresh_token and client.refresh_token != entry.data.get(CONF_REFRESH_TOKEN):
        updates[CONF_REFRESH_TOKEN] = client.refresh_token
    if updates:
        hass.config_entries.async_update_entry(entry, data={**entry.data, **updates})


async def async_unload_entry(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> bool:
    """Unload all platforms for this config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok and entry.runtime_data:
        runtime = entry.runtime_data
        # Persist current tokens so the next restart can skip reauth when
        # they are still valid.
        _async_persist_tokens_if_changed(hass, entry, runtime.client)
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> None:
    """Reload the entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)
