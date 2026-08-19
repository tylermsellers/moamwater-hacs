"""Missouri American Water (MyWater) — Home Assistant integration.

Architecture
------------
One config entry covers one MyWater account (username + password, with the
account/premise identifiers discovered during setup). On setup, the entry:
  1. Creates a dedicated ``MoAmWaterApiClient`` over its own aiohttp
     ``ClientSession`` (NOT HA's shared session -- see
     ``auth.async_create_session_with_saved_cookies``: HA's shared session
     isn't meant for cookie-based auth flows and its cookie jar doesn't
     survive a real restart anyway). Okta's session cookies are loaded from
     disk here and saved back on unload/shutdown, so a silent SSO replay can
     work across genuine HA reboots, not just entry reloads.
  2. Calls ``client.async_login(allow_interactive=False)``, which first
     attempts to reuse a still-valid stored access token (persisted in the
     config entry), then a silent Okta SSO replay. This avoids interactive
     reauth across typical HA restarts while token lifetime remains valid.
     ``allow_interactive=False`` means it will never fall through to a full
     password+SMS login here -- that would text the user an OTP with no one
     around to enter it. If both silent paths fail, it raises straight to
     reauth (``ConfigEntryAuthFailed``); the OTP is only sent once the user
     actively submits the reauth form in ``config_flow.py``.
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
from datetime import timedelta

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_track_time_interval

from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import (
    MfaRequired,
    MoAmWaterAuthError,
    async_adopt_pending_cookie_jar,
    async_create_session_with_saved_cookies,
    async_save_session_cookies,
)
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_ACCESS_TOKEN_EXPIRES_AT,
    CONF_BUSINESS_PARTNER_NUMBER,
    CONF_CONNECTION_CONTRACT_NUMBER,
    CONF_HOME_USAGE_ENTITY_ID,
    CONF_PASSWORD,
    CONF_PENDING_COOKIE_KEY,
    CONF_PREMISE_ID,
    CONF_REFRESH_TOKEN,
    CONF_STATE_CODE,
    CONF_USERNAME,
    DOMAIN,
    OKTA_KEEPALIVE_INTERVAL_MINUTES,
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
    session: aiohttp.ClientSession


type MoAmWaterConfigEntry = ConfigEntry[MoAmWaterRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> bool:
    """Set up MyWater for this account config entry."""
    # If this entry was just created by the initial (non-reauth) config
    # flow, adopt the Okta cookies it saved under its own flow_id into this
    # entry's permanent cookie-jar file before creating the session below --
    # otherwise those first `sid`/`DT` cookies would be silently lost and
    # the very first access_token expiry (~10hr from now) would always
    # force an interactive MFA reauth. See
    # `auth.async_adopt_pending_cookie_jar`'s docstring for the full story.
    pending_cookie_key = entry.data.get(CONF_PENDING_COOKIE_KEY)
    if pending_cookie_key:
        await async_adopt_pending_cookie_jar(hass, pending_cookie_key, entry.entry_id)
        hass.config_entries.async_update_entry(
            entry,
            data={k: v for k, v in entry.data.items() if k != CONF_PENDING_COOKIE_KEY},
        )

    # A dedicated session (not HA's shared one) with a real, disk-persisted
    # cookie jar -- see async_create_session_with_saved_cookies's docstring
    # for why this matters for minimizing OTPs across real HA restarts.
    session = await async_create_session_with_saved_cookies(hass, entry.entry_id)
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
        # allow_interactive=False: never start a full password+SMS login
        # here. This runs unattended on every HA startup (and reload), so
        # falling through to a real interactive login would text the user
        # an OTP with nobody there yet to enter it. If the stored token has
        # expired and Okta's own session cookies are no longer valid either,
        # just raise (via MfaRequired) straight to reauth -- the OTP will
        # only be sent once the user actively submits the reauth form.
        await client.async_login(allow_interactive=False)
    except MfaRequired as exc:
        # Stored-token/silent-login fallback failed; ask HA to trigger reauth.
        await session.close()
        raise ConfigEntryAuthFailed("MyWater requires a new MFA challenge") from exc
    except MoAmWaterAuthError as exc:
        await session.close()
        raise ConfigEntryAuthFailed(f"Invalid MyWater credentials: {exc}") from exc
    except MoAmWaterApiError as exc:
        await session.close()
        raise ConfigEntryNotReady(f"Could not reach MyWater: {exc}") from exc

    _async_persist_tokens_if_changed(hass, entry, client)

    coordinator = MoAmWaterCoordinator(hass, client, entry.entry_id)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = MoAmWaterRuntimeData(client=client, coordinator=coordinator, session=session)

    async def _async_keepalive_tick(_now) -> None:
        # Runs independently of the hourly data-poll coordinator -- see
        # OKTA_KEEPALIVE_INTERVAL_MINUTES's docstring in const.py for why a
        # keep-alive piggybacked only on the (much slower) data poll can miss
        # a short Okta idle-session timeout entirely. This carries no
        # credentials, so it's safe to run far more often than the data poll.
        await client.async_maintain_okta_session(
            min_interval_seconds=OKTA_KEEPALIVE_INTERVAL_MINUTES * 60
        )

    entry.async_on_unload(
        async_track_time_interval(
            hass,
            _async_keepalive_tick,
            timedelta(minutes=OKTA_KEEPALIVE_INTERVAL_MINUTES),
        )
    )

    async def _async_push_statistics() -> None:
        try:
            daily = await client.async_get_daily_usage(days=90)
            await async_import_daily_statistics(hass, daily)
            home_entity_id = entry.options.get(CONF_HOME_USAGE_ENTITY_ID)
            if home_entity_id:
                await async_import_irrigation_statistics(hass, daily, home_entity_id)
        except MfaRequired as exc:
            # Same terminal case as async_setup_entry()/the coordinator: the
            # session is fully dead, not just stale. The coordinator's own
            # poll will already have raised ConfigEntryAuthFailed for this,
            # so just log here rather than starting a second reauth flow.
            _LOGGER.warning("Could not import MyWater statistics: %s", exc)
        except MoAmWaterApiError as exc:
            _LOGGER.warning("Could not import MyWater statistics: %s", exc)

    entry.async_on_unload(
        coordinator.async_add_listener(lambda: hass.async_create_task(_async_push_statistics()))
    )
    # Push once immediately so the Energy dashboard has data right away.
    await _async_push_statistics()

    async def _async_save_cookies_on_stop(_event) -> None:
        # HA doesn't always call async_unload_entry on every restart path
        # (e.g. an abrupt stop), so also save on the stop event directly as
        # a belt-and-suspenders measure -- this is the persistence that lets
        # a silent SSO replay work on the NEXT boot instead of needing a new
        # OTP.
        await async_save_session_cookies(hass, session, entry.entry_id)

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_save_cookies_on_stop)
    )

    # Deliberately NOT registering entry.add_update_listener() here. The only
    # option (CONF_HOME_USAGE_ENTITY_ID) is already read live from
    # entry.options inside _async_push_statistics() above, so no reload is
    # needed when it changes. A prior update-listener that just called
    # async_reload() fired on ANY entry.data write -- including
    # _async_persist_tokens_if_changed() and reauth's own
    # async_update_reload_and_abort() -- causing a second, racing reload
    # right on top of the intentional one. That race is what let a freshly
    # completed reauth immediately re-trigger ConfigEntryAuthFailed (the
    # racing reload's client/session wasn't fully settled yet) and, more
    # broadly, kept resetting the API client (and its _last_okta_touch
    # keep-alive bookkeeping) far more often than intended.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
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
        # Persist Okta's session cookies too, so a silent SSO replay can
        # still work on the next restart even once the access token itself
        # has expired (see async_create_session_with_saved_cookies).
        await async_save_session_cookies(hass, runtime.session, entry.entry_id)
        await runtime.session.close()
    return unload_ok




