"""Missouri American Water (MyWater) — Home Assistant integration.

Architecture
------------
One config entry covers one MyWater account (username + password, with the
account/premise identifiers discovered during setup). On setup, the entry:
  1. Creates a dedicated ``aiohttp.ClientSession`` (NOT the shared HA one --
     see below) whose cookie jar is restored from disk if a prior session
     was persisted, and creates a shared ``MoAmWaterApiClient`` (handles
     Okta IDX login + MFA, plus MSO data calls against ``/api/mso/data``).
  2. Calls ``client.async_login()``, which avoids a full interactive login
     whenever possible: it reuses a still-valid stored access_token, or
     falls back to a silent Okta SSO replay of ``/v1/authorize`` (using
     Okta's own persisted session cookies) before ever falling back to a
     full password+SMS login. See ``auth.py``'s module docstring for the
     full 3-tier strategy. If Okta genuinely requires a fresh MFA challenge
     (both fallbacks failed), ``ConfigEntryAuthFailed`` is raised so HA
     prompts the user to reauthenticate via the config flow.
  3. Creates one ``MoAmWaterCoordinator`` that polls hourly/daily usage.
  4. Pushes daily usage into Home Assistant's long-term statistics via
     ``statistics.py`` so it can be added to the Energy dashboard exactly
     like the Spire gas integration.
  5. Stores everything in ``entry.runtime_data`` (HA 2026 typed pattern).
  6. Forwards to the sensor platform.
  7. On unload, saves the dedicated session's cookie jar back to disk (in
     HA's ``.storage`` dir) so Okta's own session cookies survive the
     restart -- this is what lets step 2's SSO fallback work at all.

We use a dedicated ``aiohttp.ClientSession`` (with its own
``aiohttp.CookieJar(unsafe=True)``, since Okta's session cookies are
scoped to the ``auth.amwater.com``/``amwater.com`` domains, not just paths)
instead of HA's shared session, because we need exclusive control over its
cookie jar's lifecycle (persisting it to disk, reloading it) without
interfering with -- or being interfered by -- any other integration sharing
HA's single session/cookie jar.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import MfaRequired, MoAmWaterAuthError
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_ACCESS_TOKEN_EXPIRES_AT,
    CONF_BUSINESS_PARTNER_NUMBER,
    CONF_CONNECTION_CONTRACT_NUMBER,
    CONF_PASSWORD,
    CONF_PREMISE_ID,
    CONF_REFRESH_TOKEN,
    CONF_STATE_CODE,
    CONF_USERNAME,
    COOKIE_JAR_FILENAME_TEMPLATE,
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
    session: aiohttp.ClientSession
    cookie_jar_path: Path


type MoAmWaterConfigEntry = ConfigEntry[MoAmWaterRuntimeData]


def _cookie_jar_path(hass: HomeAssistant, entry_id: str) -> Path:
    return Path(hass.config.path(".storage")) / COOKIE_JAR_FILENAME_TEMPLATE.format(entry_id=entry_id)


async def _async_create_session(hass: HomeAssistant, entry_id: str) -> tuple[aiohttp.ClientSession, Path]:
    """Create a dedicated ClientSession with a cookie jar restored from disk, if present."""
    jar_path = _cookie_jar_path(hass, entry_id)
    cookie_jar = aiohttp.CookieJar(unsafe=True)
    if jar_path.exists():
        try:
            await hass.async_add_executor_job(cookie_jar.load, jar_path)
            _LOGGER.debug("Restored persisted Okta/MyWater session cookies from %s", jar_path)
        except Exception:  # noqa: BLE001 - a corrupt/incompatible jar file must not block setup
            _LOGGER.warning("Could not load persisted cookie jar (will start a fresh session)", exc_info=True)
    session = aiohttp.ClientSession(cookie_jar=cookie_jar)
    return session, jar_path


async def _async_save_cookie_jar(hass: HomeAssistant, session: aiohttp.ClientSession, jar_path: Path) -> None:
    """Persist the session's cookie jar to disk so Okta's own session cookies survive a restart."""
    try:
        jar_path.parent.mkdir(parents=True, exist_ok=True)
        await hass.async_add_executor_job(session.cookie_jar.save, jar_path)
    except Exception:  # noqa: BLE001 - best-effort; losing this just means a fallback to full login
        _LOGGER.warning("Could not persist cookie jar to %s", jar_path, exc_info=True)


async def async_setup_entry(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> bool:
    """Set up MyWater for this account config entry."""
    session, jar_path = await _async_create_session(hass, entry.entry_id)
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
        # Both the stored-token and silent-SSO fallbacks failed -- Okta
        # genuinely requires a fresh MFA challenge (e.g. its own session
        # cookie has finally expired too). We cannot prompt for a one-time
        # code from here, so ask HA to trigger the reauth flow instead.
        await session.close()
        raise ConfigEntryAuthFailed("MyWater requires a new MFA challenge") from exc
    except MoAmWaterAuthError as exc:
        await session.close()
        raise ConfigEntryAuthFailed(f"Invalid MyWater credentials: {exc}") from exc
    except MoAmWaterApiError as exc:
        await session.close()
        raise ConfigEntryNotReady(f"Could not reach MyWater: {exc}") from exc

    _async_persist_tokens_if_changed(hass, entry, client)
    # Cookies may have been rotated by the login/SSO replay just now -- save
    # immediately so an unexpected shutdown right after setup doesn't lose
    # a freshly-minted Okta session.
    await _async_save_cookie_jar(hass, session, jar_path)

    coordinator = MoAmWaterCoordinator(hass, client, entry.entry_id)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = MoAmWaterRuntimeData(
        client=client, coordinator=coordinator, session=session, cookie_jar_path=jar_path
    )

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
        # Persist whatever tokens/cookies are current as of shutdown -- this
        # is the primary mechanism that avoids reauth on the next restart.
        _async_persist_tokens_if_changed(hass, entry, runtime.client)
        await _async_save_cookie_jar(hass, runtime.session, runtime.cookie_jar_path)
        await runtime.session.close()
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: MoAmWaterConfigEntry) -> None:
    """Reload the entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)

