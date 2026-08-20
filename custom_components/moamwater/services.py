"""Automated-reauth services for MyWater.

MoAmWater's Okta tenant enforces a hard ~23hr *absolute* session lifetime
that no amount of keep-alive activity can extend (see
`api.py`'s `async_maintain_okta_session` docstring), and the only MFA factor
observed for this account is SMS. That means a fully "silent" integration is
not possible -- Okta insists on texting a one-time code roughly once a day.

This module closes that loop anyway by splitting the interactive reauth
config-flow steps into two standalone services an *external* automation can
drive (e.g. an HA automation triggered by a webhook that an iPhone Shortcut
calls after reading the incoming SMS):

  1. `moamwater.start_reauth` -- submits the already-stored username/password
     to Okta, which is what actually triggers Okta to send the SMS. This is
     also kicked off automatically (fire-and-forget) the moment
     `__init__.py`/`coordinator.py` detect the session is fully dead, so
     nothing external has to call it for the common case -- it exists mainly
     as a manual retry/escape hatch.
  2. `moamwater.submit_mfa_code` -- submits the passcode extracted from that
     SMS to finish the login, persists the resulting tokens/cookies on the
     config entry exactly like the config-flow reauth step does, and reloads
     the entry.

The normal HA-UI reauth flow (`config_flow.py`) is left completely
untouched and still works as a manual fallback (e.g. if the automation
never fires, or credentials themselves changed) -- these services just
give an automation a way to race it to the punch.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import (
    InvalidCredentials,
    InvalidMfaCode,
    MfaRequired,
    MoAmWaterAuthError,
    async_create_session_with_saved_cookies,
    async_save_session_cookies,
)
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
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

SERVICE_START_REAUTH = "start_reauth"
SERVICE_SUBMIT_MFA_CODE = "submit_mfa_code"

# Don't let repeated HA setup retries (or a flaky automation double-firing)
# spam a fresh SMS every time -- an in-flight or just-finished attempt for
# the same entry within this window is reused/ignored instead of starting a
# new one.
_REAUTH_COOLDOWN_SECONDS = 120

_SERVICE_SCHEMA = vol.Schema({vol.Optional("entry_id"): cv.string})
_SUBMIT_SCHEMA = vol.Schema(
    {vol.Optional("entry_id"): cv.string, vol.Required("code"): cv.string}
)


@dataclass
class _PendingReauth:
    client: MoAmWaterApiClient
    session: aiohttp.ClientSession
    started_at: float


def _pending_store(hass: HomeAssistant) -> dict[str, _PendingReauth]:
    return hass.data.setdefault(DOMAIN, {}).setdefault("pending_reauth", {})


def _resolve_entry(hass: HomeAssistant, entry_id: str | None) -> ConfigEntry:
    entries = hass.config_entries.async_entries(DOMAIN)
    if entry_id:
        entry = hass.config_entries.async_get_entry(entry_id)
        if entry is None or entry.domain != DOMAIN:
            raise HomeAssistantError(f"No MyWater config entry with id '{entry_id}'")
        return entry
    if len(entries) == 1:
        return entries[0]
    if not entries:
        raise HomeAssistantError("No MyWater config entry is configured")
    raise HomeAssistantError(
        "Multiple MyWater accounts configured; pass 'entry_id' to disambiguate"
    )


async def async_start_reauth(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Submit the stored username/password to Okta, triggering its SMS challenge.

    Fire-and-forget safe: never raises. Returns True if an MFA challenge is
    now pending (i.e. `submit_mfa_code` can be called next), False if login
    finished without needing one, failed outright (bad stored credentials,
    network error), or an attempt is already in flight/cooling down.
    """
    pending = _pending_store(hass)
    existing = pending.get(entry.entry_id)
    if existing is not None and time.time() - existing.started_at < _REAUTH_COOLDOWN_SECONDS:
        _LOGGER.debug(
            "MoAmWater automated reauth already in flight for %s; not starting another",
            entry.entry_id,
        )
        return True

    session = await async_create_session_with_saved_cookies(hass, entry.entry_id)
    client = MoAmWaterApiClient(
        session=session,
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
    )
    client.business_partner_number = entry.data.get(CONF_BUSINESS_PARTNER_NUMBER)
    client.connection_contract_number = entry.data.get(CONF_CONNECTION_CONTRACT_NUMBER)
    client.premise_id = entry.data.get(CONF_PREMISE_ID)
    client.state_code = entry.data.get(CONF_STATE_CODE, "MO")

    try:
        # allow_interactive=True is what actually submits the password (and
        # therefore triggers Okta's SMS send) -- see api.py's async_login()
        # docstring for why background/unattended callers must never do
        # this with allow_interactive=False instead.
        await client.async_login(allow_interactive=True)
    except MfaRequired:
        pending[entry.entry_id] = _PendingReauth(
            client=client, session=session, started_at=time.time()
        )
        _LOGGER.info(
            "MoAmWater automated reauth: MFA challenge sent for %s; "
            "awaiting submit_mfa_code",
            entry.entry_id,
        )
        return True
    except (InvalidCredentials, MoAmWaterAuthError, MoAmWaterApiError) as exc:
        _LOGGER.warning(
            "MoAmWater automated reauth could not start for %s: %s", entry.entry_id, exc
        )
        await session.close()
        return False
    else:
        # No MFA needed after all (e.g. Okta's own session cookies were
        # still alive) -- nothing more to do, just persist what we got.
        _LOGGER.info(
            "MoAmWater automated reauth: login succeeded without MFA for %s", entry.entry_id
        )
        await _async_finish(hass, entry, client, session)
        return False


async def _async_finish(
    hass: HomeAssistant,
    entry: ConfigEntry,
    client: MoAmWaterApiClient,
    session: aiohttp.ClientSession,
) -> None:
    """Persist tokens/identifiers/cookies and reload, mirroring config_flow.py's
    reauth completion (`_async_finish_setup_with_identifiers`)."""
    try:
        await client.async_discover_account()
    except MoAmWaterApiError as exc:
        bpn = entry.data.get(CONF_BUSINESS_PARTNER_NUMBER)
        ccn = entry.data.get(CONF_CONNECTION_CONTRACT_NUMBER)
        premise_id = entry.data.get(CONF_PREMISE_ID)
        if not (bpn and ccn and premise_id):
            raise
        _LOGGER.warning(
            "MoAmWater account discovery failed during automated reauth (%s); "
            "reusing previously known account identifiers",
            exc,
        )
        client.business_partner_number = bpn
        client.connection_contract_number = ccn
        client.premise_id = premise_id
        client.state_code = entry.data.get(CONF_STATE_CODE, "MO")

    data = {
        **entry.data,
        CONF_REFRESH_TOKEN: client.refresh_token,
        CONF_ACCESS_TOKEN: client.access_token,
        CONF_ACCESS_TOKEN_EXPIRES_AT: client.access_token_expires_at,
        CONF_BUSINESS_PARTNER_NUMBER: client.business_partner_number,
        CONF_CONNECTION_CONTRACT_NUMBER: client.connection_contract_number,
        CONF_PREMISE_ID: client.premise_id,
        CONF_STATE_CODE: client.state_code,
    }
    hass.config_entries.async_update_entry(entry, data=data)
    await async_save_session_cookies(hass, session, entry.entry_id)
    await session.close()
    await hass.config_entries.async_reload(entry.entry_id)


async def async_submit_mfa_code(hass: HomeAssistant, entry: ConfigEntry, code: str) -> None:
    """Finish a pending automated reauth with the SMS passcode."""
    pending = _pending_store(hass)
    pending_reauth = pending.pop(entry.entry_id, None)
    if pending_reauth is None:
        raise HomeAssistantError(
            f"No automated MyWater reauth is pending for {entry.entry_id}; "
            "call start_reauth first (or use the normal reauth form)"
        )

    try:
        await pending_reauth.client.async_submit_mfa(code)
    except InvalidMfaCode as exc:
        # Put it back so a second attempt (e.g. a mistyped/duplicate SMS)
        # can still use the same in-flight Okta challenge instead of
        # needing an entirely new one.
        pending[entry.entry_id] = pending_reauth
        raise HomeAssistantError(f"MyWater rejected the MFA code: {exc}") from exc
    except (MoAmWaterAuthError, MoAmWaterApiError) as exc:
        await pending_reauth.session.close()
        raise HomeAssistantError(f"MyWater MFA submission failed: {exc}") from exc

    await _async_finish(hass, entry, pending_reauth.client, pending_reauth.session)


def async_setup_services(hass: HomeAssistant) -> None:
    """Register the automated-reauth services once per HA run."""
    if hass.services.has_service(DOMAIN, SERVICE_SUBMIT_MFA_CODE):
        return

    async def _handle_start_reauth(call: ServiceCall) -> None:
        entry = _resolve_entry(hass, call.data.get("entry_id"))
        await async_start_reauth(hass, entry)

    async def _handle_submit_mfa_code(call: ServiceCall) -> None:
        entry = _resolve_entry(hass, call.data.get("entry_id"))
        await async_submit_mfa_code(hass, entry, call.data["code"])

    hass.services.async_register(
        DOMAIN, SERVICE_START_REAUTH, _handle_start_reauth, schema=_SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_SUBMIT_MFA_CODE, _handle_submit_mfa_code, schema=_SUBMIT_SCHEMA
    )
