"""Config flow for Missouri American Water (MyWater).

Two-step flow to support Okta MFA:
  1. `user` step — collect username/password, attempt login.
     - If Okta requires no further factor, we're done: discover the account
       and create the entry immediately.
     - If Okta raises MfaRequired, stash the in-progress auth client on
       `self._api` and move to the `mfa` step.
  2. `mfa` step — collect the one-time passcode (SMS/email/TOTP), submit it,
     then discover the account and create the entry.

Uses Home Assistant's managed HTTP session so onboarding follows HA's
networking/SSL/proxy behavior consistently.
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import MoAmWaterApiClient, MoAmWaterApiError
from .auth import InvalidCredentials, InvalidMfaCode, MfaRequired, MoAmWaterAuthError
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

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_MFA_SCHEMA = vol.Schema(
    {
        vol.Required("passcode"): str,
    }
)


class MoAmWaterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Missouri American Water."""

    VERSION = 1

    def __init__(self) -> None:
        self._username: str | None = None
        self._password: str | None = None
        self._api: MoAmWaterApiClient | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            session = async_get_clientsession(self.hass)
            self._api = MoAmWaterApiClient(session, self._username, self._password)

            try:
                await self._api.async_login()
            except MfaRequired:
                return await self.async_step_mfa()
            except InvalidCredentials as exc:
                _LOGGER.warning("MoAmWater rejected credentials: %s", exc)
                errors["base"] = "invalid_auth"
            except MoAmWaterAuthError as exc:
                # A protocol/implementation failure (not a credential problem) --
                # log the real cause and show "unknown" so users don't waste
                # time re-typing a correct password.
                _LOGGER.error("MoAmWater login failed unexpectedly: %s", exc)
                errors["base"] = "unknown"
            except MoAmWaterApiError as exc:
                _LOGGER.error("MoAmWater connection error: %s", exc)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during MoAmWater login")
                errors["base"] = "unknown"
            else:
                return await self._async_finish_setup()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            assert self._api is not None
            try:
                await self._api.async_submit_mfa(user_input["passcode"])
            except InvalidMfaCode as exc:
                _LOGGER.warning("MoAmWater rejected MFA code: %s", exc)
                errors["base"] = "invalid_mfa"
            except MoAmWaterAuthError as exc:
                _LOGGER.error("MoAmWater MFA failed unexpectedly: %s", exc)
                errors["base"] = "unknown"
            except MoAmWaterApiError as exc:
                _LOGGER.error("MoAmWater connection error: %s", exc)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during MoAmWater MFA")
                errors["base"] = "unknown"
            else:
                return await self._async_finish_setup()

        return self.async_show_form(
            step_id="mfa", data_schema=STEP_MFA_SCHEMA, errors=errors
        )

    async def _async_finish_setup(self) -> ConfigFlowResult:
        assert self._api is not None
        try:
            await self._api.async_discover_account()
        except MoAmWaterApiError:
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_SCHEMA, errors={"base": "cannot_connect"}
            )

        await self.async_set_unique_id(self._api.connection_contract_number)
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=f"MyWater ({self._username})",
            data={
                CONF_USERNAME: self._username,
                CONF_PASSWORD: self._password,
                CONF_REFRESH_TOKEN: self._api.refresh_token,
                CONF_ACCESS_TOKEN: self._api.access_token,
                CONF_ACCESS_TOKEN_EXPIRES_AT: self._api.access_token_expires_at,
                CONF_BUSINESS_PARTNER_NUMBER: self._api.business_partner_number,
                CONF_CONNECTION_CONTRACT_NUMBER: self._api.connection_contract_number,
                CONF_PREMISE_ID: self._api.premise_id,
                CONF_STATE_CODE: self._api.state_code,
            },
        )
