"""Tests for auth.py: JWT expiry decoding, silent-SSO replay, and the
Okta session cookie jar disk persistence used to survive HA restarts.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import time
from unittest.mock import AsyncMock

import aiohttp
import pytest
from aioresponses import aioresponses

from _moamwater_modules import auth, const


def _make_jwt(payload: dict) -> str:
    """Build a syntactically-valid (unsigned) JWT string with the given payload."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


class TestDecodeJwtExp:
    def test_returns_exp_claim(self):
        token = _make_jwt({"exp": 1234567890, "sub": "user"})
        assert auth.decode_jwt_exp(token) == 1234567890.0

    def test_missing_exp_returns_none(self):
        token = _make_jwt({"sub": "user"})
        assert auth.decode_jwt_exp(token) is None

    def test_malformed_token_returns_none(self):
        assert auth.decode_jwt_exp("not-a-jwt") is None
        assert auth.decode_jwt_exp("") is None
        assert auth.decode_jwt_exp("a.b") is None

    def test_invalid_base64_payload_returns_none(self):
        assert auth.decode_jwt_exp("a.not_valid_base64!!!.c") is None

    def test_non_json_payload_returns_none(self):
        bad_payload = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        assert auth.decode_jwt_exp(f"a.{bad_payload}.c") is None


class _FakeHass:
    """Minimal stand-in for HomeAssistant, just enough for
    async_create_session_with_saved_cookies/async_save_session_cookies.
    """

    def __init__(self, storage_dir: str):
        self._storage_dir = storage_dir

    class _Config:
        def __init__(self, storage_dir: str):
            self._storage_dir = storage_dir

        def path(self, *parts: str) -> str:
            import os

            return os.path.join(self._storage_dir, *parts)

    @property
    def config(self):
        return self._Config(self._storage_dir)

    async def async_add_executor_job(self, func, *args):
        return func(*args)


@pytest.mark.asyncio
class TestCookieJarPersistence:
    async def test_round_trip_save_and_load(self, tmp_path):
        hass = _FakeHass(str(tmp_path))
        entry_id = "test_entry"

        session = await auth.async_create_session_with_saved_cookies(hass, entry_id)
        session.cookie_jar.update_cookies(
            {"sid": "abc123"},
            response_url=aiohttp.client.URL(const.OKTA_BASE_URL),
        )
        await auth.async_save_session_cookies(hass, session, entry_id)
        await session.close()

        # A fresh session for the same entry_id should recover the cookie.
        reloaded = await auth.async_create_session_with_saved_cookies(hass, entry_id)
        cookies = reloaded.cookie_jar.filter_cookies(aiohttp.client.URL(const.OKTA_BASE_URL))
        assert cookies.get("sid") is not None
        assert cookies["sid"].value == "abc123"
        await reloaded.close()

    async def test_missing_cookie_file_does_not_raise(self, tmp_path):
        hass = _FakeHass(str(tmp_path))
        # No prior save() call has happened -- the pickle file doesn't exist.
        session = await auth.async_create_session_with_saved_cookies(hass, "brand_new_entry")
        assert len(session.cookie_jar) == 0
        await session.close()

    async def test_corrupt_cookie_file_does_not_raise(self, tmp_path):
        import os

        hass = _FakeHass(str(tmp_path))
        entry_id = "corrupt_entry"
        os.makedirs(tmp_path, exist_ok=True)
        path = os.path.join(str(tmp_path), const.COOKIE_JAR_FILENAME_TEMPLATE.format(entry_id=entry_id))
        with open(path, "wb") as fh:
            fh.write(b"this is not a valid pickle")

        # Must not raise -- a corrupt jar file must never block startup.
        session = await auth.async_create_session_with_saved_cookies(hass, entry_id)
        assert len(session.cookie_jar) == 0
        await session.close()


@pytest.mark.asyncio
class TestSilentSso:
    async def test_returns_tokens_when_okta_session_still_valid(self):
        """If Okta immediately redirects (session cookie still valid), the
        whole chain (Okta redirect -> MyWater /openidlogin) should resolve
        to a fresh access_token/refresh_token with zero interactive steps.
        """
        async with aiohttp.ClientSession() as session:
            client = auth.MoAmWaterAuthClient(session)
            with aioresponses() as mocked:
                mocked.get(
                    re.compile(rf"^{re.escape(auth.AUTHORIZE_URL)}\?.*$"),
                    status=302,
                    headers={"Location": f"{const.MYWATER_BASE_URL}/openidlogin?code=abc&state=xyz"},
                    repeat=True,
                )
                mocked.get(
                    f"{const.MYWATER_BASE_URL}/openidlogin?code=abc&state=xyz",
                    status=302,
                    headers={
                        "Location": f"{const.MYWATER_BASE_URL}/#/enhancedportal",
                        "Set-Cookie": (
                            f"mw-authenticationToken={_make_jwt({'exp': time.time() + 36000})}; Path=/"
                        ),
                    },
                )

                result = await client.async_try_silent_sso()

        assert result is not None
        assert result["access_token"]

    async def test_returns_none_when_okta_session_expired(self):
        """A 200 (interactive widget HTML) instead of a redirect means Okta's
        session has expired -- must return None (not raise) so the caller
        falls back to a full interactive login.
        """
        async with aiohttp.ClientSession() as session:
            client = auth.MoAmWaterAuthClient(session)
            with aioresponses() as mocked:
                mocked.get(
                    re.compile(rf"^{re.escape(auth.AUTHORIZE_URL)}\?.*$"),
                    status=200,
                    body="<html>sign-in widget</html>",
                )
                result = await client.async_try_silent_sso()

        assert result is None

    async def test_expired_session_logs_cookie_state_at_warning(self, caplog):
        """The cookie-state diagnostic MUST be WARNING, not INFO.

        On instances with on-disk file logging disabled, the only readable
        log is HA's in-memory system buffer, which retains WARNING and above
        only -- an INFO line here is dropped and the next reauth becomes
        undiagnosable (the v1.1.3 regression this test guards against).
        """
        caplog.set_level(logging.WARNING, logger=auth._LOGGER.name)
        async with aiohttp.ClientSession() as session:
            client = auth.MoAmWaterAuthClient(session)
            with aioresponses() as mocked:
                mocked.get(
                    re.compile(rf"^{re.escape(auth.AUTHORIZE_URL)}\?.*$"),
                    status=200,
                    body="<html>sign-in widget</html>",
                )
                assert await client.async_try_silent_sso() is None

        records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert records, "silent-SSO failure must log at WARNING or above"
        message = records[0].getMessage()
        assert "DT" in message, "diagnostic must name which Okta cookies were present"

    async def test_network_error_logs_cookie_state_at_warning(self, caplog):
        caplog.set_level(logging.WARNING, logger=auth._LOGGER.name)
        async with aiohttp.ClientSession() as session:
            client = auth.MoAmWaterAuthClient(session)
            with aioresponses() as mocked:
                mocked.get(
                    re.compile(rf"^{re.escape(auth.AUTHORIZE_URL)}\?.*$"),
                    exception=aiohttp.ClientConnectionError(),
                )
                assert await client.async_try_silent_sso() is None

        assert [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.asyncio
class TestOtpGuard:
    async def test_unattended_login_blocks_explicit_challenge_request(self, caplog):
        caplog.set_level(logging.WARNING, logger=auth._LOGGER.name)
        client = auth.MoAmWaterAuthClient(AsyncMock(spec=aiohttp.ClientSession))
        client._state_handle = "state"
        client._async_post_idx = AsyncMock()
        response = {
            "stateHandle": "state-2",
            "remediation": {
                "value": [
                    {
                        "name": "authenticator-verification-data",
                        "value": [
                            {
                                "name": "authenticator",
                                "form": {
                                    "value": [
                                        {"name": "id", "value": "phone-id"},
                                        {
                                            "name": "enrollmentId",
                                            "value": "enrollment-id",
                                        },
                                    ]
                                },
                            }
                        ],
                    }
                ]
            },
        }

        with pytest.raises(auth.MfaRequired):
            await client._async_handle_remediation(
                response, allow_otp_send=False
            )

        client._async_post_idx.assert_not_called()
        assert "blocked the OTP challenge request" in caplog.text

    async def test_passcode_only_challenge_can_be_submitted(self):
        client = auth.MoAmWaterAuthClient(AsyncMock(spec=aiohttp.ClientSession))
        client._state_handle = "state"
        response = {
            "stateHandle": "state-2",
            "remediation": {
                "value": [
                    {
                        "name": "challenge-authenticator",
                        "value": [{"name": "credentials"}],
                    }
                ]
            },
        }

        with pytest.raises(auth.MfaRequired):
            await client._async_handle_remediation(response)

        client._async_post_idx = AsyncMock(
            return_value={"success": {"href": "https://example.test/success"}}
        )
        client._async_finish_from_success_href = AsyncMock(
            return_value={"access_token": "token"}
        )

        result = await client.async_submit_mfa("123456")

        assert result == {"access_token": "token"}


class TestStartLoginSkipsRedundantSteps:
    """Okta's IDX state machine doesn't always require identify+password:
    a persisted device-trust (DT) cookie can make introspect() jump straight
    to a later remediation. async_start_login() must follow whatever
    introspect() actually reports instead of blindly calling identify then
    answer-password, or Okta rejects the out-of-order request with an
    "Invalid operation for the current authentication" error.
    """

    def _client(self) -> auth.MoAmWaterAuthClient:
        client = auth.MoAmWaterAuthClient(AsyncMock(spec=aiohttp.ClientSession))
        client._async_get_initial_state_token = AsyncMock(return_value="state-token")
        return client

    async def test_normal_flow_still_calls_identify_and_password(self):
        client = self._client()
        client._async_introspect = AsyncMock(
            return_value={
                "stateHandle": "s0",
                "remediation": {"value": [{"name": "identify"}]},
            }
        )
        client._async_identify = AsyncMock(
            return_value={
                "stateHandle": "s1",
                "remediation": {"value": [{"name": "challenge-authenticator"}]},
            }
        )
        client._async_answer_password = AsyncMock(return_value={"stateHandle": "s2"})
        client._async_handle_remediation = AsyncMock(return_value={"access_token": "tok"})

        result = await client.async_start_login("user", "pass")

        client._async_identify.assert_awaited_once_with("user")
        client._async_answer_password.assert_awaited_once()
        assert result == {"access_token": "tok"}

    async def test_skips_identify_when_okta_already_recognizes_device(self):
        client = self._client()
        # introspect() jumps straight to a password challenge because a
        # persisted DT cookie already identified the user.
        client._async_introspect = AsyncMock(
            return_value={
                "stateHandle": "s0",
                "remediation": {"value": [{"name": "challenge-authenticator"}]},
            }
        )
        client._async_identify = AsyncMock()
        client._async_answer_password = AsyncMock(return_value={"stateHandle": "s1"})
        client._async_handle_remediation = AsyncMock(return_value={"access_token": "tok"})

        result = await client.async_start_login("user", "pass")

        client._async_identify.assert_not_called()
        client._async_answer_password.assert_awaited_once()
        assert result == {"access_token": "tok"}

    async def test_skips_both_steps_when_introspect_already_finished(self):
        client = self._client()
        client._async_introspect = AsyncMock(
            return_value={"stateHandle": "s0", "success": {"href": "https://x/success"}}
        )
        client._async_identify = AsyncMock()
        client._async_answer_password = AsyncMock()
        client._async_handle_remediation = AsyncMock(return_value={"access_token": "tok"})

        result = await client.async_start_login("user", "pass")

        client._async_identify.assert_not_called()
        client._async_answer_password.assert_not_called()
        assert result == {"access_token": "tok"}
