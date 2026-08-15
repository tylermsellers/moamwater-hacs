"""Tests for api.py's MoAmWaterApiClient: the three-tier login strategy
(cached token -> silent SSO -> interactive) and the Okta session keep-alive.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock

import aiohttp
import pytest

from _moamwater_modules import api, auth


def _make_client(**kwargs) -> api.MoAmWaterApiClient:
    session = AsyncMock(spec=aiohttp.ClientSession)
    client = api.MoAmWaterApiClient(
        session, username="user@example.com", password="hunter2", **kwargs
    )
    return client


@pytest.mark.asyncio
class TestAsyncLogin:
    async def test_reuses_valid_cached_token_without_any_network_call(self):
        client = _make_client(
            access_token="cached-token",
            access_token_expires_at=time.time() + 3600,
        )
        client._auth.async_try_silent_sso = AsyncMock()
        client._auth.async_start_login = AsyncMock()

        await client.async_login()

        client._auth.async_try_silent_sso.assert_not_called()
        client._auth.async_start_login.assert_not_called()
        assert client.access_token == "cached-token"

    async def test_treats_token_within_safety_margin_as_expired(self):
        """A token expiring in <5 minutes must not be reused -- there must
        be enough of a safety margin to survive a full poll cycle.
        """
        client = _make_client(
            access_token="soon-to-expire",
            access_token_expires_at=time.time() + 60,  # only 1 minute left
        )
        client._auth.async_try_silent_sso = AsyncMock(
            return_value={"access_token": "new-token", "refresh_token": "rt"}
        )

        await client.async_login()

        client._auth.async_try_silent_sso.assert_awaited_once()
        assert client.access_token == "new-token"

    async def test_falls_back_to_silent_sso_when_no_cached_token(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(
            return_value={"access_token": "sso-token", "refresh_token": "rt"}
        )
        client._auth.async_start_login = AsyncMock()

        await client.async_login()

        client._auth.async_try_silent_sso.assert_awaited_once()
        client._auth.async_start_login.assert_not_called()
        assert client.access_token == "sso-token"

    async def test_interactive_login_used_when_silent_sso_fails_and_allowed(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(return_value=None)
        client._auth.async_start_login = AsyncMock(
            return_value={"access_token": "interactive-token", "refresh_token": "rt"}
        )

        await client.async_login(allow_interactive=True)

        client._auth.async_start_login.assert_awaited_once_with(
            "user@example.com", "hunter2", allow_otp_send=True
        )
        assert client.access_token == "interactive-token"

    async def test_background_login_raises_mfa_required_without_password_attempt(self):
        """A background (unattended) recovery must never submit the stored
        password: Okta rejects the DT-cookie fallback outright (confirmed
        2026-08-15), so attempting it only risks account lockout/anomaly
        detection for no benefit. It must go straight to reauth once
        silent SSO fails.
        """
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(return_value=None)
        client._auth.async_start_login = AsyncMock()

        with pytest.raises(auth.MfaRequired):
            await client.async_login(allow_interactive=False)

        client._auth.async_start_login.assert_not_called()

    async def test_mid_poll_401_raises_mfa_required_when_unattended(self):
        client = _make_client(
            access_token="stale-token",
            access_token_expires_at=time.time() + 3600,
        )
        client._post_once = AsyncMock(side_effect=api._Unauthorized("stale-token"))
        client._auth.async_try_silent_sso = AsyncMock(return_value=None)
        client._auth.async_start_login = AsyncMock()

        with pytest.raises(auth.MfaRequired):
            await client._post({"request": "data"})

        client._auth.async_start_login.assert_not_called()

    async def test_late_401_does_not_replace_a_concurrently_refreshed_token(self):
        client = _make_client(
            access_token="new-token",
            access_token_expires_at=time.time() + 3600,
        )
        client._post_once = AsyncMock(
            side_effect=[api._Unauthorized("old-token"), {"result": "recovered"}]
        )
        client._auth.async_try_silent_sso = AsyncMock()
        client._auth.async_start_login = AsyncMock()

        result = await client._post({"request": "data"})

        assert result == {"result": "recovered"}
        assert client.access_token == "new-token"
        client._auth.async_try_silent_sso.assert_not_called()
        client._auth.async_start_login.assert_not_called()


@pytest.mark.asyncio
class TestMaintainOktaSession:
    async def test_first_call_always_attempts_keepalive(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(
            return_value={"access_token": "kept-alive-token", "refresh_token": "rt"}
        )

        await client.async_maintain_okta_session()

        client._auth.async_try_silent_sso.assert_awaited_once()
        assert client.access_token == "kept-alive-token"

    async def test_skips_if_called_again_within_interval(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(
            return_value={"access_token": "token-1", "refresh_token": "rt"}
        )

        await client.async_maintain_okta_session(min_interval_seconds=3600)
        client._auth.async_try_silent_sso.assert_awaited_once()

        # Immediately calling again should be a no-op (still well within the interval).
        await client.async_maintain_okta_session(min_interval_seconds=3600)
        client._auth.async_try_silent_sso.assert_awaited_once()  # still just the one call

    async def test_retries_once_interval_has_elapsed(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(
            return_value={"access_token": "token-1", "refresh_token": "rt"}
        )
        await client.async_maintain_okta_session(min_interval_seconds=3600)

        # Simulate an hour having passed since the last touch.
        client._last_okta_touch = time.time() - 3700

        await client.async_maintain_okta_session(min_interval_seconds=3600)
        assert client._auth.async_try_silent_sso.await_count == 2

    async def test_expired_session_is_logged_but_does_not_raise(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(return_value=None)

        # Must not raise even though the underlying session has expired --
        # this is a best-effort keep-alive, not something the poll should fail on.
        await client.async_maintain_okta_session()

    async def test_expired_session_logs_at_warning(self, caplog):
        """Must log at WARNING (not INFO) so the elapsed-minutes figure --
        the actual measurement of Okta's idle-timeout tolerance -- survives
        on instances with file logging disabled (see auth.py's identical
        WARNING promotion from v1.1.4).
        """
        caplog.set_level("WARNING", logger=api._LOGGER.name)
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(return_value=None)

        await client.async_maintain_okta_session()

        assert "session already expired" in caplog.text
        assert caplog.records[-1].levelname == "WARNING"

    async def test_unexpected_exception_is_swallowed(self):
        client = _make_client()
        client._auth.async_try_silent_sso = AsyncMock(side_effect=RuntimeError("boom"))

        # Must not propagate -- a keep-alive failure should never break a poll cycle.
        await client.async_maintain_okta_session()
