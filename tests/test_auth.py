"""Tests for auth.py: JWT expiry decoding, silent-SSO replay, and the
Okta session cookie jar disk persistence used to survive HA restarts.
"""
from __future__ import annotations

import base64
import json
import re
import time

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

    async def test_returns_none_on_network_error(self):
        async with aiohttp.ClientSession() as session:
            client = auth.MoAmWaterAuthClient(session)
            with aioresponses() as mocked:
                mocked.get(
                    re.compile(rf"^{re.escape(auth.AUTHORIZE_URL)}\?.*$"),
                    exception=aiohttp.ClientConnectionError(),
                )
                result = await client.async_try_silent_sso()

        assert result is None
