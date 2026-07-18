"""Shared test fixtures.

Provides lightweight fakes so tests never touch the real network or real API
keys — the "mock API responses" requirement. Because the framework uses
dependency injection throughout, faking is just passing a different object in;
no monkeypatching of globals is needed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from recon.core.config import Config


@pytest.fixture
def config() -> Config:
    """A Config with test API keys and near-zero delays for fast tests."""
    return Config(
        api_keys={
            "virustotal_api_key": "test-vt-key",
            "shodan_api_key": "test-shodan-key",
            "censys_api_id": None,
            "censys_api_secret": None,
        },
        request_timeout=1.0,
        rate_limit_delay=0.0,
        max_retries=0,
    )


@pytest.fixture
def config_no_keys() -> Config:
    """A Config with no API keys, to exercise SKIPPED behaviour."""
    return Config(api_keys={"virustotal_api_key": None, "shodan_api_key": None},
                  rate_limit_delay=0.0, max_retries=0)


@dataclass
class FakeResponse:
    """Minimal stand-in for requests.Response used by the fake HTTP client."""

    status_code: int
    _payload: dict
    headers: dict | None = None

    def json(self) -> dict:
        return self._payload

    @property
    def text(self) -> str:
        return json.dumps(self._payload)


class FakeHttpClient:
    """Records requests and returns queued responses.

    Behaves like :class:`recon.utils.http.HttpClient` for the ``get`` method,
    which is all collectors use. Tests queue responses keyed by URL substring.
    """

    def __init__(self, routes: dict[str, FakeResponse] | None = None):
        self.routes = routes or {}
        self.calls: list[str] = []

    def get(self, url, *, headers=None, params=None):  # noqa: D401 - mirrors real signature
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return FakeResponse(status_code=404, _payload={"error": "not found"})

    def close(self):
        pass


@pytest.fixture
def fake_http_factory():
    """Return a factory that builds a FakeHttpClient from a routes dict."""
    def _make(routes: dict[str, FakeResponse]) -> FakeHttpClient:
        return FakeHttpClient(routes)
    return _make
