"""Tests for the hostname resolver utility."""

import socket
import sys
import types

from recon.utils import resolver


class TestResolveWithSocket:
    def test_socket_success(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname", lambda h: "93.184.216.34")
        # Force the dnspython path to miss so the socket fallback is exercised.
        monkeypatch.setattr(resolver, "_resolve_with_dnspython", lambda h, t: None)
        assert resolver.resolve_hostname("example.com") == "93.184.216.34"

    def test_socket_failure_returns_none(self, monkeypatch):
        def boom(_):
            raise socket.gaierror("no such host")

        monkeypatch.setattr(socket, "gethostbyname", boom)
        monkeypatch.setattr(resolver, "_resolve_with_dnspython", lambda h, t: None)
        assert resolver.resolve_hostname("nonexistent.invalid") is None


class TestResolveWithDnspython:
    def test_prefers_dnspython_when_available(self, monkeypatch):
        # If dnspython returns an IP, socket must not even be consulted.
        monkeypatch.setattr(resolver, "_resolve_with_dnspython", lambda h, t: "1.2.3.4")

        def fail(_):  # pragma: no cover - should never be called
            raise AssertionError("socket fallback should not run")

        monkeypatch.setattr(socket, "gethostbyname", fail)
        assert resolver.resolve_hostname("example.com") == "1.2.3.4"

    def test_dnspython_import_absent_falls_through(self, monkeypatch):
        # Simulate dnspython not installed: the helper must return None (not raise)
        # so resolve_hostname moves on to the socket fallback.
        monkeypatch.setitem(sys.modules, "dns.resolver", None)
        # With the module poisoned, the internal import raises ImportError → None.
        assert resolver._resolve_with_dnspython("example.com", 1.0) is None
