"""Tests for collectors using injected fakes (no real network / keys)."""

import sys
import types

import pytest

from recon.collectors.base import BaseCollector
from recon.collectors.shodan_collector import ShodanCollector
from recon.collectors.virustotal_collector import VirusTotalCollector
from recon.core.models import Status, Target, TargetType
from tests.conftest import FakeResponse


def _domain(value="example.com") -> Target:
    return Target(raw=value, value=value, type=TargetType.DOMAIN)


def _ip(value="8.8.8.8") -> Target:
    return Target(raw=value, value=value, type=TargetType.IP)


# --- base wrapper behaviour ------------------------------------------------

class _BoomCollector(BaseCollector):
    name = "boom"
    supported_types = (TargetType.DOMAIN,)

    def _collect(self, target):
        raise RuntimeError("kaboom")


class _OkCollector(BaseCollector):
    name = "ok"
    supported_types = (TargetType.DOMAIN,)

    def _collect(self, target):
        return {"hello": "world"}


class TestBaseWrapper:
    def test_success_is_wrapped(self, config):
        result = _OkCollector(config).run(_domain())
        assert result.status == Status.SUCCESS
        assert result.data == {"hello": "world"}
        assert result.duration_ms >= 0

    def test_exception_becomes_error_result(self, config):
        result = _BoomCollector(config).run(_domain())
        assert result.status == Status.ERROR
        assert "kaboom" in result.error

    def test_not_applicable_target_type(self, config):
        result = _OkCollector(config).run(_ip())
        assert result.status == Status.NOT_APPLICABLE

    def test_missing_key_becomes_skipped(self, config_no_keys, fake_http_factory):
        http = fake_http_factory({})
        result = VirusTotalCollector(config_no_keys, http).run(_domain())
        assert result.status == Status.SKIPPED
        assert "VT_API_KEY" in result.error


# --- VirusTotal ------------------------------------------------------------

class TestVirusTotal:
    def test_successful_domain_report(self, config, fake_http_factory):
        payload = {
            "data": {
                "attributes": {
                    "reputation": -5,
                    "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60},
                    "categories": {"engine": "phishing"},
                    "registrar": "Test Registrar",
                }
            }
        }
        http = fake_http_factory({"virustotal.com": FakeResponse(200, payload)})
        result = VirusTotalCollector(config, http).run(_domain())

        assert result.ok
        summary = result.data["summary"]
        assert summary["flagged"] is True
        assert summary["detections"] == 4
        assert summary["registrar"] == "Test Registrar"

    def test_404_returns_not_found(self, config, fake_http_factory):
        http = fake_http_factory({"virustotal.com": FakeResponse(404, {})})
        result = VirusTotalCollector(config, http).run(_domain())
        assert result.ok
        assert result.data["found"] is False

    def test_401_becomes_error(self, config, fake_http_factory):
        http = fake_http_factory({"virustotal.com": FakeResponse(401, {})})
        result = VirusTotalCollector(config, http).run(_domain())
        assert result.status == Status.ERROR
        assert "401" in result.error

    def test_ip_uses_ip_endpoint(self, config, fake_http_factory):
        http = fake_http_factory({"ip_addresses": FakeResponse(200, {"data": {"attributes": {}}})})
        result = VirusTotalCollector(config, http).run(_ip())
        assert result.ok
        assert any("ip_addresses" in c for c in http.calls)


# --- Shodan ----------------------------------------------------------------

class TestShodan:
    def test_successful_host_report(self, config, fake_http_factory):
        payload = {
            "ports": [22, 80, 443],
            "hostnames": ["dns.google"],
            "org": "Google LLC",
            "data": [{"port": 443, "transport": "tcp", "product": "nginx", "_shodan": {"module": "https"}}],
        }
        http = fake_http_factory({"api.shodan.io": FakeResponse(200, payload)})
        result = ShodanCollector(config, http).run(_ip())
        assert result.ok
        assert result.data["summary"]["ports"] == [22, 80, 443]
        assert result.data["summary"]["services"][0]["product"] == "nginx"

    def test_only_applies_to_ip(self, config, fake_http_factory):
        http = fake_http_factory({})
        result = ShodanCollector(config, http).run(_domain())
        assert result.status == Status.NOT_APPLICABLE


# --- WHOIS (fake the third-party module) -----------------------------------

class TestWhois:
    @pytest.fixture
    def fake_whois_module(self, monkeypatch):
        """Inject a fake ``whois`` module so no real lookup occurs."""
        import datetime

        mod = types.ModuleType("whois")

        class _Record(dict):
            text = "raw whois text"

        def whois_func(domain):
            return _Record(
                domain_name="EXAMPLE.COM",
                registrar="Test Registrar",
                creation_date=datetime.datetime(1999, 1, 1),
                name_servers=["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
                emails="abuse@example.com",
            )

        mod.whois = whois_func  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "whois", mod)
        return mod

    def test_whois_normalises_datetime(self, config, fake_whois_module):
        from recon.collectors.whois_collector import WhoisCollector

        result = WhoisCollector(config).run(_domain())
        assert result.ok
        reg = result.data["registration"]
        assert reg["registrar"] == "Test Registrar"
        # datetime must have been coerced to an ISO string (JSON-safe)
        assert reg["creation_date"] == "1999-01-01T00:00:00"
        assert result.data["raw"] == "raw whois text"
