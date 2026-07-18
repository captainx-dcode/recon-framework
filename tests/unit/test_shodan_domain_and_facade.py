"""Tests for the upgraded (domain-capable) Shodan collector and the facade API."""

import pytest

from recon.collectors.shodan_collector import ShodanCollector
from recon.core.models import Status, Target, TargetType
from tests.conftest import FakeResponse


def _domain(value="example.com") -> Target:
    return Target(raw=value, value=value, type=TargetType.DOMAIN)


def _ip(value="8.8.8.8") -> Target:
    return Target(raw=value, value=value, type=TargetType.IP)


class TestShodanDomainSupport:
    def test_domain_is_now_supported(self):
        assert TargetType.DOMAIN in ShodanCollector.supported_types
        assert TargetType.IP in ShodanCollector.supported_types

    def test_domain_resolves_then_looks_up_host(self, config, fake_http_factory):
        # Route 1: dns/resolve returns an IP for the domain.
        # Route 2: shodan/host returns port data for that IP.
        http = fake_http_factory({
            "dns/resolve": FakeResponse(200, {"example.com": "93.184.216.34"}),
            "shodan/host": FakeResponse(200, {"ports": [80, 443], "org": "Example"}),
        })
        result = ShodanCollector(config, http).run(_domain())
        assert result.ok
        assert result.data["ip"] == "93.184.216.34"
        assert result.data["resolved_from"] == "example.com"
        assert result.data["summary"]["ports"] == [80, 443]

    def test_unresolvable_domain_reports_not_found(self, config, fake_http_factory, monkeypatch):
        # dns/resolve yields no IP, and the local resolver fallback also fails.
        http = fake_http_factory({"dns/resolve": FakeResponse(200, {})})
        monkeypatch.setattr(
            "recon.collectors.shodan_collector.resolve_hostname",
            lambda *a, **k: None,
        )
        result = ShodanCollector(config, http).run(_domain())
        assert result.ok
        assert result.data["found"] is False

    def test_ip_target_skips_resolution(self, config, fake_http_factory):
        http = fake_http_factory({"shodan/host": FakeResponse(200, {"ports": [22]})})
        result = ShodanCollector(config, http).run(_ip())
        assert result.ok
        assert result.data["ip"] == "8.8.8.8"
        # No resolve step for a raw IP.
        assert "resolved_from" not in result.data
        assert not any("dns/resolve" in c for c in http.calls)

    def test_missing_key_still_skips(self, config_no_keys, fake_http_factory):
        result = ShodanCollector(config_no_keys, fake_http_factory({})).run(_domain())
        assert result.status == Status.SKIPPED


class TestFacade:
    def test_whois_lookup_returns_data(self, monkeypatch):
        # Patch the collector the facade uses so no real WHOIS call happens.
        from recon.core.models import CollectorResult

        def fake_run(self, target):
            return CollectorResult(source="whois", status=Status.SUCCESS,
                                   data={"domain": target.value, "registration": {}})

        monkeypatch.setattr("recon.api.WhoisCollector.run", fake_run)
        from recon.api import whois_lookup

        out = whois_lookup("example.com")
        assert out["domain"] == "example.com"

    def test_facade_unwraps_error_to_envelope(self, monkeypatch):
        from recon.core.models import CollectorResult

        def fake_run(self, target):
            return CollectorResult(source="whois", status=Status.ERROR, error="boom")

        monkeypatch.setattr("recon.api.WhoisCollector.run", fake_run)
        from recon.api import whois_lookup

        out = whois_lookup("example.com")
        assert out["status"] == "error"
        assert out["error"] == "boom"
