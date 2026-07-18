"""Tests for target classification — the scope-definition stage."""

import pytest

from recon.core.exceptions import ValidationError
from recon.core.models import TargetType
from recon.utils.validators import classify, is_domain, is_ip


class TestClassify:
    def test_plain_domain(self):
        t = classify("example.com")
        assert t.type == TargetType.DOMAIN
        assert t.value == "example.com"

    def test_domain_is_lowercased(self):
        assert classify("Example.COM").value == "example.com"

    def test_subdomain(self):
        t = classify("mail.corp.example.co.uk")
        assert t.type == TargetType.DOMAIN

    def test_url_is_reduced_to_host(self):
        t = classify("https://example.com/path?q=1#frag")
        assert t.type == TargetType.DOMAIN
        assert t.value == "example.com"

    def test_url_with_port_and_userinfo(self):
        t = classify("http://user@example.com:8080/x")
        assert t.value == "example.com"

    def test_ipv4(self):
        t = classify("8.8.8.8")
        assert t.type == TargetType.IP
        assert t.value == "8.8.8.8"

    def test_ipv6(self):
        t = classify("2001:4860:4860::8888")
        assert t.type == TargetType.IP

    def test_email(self):
        t = classify("admin@example.com")
        assert t.type == TargetType.EMAIL
        assert t.value == "admin@example.com"

    def test_raw_is_preserved(self):
        t = classify("  Example.com  ")
        assert t.raw == "  Example.com  "
        assert t.value == "example.com"

    @pytest.mark.parametrize("bad", ["", "   ", "not a domain", "http://", "@@@", "..."])
    def test_invalid_raises(self, bad):
        with pytest.raises(ValidationError):
            classify(bad)

    def test_none_raises(self):
        with pytest.raises(ValidationError):
            classify(None)  # type: ignore[arg-type]


class TestPredicates:
    def test_is_domain_true(self):
        assert is_domain("example.com")

    def test_is_domain_false(self):
        assert not is_domain("8.8.8.8")

    def test_is_ip_true(self):
        assert is_ip("192.168.0.1")

    def test_is_ip_false(self):
        assert not is_ip("example.com")
