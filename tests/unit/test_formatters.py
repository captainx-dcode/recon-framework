"""Tests for output formatters and the collector registry."""

import json

import pytest

from recon.collectors.registry import build_default_registry
from recon.core.models import CollectorResult, ReconResult, Status, Target, TargetType
from recon.output.formatters import (
    CsvFormatter,
    JsonFormatter,
    TableFormatter,
    available_formats,
    get_formatter,
)


@pytest.fixture
def sample_result() -> ReconResult:
    target = Target(raw="example.com", value="example.com", type=TargetType.DOMAIN)
    result = ReconResult(target=target)
    result.add(CollectorResult(
        source="whois", status=Status.SUCCESS,
        data={"registration": {"registrar": "Test Registrar", "creation_date": "1999-01-01T00:00:00"}},
    ))
    result.add(CollectorResult(
        source="dns", status=Status.SUCCESS,
        data={"record_types_found": ["A", "MX", "NS"]},
    ))
    result.add(CollectorResult(source="shodan", status=Status.SKIPPED, error="no key"))
    return result.finalize()


class TestJsonFormatter:
    def test_produces_valid_json(self, sample_result):
        out = JsonFormatter().render(sample_result)
        parsed = json.loads(out)
        assert parsed["target"]["value"] == "example.com"
        assert parsed["results"]["whois"]["status"] == "success"


class TestCsvFormatter:
    def test_one_row_per_result(self, sample_result):
        out = CsvFormatter().render(sample_result)
        lines = [l for l in out.strip().splitlines() if l]
        assert lines[0].startswith("target,target_type,source")
        assert len(lines) == 1 + 3  # header + 3 collector rows

    def test_data_column_is_json(self, sample_result):
        out = CsvFormatter().render(sample_result)
        assert "record_types_found" in out


class TestTableFormatter:
    def test_contains_target_and_sources(self, sample_result):
        out = TableFormatter().render(sample_result)
        assert "example.com" in out
        assert "whois" in out and "dns" in out and "shodan" in out

    def test_highlights_present(self, sample_result):
        out = TableFormatter().render(sample_result)
        assert "Test Registrar" in out
        assert "A, MX, NS" in out


class TestFactory:
    def test_get_each_format(self):
        for name in available_formats():
            assert get_formatter(name).name == name

    def test_unknown_format_raises(self):
        with pytest.raises(KeyError):
            get_formatter("xml")


class TestRegistry:
    def test_default_registry_has_builtins(self):
        reg = build_default_registry()
        assert set(reg.names()) >= {"whois", "dns", "virustotal", "shodan"}

    def test_get_unknown_raises(self):
        reg = build_default_registry()
        with pytest.raises(KeyError):
            reg.get("nope")

    def test_duplicate_registration_raises(self):
        reg = build_default_registry()
        with pytest.raises(ValueError):
            reg.register(reg.get("whois"))

    def test_describe_returns_tuples(self):
        reg = build_default_registry()
        rows = reg.describe()
        assert all(len(row) == 3 for row in rows)
