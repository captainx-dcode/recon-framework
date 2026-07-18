"""Tests for the normalized data model."""

from recon.core.models import (
    CollectorResult,
    ReconResult,
    Status,
    Target,
    TargetType,
)


def _target() -> Target:
    return Target(raw="example.com", value="example.com", type=TargetType.DOMAIN)


class TestCollectorResult:
    def test_ok_true_on_success(self):
        r = CollectorResult(source="whois", status=Status.SUCCESS, data={"a": 1})
        assert r.ok is True

    def test_ok_false_on_error(self):
        r = CollectorResult(source="whois", status=Status.ERROR, error="boom")
        assert r.ok is False

    def test_to_dict_serialises_enum(self):
        r = CollectorResult(source="dns", status=Status.SUCCESS)
        assert r.to_dict()["status"] == "success"


class TestReconResult:
    def test_add_and_successful_filter(self):
        result = ReconResult(target=_target())
        result.add(CollectorResult(source="whois", status=Status.SUCCESS))
        result.add(CollectorResult(source="dns", status=Status.ERROR, error="x"))
        assert len(result.results) == 2
        assert [r.source for r in result.successful] == ["whois"]

    def test_finalize_sets_duration(self):
        result = ReconResult(target=_target()).finalize()
        assert result.finished_at is not None
        assert result.duration_ms >= 0

    def test_to_dict_shape(self):
        result = ReconResult(target=_target())
        result.add(CollectorResult(source="whois", status=Status.SUCCESS, data={"x": 1}))
        result.finalize()
        d = result.to_dict()
        assert d["target"]["value"] == "example.com"
        assert d["sources"] == ["whois"]
        assert d["results"]["whois"]["data"] == {"x": 1}
