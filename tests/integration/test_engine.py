"""Integration tests for the orchestration engine.

These wire the real engine, real registry mechanics, real models, and real
planning logic together — only the outermost network boundary is faked. This is
where we prove the *workflow* (classify -> plan -> collect -> aggregate) holds
end to end.
"""

import pytest

from recon.collectors.base import BaseCollector
from recon.collectors.registry import CollectorRegistry
from recon.core.engine import ReconEngine
from recon.core.exceptions import ValidationError
from recon.core.models import Status, TargetType
from tests.conftest import FakeHttpClient


# --- fake collectors --------------------------------------------------------

class PassiveDomainCollector(BaseCollector):
    name = "passive_dom"
    supported_types = (TargetType.DOMAIN,)
    active = False

    def _collect(self, target):
        return {"ran": "passive", "target": target.value}


class ActiveDomainCollector(BaseCollector):
    name = "active_dom"
    supported_types = (TargetType.DOMAIN,)
    active = True

    def _collect(self, target):
        return {"ran": "active", "target": target.value}


class IpOnlyCollector(BaseCollector):
    name = "ip_only"
    supported_types = (TargetType.IP,)

    def _collect(self, target):
        return {"ran": "ip"}


@pytest.fixture
def registry() -> CollectorRegistry:
    reg = CollectorRegistry()
    reg.register(PassiveDomainCollector)
    reg.register(ActiveDomainCollector)
    reg.register(IpOnlyCollector)
    return reg


@pytest.fixture
def engine(config, registry) -> ReconEngine:
    return ReconEngine(config, registry=registry, http=FakeHttpClient())


class TestEnginePlanning:
    def test_only_applicable_collectors_selected(self, engine):
        from recon.utils.validators import classify

        collectors = engine.plan(classify("example.com"))
        names = {c.name for c in collectors}
        assert names == {"passive_dom", "active_dom"}  # ip_only excluded

    def test_passive_only_excludes_active(self, engine):
        from recon.utils.validators import classify

        collectors = engine.plan(classify("example.com"), passive_only=True)
        assert {c.name for c in collectors} == {"passive_dom"}

    def test_tool_filter(self, engine):
        from recon.utils.validators import classify

        collectors = engine.plan(classify("example.com"), only=["passive_dom"])
        assert {c.name for c in collectors} == {"passive_dom"}


class TestEngineRun:
    def test_full_run_domain(self, engine):
        result = engine.run("example.com")
        assert result.target.type == TargetType.DOMAIN
        assert {r.source for r in result.results} == {"passive_dom", "active_dom"}
        assert all(r.status == Status.SUCCESS for r in result.results)
        assert result.duration_ms >= 0

    def test_full_run_ip(self, engine):
        result = engine.run("8.8.8.8")
        assert {r.source for r in result.results} == {"ip_only"}

    def test_passive_flag_end_to_end(self, engine):
        result = engine.run("example.com", passive_only=True)
        assert {r.source for r in result.results} == {"passive_dom"}

    def test_invalid_target_raises(self, engine):
        with pytest.raises(ValidationError):
            engine.run("this is not valid")

    def test_serialisable_output(self, engine):
        import json

        result = engine.run("example.com")
        # Must round-trip through JSON — guards against non-serialisable data.
        json.dumps(result.to_dict())
