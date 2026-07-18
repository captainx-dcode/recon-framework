"""Tests for configuration management."""

import pytest

from recon.core.config import Config
from recon.core.exceptions import ConfigError


class TestConfigLoad:
    def test_load_reads_env_var(self, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "abc123")
        cfg = Config.load(env_file=None)
        assert cfg.get_key("virustotal_api_key") == "abc123"

    def test_missing_key_is_none(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        cfg = Config.load(env_file=None)
        assert cfg.get_key("shodan_api_key") is None

    def test_numeric_override(self, monkeypatch):
        monkeypatch.setenv("RECON_TIMEOUT", "42")
        cfg = Config.load(env_file=None)
        assert cfg.request_timeout == 42.0

    def test_invalid_numeric_falls_back(self, monkeypatch):
        monkeypatch.setenv("RECON_TIMEOUT", "not-a-number")
        cfg = Config.load(env_file=None)
        assert cfg.request_timeout == 15.0  # default


class TestRequireKey:
    def test_require_key_returns_value(self):
        cfg = Config(api_keys={"virustotal_api_key": "k"})
        assert cfg.require_key("virustotal_api_key") == "k"

    def test_require_key_raises_when_missing(self):
        cfg = Config(api_keys={"virustotal_api_key": None})
        with pytest.raises(ConfigError) as exc:
            cfg.require_key("virustotal_api_key")
        assert "VT_API_KEY" in str(exc.value)


class TestDotenv:
    def test_dotenv_file_is_loaded(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        env = tmp_path / ".env"
        env.write_text('VT_API_KEY="from-file"\n# comment\nRECON_TIMEOUT=5\n')
        cfg = Config.load(env_file=env)
        assert cfg.get_key("virustotal_api_key") == "from-file"
        assert cfg.request_timeout == 5.0

    def test_available_keys(self):
        cfg = Config(api_keys={"virustotal_api_key": "x", "shodan_api_key": None})
        assert cfg.available_keys() == ["virustotal_api_key"]
