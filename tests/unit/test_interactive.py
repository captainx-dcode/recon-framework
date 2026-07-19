"""Tests for interactive mode and the Config.with_keys helper.

Interactive prompts are tested by monkeypatching ``builtins.input`` to feed
scripted answers, and ``isatty`` to simulate (or deny) a terminal. No real
terminal or network is involved.
"""

import builtins

import pytest

from recon.core.config import Config
from recon.interactive import WizardChoices, is_interactive, run_wizard


# --- Config.with_keys -------------------------------------------------------

class TestWithKeys:
    def test_merges_new_key(self):
        base = Config(api_keys={"shodan_api_key": None})
        merged = base.with_keys({"shodan_api_key": "abc"})
        assert merged.get_key("shodan_api_key") == "abc"

    def test_returns_new_instance_original_unchanged(self):
        base = Config(api_keys={"shodan_api_key": None})
        merged = base.with_keys({"shodan_api_key": "abc"})
        # Immutability: the original must be untouched.
        assert base.get_key("shodan_api_key") is None
        assert merged is not base

    def test_empty_value_is_ignored(self):
        base = Config(api_keys={"shodan_api_key": "existing"})
        merged = base.with_keys({"shodan_api_key": ""})
        assert merged.get_key("shodan_api_key") == "existing"

    def test_empty_dict_is_noop_same_instance(self):
        base = Config(api_keys={"shodan_api_key": "x"})
        assert base.with_keys({}) is base

    def test_preserves_behavioural_settings(self):
        base = Config(api_keys={}, request_timeout=42.0, max_retries=5)
        merged = base.with_keys({"shodan_api_key": "k"})
        assert merged.request_timeout == 42.0
        assert merged.max_retries == 5


# --- TTY gate ---------------------------------------------------------------

class TestIsInteractive:
    def test_true_when_both_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert is_interactive() is True

    def test_false_when_stdin_not_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert is_interactive() is False

    def test_false_when_stdout_not_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: False)
        assert is_interactive() is False


# --- Wizard flow ------------------------------------------------------------

def _feed(monkeypatch, answers):
    """Patch input() to return each scripted answer in turn."""
    it = iter(answers)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))


class TestRunWizard:
    def test_passive_table_no_save(self, monkeypatch):
        cfg = Config(api_keys={"shodan_api_key": None, "virustotal_api_key": None})
        # target, mode=1 (passive), output=3 (table), save=n
        _feed(monkeypatch, ["example.com", "1", "3", "n"])
        choices = run_wizard(cfg)
        assert isinstance(choices, WizardChoices)
        assert choices.target == "example.com"
        assert choices.passive_only is True
        assert choices.output == "table"
        assert choices.save is False
        assert choices.provided_keys == {}

    def test_invalid_target_reprompts(self, monkeypatch):
        cfg = Config(api_keys={})
        # first target invalid, then valid; passive; table; no save
        _feed(monkeypatch, ["not a domain!!", "example.com", "1", "3", "n"])
        choices = run_wizard(cfg)
        assert choices.target == "example.com"

    def test_full_mode_collects_provided_key(self, monkeypatch):
        cfg = Config(api_keys={"shodan_api_key": None, "virustotal_api_key": None})
        # target; mode=2 (full);
        # Shodan prompt: y, then paste key;
        # VirusTotal prompt: n (skip);
        # output=2 (json); save=y
        _feed(monkeypatch, [
            "example.com", "2",
            "y", "PASTED_SHODAN",
            "n",
            "2", "y",
        ])
        choices = run_wizard(cfg)
        assert choices.passive_only is False
        assert choices.provided_keys == {"shodan_api_key": "PASTED_SHODAN"}
        assert choices.output == "json"
        assert choices.save is True

    def test_full_mode_skips_when_key_present(self, monkeypatch):
        # Shodan key already set → not asked. Only VT is prompted (skipped).
        cfg = Config(api_keys={"shodan_api_key": "already", "virustotal_api_key": None})
        # target; mode=2; VT prompt: n; output=3; save=n
        _feed(monkeypatch, ["example.com", "2", "n", "3", "n"])
        choices = run_wizard(cfg)
        assert choices.provided_keys == {}

    def test_defaults_on_empty_answers(self, monkeypatch):
        cfg = Config(api_keys={})
        # target given, then all empty → mode default passive, output default table, save default no
        _feed(monkeypatch, ["example.com", "", "", ""])
        choices = run_wizard(cfg)
        assert choices.passive_only is True
        assert choices.output == "table"
        assert choices.save is False
