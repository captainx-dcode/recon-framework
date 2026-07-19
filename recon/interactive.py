"""Interactive mode (the "wizard").

A human sitting at a terminal doing a single lookup shouldn't have to remember
flag syntax. This module provides a guided, question-and-answer flow that
collects the same information the flags would — target, passive/full mode,
output format — and, when a chosen collector is missing its API key, offers to
supply the key or skip that source.

**Why this lives in its own module and is strictly opt-in.**
The framework's core value is that it runs non-interactively: CodeGrade imports
it, scripts pipe its JSON, cron schedules it. A blocking ``input()`` prompt would
break every one of those uses. So all prompting is quarantined here and is only
ever triggered by :mod:`recon.cli` when (a) the user supplied no target argument
*and* (b) the program is attached to a real interactive terminal. Pass any target
flag, or redirect stdin, and this module is never entered — the flag-driven,
scriptable behaviour is completely preserved.

The wizard returns a plain :class:`WizardChoices` dataclass; it does not run
collectors itself. The CLI takes those choices and drives the engine exactly as
it would for equivalent flags, so there is one execution path, not two.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from recon.core.config import ENV_KEYS, Config
from recon.output.formatters import available_formats
from recon.utils.validators import classify


@dataclass
class WizardChoices:
    """The user's answers, mirroring the equivalent command-line flags."""

    target: str
    passive_only: bool
    output: str
    save: bool
    # Keys the user pasted at the prompt, by logical name (e.g. "shodan_api_key").
    # These are merged into the Config the CLI builds so the run can use them
    # without the user having to edit .env first.
    provided_keys: dict[str, str] = field(default_factory=dict)


def is_interactive() -> bool:
    """True only when both stdin and stdout are attached to a real terminal.

    This is the gate that keeps the wizard from ever firing in a non-interactive
    context (piped input, CodeGrade, CI, ``recon.py < file``). If either stream
    is not a TTY, the CLI treats a missing target as the usual error instead of
    prompting.
    """
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(prompt: str, default: str | None = None) -> str:
    """Prompt for free text, returning ``default`` on an empty response."""
    suffix = f" [{default}]" if default else ""
    while True:
        answer = input(f"{prompt}{suffix}: ").strip()
        if answer:
            return answer
        if default is not None:
            return default


def _ask_choice(prompt: str, options: list[tuple[str, str]], default_index: int = 0) -> str:
    """Prompt the user to pick one numbered option.

    ``options`` is a list of (value, label). Returns the chosen *value*. Accepts
    either the number or the value text; re-asks on invalid input.
    """
    print(prompt)
    for i, (_value, label) in enumerate(options, start=1):
        marker = " (default)" if i - 1 == default_index else ""
        print(f"  [{i}] {label}{marker}")

    values = [v for v, _ in options]
    while True:
        raw = input("  Choose: ").strip().lower()
        if not raw:
            return values[default_index]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return values[int(raw) - 1]
        if raw in values:
            return raw
        print("  Please enter one of the numbers shown.")


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    """Prompt for a yes/no answer."""
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Please answer y or n.")


def _prompt_for_missing_keys(config: Config) -> dict[str, str]:
    """In full mode, offer to supply any API keys that aren't configured.

    For each key an active collector might need, if it's absent from config we
    ask the user to paste one or skip. Skipping simply means that collector will
    report ``skipped`` at run time — the same graceful behaviour as flag mode.
    Returns only the keys the user actually provided.
    """
    provided: dict[str, str] = {}
    # Only the keys that back the active collectors are worth asking about here.
    interesting = ("shodan_api_key", "virustotal_api_key")

    for logical_name in interesting:
        if config.get_key(logical_name):
            continue  # already set via environment/.env — nothing to ask
        env_var = ENV_KEYS.get(logical_name, logical_name.upper())
        friendly = logical_name.replace("_api_key", "").replace("_", " ").title()
        print(f"\n  No {friendly} API key found ({env_var}).")
        if _ask_yes_no(f"  Provide a {friendly} key now? (No = skip {friendly})", default=False):
            value = input(f"  Paste {friendly} key: ").strip()
            if value:
                provided[logical_name] = value
        # If they decline or paste nothing, the collector will just be skipped.
    return provided


def run_wizard(config: Config | None = None) -> WizardChoices:
    """Run the interactive flow and return the collected choices.

    ``config`` is the already-loaded Config (so we can tell which keys are
    present). If not supplied, one is loaded.
    """
    cfg = config or Config.load()

    print("\n  Recon Framework — interactive mode")
    print("  (tip: pass --domain / --ip to skip these questions)\n")

    # 1) Target — validated immediately so the user finds out now, not later.
    while True:
        target = _ask("  Target domain or IP")
        try:
            classify(target)
            break
        except Exception as exc:  # noqa: BLE001
            print(f"  '{target}' doesn't look like a valid domain or IP ({exc}). Try again.")

    # 2) Mode.
    mode = _ask_choice(
        "\n  Which mode?",
        [
            ("passive", "Passive only  — WHOIS + DNS, no API keys needed"),
            ("full", "Full          — also Shodan / VirusTotal (needs keys)"),
        ],
        default_index=0,
    )
    passive_only = mode == "passive"

    # 3) In full mode, offer to collect any missing keys.
    provided_keys: dict[str, str] = {}
    if not passive_only:
        provided_keys = _prompt_for_missing_keys(cfg)

    # 4) Output format (+ whether to save).
    fmt_options = [(f, f) for f in available_formats()]
    default_fmt_index = available_formats().index("table") if "table" in available_formats() else 0
    output = _ask_choice("\n  Output format?", fmt_options, default_index=default_fmt_index)
    save = _ask_yes_no("\n  Save the report to a file?", default=False)

    print()  # blank line before the run begins
    return WizardChoices(
        target=target,
        passive_only=passive_only,
        output=output,
        save=save,
        provided_keys=provided_keys,
    )
