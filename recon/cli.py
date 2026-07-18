"""Command-line interface.

The composition root of the application: this is the one place that wires the
pieces together (parse args -> load config -> build engine -> run -> format ->
store). Keeping wiring here and logic in the library means the whole framework
is importable and testable *without* a shell, while the CLI stays a thin,
declarative layer.

Implements the flags the module illustrates and generalises them:
    recon.py --domain example.com
    recon.py --ip 8.8.8.8
    recon.py --target example.com          (auto-detects type)
    recon.py --output json|csv|table
    recon.py --tool whois --tool dns       (run specific collectors)
    recon.py --passive                     (skip active collectors)
    recon.py --save [--output-dir reports]
    recon.py --verbose / --quiet
    recon.py --list-tools
"""

from __future__ import annotations

import argparse
import sys

from recon.collectors.registry import build_default_registry
from recon.core.config import Config
from recon.core.engine import ReconEngine
from recon.core.exceptions import ReconError
from recon.output.formatters import available_formats, get_formatter
from recon.output.storage import ReportStore
from recon.utils.logging import configure_logging, get_logger

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser (kept separate so tests can inspect it)."""
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="Modular reconnaissance / OSINT framework (Recon Part 1).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  recon.py --domain example.com\n"
            "  recon.py --ip 8.8.8.8 --output json --save\n"
            "  recon.py --target example.com --tool whois --tool dns --passive\n"
        ),
    )

    # Target selection: mutually exclusive typed flags, or a generic --target.
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--domain", help="Domain to investigate (e.g. example.com).")
    group.add_argument("--ip", help="IP address to investigate (e.g. 8.8.8.8).")
    group.add_argument("--target", help="Any target; type is auto-detected.")

    parser.add_argument(
        "--tool", action="append", dest="tools", metavar="NAME",
        help="Run only this collector (repeatable). Omit to run all applicable.",
    )
    parser.add_argument(
        "--output", "-o", default="table", choices=available_formats(),
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--passive", action="store_true",
        help="Passive collectors only; skip anything that actively touches the network.",
    )
    parser.add_argument(
        "--save", action="store_true",
        help="Also write the report to disk.",
    )
    parser.add_argument(
        "--output-dir", default="reports", metavar="DIR",
        help="Directory for saved reports (default: reports/).",
    )
    parser.add_argument(
        "--env-file", default=".env", metavar="PATH",
        help="Path to a .env file with API keys (default: .env).",
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG logging.")
    verbosity.add_argument("--quiet", "-q", action="store_true", help="Only warnings and errors.")

    parser.add_argument(
        "--list-tools", action="store_true",
        help="List available collectors and exit.",
    )
    return parser


def _resolve_target(args: argparse.Namespace) -> str | None:
    """Pick whichever target flag the user supplied."""
    return args.domain or args.ip or args.target


def _print_tools() -> None:
    registry = build_default_registry()
    print("Available collectors:\n")
    for name, description, active in registry.describe():
        kind = "active " if active else "passive"
        print(f"  {name:<12} [{kind}]  {description}")


def run(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0 = success)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose, quiet=args.quiet)

    if args.list_tools:
        _print_tools()
        return 0

    raw_target = _resolve_target(args)
    if not raw_target:
        parser.error("no target given; use --domain, --ip, or --target (or --list-tools).")

    try:
        config = Config.load(env_file=args.env_file)
        with ReconEngine(config) as engine:
            result = engine.run(
                raw_target,
                only=args.tools,
                passive_only=args.passive,
            )

        formatter = get_formatter(args.output)
        rendered = formatter.render(result)
        print(rendered)

        if args.save:
            store = ReportStore(args.output_dir)
            path = store.save(result, formatter)
            # Note goes to stderr so it never pollutes piped structured output.
            print(f"\nSaved report to: {path}", file=sys.stderr)

        # Non-zero exit if literally nothing succeeded, so scripts can detect it.
        return 0 if result.successful or not result.results else 2

    except ReconError as exc:
        # Expected, framework-level failures: clean message, no traceback.
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")
        return 130


def main() -> None:
    """Console-script wrapper that translates the exit code to ``sys.exit``."""
    sys.exit(run())


if __name__ == "__main__":
    main()
