"""Centralized logging configuration.

The module teaches "add logging and debugging options to track script
execution." Rather than sprinkle ``print`` statements or configure logging in
many places (which fights itself), the whole framework configures logging once,
here, and every module obtains its logger via :func:`get_logger`. This keeps
log format consistent and lets ``--verbose`` flip the level globally.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False
_ROOT_NAME = "recon"


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the framework's root logger exactly once.

    Args:
        verbose: emit DEBUG-level records.
        quiet: suppress everything below WARNING (useful when piping machine
            output to stdout and you don't want logs interleaved).

    Idempotent: calling twice will not attach duplicate handlers, which would
    otherwise double every log line.
    """
    global _CONFIGURED

    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logger = logging.getLogger(_ROOT_NAME)
    logger.setLevel(level)

    if not _CONFIGURED:
        # Logs go to stderr so that stdout stays clean for structured output
        # (JSON/CSV), which is essential for piping and for CodeGrade capture.
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
        _CONFIGURED = True
    else:
        logger.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Return a child logger namespaced under the framework root.

    Passing ``__name__`` from a module inside the ``recon`` package yields a
    dotted logger name like ``recon.collectors.whois`` that inherits the root
    configuration.
    """
    return logging.getLogger(name if name.startswith(_ROOT_NAME) else f"{_ROOT_NAME}.{name}")
