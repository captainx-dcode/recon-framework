#!/usr/bin/env python3
"""Executable entry point.

Thin shim so the documented commands work verbatim:

    python recon.py --domain example.com

All real logic lives in :mod:`recon.cli`; this file exists only to give the
project a runnable script at its root, matching the module's usage examples.
"""

from recon.cli import main

if __name__ == "__main__":
    main()
