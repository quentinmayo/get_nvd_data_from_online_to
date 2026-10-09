#!/usr/bin/env python3
"""Compatibility entry point; prefer the installed `nvd-export` command."""

from nvd_exporter.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
