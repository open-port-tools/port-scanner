#!/usr/bin/env python3
"""Convenience launcher for Async Port Scanner (CLI & GUI)."""

from __future__ import annotations

import sys

from port_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
