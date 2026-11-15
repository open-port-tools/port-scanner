#!/usr/bin/env python3
"""Dedicated GUI entry point for standalone windowed executables (.exe / .app)."""

from __future__ import annotations

import sys

from port_scanner.cli import main_gui

if __name__ == "__main__":
    sys.exit(main_gui())
