"""Allow running `python -m port_scanner`."""

from __future__ import annotations

import sys

from port_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
