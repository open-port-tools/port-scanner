"""Cross-platform asynchronous port scanner with CLI and GUI modes."""

from __future__ import annotations

from port_scanner.engine import AsyncPortScanner, configure_event_loop, get_safe_concurrency
from port_scanner.models import (
    HostScanSummary,
    PortResult,
    PortState,
    ScanConfig,
    ScanProgress,
    ScanReport,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "AsyncPortScanner",
    "HostScanSummary",
    "PortResult",
    "PortState",
    "ScanConfig",
    "ScanProgress",
    "ScanReport",
    "configure_event_loop",
    "get_safe_concurrency",
]
