"""Data models for asynchronous port scanning."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class PortState(str, Enum):
    """Possible TCP port states observed during a scan."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class ScanConfig:
    """Configuration for an asynchronous port scan."""

    targets: list[str]
    ports: list[int]
    timeout: float = 1.0
    concurrency: int = 500
    grab_banner: bool = True
    inspect_tls: bool = True
    show_closed: bool = False
    rate_limit: float = 0.0

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError("At least one scan target is required.")
        if not self.ports:
            raise ValueError("At least one port is required.")
        if self.timeout <= 0:
            raise ValueError("Timeout must be greater than 0.")
        if self.concurrency < 1:
            raise ValueError("Concurrency must be at least 1.")
        if self.rate_limit < 0:
            raise ValueError("Rate limit cannot be negative.")


@dataclass
class PortResult:
    """Result for a single host/port probe."""

    host: str
    ip: str
    port: int
    state: str
    service: str
    latency_ms: float
    banner: str = ""
    tls_info: str = ""
    http_info: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize result to a JSON-compatible dictionary."""
        return asdict(self)

    @property
    def summary_detail(self) -> str:
        """Combined single-line fingerprint string for tables."""
        parts = [p for p in (self.http_info, self.tls_info, self.banner) if p]
        return " | ".join(parts)


@dataclass
class ScanProgress:
    """Real-time progress snapshot emitted during scanning."""

    completed: int
    total: int
    open_found: int
    elapsed_sec: float
    rate_pps: float
    eta_sec: float

    @property
    def percent(self) -> float:
        """Completion percentage in range 0..100."""
        if self.total <= 0:
            return 100.0
        return min(100.0, (self.completed / self.total) * 100.0)


@dataclass
class HostScanSummary:
    """Aggregated scan outcome for a single target host."""

    host: str
    ip: str
    resolved: bool
    error: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize host summary to a JSON-compatible dictionary."""
        return {
            "host": self.host,
            "ip": self.ip,
            "resolved": self.resolved,
            "error": self.error,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "closed_count": self.closed_count,
            "filtered_count": self.filtered_count,
        }


@dataclass
class ScanReport:
    """Full report produced after a scan finishes or is cancelled."""

    started_at: str
    finished_at: str
    duration_sec: float
    platform: str
    concurrency_used: int
    total_probes: int
    completed_probes: int
    cancelled: bool
    hosts: list[HostScanSummary] = field(default_factory=list)
    results: list[PortResult] = field(default_factory=list)

    @property
    def open_results(self) -> list[PortResult]:
        """Return only open port results."""
        return [r for r in self.results if r.state == PortState.OPEN.value]

    def to_dict(self) -> dict[str, Any]:
        """Serialize full report to a JSON-compatible dictionary."""
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": round(self.duration_sec, 3),
            "platform": self.platform,
            "concurrency_used": self.concurrency_used,
            "total_probes": self.total_probes,
            "completed_probes": self.completed_probes,
            "cancelled": self.cancelled,
            "open_count": len(self.open_results),
            "hosts": [h.to_dict() for h in self.hosts],
            "results": [r.to_dict() for r in self.results],
        }
