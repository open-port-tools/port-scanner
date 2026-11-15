"""Report exporters for JSON, CSV, Markdown, and plain text outputs."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from port_scanner.models import ScanReport


def format_report_json(report: ScanReport) -> str:
    """Serialize scan report as pretty-printed JSON."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def format_report_csv(report: ScanReport) -> str:
    """Serialize scan results as RFC 4180 CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "host",
            "ip",
            "port",
            "state",
            "service",
            "latency_ms",
            "http_info",
            "tls_info",
            "banner",
        ]
    )
    for res in report.results:
        writer.writerow(
            [
                res.host,
                res.ip,
                res.port,
                res.state,
                res.service,
                f"{res.latency_ms:.2f}",
                res.http_info,
                res.tls_info,
                res.banner,
            ]
        )
    return buf.getvalue()


def format_report_markdown(report: ScanReport) -> str:
    """Render scan report as clean GitHub-flavored Markdown."""
    lines = [
        "# Port Scan Report",
        "",
        f"- **Started:** `{report.started_at}`",
        f"- **Finished:** `{report.finished_at}`",
        f"- **Duration:** `{report.duration_sec:.2f}s`",
        f"- **Platform:** `{report.platform}` (concurrency `{report.concurrency_used}`)",
        f"- **Probes:** `{report.completed_probes}/{report.total_probes}`"
        + (" *(cancelled)*" if report.cancelled else ""),
        f"- **Open Ports Found:** `{len(report.open_results)}`",
        "",
    ]

    for host in report.hosts:
        status = f"IP `{host.ip}`" if host.resolved else f"Unresolved ({host.error})"
        lines.append(f"## Target: `{host.host}` ({status})")
        lines.append("")
        if not host.resolved:
            continue
        lines.append(
            f"Open: **{len(host.open_ports)}** | Closed: `{host.closed_count}` | Filtered: `{host.filtered_count}`"
        )
        lines.append("")
        if host.open_ports:
            lines.append("| Port | Service | Latency (ms) | Fingerprint / Banner |")
            lines.append("| ---: | :--- | ---: | :--- |")
            for r in host.open_ports:
                detail = r.summary_detail.replace("|", "\\|")
                lines.append(
                    f"| {r.port} | `{r.service}` | {r.latency_ms:.2f} | {detail} |"
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_report_text(report: ScanReport) -> str:
    """Render scan report as human-readable plain text."""
    lines = [
        "=== Async Port Scanner Report ===",
        f"Started:     {report.started_at}",
        f"Finished:    {report.finished_at}",
        f"Duration:    {report.duration_sec:.2f}s",
        f"Platform:    {report.platform} (concurrency={report.concurrency_used})",
        f"Probes:      {report.completed_probes}/{report.total_probes}"
        + (" [CANCELLED]" if report.cancelled else ""),
        f"Open Ports:  {len(report.open_results)}",
        "",
    ]
    for host in report.hosts:
        if not host.resolved:
            lines.append(f"[{host.host}] UNRESOLVED: {host.error}")
            continue
        lines.append(
            f"[{host.host} ({host.ip})] open={len(host.open_ports)} "
            f"closed={host.closed_count} filtered={host.filtered_count}"
        )
        for r in host.open_ports:
            detail = f" -> {r.summary_detail}" if r.summary_detail else ""
            lines.append(
                f"  {r.port:<5}/tcp  {r.state:<8} {r.service:<18} {r.latency_ms:>7.2f}ms{detail}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_report(report: ScanReport, fmt: str) -> str:
    """Render a scan report in the requested format (`json`, `csv`, `md`, `txt`)."""
    norm = fmt.strip().lower().lstrip(".")
    if norm == "json":
        return format_report_json(report)
    if norm == "csv":
        return format_report_csv(report)
    if norm in ("md", "markdown"):
        return format_report_markdown(report)
    if norm in ("txt", "text"):
        return format_report_text(report)
    raise ValueError(
        f"Unsupported export format '{fmt}'. Choose from: json, csv, md, txt."
    )


def export_report(report: ScanReport, path: str | Path, fmt: str | None = None) -> Path:
    """Write a scan report to disk, inferring format from extension if omitted."""
    target = Path(path)
    resolved_fmt = fmt or target.suffix.lstrip(".") or "json"
    content = render_report(report, resolved_fmt)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target
