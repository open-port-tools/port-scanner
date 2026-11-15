"""Cross-platform CLI entry point for Async Port Scanner."""

from __future__ import annotations

import argparse
import asyncio
import io
import os
import signal
import sys
import threading
from typing import Any

from port_scanner.engine import (
    AsyncPortScanner,
    configure_event_loop,
    get_safe_concurrency,
)
from port_scanner.exporters import export_report, render_report
from port_scanner.models import ScanConfig, ScanProgress, ScanReport
from port_scanner.services import (
    PROFILES,
    detect_local_networks,
    parse_ports,
    parse_targets,
)


def _enable_windows_ansi() -> bool:
    """Enable ANSI escape sequences in Windows 10/11 Command Prompt / PowerShell."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if mode.value & enable_vt:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except Exception:
        return False


def _ensure_std_streams() -> None:
    """
    Ensure sys.stdout and sys.stderr are valid writable streams.

    PyInstaller --windowed/--noconsole executables on Windows set stdout and
    stderr to None, which causes print() or argparse writes to crash.
    """
    for attr in ("stdout", "stderr"):
        if getattr(sys, attr, None) is None:
            try:
                setattr(sys, attr, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                setattr(sys, attr, io.StringIO())


def _is_tty(stream: Any) -> bool:
    """Safely check whether a stream is an interactive TTY."""
    return stream is not None and hasattr(stream, "isatty") and bool(stream.isatty())


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not _is_tty(sys.stdout):
        return False
    if sys.platform == "win32":
        return _enable_windows_ansi()
    return True


class _Colors:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self.wrap("1", text)

    def cyan(self, text: str) -> str:
        return self.wrap("36", text)

    def green(self, text: str) -> str:
        return self.wrap("32", text)

    def yellow(self, text: str) -> str:
        return self.wrap("33", text)

    def red(self, text: str) -> str:
        return self.wrap("31", text)

    def dim(self, text: str) -> str:
        return self.wrap("2", text)


def _format_progress_bar(prog: ScanProgress, width: int = 24) -> str:
    filled = int((prog.percent / 100.0) * width) if prog.total > 0 else width
    bar = "#" * filled + "-" * max(0, width - filled)
    eta = f" ETA {prog.eta_sec:.1f}s" if prog.eta_sec > 0.2 else ""
    return (
        f"[{bar}] {prog.percent:5.1f}% "
        f"({prog.completed}/{prog.total}) "
        f"open:{prog.open_found} "
        f"{prog.rate_pps:,.0f} pps{eta}"
    )


def _print_table(report: ScanReport, colors: _Colors, show_closed: bool) -> None:
    for host in report.hosts:
        if not host.resolved:
            print(
                f"\n{colors.bold(host.host)} -> {colors.red('UNRESOLVED')}: {host.error}"
            )
            continue

        header_ip = f" ({host.ip})" if host.ip and host.ip != host.host else ""
        print(
            f"\n{colors.bold('Target:')} {colors.cyan(host.host + header_ip)}  "
            f"{colors.green(f'{len(host.open_ports)} open')} | "
            f"{colors.dim(f'{host.closed_count} closed')} | "
            f"{colors.yellow(f'{host.filtered_count} filtered')}"
        )

        rows = (
            [r for r in report.results if r.host == host.host]
            if show_closed
            else host.open_ports
        )
        if not rows:
            print(colors.dim("  No matching ports found."))
            continue

        print(
            f"  {'PORT':<9} {'STATE':<10} {'SERVICE':<18} {'LATENCY':>9}   {'DETAILS'}"
        )
        print("  " + "-" * 78)
        for r in rows:
            port_col = f"{r.port}/tcp"
            if r.state == "open":
                state_col = colors.green(f"{r.state:<10}")
            elif r.state == "filtered":
                state_col = colors.yellow(f"{r.state:<10}")
            else:
                state_col = colors.dim(f"{r.state:<10}")
            lat_col = f"{r.latency_ms:>7.2f}ms"
            detail = r.summary_detail
            print(
                f"  {port_col:<9} {state_col} {r.service:<18} {lat_col:>9}   {detail}"
            )

    status = "Cancelled" if report.cancelled else "Completed"
    print(
        f"\n{colors.bold(status)} in {report.duration_sec:.2f}s "
        f"(platform={report.platform}, concurrency={report.concurrency_used}, "
        f"probes={report.completed_probes}/{report.total_probes})."
    )


def _launch_gui_with_fallback(
    prefer_web: bool,
    initial_target: str,
    web_host: str,
    web_port: int,
    no_browser: bool,
) -> int:
    if not prefer_web:
        try:
            from port_scanner.gui_tk import launch_tk_gui

            launch_tk_gui(initial_target=initial_target)
            return 0
        except Exception as exc:
            print(
                f"[!] Tkinter GUI unavailable ({exc}). Falling back to Web Dashboard GUI...",
                file=sys.stderr,
            )

    from port_scanner.gui_web import launch_web_gui

    launch_web_gui(
        host=web_host,
        port=web_port,
        initial_target=initial_target,
        open_browser=not no_browser,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description=(
            "Cross-platform asynchronous TCP port scanner with service fingerprinting, "
            "TLS inspection, Console CLI, Desktop Tkinter GUI, and Web Dashboard."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  port-scanner 127.0.0.1 --profile quick\n"
            "  port-scanner scanme.nmap.org -p 22,80,443,8000-8090\n"
            "  port-scanner 192.168.1.0/24 -p 22,80,443 -o scan.json\n"
            "  port-scanner --gui\n"
            "  port-scanner --web --web-port 8765\n"
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target host, IP, CIDR (192.168.1.0/24), IPv4 range, or 'lan'. Comma-separated allowed.",
    )
    parser.add_argument(
        "--lan",
        action="store_true",
        help="Scan the automatically detected local /24 network.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="",
        help="Port(s), ranges (1-1024), or profile name. Overrides --profile.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default="common",
        help="Built-in port preset when --ports is omitted (default: common).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Per-connection TCP timeout in seconds (default: 1.0).",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=500,
        help="Maximum concurrent async probes (auto-clamped to OS limits; default: 500).",
    )
    parser.add_argument(
        "-r",
        "--rate-limit",
        type=float,
        default=0.0,
        help="Optional probe rate limit in probes/sec (0 = unlimited).",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip HTTP/service banner grabbing for maximum speed.",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Skip TLS handshake and certificate inspection.",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Include closed and filtered ports in output and exports.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write scan report to file (.json, .csv, .md, .txt).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "md", "txt"],
        help="Explicit report format for --output (inferred from extension if omitted).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON report directly to stdout.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch desktop GUI (falls back to Web GUI if Tkinter is unavailable).",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch local Web Dashboard GUI in your browser.",
    )
    parser.add_argument(
        "--web-host",
        default="127.0.0.1",
        help="Bind host for --web mode (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8765,
        help="Bind port for --web mode (default: 8765).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open a browser tab in --web mode.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress live progress output.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version="async-port-scanner 1.0.0",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _ensure_std_streams()
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    if getattr(sys, "frozen", False) and not effective_argv:
        effective_argv = ["--gui"]

    parser = build_parser()
    args = parser.parse_args(effective_argv)

    if args.gui or args.web:
        initial = args.target or (
            detect_local_networks().get("lan_cidr") if args.lan else "127.0.0.1"
        ) or "127.0.0.1"
        return _launch_gui_with_fallback(
            prefer_web=bool(args.web),
            initial_target=initial,
            web_host=args.web_host,
            web_port=args.web_port,
            no_browser=args.no_browser,
        )

    target_spec = args.target or ("lan" if args.lan else "")
    if not target_spec:
        parser.print_help()
        return 2

    try:
        targets = parse_targets(target_spec)
        ports = parse_ports(args.ports, profile=args.profile)
        config = ScanConfig(
            targets=targets,
            ports=ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            grab_banner=not args.no_banner,
            inspect_tls=not args.no_tls,
            show_closed=args.show_closed,
            rate_limit=args.rate_limit,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    configure_event_loop()
    colors = _Colors(_supports_color() and not args.json)
    show_progress = not args.quiet and not args.json and _is_tty(sys.stderr)

    if not args.quiet and not args.json:
        safe_conc = get_safe_concurrency(config.concurrency)
        print(
            colors.bold("Async Port Scanner")
            + f" | targets={len(config.targets)} ports={len(config.ports)} "
            f"timeout={config.timeout}s concurrency={safe_conc}"
        )

    cancel_event = threading.Event()
    prev_sigint: Any = None
    has_sigint = hasattr(signal, "SIGINT")

    def _handle_sigint(_signum: int, _frame: Any) -> None:
        if not cancel_event.is_set():
            cancel_event.set()
            if not args.json:
                print(
                    "\n[!] Stopping scan gracefully (press Ctrl+C again to force exit)...",
                    file=sys.stderr,
                )
            if has_sigint:
                signal.signal(signal.SIGINT, signal.SIG_DFL)

    if has_sigint and threading.current_thread() is threading.main_thread():
        prev_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _handle_sigint)

    last_line_len = 0

    def _on_progress(prog: ScanProgress) -> None:
        nonlocal last_line_len
        if not show_progress:
            return
        line = _format_progress_bar(prog)
        pad = " " * max(0, last_line_len - len(line))
        last_line_len = len(line)
        sys.stderr.write(f"\r{line}{pad}")
        sys.stderr.flush()

    scanner = AsyncPortScanner(config)
    try:
        report = asyncio.run(
            scanner.scan(on_progress=_on_progress, cancel_event=cancel_event)
        )
    finally:
        if show_progress and last_line_len > 0:
            sys.stderr.write("\r" + (" " * last_line_len) + "\r")
            sys.stderr.flush()
        if has_sigint and prev_sigint is not None:
            signal.signal(signal.SIGINT, prev_sigint)

    if args.json:
        print(render_report(report, "json"), end="")
    else:
        _print_table(report, colors, show_closed=config.show_closed)

    if args.output:
        saved = export_report(report, args.output, fmt=args.format)
        if not args.json:
            print(colors.dim(f"Saved report -> {saved}"))

    return 130 if report.cancelled else 0


def main_gui(argv: list[str] | None = None) -> int:
    """Entry point for `port-scanner-gui`."""
    _ensure_std_streams()
    extra = list(argv) if argv is not None else sys.argv[1:]
    if "--gui" not in extra and "--web" not in extra:
        extra = ["--gui", *extra]
    return main(extra)
