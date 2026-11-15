"""Unit and integration tests for Async Port Scanner."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from port_scanner.cli import _ensure_std_streams, _is_tty, main as cli_main
from port_scanner.engine import AsyncPortScanner, get_safe_concurrency
from port_scanner.exporters import export_report, render_report
from port_scanner.gui_web import WebDashboardServer
from port_scanner.models import PortState, ScanConfig
from port_scanner.services import (
    detect_local_networks,
    identify_service,
    parse_ports,
    parse_targets,
)


class TestParsersAndModels(unittest.TestCase):
    def test_parse_ports_profiles_and_ranges(self) -> None:
        quick = parse_ports(profile="quick")
        self.assertIn(22, quick)
        self.assertIn(443, quick)
        self.assertEqual(len(quick), 25)

        custom = parse_ports("443, 80, 8000-8002, 80")
        self.assertEqual(custom, [80, 443, 8000, 8001, 8002])

        full = parse_ports(profile="full")
        self.assertEqual(len(full), 65535)
        self.assertEqual(full[0], 1)
        self.assertEqual(full[-1], 65535)

    def test_parse_ports_validation(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("65536")
        with self.assertRaises(ValueError):
            parse_ports("100-50")
        with self.assertRaises(ValueError):
            parse_ports("abc")
        with self.assertRaises(ValueError):
            parse_ports(profile="nonexistent")

    def test_parse_targets(self) -> None:
        self.assertEqual(parse_targets("127.0.0.1, localhost"), ["127.0.0.1", "localhost"])
        cidr = parse_targets("192.168.10.0/30")
        self.assertEqual(cidr, ["192.168.10.1", "192.168.10.2"])

        dash_short = parse_targets("10.0.0.1-3")
        self.assertEqual(dash_short, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

        dash_full = parse_targets("10.0.0.10-10.0.0.12")
        self.assertEqual(dash_full, ["10.0.0.10", "10.0.0.11", "10.0.0.12"])

        with self.assertRaises(ValueError):
            parse_targets("   ")

    def test_identify_service_and_safe_concurrency(self) -> None:
        self.assertEqual(identify_service(22), "ssh")
        self.assertEqual(identify_service(5432), "postgresql")
        safe = get_safe_concurrency(100000)
        self.assertGreaterEqual(safe, 32)
        self.assertLessEqual(safe, 100000)

    def test_detect_local_networks_and_lan_keyword(self) -> None:
        net_info = detect_local_networks()
        self.assertIn("local_ip", net_info)
        self.assertIn("lan_cidr", net_info)
        self.assertIsInstance(net_info["candidates"], list)

        with patch(
            "port_scanner.services.detect_local_networks",
            return_value={
                "local_ip": "192.168.0.10",
                "lan_cidr": "192.168.0.0/30",
                "candidates": [{"ip": "192.168.0.10", "cidr": "192.168.0.0/30"}],
            },
        ):
            self.assertEqual(parse_targets("lan"), ["192.168.0.1", "192.168.0.2"])

        with patch(
            "port_scanner.services.detect_local_networks",
            return_value={"local_ip": "", "lan_cidr": "", "candidates": []},
        ):
            with self.assertRaises(ValueError):
                parse_targets("lan")


class TestAsyncScannerIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_scan_open_closed_and_banner(self) -> None:
        # Mock passive banner server (e.g. SSH-like greeting)
        async def handle_banner(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                writer.write(b"SSH-2.0-MockAsyncBanner\r\n")
                await writer.drain()
            finally:
                writer.close()

        # Mock HTTP server
        async def handle_http(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await asyncio.wait_for(reader.read(1024), timeout=1.0)
                body = b"<html><head><title>Scanner Test Page</title></head><body>OK</body></html>"
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: MockAsyncHTTP/1.0\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                writer.write(resp)
                await writer.drain()
            finally:
                writer.close()

        banner_srv = await asyncio.start_server(handle_banner, "127.0.0.1", 0)
        http_srv = await asyncio.start_server(handle_http, "127.0.0.1", 0)
        banner_port = banner_srv.sockets[0].getsockname()[1]
        http_port = http_srv.sockets[0].getsockname()[1]

        # Bind & close an ephemeral socket to get an unused port
        probe_srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        closed_port = probe_srv.sockets[0].getsockname()[1]
        probe_srv.close()
        await probe_srv.wait_closed()

        try:
            config = ScanConfig(
                targets=["127.0.0.1"],
                ports=[banner_port, http_port, closed_port],
                timeout=1.5,
                concurrency=10,
                grab_banner=True,
                inspect_tls=False,
                show_closed=True,
            )
            scanner = AsyncPortScanner(config)
            report = await scanner.scan()

            by_port = {r.port: r for r in report.results}
            self.assertEqual(by_port[banner_port].state, PortState.OPEN.value)
            self.assertIn("SSH-2.0-MockAsyncBanner", by_port[banner_port].banner)

            self.assertEqual(by_port[http_port].state, PortState.OPEN.value)
            # Trigger HTTP probe even on ephemeral port via response inspection
            self.assertTrue(
                "MockAsyncHTTP" in by_port[http_port].http_info
                or "200 OK" in by_port[http_port].http_info
                or "Scanner Test Page" in by_port[http_port].http_info
            )

            self.assertEqual(by_port[closed_port].state, PortState.CLOSED.value)
            self.assertEqual(len(report.open_results), 2)

            # Verify all exporters render cleanly
            for fmt in ("json", "csv", "md", "txt"):
                rendered = render_report(report, fmt)
                self.assertTrue(len(rendered) > 20)

            with tempfile.TemporaryDirectory() as tmpdir:
                out_path = Path(tmpdir) / "out.json"
                export_report(report, out_path)
                loaded = json.loads(out_path.read_text(encoding="utf-8"))
                self.assertEqual(loaded["open_count"], 2)
        finally:
            banner_srv.close()
            http_srv.close()
            await banner_srv.wait_closed()
            await http_srv.wait_closed()

    async def test_cancellation_and_unresolved_host(self) -> None:
        cancel = threading.Event()
        cancel.set()
        bad_host = "unresolved.example.invalid"
        config = ScanConfig(
            targets=["127.0.0.1", bad_host],
            ports=list(range(1, 50)),
            timeout=0.3,
            concurrency=10,
        )
        scanner = AsyncPortScanner(config)
        loop = asyncio.get_running_loop()
        orig_getaddrinfo = loop.getaddrinfo

        async def fake_getaddrinfo(host: str, *args, **kwargs):
            if host == bad_host:
                raise socket.gaierror(8, "nodename nor servname provided")
            return await orig_getaddrinfo(host, *args, **kwargs)

        with patch.object(loop, "getaddrinfo", side_effect=fake_getaddrinfo):
            report = await scanner.scan(cancel_event=cancel)

        self.assertTrue(report.cancelled)
        self.assertEqual(report.completed_probes, 0)
        unresolved = [h for h in report.hosts if h.host == bad_host][0]
        self.assertFalse(unresolved.resolved)
        self.assertIn("DNS resolution failed", unresolved.error)

    async def test_web_dashboard_api_lifecycle(self) -> None:
        srv = WebDashboardServer(host="127.0.0.1", port=0)
        await srv.start()
        try:
            port = srv.bound_port
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            writer.close()
            text = raw.decode("utf-8", errors="replace")
            self.assertIn("200 OK", text)
            self.assertIn('"profiles"', text)

            reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
            writer2.write(b"GET /api/network HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await writer2.drain()
            raw2 = await asyncio.wait_for(reader2.read(4096), timeout=2.0)
            writer2.close()
            text2 = raw2.decode("utf-8", errors="replace")
            self.assertIn("200 OK", text2)
            self.assertIn('"lan_cidr"', text2)
        finally:
            await srv.stop()


class TestCliJson(unittest.TestCase):
    def test_cli_help_and_json_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_md = Path(tmpdir) / "report.md"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli_main(
                    [
                        "127.0.0.1",
                        "-p",
                        "65534",
                        "-t",
                        "0.2",
                        "-q",
                        "--json",
                        "-o",
                        str(out_md),
                    ]
                )
            self.assertEqual(code, 0)
            payload = json.loads(buf.getvalue())
            self.assertIn("hosts", payload)
            self.assertTrue(out_md.exists())
            self.assertIn("# Port Scan Report", out_md.read_text(encoding="utf-8"))

    def test_windowed_exe_none_streams_and_frozen_gui_dispatch(self) -> None:
        orig_out, orig_err = sys.stdout, sys.stderr
        try:
            sys.stdout = None  # type: ignore[assignment]
            sys.stderr = None  # type: ignore[assignment]
            self.assertFalse(_is_tty(sys.stdout))
            _ensure_std_streams()
            self.assertIsNotNone(sys.stdout)
            self.assertIsNotNone(sys.stderr)
            print("safe write after stream init")
        finally:
            if sys.stdout is not None and sys.stdout is not orig_out:
                sys.stdout.close()
            if sys.stderr is not None and sys.stderr is not orig_err:
                sys.stderr.close()
            sys.stdout = orig_out
            sys.stderr = orig_err

        with patch.object(sys, "frozen", True, create=True), patch(
            "port_scanner.cli._launch_gui_with_fallback", return_value=0
        ) as mock_gui:
            code = cli_main([])
            self.assertEqual(code, 0)
            mock_gui.assert_called_once()


if __name__ == "__main__":
    unittest.main()
