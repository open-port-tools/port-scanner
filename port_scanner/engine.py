"""Cross-platform asynchronous port scanning engine."""

from __future__ import annotations

import asyncio
import datetime
import errno
import ipaddress
import re
import socket
import ssl
import sys
import time
from typing import Any, Callable

from port_scanner.models import (
    HostScanSummary,
    PortResult,
    PortState,
    ScanConfig,
    ScanProgress,
    ScanReport,
)
from port_scanner.services import (
    HTTP_LIKELY_PORTS,
    TLS_LIKELY_PORTS,
    identify_service,
)

try:
    import resource
except ImportError:  # Windows does not provide the resource module
    resource = None  # type: ignore[assignment]

ResultCallback = Callable[[PortResult], Any]
ProgressCallback = Callable[[ScanProgress], Any]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^(HTTP/\d(?:\.\d)?\s+\d{3}[^\r\n]*)", re.IGNORECASE)


def configure_event_loop() -> None:
    """Apply OS-appropriate asyncio event loop policies."""
    if sys.platform == "win32":
        # WindowsProactorEventLoopPolicy avoids the 512-socket FD_SETSIZE ceiling
        # of SelectorEventLoop and is the default on Python 3.8+, ensure it stays active.
        proactor_cls = getattr(asyncio, "WindowsProactorEventLoopPolicy", None)
        if proactor_cls is not None and not isinstance(
            asyncio.get_event_loop_policy(), proactor_cls
        ):
            asyncio.set_event_loop_policy(proactor_cls())


def get_safe_concurrency(requested: int) -> int:
    """
    Clamp concurrency to safe OS file-descriptor / socket limits.

    Prevents `EMFILE` (Too many open files) on macOS/Linux and Winsock
    ephemeral port exhaustion on Windows.
    """
    requested = max(1, int(requested))

    if sys.platform == "win32":
        policy = asyncio.get_event_loop_policy()
        selector_cls = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
        if selector_cls is not None and isinstance(policy, selector_cls):
            return min(requested, 450)
        return min(requested, 1000)

    if resource is not None:
        try:
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_limit = min(hard_limit, max(soft_limit, requested + 256, 2048))
            if target_limit > soft_limit:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard_limit))
                    soft_limit = target_limit
                except (ValueError, OSError):
                    pass
            # Leave headroom for stdin/stdout/stderr, sockets, DNS, GUI, and files
            max_safe = max(32, soft_limit - 96)
            return min(requested, max_safe)
        except (ValueError, OSError):
            return min(requested, 500)

    return min(requested, 500)


def _sanitize_banner(raw: bytes, max_len: int = 160) -> str:
    """Decode raw network bytes into a clean single-line printable string."""
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    cleaned = "".join(ch if (32 <= ord(ch) < 127 or ch in "\t") else " " for ch in text)
    collapsed = " ".join(cleaned.split())
    if len(collapsed) > max_len:
        return collapsed[: max_len - 3] + "..."
    return collapsed


def _parse_http_response(raw: bytes) -> str:
    """Extract status code, Server header, and page title from an HTTP payload."""
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    parts: list[str] = []

    status_match = _STATUS_RE.match(text)
    if status_match:
        parts.append(status_match.group(1).strip())

    server_match = _SERVER_RE.search(text)
    if server_match:
        parts.append(f"Server: {server_match.group(1).strip()}")

    title_match = _TITLE_RE.search(text)
    if title_match:
        title = " ".join(title_match.group(1).split())
        if title:
            if len(title) > 60:
                title = title[:57] + "..."
            parts.append(f'Title: "{title}"')

    if parts:
        return " | ".join(parts)
    return _sanitize_banner(raw)


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Gracefully close an asyncio StreamWriter without hanging."""
    if writer is None:
        return
    try:
        writer.close()
        wait_closed = getattr(writer, "wait_closed", None)
        if wait_closed is not None:
            await asyncio.wait_for(wait_closed(), timeout=0.25)
    except Exception:
        pass


async def _maybe_await(func: Callable[..., Any], arg: Any) -> None:
    """Invoke a callback that may be synchronous or async."""
    res = func(arg)
    if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
        await res


class AsyncPortScanner:
    """High-performance cross-platform asynchronous TCP port scanner."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def _resolve_target(
        self, loop: asyncio.AbstractEventLoop, target: str
    ) -> tuple[str, bool, str]:
        """Resolve a hostname or IP literal to a single IP address string."""
        try:
            addr = ipaddress.ip_address(target)
            return str(addr), True, ""
        except ValueError:
            pass

        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(
                    target,
                    None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                ),
                timeout=max(2.0, self.config.timeout * 2),
            )
            if not infos:
                return "", False, "DNS returned no addresses"
            # Prefer IPv4 when both IPv4 and IPv6 records exist for deterministic scanning
            ipv4 = [info for info in infos if info[0] == socket.AF_INET]
            chosen = ipv4[0] if ipv4 else infos[0]
            ip = str(chosen[4][0])
            return ip, True, ""
        except asyncio.TimeoutError:
            return "", False, "DNS resolution timed out"
        except socket.gaierror as exc:
            return "", False, f"DNS resolution failed: {exc}"
        except OSError as exc:
            return "", False, f"Resolution error: {exc}"

    async def _probe_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        timeout: float,
    ) -> str:
        """Send a lightweight HTTP GET request and parse response metadata."""
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: AsyncPortScanner/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        try:
            writer.write(req)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            chunks: list[bytes] = []
            total_bytes = 0
            while total_bytes < 8192:
                chunk = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                if not chunk:
                    break
                chunks.append(chunk)
                total_bytes += len(chunk)
                if b"</title>" in b"".join(chunks).lower():
                    break
            return _parse_http_response(b"".join(chunks))
        except Exception:
            return ""

    async def _inspect_tls_endpoint(
        self, host: str, ip: str, port: int, timeout: float
    ) -> tuple[str, str]:
        """
        Inspect TLS protocol version, cipher, certificate CN, and optional HTTPS info.

        Tries verified TLS first to extract full certificate subject fields,
        then falls back to unverified mode for self-signed / IP endpoints.
        """
        tls_parts: list[str] = []
        http_info = ""
        probe_timeout = min(max(timeout, 0.6), 2.5)

        for verify in (True, False):
            writer: asyncio.StreamWriter | None = None
            try:
                ctx = ssl.create_default_context()
                if not verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                server_hostname = host if verify else None
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        ip, port, ssl=ctx, server_hostname=server_hostname
                    ),
                    timeout=probe_timeout,
                )
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is not None:
                    proto = ssl_obj.version() or "TLS"
                    cipher_info = ssl_obj.cipher()
                    cipher_name = cipher_info[0] if cipher_info else ""
                    tls_desc = f"{proto}"
                    if cipher_name:
                        tls_desc += f" ({cipher_name})"
                    cert = ssl_obj.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        cn = subject.get("commonName")
                        if cn:
                            tls_desc += f" CN={cn}"
                        not_after = cert.get("notAfter")
                        if not_after:
                            tls_desc += f" exp={not_after}"
                    elif not verify:
                        tls_desc += " [unverified/self-signed]"
                    tls_parts.append(tls_desc)

                if self.config.grab_banner and port in {443, 2083, 2376, 5001, 5986, 6443, 8443, 9443}:
                    http_info = await self._probe_http(reader, writer, host, probe_timeout)

                await _close_writer(writer)
                return " ".join(tls_parts), http_info
            except ssl.SSLCertVerificationError:
                await _close_writer(writer)
                if verify:
                    continue
                return "TLS (certificate verification failed)", ""
            except ssl.SSLError:
                await _close_writer(writer)
                return "", ""
            except Exception:
                await _close_writer(writer)
                if verify:
                    continue
                return "", ""

        return "", ""

    async def _probe_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> tuple[str, str]:
        """Grab service banner or HTTP metadata from an already-connected socket."""
        probe_timeout = min(max(self.config.timeout, 0.5), 1.5)

        if port in HTTP_LIKELY_PORTS:
            http_info = await self._probe_http(reader, writer, host, probe_timeout)
            return "", http_info

        # Wait briefly for servers that send an immediate greeting (SSH, FTP, SMTP, POP3, IMAP)
        try:
            data = await asyncio.wait_for(
                reader.read(512), timeout=min(probe_timeout, 0.55)
            )
            if data:
                if data.lstrip().startswith(b"HTTP/"):
                    return "", _parse_http_response(data)
                return _sanitize_banner(data), ""
        except asyncio.TimeoutError:
            pass
        except Exception:
            return "", ""

        # If server stayed silent, nudge with CRLF
        try:
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=0.3)
            data = await asyncio.wait_for(reader.read(512), timeout=0.45)
            if data:
                if data.lstrip().startswith(b"HTTP/"):
                    return "", _parse_http_response(data)
                return _sanitize_banner(data), ""
        except Exception:
            pass

        return "", ""

    async def _probe_port(self, host: str, ip: str, port: int) -> PortResult:
        """Probe a single TCP port on a resolved IP and optionally inspect banner/TLS."""
        service = identify_service(port)
        writer: asyncio.StreamWriter | None = None
        t0 = time.perf_counter()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.config.timeout,
            )
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            banner = ""
            http_info = ""
            tls_info = ""

            if self.config.grab_banner and port not in TLS_LIKELY_PORTS:
                banner, http_info = await self._probe_banner(reader, writer, host, port)

            await _close_writer(writer)
            writer = None

            if self.config.inspect_tls and port in TLS_LIKELY_PORTS:
                tls_info, tls_http = await self._inspect_tls_endpoint(
                    host, ip, port, self.config.timeout
                )
                if tls_http and not http_info:
                    http_info = tls_http

            return PortResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.OPEN.value,
                service=service,
                latency_ms=latency_ms,
                banner=banner,
                tls_info=tls_info,
                http_info=http_info,
            )

        except ConnectionRefusedError:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return PortResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.CLOSED.value,
                service=service,
                latency_ms=latency_ms,
            )
        except (asyncio.TimeoutError, TimeoutError):
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return PortResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.FILTERED.value,
                service=service,
                latency_ms=latency_ms,
            )
        except OSError as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            refused_errnos = {errno.ECONNREFUSED}
            if hasattr(errno, "WSAECONNREFUSED"):
                refused_errnos.add(errno.WSAECONNREFUSED)
            state = (
                PortState.CLOSED.value
                if exc.errno in refused_errnos
                else PortState.FILTERED.value
            )
            return PortResult(
                host=host,
                ip=ip,
                port=port,
                state=state,
                service=service,
                latency_ms=latency_ms,
            )
        finally:
            await _close_writer(writer)

    async def scan(
        self,
        on_result: ResultCallback | None = None,
        on_progress: ProgressCallback | None = None,
        cancel_event: Any = None,
    ) -> ScanReport:
        """
        Execute the asynchronous scan across all configured targets and ports.

        Uses a bounded worker pool so even a full 1-65535 scan uses constant memory.
        """
        loop = asyncio.get_running_loop()
        started_wall = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scan_start = time.perf_counter()

        # Resolve targets concurrently
        resolve_tasks = [self._resolve_target(loop, t) for t in self.config.targets]
        resolved_list = await asyncio.gather(*resolve_tasks)

        summaries: dict[str, HostScanSummary] = {}
        active_targets: list[tuple[str, str]] = []
        for target, (ip, ok, err) in zip(self.config.targets, resolved_list):
            summaries[target] = HostScanSummary(
                host=target, ip=ip, resolved=ok, error=err
            )
            if ok:
                active_targets.append((target, ip))

        total_probes = len(active_targets) * len(self.config.ports)
        effective_concurrency = min(
            get_safe_concurrency(self.config.concurrency),
            max(1, total_probes),
        )

        # Create queue/lock inside the running event loop (Python 3.9 compatibility)
        queue: asyncio.Queue[tuple[str, str, int] | None] = asyncio.Queue(
            maxsize=max(1024, effective_concurrency * 4)
        )
        rate_lock = asyncio.Lock() if self.config.rate_limit > 0 else None
        min_interval = (
            1.0 / self.config.rate_limit if self.config.rate_limit > 0 else 0.0
        )
        last_dispatch = 0.0

        results: list[PortResult] = []
        completed = 0
        open_found = 0
        last_progress_emit = 0.0

        def _is_cancelled() -> bool:
            return bool(cancel_event is not None and cancel_event.is_set())

        async def _emit_progress(force: bool = False) -> None:
            nonlocal last_progress_emit
            if on_progress is None:
                return
            now = time.perf_counter()
            if not force and (now - last_progress_emit) < 0.08:
                return
            last_progress_emit = now
            elapsed = max(0.001, now - scan_start)
            rate_pps = completed / elapsed
            remaining = max(0, total_probes - completed)
            eta_sec = remaining / rate_pps if rate_pps > 0 else 0.0
            await _maybe_await(
                on_progress,
                ScanProgress(
                    completed=completed,
                    total=total_probes,
                    open_found=open_found,
                    elapsed_sec=elapsed,
                    rate_pps=rate_pps,
                    eta_sec=eta_sec,
                ),
            )

        async def _acquire_rate_slot() -> None:
            nonlocal last_dispatch
            if rate_lock is None or min_interval <= 0:
                return
            async with rate_lock:
                now = time.perf_counter()
                wait_for = (last_dispatch + min_interval) - now
                if wait_for > 0:
                    await asyncio.sleep(wait_for)
                    last_dispatch = time.perf_counter()
                else:
                    last_dispatch = now

        async def _producer() -> None:
            try:
                # Port-major order distributes probes evenly across all hosts in a LAN/CIDR scan
                for port in self.config.ports:
                    for target, ip in active_targets:
                        if _is_cancelled():
                            return
                        await queue.put((target, ip, port))
            finally:
                for _ in range(effective_concurrency):
                    await queue.put(None)

        async def _worker() -> None:
            nonlocal completed, open_found
            while True:
                item = await queue.get()
                try:
                    if item is None:
                        return
                    if _is_cancelled():
                        continue
                    if rate_lock is not None:
                        await _acquire_rate_slot()
                    if _is_cancelled():
                        continue

                    target, ip, port = item
                    res = await self._probe_port(target, ip, port)
                    completed += 1

                    summary = summaries[target]
                    if res.state == PortState.OPEN.value:
                        open_found += 1
                        summary.open_ports.append(res)
                        results.append(res)
                        if on_result is not None:
                            await _maybe_await(on_result, res)
                    elif res.state == PortState.CLOSED.value:
                        summary.closed_count += 1
                        if self.config.show_closed:
                            results.append(res)
                            if on_result is not None:
                                await _maybe_await(on_result, res)
                    else:
                        summary.filtered_count += 1
                        if self.config.show_closed:
                            results.append(res)
                            if on_result is not None:
                                await _maybe_await(on_result, res)

                    await _emit_progress(force=False)
                finally:
                    queue.task_done()

        if total_probes > 0:
            producer_task = asyncio.create_task(_producer())
            worker_tasks = [
                asyncio.create_task(_worker()) for _ in range(effective_concurrency)
            ]
            await asyncio.gather(producer_task, *worker_tasks)

        await _emit_progress(force=True)

        # Sort results deterministically by host order then port number
        host_order = {t: idx for idx, t in enumerate(self.config.targets)}
        results.sort(key=lambda r: (host_order.get(r.host, 0), r.port))
        for summary in summaries.values():
            summary.open_ports.sort(key=lambda r: r.port)

        duration_sec = time.perf_counter() - scan_start
        finished_wall = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return ScanReport(
            started_at=started_wall,
            finished_at=finished_wall,
            duration_sec=duration_sec,
            platform=sys.platform,
            concurrency_used=effective_concurrency,
            total_probes=total_probes,
            completed_probes=completed,
            cancelled=_is_cancelled(),
            hosts=[summaries[t] for t in self.config.targets],
            results=results,
        )
