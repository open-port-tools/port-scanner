"""Zero-dependency async Web Dashboard GUI using asyncio HTTP + SSE."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from typing import Any

from port_scanner.engine import AsyncPortScanner, configure_event_loop
from port_scanner.exporters import render_report
from port_scanner.models import PortResult, ScanConfig, ScanProgress, ScanReport
from port_scanner.services import (
    PROFILES,
    detect_local_networks,
    parse_ports,
    parse_targets,
)

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Сканер портов</title>
<style>
  :root {
    --bg: #111214;
    --surface: #181a1f;
    --input-bg: #101114;
    --border: #272a31;
    --border-strong: #373c46;
    --text: #eceef2;
    --muted: #8b929e;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --danger: #dc2626;
    --danger-hover: #b91c1c;
    --ok: #4ade80;
    --err-bg: #2a1416;
    --err-border: #7f1d1d;
    --err-text: #fca5a5;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.45;
    overflow-x: clip;
  }
  :focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .wrap {
    max-width: 1080px;
    margin: 0 auto;
    padding: 20px 24px 36px;
  }
  .topbar {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 14px;
  }
  h1 {
    margin: 0;
    font-size: 17px;
    font-weight: 600;
    letter-spacing: -0.01em;
  }
  .host-note {
    font-size: 12px;
    color: var(--muted);
    font-family: var(--font-mono);
  }
  .toolbar {
    position: relative;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    overflow: hidden;
  }
  .seg {
    display: inline-flex;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 2px;
    gap: 2px;
  }
  .seg-btn {
    background: transparent;
    color: var(--muted);
    border: none;
    border-radius: 4px;
    padding: 6px 10px;
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
  }
  .seg-btn:hover:not(:disabled) {
    color: var(--text);
  }
  .seg-btn.active {
    background: #272b33;
    color: var(--text);
  }
  .seg-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  input[type="text"], select {
    background: var(--input-bg);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 7px 10px;
    font-family: var(--font-sans);
    font-size: 13px;
    height: 34px;
  }
  input[type="text"]:hover, select:hover {
    border-color: var(--border-strong);
  }
  .target-input {
    flex: 1 1 200px;
    min-width: 170px;
    font-family: var(--font-mono);
  }
  .ports-select {
    flex: 0 0 auto;
  }
  .custom-ports {
    width: 175px;
    font-family: var(--font-mono);
    display: none;
  }
  .custom-ports.visible {
    display: block;
  }
  .run-btn {
    margin-left: auto;
    height: 34px;
    padding: 0 16px;
    border: none;
    border-radius: 6px;
    background: var(--accent);
    color: #fff;
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .run-btn:hover {
    background: var(--accent-hover);
  }
  .run-btn.stop {
    background: var(--danger);
  }
  .run-btn.stop:hover {
    background: var(--danger-hover);
  }
  .progress-line {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    height: 2px;
    background: transparent;
  }
  .progress-fill {
    height: 100%;
    width: 0%;
    background: var(--accent);
    transition: width 80ms linear;
  }
  @media (prefers-reduced-motion: reduce) {
    .progress-fill { transition: none; }
  }
  .error-bar {
    margin-top: 10px;
    padding: 8px 12px;
    background: var(--err-bg);
    border: 1px solid var(--err-border);
    color: var(--err-text);
    border-radius: 6px;
    font-size: 13px;
    display: none;
  }
  .meta-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin: 14px 0 8px;
    min-height: 30px;
  }
  .status-line {
    font-size: 13px;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .meta-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .filter-input {
    width: 210px;
    height: 30px;
    font-size: 12px;
  }
  .export-links {
    display: none;
    align-items: center;
    gap: 8px;
  }
  .export-links.visible {
    display: inline-flex;
  }
  .export-link {
    color: var(--muted);
    text-decoration: none;
    font-size: 12px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 5px;
    background: var(--surface);
  }
  .export-link:hover {
    color: var(--text);
    border-color: var(--border-strong);
  }
  .table-wrap {
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th, td {
    padding: 9px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  th {
    color: var(--muted);
    font-weight: 500;
    font-size: 12px;
    background: #15171c;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  th:hover {
    color: var(--text);
  }
  tbody tr:hover td {
    background: #1d2026;
  }
  td.mono {
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
  }
  td.port-cell {
    color: var(--ok);
    font-weight: 600;
  }
  td.detail-cell {
    color: var(--muted);
    word-break: break-word;
  }
  .empty {
    text-align: center;
    padding: 36px 16px;
    color: var(--muted);
  }
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <h1>Сканер портов</h1>
    <span id="hostNote" class="host-note"></span>
  </div>

  <div class="toolbar">
    <div class="seg" role="group" aria-label="Выбор цели">
      <button type="button" id="btnLocal" class="seg-btn active">Этот ПК</button>
      <button type="button" id="btnLan" class="seg-btn">Вся сеть</button>
    </div>

    <input id="targets" class="target-input" type="text" value="127.0.0.1" aria-label="Цель сканирования" placeholder="IP, хост или подсеть (192.168.0.0/24)" />

    <select id="profile" class="ports-select" aria-label="Набор портов">
      <option value="quick" selected>Быстрый (25 портов)</option>
      <option value="common">Стандартный (96 портов)</option>
      <option value="web">Веб-сервисы (19)</option>
      <option value="database">Базы данных (17)</option>
      <option value="full">Все порты (1–65535)</option>
      <option value="custom">Свои порты...</option>
    </select>

    <input id="ports" class="custom-ports" type="text" aria-label="Свои порты" placeholder="22,80,443,8000-8100" />

    <button type="button" id="runBtn" class="run-btn">Сканировать</button>

    <div class="progress-line"><div id="progressFill" class="progress-fill"></div></div>
  </div>

  <div id="errorBox" class="error-bar" role="alert"></div>

  <div class="meta-bar">
    <div id="statusText" class="status-line">Готово</div>
    <div class="meta-right">
      <input id="filterInput" class="filter-input" type="text" aria-label="Фильтр результатов" placeholder="Поиск по результатам..." />
      <div id="exportLinks" class="export-links">
        <a class="export-link" href="/api/scan/export?format=csv">CSV</a>
        <a class="export-link" href="/api/scan/export?format=json">JSON</a>
      </div>
    </div>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th data-col="host">IP / Хост</th>
          <th data-col="port">Порт</th>
          <th data-col="service">Сервис</th>
          <th data-col="latency_ms">Пинг</th>
          <th data-col="detail">Ответ сервиса</th>
        </tr>
      </thead>
      <tbody id="resultsBody">
        <tr><td colspan="5" class="empty">Выберите «Этот ПК» или «Вся сеть» и нажмите «Сканировать».</td></tr>
      </tbody>
    </table>
  </div>
</div>

<script>
(() => {
  const qs = (id) => document.getElementById(id);
  let rows = [];
  let sortCol = "host";
  let sortAsc = true;
  let scanning = false;
  let detectedLan = "";
  let hasReport = false;

  const params = new URLSearchParams(window.location.search);
  if (params.get("target")) qs("targets").value = params.get("target");

  function ipKey(ip) {
    const parts = String(ip || "").split(".");
    if (parts.length === 4 && parts.every((p) => /^\\d+$/.test(p))) {
      return parts.map((p) => p.padStart(3, "0")).join(".");
    }
    return String(ip || "");
  }

  function applyNetworkInfo(net) {
    if (!net) return;
    detectedLan = net.lan_cidr || "";
    const btnLan = qs("btnLan");
    if (detectedLan) {
      btnLan.textContent = "Вся сеть · " + detectedLan;
      btnLan.disabled = false;
    } else {
      btnLan.textContent = "Вся сеть (не найдена)";
      btnLan.disabled = true;
    }
    if (net.local_ip) {
      qs("hostNote").textContent = "Ваш IP: " + net.local_ip;
    }
    syncTargetButtons();
  }

  function syncTargetButtons() {
    const val = qs("targets").value.trim();
    qs("btnLocal").classList.toggle("active", val === "127.0.0.1" || val === "localhost");
    qs("btnLan").classList.toggle("active", Boolean(detectedLan) && (val === detectedLan || val.toLowerCase() === "lan"));
  }

  function showError(msg) {
    const box = qs("errorBox");
    if (!msg) { box.style.display = "none"; box.textContent = ""; return; }
    box.style.display = "block";
    box.textContent = msg;
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function detailFor(r) {
    return [r.http_info, r.tls_info, r.banner].filter(Boolean).join(" · ");
  }

  function setScanning(active) {
    scanning = Boolean(active);
    const btn = qs("runBtn");
    btn.textContent = scanning ? "Остановить" : "Сканировать";
    btn.classList.toggle("stop", scanning);
  }

  function renderTable() {
    const needle = qs("filterInput").value.trim().toLowerCase();
    const filtered = rows.filter((r) => {
      if (!needle) return true;
      return `${r.host} ${r.ip} ${r.port} ${r.service} ${detailFor(r)}`.toLowerCase().includes(needle);
    });

    filtered.sort((a, b) => {
      let cmp = 0;
      if (sortCol === "port" || sortCol === "latency_ms") {
        cmp = Number(a[sortCol]) - Number(b[sortCol]);
      } else if (sortCol === "host") {
        cmp = ipKey(a.ip || a.host).localeCompare(ipKey(b.ip || b.host));
        if (cmp === 0) cmp = Number(a.port) - Number(b.port);
      } else {
        const av = sortCol === "detail" ? detailFor(a) : a[sortCol];
        const bv = sortCol === "detail" ? detailFor(b) : b[sortCol];
        cmp = String(av).localeCompare(String(bv));
      }
      return sortAsc ? cmp : -cmp;
    });

    const body = qs("resultsBody");
    qs("exportLinks").classList.toggle("visible", hasReport && rows.length > 0);
    if (!filtered.length) {
      const msg = scanning
        ? "Идёт сканирование..."
        : (rows.length ? "По фильтру ничего не найдено." : "Открытых портов пока не найдено.");
      body.innerHTML = `<tr><td colspan="5" class="empty">${msg}</td></tr>`;
      return;
    }

    body.innerHTML = filtered.map((r) => {
      const hostLabel = r.ip && r.ip !== r.host ? `${escapeHtml(r.host)} (${escapeHtml(r.ip)})` : escapeHtml(r.host);
      return `
        <tr>
          <td class="mono">${hostLabel}</td>
          <td class="mono port-cell">${r.port}</td>
          <td class="mono">${escapeHtml(r.service)}</td>
          <td class="mono">${Number(r.latency_ms).toFixed(1)} мс</td>
          <td class="mono detail-cell">${escapeHtml(detailFor(r))}</td>
        </tr>
      `;
    }).join("");
  }

  qs("btnLocal").addEventListener("click", () => {
    qs("targets").value = "127.0.0.1";
    syncTargetButtons();
  });

  qs("btnLan").addEventListener("click", () => {
    if (detectedLan) {
      qs("targets").value = detectedLan;
      syncTargetButtons();
    }
  });

  qs("targets").addEventListener("input", syncTargetButtons);

  qs("profile").addEventListener("change", () => {
    const isCustom = qs("profile").value === "custom";
    qs("ports").classList.toggle("visible", isCustom);
    if (isCustom) qs("ports").focus();
  });

  qs("filterInput").addEventListener("input", renderTable);

  document.querySelectorAll("th[data-col]").forEach((th) => {
    th.addEventListener("click", () => {
      const col = th.getAttribute("data-col");
      if (sortCol === col) sortAsc = !sortAsc;
      else { sortCol = col; sortAsc = true; }
      renderTable();
    });
  });

  async function startOrStop() {
    if (scanning) {
      await fetch("/api/scan/stop", { method: "POST" });
      qs("statusText").textContent = "Остановка...";
      return;
    }

    showError("");
    const targetVal = qs("targets").value.trim();
    const profVal = qs("profile").value;
    const isCustom = profVal === "custom";
    const isSubnet = targetVal.includes("/") || targetVal.includes("-") || targetVal.toLowerCase() === "lan";

    rows = [];
    hasReport = false;
    renderTable();
    qs("progressFill").style.width = "0%";

    const payload = {
      targets: targetVal,
      profile: isCustom ? "common" : profVal,
      ports: isCustom ? qs("ports").value.trim() : "",
      timeout: isSubnet ? 0.65 : 1.0,
      concurrency: isSubnet ? 600 : 400,
      grab_banner: true,
      inspect_tls: true,
      show_closed: false,
    };

    const resp = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showError(data.error || "Не удалось запустить сканирование");
      return;
    }
    setScanning(true);
    qs("statusText").textContent = `Сканирование: узлов ${data.targets_count}, портов ${data.ports_count}...`;
  }

  qs("runBtn").addEventListener("click", startOrStop);
  qs("targets").addEventListener("keydown", (e) => { if (e.key === "Enter" && !scanning) startOrStop(); });
  qs("ports").addEventListener("keydown", (e) => { if (e.key === "Enter" && !scanning) startOrStop(); });

  const evtSource = new EventSource("/api/scan/stream");
  evtSource.addEventListener("init", (e) => {
    const data = JSON.parse(e.data);
    applyNetworkInfo(data.network);
    rows = data.results || [];
    hasReport = Boolean(data.has_report);
    setScanning(Boolean(data.scanning));
    renderTable();
  });
  evtSource.addEventListener("result", (e) => {
    rows.push(JSON.parse(e.data));
    renderTable();
  });
  evtSource.addEventListener("progress", (e) => {
    const p = JSON.parse(e.data);
    qs("progressFill").style.width = (p.percent || 0) + "%";
    const eta = p.eta_sec > 0.5 ? ` · ~${p.eta_sec.toFixed(0)} с` : "";
    qs("statusText").textContent =
      `${p.completed} / ${p.total} (${Math.round(p.percent)}%) · открыто: ${p.open_found} · ${Math.round(p.rate_pps)}/с${eta}`;
  });
  evtSource.addEventListener("done", (e) => {
    const rep = JSON.parse(e.data);
    setScanning(false);
    hasReport = true;
    rows = rep.results || rows;
    qs("progressFill").style.width = rep.cancelled ? qs("progressFill").style.width : "100%";
    const uniqueHosts = new Set(rows.map((r) => r.ip || r.host)).size;
    const prefix = rep.cancelled ? "Остановлено" : "Готово";
    qs("statusText").textContent =
      `${prefix} за ${rep.duration_sec.toFixed(1)} с · найдено портов: ${rows.length}` +
      (uniqueHosts ? ` (узлов: ${uniqueHosts})` : "");
    renderTable();
  });
  evtSource.addEventListener("scan_error", (e) => {
    const err = JSON.parse(e.data);
    setScanning(false);
    showError(err.error || "Ошибка сканирования");
    qs("statusText").textContent = "Ошибка";
  });
})();
</script>
</body>
</html>
"""


class WebDashboardServer:
    """Async HTTP + Server-Sent Events server hosting the Web GUI."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        self.host = host
        self.port = port
        self._server: asyncio.AbstractServer | None = None
        self._scan_task: asyncio.Task[Any] | None = None
        self._cancel_event: asyncio.Event | None = None
        self._scanning: bool = False
        self._results: list[dict[str, Any]] = []
        self._last_report: ScanReport | None = None
        self._subscribers: set[asyncio.Queue[tuple[str, Any]]] = set()

    @property
    def bound_port(self) -> int:
        if self._server and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
        return self.port

    def _broadcast(self, event_name: str, payload: Any) -> None:
        dead: list[asyncio.Queue[tuple[str, Any]]] = []
        for q in self._subscribers:
            try:
                q.put_nowait((event_name, payload))
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    async def start(self) -> None:
        try:
            self._server = await asyncio.start_server(
                self._handle_client, self.host, self.port
            )
        except OSError:
            if self.port == 0:
                raise
            self._server = await asyncio.start_server(
                self._handle_client, self.host, 0
            )

    async def stop(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._scan_task is not None and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except BaseException:
                pass
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        reason: str,
        content_type: str,
        body: bytes,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Cache-Control: no-store",
            "Connection: close",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                headers.append(f"{k}: {v}")
        raw = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        writer.write(raw)
        await writer.drain()

    async def _send_json(
        self, writer: asyncio.StreamWriter, status: int, data: Any
    ) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        reason = "OK" if status == 200 else "Bad Request"
        await self._send_response(
            writer, status, reason, "application/json; charset=utf-8", body
        )

    async def _start_scan(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if self._scanning:
            return 409, {"error": "A scan is already running."}

        try:
            targets = parse_targets(str(payload.get("targets", "")))
            ports = parse_ports(
                str(payload.get("ports", "")),
                profile=str(payload.get("profile", "common")),
            )
            config = ScanConfig(
                targets=targets,
                ports=ports,
                timeout=float(payload.get("timeout", 1.0)),
                concurrency=int(payload.get("concurrency", 500)),
                grab_banner=bool(payload.get("grab_banner", True)),
                inspect_tls=bool(payload.get("inspect_tls", True)),
                show_closed=bool(payload.get("show_closed", False)),
                rate_limit=float(payload.get("rate_limit", 0.0)),
            )
        except (ValueError, TypeError) as exc:
            return 400, {"error": str(exc)}

        self._results = []
        self._last_report = None
        self._scanning = True
        self._cancel_event = asyncio.Event()
        cancel_event = self._cancel_event

        async def _runner() -> None:
            scanner = AsyncPortScanner(config)
            try:

                def _on_res(res: PortResult) -> None:
                    item = res.to_dict()
                    self._results.append(item)
                    self._broadcast("result", item)

                def _on_prog(prog: ScanProgress) -> None:
                    self._broadcast(
                        "progress",
                        {
                            "completed": prog.completed,
                            "total": prog.total,
                            "open_found": prog.open_found,
                            "elapsed_sec": prog.elapsed_sec,
                            "rate_pps": prog.rate_pps,
                            "eta_sec": prog.eta_sec,
                            "percent": prog.percent,
                        },
                    )

                report = await scanner.scan(
                    on_result=_on_res,
                    on_progress=_on_prog,
                    cancel_event=cancel_event,
                )
                self._last_report = report
                self._scanning = False
                self._broadcast("done", report.to_dict())
            except Exception as exc:
                self._scanning = False
                self._broadcast("scan_error", {"error": str(exc)})

        self._scan_task = asyncio.create_task(_runner())
        return 200, {
            "status": "started",
            "targets_count": len(targets),
            "ports_count": len(ports),
        }

    async def _handle_sse(self, writer: asyncio.StreamWriter) -> None:
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream; charset=utf-8\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii")
        writer.write(header)
        await writer.drain()

        sub: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=2048)
        self._subscribers.add(sub)
        try:
            net_info = detect_local_networks()
            init_data = json.dumps(
                {
                    "scanning": self._scanning,
                    "results": self._results,
                    "has_report": self._last_report is not None,
                    "network": net_info,
                },
                ensure_ascii=False,
            )
            writer.write(f"event: init\ndata: {init_data}\n\n".encode("utf-8"))
            await writer.drain()

            while True:
                try:
                    event_name, payload = await asyncio.wait_for(
                        sub.get(), timeout=15.0
                    )
                    encoded = json.dumps(payload, ensure_ascii=False)
                    msg = f"event: {event_name}\ndata: {encoded}\n\n".encode("utf-8")
                except asyncio.TimeoutError:
                    msg = b": keepalive\n\n"
                writer.write(msg)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self._subscribers.discard(sub)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                return
            parts = request_line.decode("latin-1").strip().split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]

            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if line in (b"\r\n", b"\n", b""):
                    break
                decoded = line.decode("latin-1").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = b""
            content_len = int(headers.get("content-length", "0") or "0")
            if content_len > 0:
                body = await asyncio.wait_for(
                    reader.readexactly(min(content_len, 1024 * 1024)), timeout=5.0
                )

            parsed = urllib.parse.urlsplit(target)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)

            if method == "GET" and path == "/":
                await self._send_response(
                    writer,
                    200,
                    "OK",
                    "text/html; charset=utf-8",
                    _DASHBOARD_HTML.encode("utf-8"),
                )
            elif method == "GET" and path == "/api/network":
                await self._send_json(writer, 200, detect_local_networks())
            elif method == "GET" and path == "/api/status":
                await self._send_json(
                    writer,
                    200,
                    {
                        "scanning": self._scanning,
                        "results_count": len(self._results),
                        "has_report": self._last_report is not None,
                        "profiles": list(PROFILES.keys()),
                        "network": detect_local_networks(),
                    },
                )
            elif method == "POST" and path == "/api/scan/start":
                try:
                    data = json.loads(body.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    await self._send_json(writer, 400, {"error": "Invalid JSON body."})
                    return
                code, resp = await self._start_scan(data)
                await self._send_json(writer, code, resp)
            elif method == "POST" and path == "/api/scan/stop":
                if self._cancel_event is not None:
                    self._cancel_event.set()
                await self._send_json(writer, 200, {"status": "stopping"})
            elif method == "GET" and path == "/api/scan/stream":
                await self._handle_sse(writer)
                return
            elif method == "GET" and path == "/api/scan/export":
                if self._last_report is None:
                    await self._send_json(
                        writer, 400, {"error": "No completed scan report available yet."}
                    )
                    return
                fmt = (query.get("format", ["json"])[0]).lower()
                try:
                    text = render_report(self._last_report, fmt)
                except ValueError as exc:
                    await self._send_json(writer, 400, {"error": str(exc)})
                    return
                ext = "md" if fmt in ("md", "markdown") else fmt
                mime = {
                    "json": "application/json; charset=utf-8",
                    "csv": "text/csv; charset=utf-8",
                    "md": "text/markdown; charset=utf-8",
                    "txt": "text/plain; charset=utf-8",
                }.get(ext, "text/plain; charset=utf-8")
                await self._send_response(
                    writer,
                    200,
                    "OK",
                    mime,
                    text.encode("utf-8"),
                    extra_headers={
                        "Content-Disposition": f'attachment; filename="port-scan-report.{ext}"'
                    },
                )
            else:
                await self._send_json(writer, 404, {"error": f"Not found: {path}"})
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def _find_chromium_app_browser() -> str | None:
    """Locate a Chromium-based browser supporting `--app=` standalone windows."""
    candidates: list[str] = []
    if sys.platform == "win32":
        roots = [
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        rel_paths = [
            os.path.join("Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join("Google", "Chrome", "Application", "chrome.exe"),
            os.path.join("BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        ]
        for root in roots:
            if root:
                for rel in rel_paths:
                    candidates.append(os.path.join(root, rel))
        for exe in ("msedge", "chrome", "brave"):
            found = shutil.which(exe)
            if found:
                candidates.append(found)
    elif sys.platform == "darwin":
        candidates.extend(
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]
        )
    else:
        for exe in (
            "google-chrome",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "brave-browser",
        ):
            found = shutil.which(exe)
            if found:
                candidates.append(found)

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _open_app_window(url: str) -> None:
    """Open the local dashboard in an app-style window without browser tabs."""
    browser = _find_chromium_app_browser()
    if browser:
        try:
            subprocess.Popen(
                [browser, f"--app={url}", "--window-size=1080,720"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except OSError:
            pass
    webbrowser.open(url)


def launch_web_gui(
    host: str = "127.0.0.1",
    port: int = 8765,
    initial_target: str = "127.0.0.1",
    open_browser: bool = True,
) -> None:
    """Run the async Web Dashboard GUI and optionally open the browser."""
    configure_event_loop()

    async def _run() -> None:
        srv = WebDashboardServer(host=host, port=port)
        await srv.start()
        actual_port = srv.bound_port
        url = f"http://{host}:{actual_port}/"
        if initial_target:
            url += "?" + urllib.parse.urlencode({"target": initial_target})
        print(f"Async Port Scanner Web GUI running at: {url}")
        print("Press Ctrl+C to stop the web dashboard.")
        if open_browser:
            threading.Timer(0.35, lambda: _open_app_window(url)).start()
        try:
            await srv.serve_forever()
        finally:
            await srv.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nWeb GUI stopped.")
