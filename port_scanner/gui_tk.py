"""Cross-platform Tkinter desktop GUI for Async Port Scanner."""

from __future__ import annotations

import asyncio
import os
import queue
import sys
import threading

if sys.platform == "darwin":
    os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any

from port_scanner.engine import AsyncPortScanner, configure_event_loop
from port_scanner.exporters import export_report
from port_scanner.models import PortResult, ScanConfig, ScanProgress, ScanReport
from port_scanner.services import (
    PROFILES,
    describe_service,
    detect_local_networks,
    parse_ports,
    parse_targets,
)

# Color palette (modern dark slate)
BG_MAIN = "#0f172a"
BG_PANEL = "#1e293b"
BG_INPUT = "#0b1220"
FG_TEXT = "#f1f5f9"
FG_MUTED = "#94a3b8"
ACCENT = "#38bdf8"
ACCENT_HOVER = "#0ea5e9"
SUCCESS = "#22c55e"
WARN = "#f59e0b"
DANGER = "#ef4444"
BORDER = "#334155"


def _enable_windows_hidpi() -> None:
    """Enable sharp DPI scaling on Windows 8.1/10/11 when available."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:
        pass


class PortScannerTkApp:
    """Interactive Tkinter GUI wrapping AsyncPortScanner."""

    def __init__(self, root: tk.Tk, initial_target: str = "127.0.0.1") -> None:
        self.root = root
        self.root.title("Async Port Scanner — Cross-Platform GUI")
        self.root.geometry("1120x740")
        self.root.minsize(920, 600)
        self.root.configure(bg=BG_MAIN)

        self._msg_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._cancel_event: threading.Event | None = None
        self._worker_thread: threading.Thread | None = None
        self._scanning = False

        self._all_results: list[PortResult] = []
        self._row_lookup: dict[str, PortResult] = {}
        self._last_report: ScanReport | None = None
        self._sort_col: str = "port"
        self._sort_reverse: bool = False

        # Form variables
        self.target_var = tk.StringVar(value=initial_target)
        self.profile_var = tk.StringVar(value="common")
        self.ports_var = tk.StringVar(value="")
        self.timeout_var = tk.StringVar(value="1.0")
        self.concurrency_var = tk.StringVar(value="500")
        self.rate_limit_var = tk.StringVar(value="0")
        self.banner_var = tk.BooleanVar(value=True)
        self.tls_var = tk.BooleanVar(value=True)
        self.show_closed_var = tk.BooleanVar(value=False)
        self.filter_var = tk.StringVar(value="")

        self.status_var = tk.StringVar(value="Ready. Enter target(s) and click Start Scan.")
        self.stats_var = tk.StringVar(value="0 / 0 probes | 0 open | 0 pps")

        self._configure_styles()
        self._build_ui()

        self.filter_var.trace_add("write", lambda *_: self._refresh_table())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(40, self._poll_queue)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        available = style.theme_names()
        if "clam" in available:
            style.theme_use("clam")

        base_font = ("Segoe UI", 10) if sys.platform == "win32" else ("Helvetica Neue", 11)
        mono_font = ("Consolas", 10) if sys.platform == "win32" else ("Menlo", 11)
        self._mono_font = mono_font

        style.configure(".", background=BG_MAIN, foreground=FG_TEXT, font=base_font)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("Main.TFrame", background=BG_MAIN)
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_TEXT)
        style.configure("Muted.TLabel", background=BG_PANEL, foreground=FG_MUTED)
        style.configure("Status.TLabel", background=BG_MAIN, foreground=FG_MUTED)

        style.configure(
            "TEntry",
            fieldbackground=BG_INPUT,
            foreground=FG_TEXT,
            insertcolor=FG_TEXT,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
            padding=5,
        )
        style.configure(
            "TCombobox",
            fieldbackground=BG_INPUT,
            background=BG_PANEL,
            foreground=FG_TEXT,
            arrowcolor=FG_TEXT,
            bordercolor=BORDER,
            padding=4,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", BG_INPUT)],
            foreground=[("readonly", FG_TEXT)],
        )

        style.configure(
            "TCheckbutton",
            background=BG_PANEL,
            foreground=FG_TEXT,
        )
        style.map(
            "TCheckbutton",
            background=[("active", BG_PANEL)],
            foreground=[("active", ACCENT)],
        )

        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#04101d",
            font=(base_font[0], base_font[1], "bold"),
            padding=(14, 7),
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", ACCENT_HOVER), ("disabled", BORDER)],
            foreground=[("disabled", FG_MUTED)],
        )

        style.configure(
            "Stop.TButton",
            background=DANGER,
            foreground="#ffffff",
            font=(base_font[0], base_font[1], "bold"),
            padding=(12, 7),
            borderwidth=0,
        )
        style.map(
            "Stop.TButton",
            background=[("active", "#dc2626"), ("disabled", BORDER)],
            foreground=[("disabled", FG_MUTED)],
        )

        style.configure(
            "Secondary.TButton",
            background="#334155",
            foreground=FG_TEXT,
            padding=(10, 7),
            borderwidth=0,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#475569"), ("disabled", "#1e293b")],
            foreground=[("disabled", FG_MUTED)],
        )

        style.configure(
            "Treeview",
            background=BG_INPUT,
            fieldbackground=BG_INPUT,
            foreground=FG_TEXT,
            rowheight=26,
            borderwidth=0,
            font=mono_font,
        )
        style.configure(
            "Treeview.Heading",
            background=BG_PANEL,
            foreground=ACCENT,
            relief="flat",
            padding=(6, 6),
            font=(base_font[0], base_font[1], "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", "#1d4ed8")],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=BG_INPUT,
            background=ACCENT,
            bordercolor=BORDER,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, style="Main.TFrame", padding=12)
        outer.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Frame(outer, style="Main.TFrame")
        header.pack(fill=tk.X, pady=(0, 8))
        title_lbl = tk.Label(
            header,
            text="Async Port Scanner",
            bg=BG_MAIN,
            fg=FG_TEXT,
            font=("Helvetica Neue", 16, "bold")
            if sys.platform != "win32"
            else ("Segoe UI", 15, "bold"),
        )
        title_lbl.pack(side=tk.LEFT)
        sub_lbl = tk.Label(
            header,
            text=f"  •  Platform: {sys.platform}  •  Non-blocking asyncio TCP & TLS engine",
            bg=BG_MAIN,
            fg=FG_MUTED,
        )
        sub_lbl.pack(side=tk.LEFT, pady=(4, 0))

        # Config Panel
        cfg_panel = ttk.Frame(outer, style="Panel.TFrame", padding=12)
        cfg_panel.pack(fill=tk.X, pady=(0, 10))

        # Row 1: Quick Targets, Target input, Profile, Custom Ports
        row1 = ttk.Frame(cfg_panel, style="Panel.TFrame")
        row1.pack(fill=tk.X, pady=(0, 8))

        net_info = detect_local_networks()
        lan_cidr = net_info.get("lan_cidr", "")

        ttk.Button(
            row1,
            text="Этот ПК",
            command=lambda: self.target_var.set("127.0.0.1"),
            style="Secondary.TButton",
        ).pack(side=tk.LEFT, padx=(0, 4))

        lan_btn = ttk.Button(
            row1,
            text=f"Вся сеть ({lan_cidr})" if lan_cidr else "Вся сеть",
            command=lambda: self.target_var.set(lan_cidr) if lan_cidr else None,
            style="Secondary.TButton",
            state=tk.NORMAL if lan_cidr else tk.DISABLED,
        )
        lan_btn.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(row1, text="Цель / CIDR:", style="Panel.TLabel").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        target_entry = ttk.Entry(row1, textvariable=self.target_var, width=26)
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))
        target_entry.bind("<Return>", lambda *_: self.start_scan())

        ttk.Label(row1, text="Profile:", style="Panel.TLabel").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        profile_combo = ttk.Combobox(
            row1,
            textvariable=self.profile_var,
            values=list(PROFILES.keys()),
            state="readonly",
            width=11,
        )
        profile_combo.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(row1, text="Custom Ports:", style="Panel.TLabel").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ports_entry = ttk.Entry(row1, textvariable=self.ports_var, width=22)
        ports_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ports_entry.bind("<Return>", lambda *_: self.start_scan())

        # Row 2: Tuning, Flags, Actions
        row2 = ttk.Frame(cfg_panel, style="Panel.TFrame")
        row2.pack(fill=tk.X)

        ttk.Label(row2, text="Timeout (s):", style="Panel.TLabel").pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Entry(row2, textvariable=self.timeout_var, width=6).pack(
            side=tk.LEFT, padx=(0, 10)
        )

        ttk.Label(row2, text="Concurrency:", style="Panel.TLabel").pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Entry(row2, textvariable=self.concurrency_var, width=7).pack(
            side=tk.LEFT, padx=(0, 10)
        )

        ttk.Label(row2, text="Rate (pps):", style="Panel.TLabel").pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Entry(row2, textvariable=self.rate_limit_var, width=7).pack(
            side=tk.LEFT, padx=(0, 12)
        )

        ttk.Checkbutton(
            row2, text="Banners", variable=self.banner_var, style="TCheckbutton"
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Checkbutton(
            row2, text="TLS Info", variable=self.tls_var, style="TCheckbutton"
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Checkbutton(
            row2, text="Show Closed", variable=self.show_closed_var, style="TCheckbutton"
        ).pack(side=tk.LEFT, padx=(0, 12))

        self.export_btn = ttk.Button(
            row2,
            text="Export...",
            command=self._export_results,
            style="Secondary.TButton",
            state=tk.DISABLED,
        )
        self.export_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.clear_btn = ttk.Button(
            row2, text="Clear", command=self._clear_results, style="Secondary.TButton"
        )
        self.clear_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.stop_btn = ttk.Button(
            row2,
            text="Stop",
            command=self.stop_scan,
            style="Stop.TButton",
            state=tk.DISABLED,
        )
        self.stop_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.start_btn = ttk.Button(
            row2, text="Start Scan", command=self.start_scan, style="Accent.TButton"
        )
        self.start_btn.pack(side=tk.RIGHT)

        # Progress + Filter bar
        mid_bar = ttk.Frame(outer, style="Main.TFrame")
        mid_bar.pack(fill=tk.X, pady=(0, 8))

        self.progress = ttk.Progressbar(
            mid_bar, mode="determinate", maximum=100.0, value=0.0
        )
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))

        ttk.Label(mid_bar, text="Filter:", style="Status.TLabel").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Entry(mid_bar, textvariable=self.filter_var, width=26).pack(side=tk.LEFT)

        # Results Treeview + Scrollbars
        tree_frame = ttk.Frame(outer, style="Main.TFrame")
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        columns = ("host", "ip", "port", "state", "service", "latency", "detail")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "host": ("Target Host", 150),
            "ip": ("IP Address", 130),
            "port": ("Port", 75),
            "state": ("State", 85),
            "service": ("Service", 130),
            "latency": ("Latency (ms)", 105),
            "detail": ("Banner / HTTP / TLS Fingerprint", 380),
        }
        for col, (label, width) in headings.items():
            anchor = tk.E if col in ("port", "latency") else tk.W
            self.tree.heading(
                col, text=label, command=lambda c=col: self._sort_by_column(c)
            )
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "detail"))

        self.tree.tag_configure("open", foreground=SUCCESS)
        self.tree.tag_configure("closed", foreground=FG_MUTED)
        self.tree.tag_configure("filtered", foreground=WARN)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select_row)

        # Details Inspector
        detail_panel = ttk.Frame(outer, style="Panel.TFrame", padding=8)
        detail_panel.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            detail_panel, text="Selected Port Details", style="Muted.TLabel"
        ).pack(anchor=tk.W, pady=(0, 4))
        self.detail_text = tk.Text(
            detail_panel,
            height=4,
            bg=BG_INPUT,
            fg=FG_TEXT,
            font=self._mono_font,
            relief="flat",
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.detail_text.pack(fill=tk.X)

        # Status Bar
        status_bar = ttk.Frame(outer, style="Main.TFrame")
        status_bar.pack(fill=tk.X)
        ttk.Label(status_bar, textvariable=self.status_var, style="Status.TLabel").pack(
            side=tk.LEFT
        )
        ttk.Label(status_bar, textvariable=self.stats_var, style="Status.TLabel").pack(
            side=tk.RIGHT
        )

    def _set_detail_text(self, content: str) -> None:
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", content)
        self.detail_text.configure(state=tk.DISABLED)

    def _on_select_row(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        res = self._row_lookup.get(sel[0])
        if res is None:
            return
        lines = [
            f"Endpoint: {res.host} ({res.ip}):{res.port}/tcp   State: {res.state.upper()}   Latency: {res.latency_ms:.2f} ms",
            f"Service:  {res.service} — {describe_service(res.port)}",
        ]
        if res.http_info:
            lines.append(f"HTTP:     {res.http_info}")
        if res.tls_info:
            lines.append(f"TLS:      {res.tls_info}")
        if res.banner:
            lines.append(f"Banner:   {res.banner}")
        self._set_detail_text("\n".join(lines))

    def _clear_results(self) -> None:
        if self._scanning:
            return
        self._all_results.clear()
        self._row_lookup.clear()
        self._last_report = None
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress["value"] = 0.0
        self.export_btn.configure(state=tk.DISABLED)
        self._set_detail_text("")
        self.status_var.set("Cleared results.")
        self.stats_var.set("0 / 0 probes | 0 open | 0 pps")

    def _matches_filter(self, res: PortResult, needle: str) -> bool:
        if not needle:
            return True
        haystack = " ".join(
            [
                res.host,
                res.ip,
                str(res.port),
                res.state,
                res.service,
                res.summary_detail,
            ]
        ).lower()
        return needle in haystack

    def _sort_key(self, res: PortResult) -> Any:
        if self._sort_col == "port":
            return res.port
        if self._sort_col == "latency":
            return res.latency_ms
        if self._sort_col == "host":
            return (res.host.lower(), res.port)
        if self._sort_col == "ip":
            return (res.ip, res.port)
        if self._sort_col == "state":
            return (res.state, res.port)
        if self._sort_col == "service":
            return (res.service.lower(), res.port)
        return (res.summary_detail.lower(), res.port)

    def _sort_by_column(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self._refresh_table()

    def _insert_tree_row(self, res: PortResult) -> None:
        iid = self.tree.insert(
            "",
            tk.END,
            values=(
                res.host,
                res.ip,
                res.port,
                res.state,
                res.service,
                f"{res.latency_ms:.2f}",
                res.summary_detail,
            ),
            tags=(res.state,),
        )
        self._row_lookup[iid] = res

    def _refresh_table(self) -> None:
        needle = self.filter_var.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._row_lookup.clear()

        filtered = [r for r in self._all_results if self._matches_filter(r, needle)]
        filtered.sort(key=self._sort_key, reverse=self._sort_reverse)
        for res in filtered:
            self._insert_tree_row(res)

    def start_scan(self) -> None:
        if self._scanning:
            return

        try:
            targets = parse_targets(self.target_var.get())
            ports = parse_ports(self.ports_var.get(), profile=self.profile_var.get())
            timeout = float(self.timeout_var.get().strip())
            concurrency = int(self.concurrency_var.get().strip())
            rate_limit = float(self.rate_limit_var.get().strip() or "0")
            config = ScanConfig(
                targets=targets,
                ports=ports,
                timeout=timeout,
                concurrency=concurrency,
                grab_banner=self.banner_var.get(),
                inspect_tls=self.tls_var.get(),
                show_closed=self.show_closed_var.get(),
                rate_limit=rate_limit,
            )
        except ValueError as exc:
            messagebox.showerror("Invalid Scan Configuration", str(exc))
            return

        self._clear_results()
        self._scanning = True
        self._cancel_event = threading.Event()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.clear_btn.configure(state=tk.DISABLED)
        self.export_btn.configure(state=tk.DISABLED)

        total_probes = len(config.targets) * len(config.ports)
        self.status_var.set(
            f"Scanning {len(config.targets)} target(s), {len(config.ports)} port(s)..."
        )
        self.stats_var.set(f"0 / {total_probes} probes | 0 open | 0 pps")

        cancel_event = self._cancel_event

        def _worker() -> None:
            configure_event_loop()
            scanner = AsyncPortScanner(config)

            def _on_result(res: PortResult) -> None:
                self._msg_queue.put(("result", res))

            def _on_progress(prog: ScanProgress) -> None:
                self._msg_queue.put(("progress", prog))

            try:
                report = asyncio.run(
                    scanner.scan(
                        on_result=_on_result,
                        on_progress=_on_progress,
                        cancel_event=cancel_event,
                    )
                )
                self._msg_queue.put(("done", report))
            except Exception as exc:  # pragma: no cover - defensive UI guard
                self._msg_queue.put(("error", str(exc)))

        self._worker_thread = threading.Thread(target=_worker, daemon=True)
        self._worker_thread.start()

    def stop_scan(self) -> None:
        if self._scanning and self._cancel_event is not None:
            self._cancel_event.set()
            self.status_var.set("Stopping scan gracefully...")
            self.stop_btn.configure(state=tk.DISABLED)

    def _poll_queue(self) -> None:
        batch_added = False
        try:
            while True:
                kind, payload = self._msg_queue.get_nowait()
                if kind == "result":
                    res: PortResult = payload
                    self._all_results.append(res)
                    needle = self.filter_var.get().strip().lower()
                    if self._matches_filter(res, needle):
                        batch_added = True
                elif kind == "progress":
                    prog: ScanProgress = payload
                    self.progress["value"] = prog.percent
                    eta_str = f" | ETA {prog.eta_sec:.1f}s" if prog.eta_sec > 0.2 else ""
                    self.stats_var.set(
                        f"{prog.completed} / {prog.total} probes | "
                        f"{prog.open_found} open | {prog.rate_pps:,.0f} pps{eta_str}"
                    )
                elif kind == "done":
                    report: ScanReport = payload
                    self._finish_scan(report)
                    batch_added = False
                elif kind == "error":
                    self._scanning = False
                    self.start_btn.configure(state=tk.NORMAL)
                    self.stop_btn.configure(state=tk.DISABLED)
                    self.clear_btn.configure(state=tk.NORMAL)
                    self.status_var.set(f"Scan error: {payload}")
                    messagebox.showerror("Scan Failed", str(payload))
        except queue.Empty:
            pass

        if batch_added:
            self._refresh_table()

        self.root.after(40, self._poll_queue)

    def _finish_scan(self, report: ScanReport) -> None:
        self._scanning = False
        self._last_report = report
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.clear_btn.configure(state=tk.NORMAL)
        self.export_btn.configure(state=tk.NORMAL)

        # Ensure table mirrors final deterministic order
        self._all_results = list(report.results)
        self._refresh_table()

        unresolved = [h for h in report.hosts if not h.resolved]
        state_word = "Cancelled" if report.cancelled else "Completed"
        msg = (
            f"{state_word} in {report.duration_sec:.2f}s — "
            f"{len(report.open_results)} open port(s) found."
        )
        if unresolved:
            msg += f" ({len(unresolved)} unresolved host(s))"
        self.status_var.set(msg)
        self.progress["value"] = 100.0 if not report.cancelled else self.progress["value"]

    def _export_results(self) -> None:
        if self._last_report is None:
            return
        file_path = filedialog.asksaveasfilename(
            title="Export Scan Report",
            defaultextension=".json",
            filetypes=[
                ("JSON Report", "*.json"),
                ("CSV Spreadsheet", "*.csv"),
                ("Markdown Report", "*.md"),
                ("Plain Text", "*.txt"),
            ],
        )
        if not file_path:
            return
        try:
            saved = export_report(self._last_report, file_path)
            self.status_var.set(f"Report exported to {saved}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def _on_close(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
        self.root.destroy()


def launch_tk_gui(initial_target: str = "127.0.0.1") -> None:
    """Start the Tkinter desktop GUI."""
    if sys.platform == "darwin" and float(getattr(tk, "TkVersion", 0.0)) < 8.6:
        raise RuntimeError(
            "macOS system Tcl/Tk 8.5 does not render ttk widgets on modern macOS; requires Tk >= 8.6"
        )
    _enable_windows_hidpi()
    root = tk.Tk()
    PortScannerTkApp(root, initial_target=initial_target)
    root.mainloop()
