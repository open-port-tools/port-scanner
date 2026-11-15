use crate::services::identify_service;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc;

/// TCP port classification returned by the async scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        }
    }
}

/// Configuration parameters for a scan run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub timeout_secs: f64,
    pub concurrency: usize,
    pub grab_banner: bool,
    pub include_closed: bool,
    pub include_filtered: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: vec!["127.0.0.1".to_string()],
            ports: Vec::new(),
            timeout_secs: 0.8,
            concurrency: 300,
            grab_banner: true,
            include_closed: false,
            include_filtered: false,
        }
    }
}

/// Result for a single scanned target and TCP port.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortResult {
    pub target: String,
    pub ip: String,
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub banner: String,
    pub latency_ms: Option<f64>,
}

/// Live progress snapshot emitted during scanning.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub scanned: usize,
    pub total: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub filtered_count: usize,
    pub elapsed_secs: f64,
    pub rate: f64,
    pub cancelled: bool,
}

/// Final aggregated report produced when a scan completes or stops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub targets: Vec<String>,
    pub resolved_targets: BTreeMap<String, String>,
    pub total_ports_scanned: usize,
    pub duration_secs: f64,
    pub open_count: usize,
    pub closed_count: usize,
    pub filtered_count: usize,
    pub cancelled: bool,
    pub results: Vec<PortResult>,
}

/// Streaming events sent from the async engine to CLI or GUI consumers.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    Finding(PortResult),
    Progress(ScanProgress),
    Completed(ScanReport),
    Error(String),
}

/// Sort key placing IPv4 addresses in numerical octet order before hostnames/IPv6.
pub fn ip_sort_key(ip: &str) -> (u8, u128, &str) {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => (0, u32::from(v4) as u128, ip),
        Ok(IpAddr::V6(v6)) => (1, u128::from(v6), ip),
        Err(_) => (2, 0, ip),
    }
}

fn clamp_concurrency(requested: usize) -> usize {
    let base = requested.clamp(1, 2000);
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("sh")
            .args(["-c", "ulimit -n"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Ok(limit) = text.trim().parse::<usize>() {
                // Reserve file descriptors for stdin/out/err, GUI/runtime, and DNS sockets.
                let safe_cap = (limit / 2).max(32);
                return base.min(safe_cap);
            }
        }
    }
    base.min(1000)
}

async fn resolve_target_ip(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs = lookup_host((target, 0))
        .await
        .map_err(|e| format!("DNS resolution failed for '{target}': {e}"))?;
    let mut fallback: Option<IpAddr> = None;
    for sock in addrs {
        let ip = sock.ip();
        if ip.is_ipv4() {
            return Ok(ip);
        }
        if fallback.is_none() {
            fallback = Some(ip);
        }
    }
    fallback.ok_or_else(|| format!("No IP address resolved for '{target}'"))
}

fn is_http_probe_port(port: u16) -> bool {
    matches!(
        port,
        80 | 81
            | 443
            | 3000
            | 3001
            | 4000
            | 4200
            | 4443
            | 5000
            | 5001
            | 5173
            | 7001
            | 8000
            | 8008
            | 8080
            | 8081
            | 8443
            | 8888
            | 9000
            | 9090
            | 9443
            | 10000
    )
}

fn clean_ascii_line(raw: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(max_chars.min(text.len()));
    let mut prev_space = false;
    for ch in text.chars() {
        let mapped = if ch.is_control() { ' ' } else { ch };
        if mapped.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(mapped);
            prev_space = false;
        }
        if out.chars().count() >= max_chars {
            break;
        }
    }
    out.trim().to_string()
}

fn summarize_http_response(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut status = String::new();
    let mut server = String::new();

    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if idx == 0 && trimmed.starts_with("HTTP/") {
            status = trimmed.to_string();
            continue;
        }
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.eq_ignore_ascii_case("server") {
                server = v.trim().to_string();
            }
        }
    }

    let lower = text.to_ascii_lowercase();
    let mut title = String::new();
    if let Some(start) = lower.find("<title>") {
        let after = &text[start + 7..];
        let after_lower = &lower[start + 7..];
        if let Some(end) = after_lower.find("</title>") {
            title = clean_ascii_line(after[..end].as_bytes(), 64);
        }
    }

    let mut parts = Vec::new();
    if !status.is_empty() {
        parts.push(status);
    }
    if !server.is_empty() {
        parts.push(format!("Server: {server}"));
    }
    if !title.is_empty() {
        parts.push(format!("Title: {title}"));
    }
    if parts.is_empty() {
        clean_ascii_line(raw, 140)
    } else {
        clean_ascii_line(parts.join(" | ").as_bytes(), 140)
    }
}

async fn grab_tcp_banner(stream: &mut TcpStream, target: &str, port: u16, timeout: Duration) -> String {
    let read_wait = timeout.min(Duration::from_millis(450));
    let mut buf = [0u8; 1024];

    // Passive greeting check first (SSH, SMTP, FTP, POP3, IMAP banners arrive immediately).
    let passive_wait = timeout.min(Duration::from_millis(220));
    if let Ok(Ok(n)) = tokio::time::timeout(passive_wait, stream.read(&mut buf)).await {
        if n > 0 {
            let chunk = &buf[..n];
            if chunk.starts_with(b"HTTP/") {
                return summarize_http_response(chunk);
            }
            return clean_ascii_line(chunk, 140);
        }
    }

    // Active lightweight probe if service remained silent.
    let probe: Vec<u8> = if is_http_probe_port(port) {
        format!("GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: port-scanner/2.0\r\n\r\n")
            .into_bytes()
    } else {
        b"\r\n".to_vec()
    };

    if tokio::time::timeout(read_wait, stream.write_all(&probe))
        .await
        .is_err()
    {
        return String::new();
    }

    match tokio::time::timeout(read_wait, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let chunk = &buf[..n];
            if chunk.starts_with(b"HTTP/") || is_http_probe_port(port) {
                summarize_http_response(chunk)
            } else {
                clean_ascii_line(chunk, 140)
            }
        }
        _ => String::new(),
    }
}

async fn scan_single_port(
    target: &str,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    grab_banner: bool,
) -> (PortState, String, Option<f64>) {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let rtt_ms = (started.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
            let banner = if grab_banner {
                grab_tcp_banner(&mut stream, target, port, timeout).await
            } else {
                String::new()
            };
            (PortState::Open, banner, Some(rtt_ms))
        }
        Ok(Err(err)) => {
            use std::io::ErrorKind;
            match err.kind() {
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
                    (PortState::Closed, String::new(), None)
                }
                _ => (PortState::Filtered, String::new(), None),
            }
        }
        Err(_) => (PortState::Filtered, String::new(), None),
    }
}

/// Run an asynchronous bounded-concurrency port scan, optionally streaming live events.
pub async fn run_scan(
    config: ScanConfig,
    cancel_flag: Arc<AtomicBool>,
    events: Option<mpsc::UnboundedSender<ScanEvent>>,
) -> Result<ScanReport, String> {
    if config.targets.is_empty() {
        let err = "No targets provided.".to_string();
        if let Some(tx) = &events {
            let _ = tx.send(ScanEvent::Error(err.clone()));
        }
        return Err(err);
    }
    if config.ports.is_empty() {
        let err = "No ports provided.".to_string();
        if let Some(tx) = &events {
            let _ = tx.send(ScanEvent::Error(err.clone()));
        }
        return Err(err);
    }

    let timeout = Duration::from_secs_f64(config.timeout_secs.clamp(0.05, 30.0));
    let start_instant = Instant::now();

    // Resolve targets concurrently.
    let mut resolved_targets = BTreeMap::new();
    let mut resolved_list: Vec<(String, IpAddr)> = Vec::new();
    let mut dns_errors = Vec::new();

    let mut resolve_tasks = Vec::with_capacity(config.targets.len());
    for target in &config.targets {
        let t = target.clone();
        resolve_tasks.push(tokio::spawn(async move {
            let res = resolve_target_ip(&t).await;
            (t, res)
        }));
    }

    for handle in resolve_tasks {
        if let Ok((t, res)) = handle.await {
            match res {
                Ok(ip) => {
                    let ip_str = ip.to_string();
                    resolved_targets.insert(t.clone(), ip_str);
                    resolved_list.push((t, ip));
                }
                Err(msg) => {
                    dns_errors.push(msg);
                }
            }
        }
    }

    if resolved_list.is_empty() {
        let err = if dns_errors.is_empty() {
            "Failed to resolve any target.".to_string()
        } else {
            dns_errors.join("; ")
        };
        if let Some(tx) = &events {
            let _ = tx.send(ScanEvent::Error(err.clone()));
        }
        return Err(err);
    }

    let num_hosts = resolved_list.len();
    let num_ports = config.ports.len();
    let total_probes = num_hosts.saturating_mul(num_ports);
    let effective_concurrency = clamp_concurrency(config.concurrency).min(total_probes.max(1));

    let shared_hosts = Arc::new(resolved_list);
    let shared_ports = Arc::new(config.ports.clone());
    let next_idx = Arc::new(AtomicUsize::new(0));
    let scanned_cnt = Arc::new(AtomicUsize::new(0));
    let open_cnt = Arc::new(AtomicUsize::new(0));
    let closed_cnt = Arc::new(AtomicUsize::new(0));
    let filtered_cnt = Arc::new(AtomicUsize::new(0));
    let findings = Arc::new(tokio::sync::Mutex::new(Vec::<PortResult>::new()));

    let emit_every = (total_probes / 80).clamp(1, 64);

    let mut workers = Vec::with_capacity(effective_concurrency);
    for _ in 0..effective_concurrency {
        let hosts = Arc::clone(&shared_hosts);
        let ports = Arc::clone(&shared_ports);
        let idx_cursor = Arc::clone(&next_idx);
        let scanned = Arc::clone(&scanned_cnt);
        let open_c = Arc::clone(&open_cnt);
        let closed_c = Arc::clone(&closed_cnt);
        let filtered_c = Arc::clone(&filtered_cnt);
        let cancel = Arc::clone(&cancel_flag);
        let tx_opt = events.clone();
        let results_acc = Arc::clone(&findings);
        let include_closed = config.include_closed;
        let include_filtered = config.include_filtered;
        let grab_banner = config.grab_banner;

        workers.push(tokio::spawn(async move {
            loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let idx = idx_cursor.fetch_add(1, Ordering::Relaxed);
                if idx >= total_probes {
                    break;
                }

                // Port-major ordering spreads traffic evenly across hosts during LAN scans.
                let port_idx = idx / num_hosts;
                let host_idx = idx % num_hosts;
                let port = ports[port_idx];
                let (ref target_name, ip) = hosts[host_idx];

                let (state, banner, latency_ms) =
                    scan_single_port(target_name, ip, port, timeout, grab_banner).await;

                match state {
                    PortState::Open => {
                        open_c.fetch_add(1, Ordering::Relaxed);
                    }
                    PortState::Closed => {
                        closed_c.fetch_add(1, Ordering::Relaxed);
                    }
                    PortState::Filtered => {
                        filtered_c.fetch_add(1, Ordering::Relaxed);
                    }
                }

                let should_record = match state {
                    PortState::Open => true,
                    PortState::Closed => include_closed,
                    PortState::Filtered => include_filtered,
                };

                if should_record {
                    let row = PortResult {
                        target: target_name.clone(),
                        ip: ip.to_string(),
                        port,
                        state,
                        service: identify_service(port).to_string(),
                        banner,
                        latency_ms,
                    };
                    results_acc.lock().await.push(row.clone());
                    if let Some(tx) = &tx_opt {
                        let _ = tx.send(ScanEvent::Finding(row));
                    }
                }

                let done = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(tx) = &tx_opt {
                    if done % emit_every == 0 || done == total_probes {
                        let elapsed = start_instant.elapsed().as_secs_f64();
                        let rate = if elapsed > 0.001 {
                            done as f64 / elapsed
                        } else {
                            done as f64
                        };
                        let _ = tx.send(ScanEvent::Progress(ScanProgress {
                            scanned: done,
                            total: total_probes,
                            open_count: open_c.load(Ordering::Relaxed),
                            closed_count: closed_c.load(Ordering::Relaxed),
                            filtered_count: filtered_c.load(Ordering::Relaxed),
                            elapsed_secs: elapsed,
                            rate,
                            cancelled: cancel.load(Ordering::Relaxed),
                        }));
                    }
                }
            }
        }));
    }

    for worker in workers {
        let _ = worker.await;
    }

    let duration_secs = (start_instant.elapsed().as_secs_f64() * 1000.0).round() / 1000.0;
    let cancelled = cancel_flag.load(Ordering::Relaxed);
    let mut final_results = findings.lock().await.clone();
    final_results.sort_by(|a, b| {
        ip_sort_key(&a.ip)
            .cmp(&ip_sort_key(&b.ip))
            .then_with(|| a.port.cmp(&b.port))
    });

    let report = ScanReport {
        targets: config.targets,
        resolved_targets,
        total_ports_scanned: scanned_cnt.load(Ordering::Relaxed),
        duration_secs,
        open_count: open_cnt.load(Ordering::Relaxed),
        closed_count: closed_cnt.load(Ordering::Relaxed),
        filtered_count: filtered_cnt.load(Ordering::Relaxed),
        cancelled,
        results: final_results,
    };

    if let Some(tx) = &events {
        let _ = tx.send(ScanEvent::Completed(report.clone()));
    }

    Ok(report)
}

fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Serialize a `ScanReport` into pretty JSON.
pub fn render_report_json(report: &ScanReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| format!("JSON serialization error: {e}"))
}

/// Serialize a `ScanReport` into RFC 4180 CSV.
pub fn render_report_csv(report: &ScanReport) -> String {
    let mut out = String::from("target,ip,port,state,service,latency_ms,banner\n");
    for r in &report.results {
        let latency = r
            .latency_ms
            .map(|ms| format!("{ms:.2}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            csv_escape(&r.target),
            csv_escape(&r.ip),
            r.port,
            r.state.as_str(),
            csv_escape(&r.service),
            latency,
            csv_escape(&r.banner),
        ));
    }
    out
}

/// Serialize a `ScanReport` into a GitHub-flavored Markdown report.
pub fn render_report_markdown(report: &ScanReport) -> String {
    let mut out = String::from("# Port Scan Report\n\n");
    out.push_str(&format!(
        "- **Ports Scanned**: {}\n- **Open Ports**: {}\n- **Duration**: {:.3}s\n- **Cancelled**: {}\n\n",
        report.total_ports_scanned, report.open_count, report.duration_secs, report.cancelled
    ));
    out.push_str("| Target | IP | Port | State | Service | Latency | Banner |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for r in &report.results {
        let latency = r
            .latency_ms
            .map(|ms| format!("{ms:.1} ms"))
            .unwrap_or_else(|| "-".to_string());
        let banner = r.banner.replace('|', "\\|");
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            r.target,
            r.ip,
            r.port,
            r.state.as_str(),
            r.service,
            latency,
            banner
        ));
    }
    out
}

/// Write a `ScanReport` to disk inferred by extension (`.json`, `.csv`, `.md`).
pub fn export_report(report: &ScanReport, path: &Path) -> Result<(), String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let content = match ext.as_str() {
        "csv" => render_report_csv(report),
        "md" | "markdown" => render_report_markdown(report),
        _ => render_report_json(report)?,
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
        }
    }

    fs::write(path, content)
        .map_err(|e| format!("Failed to write report to {}: {e}", path.display()))
}
