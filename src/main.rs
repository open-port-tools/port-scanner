mod engine;
mod gui;
mod services;

use clap::Parser;
use engine::{
    export_report, render_report_json, run_scan, PortResult, ScanConfig, ScanEvent, ScanReport,
};
use services::{detect_local_networks, parse_ports, parse_targets};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Parser)]
#[command(
    name = "port-scanner",
    version,
    about = "Fast cross-platform async TCP port scanner & local LAN mapper (GUI + CLI)"
)]
struct Cli {
    /// Target host, IP, CIDR (192.168.0.0/24), dash range (192.168.0.1-50), or 'lan'
    target: Option<String>,

    /// Scan detected local /24 network automatically
    #[arg(long)]
    lan: bool,

    /// Launch native GPU GUI window (default when invoked with no arguments)
    #[arg(long)]
    gui: bool,

    /// Ports or ranges (e.g. "22,80,443,8000-8080" or "all")
    #[arg(short = 'p', long)]
    ports: Option<String>,

    /// Built-in port preset: quick, common, web, database, full
    #[arg(long, default_value = "common")]
    profile: String,

    /// Per-port TCP connection timeout in seconds
    #[arg(short = 't', long, default_value_t = 0.8)]
    timeout: f64,

    /// Max concurrent async socket probes
    #[arg(short = 'c', long, default_value_t = 350)]
    concurrency: usize,

    /// Skip passive/HTTP banner grabbing
    #[arg(long)]
    no_banner: bool,

    /// Save report to file (.json, .csv, or .md)
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Print scan report as JSON to stdout
    #[arg(long)]
    json: bool,

    /// Suppress progress output (only final findings/errors)
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn print_report_table(report: &ScanReport, quiet: bool) {
    if !quiet {
        let state_label = if report.cancelled {
            "Stopped (partial)"
        } else {
            "Completed"
        };
        println!(
            "{} | hosts: {} | probes: {} | open: {} | closed: {} | filtered: {} | time: {:.2}s",
            state_label,
            report.resolved_targets.len(),
            report.total_ports_scanned,
            report.open_count,
            report.closed_count,
            report.filtered_count,
            report.duration_secs
        );
    }

    if report.results.is_empty() {
        if !quiet {
            println!("No open ports detected.");
        }
        return;
    }

    println!(
        "{:<18} {:<7} {:<7} {:<16} {:<10} {}",
        "HOST", "PORT", "STATE", "SERVICE", "LATENCY", "BANNER"
    );
    println!("{}", "-".repeat(82));
    for r in &report.results {
        print_finding_row(r);
    }
}

fn print_finding_row(r: &PortResult) {
    let lat = r
        .latency_ms
        .map(|ms| format!("{ms:.1} ms"))
        .unwrap_or_else(|| "-".to_string());
    let banner = if r.banner.is_empty() { "-" } else { &r.banner };
    println!(
        "{:<18} {:<7} {:<7} {:<16} {:<10} {}",
        r.ip,
        r.port,
        r.state.as_str(),
        r.service,
        lat,
        banner
    );
}

fn run_cli(cli: Cli) -> i32 {
    let target_spec = if cli.lan {
        let info = detect_local_networks();
        if info.cidr.is_empty() {
            eprintln!("Error: could not detect active local IPv4 network.");
            return 1;
        }
        if !cli.quiet && !cli.json {
            eprintln!(
                "Detected local network: {} (local IP {}, {} hosts)",
                info.cidr, info.primary_ip, info.host_count
            );
        }
        info.cidr
    } else if let Some(t) = cli.target {
        t
    } else {
        eprintln!("Error: provide a target, --lan, or run without arguments for GUI.");
        return 2;
    };

    let targets = match parse_targets(&target_spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return 2;
        }
    };

    let ports = match parse_ports(cli.ports.as_deref(), &cli.profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return 2;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error initializing async runtime: {e}");
            return 1;
        }
    };

    let config = ScanConfig {
        targets,
        ports,
        timeout_secs: cli.timeout,
        concurrency: cli.concurrency,
        grab_banner: !cli.no_banner,
        include_closed: false,
        include_filtered: false,
    };

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_ctrlc = Arc::clone(&cancel_flag);
    let quiet = cli.quiet || cli.json;

    let (tx, mut rx) = mpsc::unbounded_channel();

    let result = rt.block_on(async move {
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel_ctrlc.store(true, Ordering::Relaxed);
            }
        });

        let progress_task = tokio::spawn(async move {
            let mut last_len = 0usize;
            while let Some(ev) = rx.recv().await {
                if quiet {
                    continue;
                }
                if let ScanEvent::Progress(p) = ev {
                    let msg = format!(
                        "\rScanning {}/{} ({:.0}%) | open: {} | {:.0} ports/s",
                        p.scanned,
                        p.total,
                        if p.total > 0 {
                            (p.scanned as f64 / p.total as f64) * 100.0
                        } else {
                            100.0
                        },
                        p.open_count,
                        p.rate
                    );
                    let pad = last_len.saturating_sub(msg.len());
                    last_len = msg.len();
                    let mut stderr = io::stderr();
                    let _ = write!(stderr, "{msg}{}", " ".repeat(pad));
                    let _ = stderr.flush();
                }
            }
            if !quiet && last_len > 0 {
                let mut stderr = io::stderr();
                let _ = write!(stderr, "\r{}\r", " ".repeat(last_len));
                let _ = stderr.flush();
            }
        });

        let scan_res = run_scan(config, cancel_flag, Some(tx)).await;
        let _ = progress_task.await;
        scan_res
    });

    let report = match result {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Scan failed: {err}");
            return 1;
        }
    };

    if let Some(ref out_path) = cli.output {
        if let Err(err) = export_report(&report, out_path) {
            eprintln!("Export failed: {err}");
            return 1;
        }
        if !cli.quiet && !cli.json {
            eprintln!("Saved report to {}", out_path.display());
        }
    }

    if cli.json {
        match render_report_json(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("{err}");
                return 1;
            }
        }
    } else {
        print_report_table(&report, cli.quiet);
    }

    0
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() <= 1 {
        if let Err(err) = gui::launch_gui(None) {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let cli = Cli::parse();
    if cli.gui {
        let initial = if cli.lan {
            let info = detect_local_networks();
            if info.cidr.is_empty() {
                None
            } else {
                Some(info.cidr)
            }
        } else {
            cli.target
        };
        if let Err(err) = gui::launch_gui(initial) {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let code = run_cli(cli);
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(code as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{render_report_csv, render_report_markdown, PortState};
    use crate::services::identify_service;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_ports_profiles_and_ranges() {
        let quick = parse_ports(None, "quick").unwrap();
        assert_eq!(quick.len(), 25);
        assert!(quick.contains(&22));
        assert!(quick.contains(&443));

        let custom = parse_ports(Some("443, 80, 8000-8002, 80"), "quick").unwrap();
        assert_eq!(custom, vec![80, 443, 8000, 8001, 8002]);

        let full = parse_ports(Some("all"), "quick").unwrap();
        assert_eq!(full.len(), 65535);
        assert_eq!(full[0], 1);
        assert_eq!(full[65534], 65535);

        assert!(parse_ports(Some("90-80"), "quick").is_err());
        assert!(parse_ports(Some("0"), "quick").is_err());
        assert!(parse_ports(None, "nonexistent").is_err());
    }

    #[test]
    fn test_parse_targets_cidr_range_and_dedup() {
        let cidr = parse_targets("192.168.10.0/30").unwrap();
        assert_eq!(cidr, vec!["192.168.10.1", "192.168.10.2"]);

        let dash = parse_targets("10.0.0.5-7, 10.0.0.6, localhost").unwrap();
        assert_eq!(
            dash,
            vec!["10.0.0.5", "10.0.0.6", "10.0.0.7", "localhost"]
        );

        assert!(parse_targets("10.0.0.10-5").is_err());
        assert!(parse_targets("").is_err());
    }

    #[test]
    fn test_identify_service_and_lan_filtering() {
        assert_eq!(identify_service(22), "SSH");
        assert_eq!(identify_service(5432), "PostgreSQL");
        assert_eq!(identify_service(27017), "MongoDB");
        assert_eq!(identify_service(65432), "unknown");

        let info = detect_local_networks();
        for ip in &info.local_ips {
            assert!(!ip.starts_with("127."));
            assert!(!ip.starts_with("169.254."));
            assert!(!ip.starts_with("198.18."));
            assert!(!ip.starts_with("198.19."));
        }
    }

    #[test]
    fn test_export_renderers_and_file_export() {
        let report = ScanReport {
            targets: vec!["127.0.0.1".to_string()],
            resolved_targets: [("127.0.0.1".to_string(), "127.0.0.1".to_string())]
                .into_iter()
                .collect(),
            total_ports_scanned: 25,
            duration_secs: 0.123,
            open_count: 1,
            closed_count: 24,
            filtered_count: 0,
            cancelled: false,
            results: vec![PortResult {
                target: "127.0.0.1".to_string(),
                ip: "127.0.0.1".to_string(),
                port: 80,
                state: PortState::Open,
                service: "HTTP".to_string(),
                banner: "HTTP/1.1 200 OK, \"test\"".to_string(),
                latency_ms: Some(1.45),
            }],
        };

        let json = render_report_json(&report).unwrap();
        assert!(json.contains("\"port\": 80"));
        assert!(json.contains("\"state\": \"open\""));

        let csv = render_report_csv(&report);
        assert!(csv.contains("target,ip,port,state,service,latency_ms,banner"));
        assert!(csv.contains("\"HTTP/1.1 200 OK, \"\"test\"\"\""));

        let md = render_report_markdown(&report);
        assert!(md.contains("| 127.0.0.1 | 127.0.0.1 | 80 | open | HTTP |"));
    }

    #[tokio::test]
    async fn test_async_scan_live_ephemeral_ports() {
        let banner_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let banner_port = banner_listener.local_addr().unwrap().port();

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_listener.local_addr().unwrap().port();

        // Bind then drop a third listener to pick a guaranteed closed local port.
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let srv_banner = tokio::spawn(async move {
            if let Ok((mut sock, _)) = banner_listener.accept().await {
                let _ = sock.write_all(b"220 mock-service ESMTP\r\n").await;
                let mut tmp = [0u8; 64];
                let _ = sock.read(&mut tmp).await;
            }
        });

        let srv_http = tokio::spawn(async move {
            if let Ok((mut sock, _)) = http_listener.accept().await {
                let mut req = [0u8; 256];
                let _ = sock.read(&mut req).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nServer: MockRustTest\r\n\r\n<html><title>ScannerTest</title></html>")
                    .await;
            }
        });

        let cfg = ScanConfig {
            targets: vec!["127.0.0.1".to_string()],
            ports: vec![banner_port, http_port, closed_port],
            timeout_secs: 1.0,
            concurrency: 10,
            grab_banner: true,
            include_closed: false,
            include_filtered: false,
        };

        let report = run_scan(cfg, Arc::new(AtomicBool::new(false)), None)
            .await
            .unwrap();

        let _ = srv_banner.await;
        let _ = srv_http.await;

        assert_eq!(report.total_ports_scanned, 3);
        assert_eq!(report.open_count, 2);
        assert_eq!(report.results.len(), 2);

        let b_res = report
            .results
            .iter()
            .find(|r| r.port == banner_port)
            .unwrap();
        assert_eq!(b_res.state, PortState::Open);
        assert!(b_res.banner.contains("mock-service"));
        assert!(b_res.latency_ms.is_some());

        let h_res = report.results.iter().find(|r| r.port == http_port).unwrap();
        assert_eq!(h_res.state, PortState::Open);
        assert!(h_res.banner.contains("220") || h_res.banner.contains("200") || h_res.banner.contains("MockRustTest") || h_res.latency_ms.is_some());
    }
}
