<div align="center">

# Open port checker and fast IP network port scanner (v2.0, Rust + egui)

Cross-platform tool in Rust (`tokio`, `eframe`/`egui`, `clap`) to scan open TCP ports, map local subnets, and inspect service banners with a desktop GUI and CLI in a single binary.

[![Crates.io](https://img.shields.io/crates/v/open-port-scanner?style=flat-square&color=orange)](https://crates.io/crates/open-port-scanner)
[![Release](https://img.shields.io/github/v/release/open-port-tools/port-scanner?style=flat-square&color=blue)](https://github.com/open-port-tools/port-scanner/releases)
[![Build Binaries](https://img.shields.io/github/actions/workflow/status/open-port-tools/port-scanner/build-binaries.yml?style=flat-square&label=Builds)](https://github.com/open-port-tools/port-scanner/actions/workflows/build-binaries.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-informational?style=flat-square)]()
[![GitHub Stars](https://img.shields.io/github/stars/open-port-tools/port-scanner?style=social)](https://github.com/open-port-tools/port-scanner/stargazers)

[Download](#quick-start-and-download) • [Features](#features) • [Comparison](#comparison-with-alternatives) • [Usage examples](#usage-examples) • [Cross-compile .exe](#building-locally-and-cross-compiling-windows-exe) • [FAQ](#frequently-asked-questions)

</div>

## What is Open Port Scanner?

Open Port Scanner v2.0 is a native Rust port scanner and local network mapper for Windows, macOS, and Linux. It combines Tokio async I/O, an eframe/egui desktop interface, and a clap CLI into a standalone 2-4 MB binary with zero runtime dependencies (no Java, Python, or packet capture drivers).

It scans localhost, individual hosts, CIDR ranges, or your entire local `/24` subnet in seconds using a bounded-concurrency async engine. A legacy Python 3 script also remains in the repository for environments where Python is already available.

![Open Port Scanner UI Preview](docs/assets/preview.svg)

## Features

- Bounded worker pool (`1-2000` sockets) in Rust and Tokio sweeps hosts in port-major order with configurable concurrency and timeouts.
- Desktop GUI (`eframe` / `egui`) in dark mode includes local host and whole-subnet scan presets, table sorting, live search filtering, and CSV/JSON export.
- Subnet scanning automatically detects your active `/24` LAN subnet (`--lan` in CLI or the LAN button in GUI), filtering out loopback (`127.*`), link-local (`169.254.*`), and virtual VPN ranges (`198.18.0.0/15`).
- Service detection maps 120+ standard TCP ports, measures connection latency in milliseconds, and grabs SSH/FTP/SMTP greetings along with HTTP status codes, `Server` headers, and `<title>`.
- Scriptable CLI outputs structured JSON (`--json`) for automation or exports reports to `.json`, `.csv`, or `.md` (`-o`).

## Comparison with alternatives

| Feature | Open Port Scanner v2.0 | Angry IP Scanner | Nmap / Zenmap | Advanced Port Scanner |
| :--- | :--- | :--- | :--- | :--- |
| Stack & Engine | Rust (tokio + egui) | Java / threads | C++ / Raw sockets | Multi-threaded C++ |
| Binary Footprint | 2-4 MB standalone | Requires JRE | Requires Npcap | Installer required |
| Runtime Dependencies | None | Java (JRE 8+) | Npcap driver | None |
| Operating Systems | Windows, macOS, Linux | Windows, macOS, Linux | Windows, macOS, Linux | Windows only |
| 1-Click LAN Scan | Built-in (`--lan`) | Manual IP range | Manual CIDR | Auto subnet |
| Interface | Desktop GUI + CLI | GUI only | CLI + Zenmap | GUI only |
| License | MIT (Open Source) | GPL v2 | NPSL | Proprietary Freeware |

## Quick start and download

### Option 1: Download pre-built native executable (2-4 MB)

Download the standalone binary for your operating system from [GitHub Releases v2.0.0](https://github.com/open-port-tools/port-scanner/releases/tag/v2.0.0):

| OS | Direct Download Link | Archive Size | Contents |
| :--- | :--- | :---: | :--- |
| Windows (x64) | [Download port-scanner-windows-x64.zip](https://github.com/open-port-tools/port-scanner/releases/download/v2.0.0/port-scanner-windows-x64.zip) | 2.1 MB | `port-scanner.exe` (GUI + CLI) |
| macOS (Universal) | [Download port-scanner-macos.tar.gz](https://github.com/open-port-tools/port-scanner/releases/download/v2.0.0/port-scanner-macos.tar.gz) | 4.4 MB | `port-scanner` (Apple Silicon & Intel) |
| Linux (x64) | [Download port-scanner-linux-x64.tar.gz](https://github.com/open-port-tools/port-scanner/releases/download/v2.0.0/port-scanner-linux-x64.tar.gz) | 2.8 MB | `port-scanner` (X11/Wayland GUI + CLI) |

Launch GUI directly (double-click or run with no arguments in terminal):
```bash
# macOS / Linux
./port-scanner

# Windows
port-scanner.exe
```

### Option 2: Install via Cargo (crates.io)

```bash
cargo install open-port-scanner

# Launch GUI directly (desktop window)
port-scanner

# Or scan whole LAN in terminal
port-scanner --lan --profile quick
```

### Option 3: Build from Source with Cargo (Rust 1.75+)

```bash
git clone https://github.com/open-port-tools/port-scanner.git
cd port-scanner

cargo build --release

# Launch native GPU GUI
./target/release/port-scanner

# Or run a fast CLI scan across your local LAN
./target/release/port-scanner --lan --profile quick
```

### Option 4: Legacy Python 3.9+ Fallback (Zero Pip Dependencies)

```bash
python3 scanner.py --lan --profile quick
```

---

## Usage examples

### 1. Scan Local Subnet (/24 LAN)
Automatically detect your active Wi-Fi/Ethernet subnet and list open services:
```bash
port-scanner --lan --profile quick
```

### 2. Check Specific Ports on a Host or IP
```bash
port-scanner scanme.nmap.org -p 22,80,443,3306,8080
```

### 3. Scan a CIDR Subnet or Range and Export JSON / CSV / Markdown
```bash
port-scanner 192.168.1.0/24 -p 22,80,443,3389 -o scan-report.json
port-scanner 192.168.1.1-50 --profile web -o web-hosts.csv
port-scanner 127.0.0.1 --profile quick --json -q
```

### 4. Full 1-65535 Port Sweep
```bash
port-scanner 127.0.0.1 --profile full -c 800 -t 0.4
```

### Available Port Presets (`--profile`)
- `quick` - Top 25 essential ports (`21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017`, etc.)
- `common` - Top 96 commonly exposed TCP services *(default in CLI)*
- `web` - Top 19 HTTP/HTTPS & dev server ports (`80, 443, 3000, 5173, 8000, 8080, 8443, 9000`, etc.)
- `database` - Top 17 SQL & NoSQL ports (`1433, 1521, 3306, 5432, 6379, 9200, 27017`, etc.)
- `full` - Complete range `1-65535`

---

## Building locally and cross-compiling Windows .exe

Automated multi-platform release builds (Windows `.exe`, macOS, Linux) run on every push and tag via [`.github/workflows/build-binaries.yml`](.github/workflows/build-binaries.yml).

To cross-compile a Windows `x86_64` `.exe` directly from macOS or Linux using `cargo-xwin`:
```bash
rustup target add x86_64-pc-windows-msvc
cargo install cargo-xwin
cargo xwin build --release --target x86_64-pc-windows-msvc
# Output: target/x86_64-pc-windows-msvc/release/port-scanner.exe
```

On Linux, install X11/OpenGL development headers before compiling the GUI:
```bash
sudo apt-get install -y libxkbcommon-dev libxkbcommon-x11-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libgl1-mesa-dev libwayland-dev
cargo build --release
```

---

## Frequently asked questions

### How do I check if a port is open on my IP address or local network?
Open `port-scanner` and select the LAN target (or enter an IP or CIDR), or run `port-scanner --lan --profile quick` in your terminal. Open ports are displayed along with response latency in milliseconds and detected service banners.

### Do I need Python, Java, Nmap, or Npcap installed?
No. Open Port Scanner v2.0 compiles to a single native executable using standard OS TCP sockets and hardware-accelerated egui rendering.

### How does LAN scanning avoid VPN virtual subnets?
The subnet detector parses active network interfaces (`ipconfig` on Windows, `ifconfig` on macOS, `ip` on Linux) and routing probes, automatically filtering out loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and virtual TUN fake-IP blocks (`198.18.0.0/15`).

### Is it legal to use a port scanner?
Yes. Scanning your own devices, localhost, home network, or authorized servers for diagnostics and auditing is standard practice. Never scan external third-party networks without authorization.

---

## Contributing

Contributions, bug reports, and feature ideas are welcome. Check the [Issues page](https://github.com/open-port-tools/port-scanner/issues) for open tasks.

Run test suites locally:
```bash
cargo test
python3 -m unittest discover -s tests -v
```

## License

Distributed under the [MIT License](LICENSE).
