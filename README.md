<div align="center">

# Open Port Checker & Fast IP Network Port Scanner

**Lightning-fast, cross-platform tool to scan open TCP ports, discover active local network devices, and inspect services with GUI & CLI.**

[![Release](https://img.shields.io/github/v/release/open-port-tools/port-scanner?style=flat-square&color=blue)](https://github.com/open-port-tools/port-scanner/releases)
[![Build Binaries](https://img.shields.io/github/actions/workflow/status/open-port-tools/port-scanner/build-binaries.yml?style=flat-square&label=Builds)](https://github.com/open-port-tools/port-scanner/actions/workflows/build-binaries.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-informational?style=flat-square)]()
[![GitHub Stars](https://img.shields.io/github/stars/open-port-tools/port-scanner?style=social)](https://github.com/open-port-tools/port-scanner/stargazers)

[Download](#-quick-start--download) • [Features](#-key-features) • [Comparison](#-why-use-this-over-angry-ip-scanner-or-nmap) • [CLI Examples](#-how-to-check-open-ports-usage-examples) • [FAQ](#-frequently-asked-questions-faq)

</div>

---

## What is Open Port Scanner?

**Open Port Scanner** is a free, open-source **port scanner** and **open port checker** built for developers, system administrators, and network engineers on **Windows, macOS, and Linux**. It scans localhost, remote hosts, IPv4 ranges, or your entire local subnet in seconds using a bounded asynchronous TCP engine with **zero external dependencies**.

Designed as a modern, lightweight alternative to **Angry IP Scanner**, **Nmap (Zenmap)**, and **Advanced Port Scanner**, it ships with both a standalone **Desktop / App GUI** (including 1-click **Whole LAN** discovery) and a scriptable **CLI** — without requiring Java or Npcap drivers.

![Open Port Scanner UI Preview](docs/assets/preview.svg)

---

## ✨ Key Features

- **⚡ High-Speed Asynchronous Engine:** Bounded `asyncio.Queue` worker pool scans all `1–65535` TCP ports in constant memory without socket exhaustion.
- **🌐 1-Click Whole Local Network (LAN) Scan:** Automatically detects your active `/24` LAN subnet (`--lan` in CLI or **«Вся сеть»** button in GUI), filtering out loopback and VPN virtual interfaces.
- **🔍 Instant Open Port Checker & Banner Grabbing:** Detects open, closed, and filtered ports across 120+ well-known services and captures SSH/FTP/SMTP/VNC greetings and HTTP status + `<title>`.
- **🔒 TLS / SSL Certificate Inspection:** Extracts TLS version, cipher suite, certificate CN, and expiry date (with self-signed fallback).
- **🖥️ Clean GUI + Scriptable CLI:** Launch a distraction-free Desktop GUI (`--gui` / `--web` in standalone app-window mode) or pipe structured `--json` output in automation.
- **📊 Ready-to-Use Exports:** Save reports directly to `JSON`, `CSV`, `Markdown`, or plain text.

---

## 📊 Why Use This Over Angry IP Scanner or Nmap?

| Feature | Open Port Scanner | Angry IP Scanner | Nmap / Zenmap | Advanced Port Scanner |
| :--- | :---: | :---: | :---: | :---: |
| **Scanning Engine** | ⚡ **Async Worker Pool** | Multi-threaded | Raw / Tunable | Multi-threaded |
| **Requires Java / Npcap** | ✅ **No (Zero-Dep)** | ❌ Requires JVM | ❌ Requires Npcap | ✅ No |
| **Operating Systems** | **Windows, Mac, Linux** | Windows, Mac, Linux | Windows, Mac, Linux | ❌ Windows Only |
| **1-Click Whole LAN Scan** | ✅ **Built-in (`--lan`)** | Manual IP range | Manual CIDR | Auto subnet |
| **GUI + CLI in One Tool** | ✅ **Both Included** | GUI Only | CLI + Legacy Zenmap | GUI Only |
| **JSON / CSV / MD Export** | ✅ **Built-in** | Basic CSV/TXT | XML / Grepable | Basic HTML/CSV |
| **License** | **100% Free (MIT)** | GPL | NPSL | Proprietary Freeware |

---

## 🚀 Quick Start & Download

### Option 1: Download Pre-built Executable (No Python Required)

Download the latest standalone package for your operating system from the **[GitHub Releases](https://github.com/open-port-tools/port-scanner/releases)** page:

| OS | Package | Included Binaries |
| :--- | :--- | :--- |
| **Windows (x64)** | `port-scanner-windows-x64.zip` | `PortScanner-GUI.exe` (windowed GUI), `port-scanner.exe` (CLI + GUI) |
| **macOS** | `port-scanner-macos.tar.gz` | `PortScanner-GUI.app`, `port-scanner` (CLI + GUI) |
| **Linux (x64)** | `port-scanner-linux-x64.tar.gz` | `PortScanner-GUI`, `port-scanner` (CLI + GUI) |

### Option 2: Run Directly with Python 3.9+ (Zero Dependencies)

```bash
git clone https://github.com/open-port-tools/port-scanner.git
cd port-scanner

# Launch the GUI (opens standalone window)
python3 scanner.py --gui

# Or scan your entire detected local network immediately
python3 scanner.py --lan --profile quick
```

### Option 3: Install Locally as a Command

```bash
pip install -e .
port-scanner --lan --profile quick
port-scanner-gui
```

---

## 🛠 How to Check Open Ports (Usage Examples)

### 1. Scan Your Whole Local Network (LAN /24) in 1 Click
Automatically detect your active Wi-Fi/Ethernet subnet and list all open services:
```bash
python3 scanner.py --lan --profile quick
```

### 2. Check Specific Open Ports on a Host or IP
Verify web, SSH, RDP, or database ports with banner & TLS inspection:
```bash
python3 scanner.py scanme.nmap.org -p 22,80,443,3306,8080
```

### 3. Scan an IP Range or CIDR Subnet and Export JSON / CSV
```bash
python3 scanner.py 192.168.1.0/24 -p 22,80,443,3389 -o scan-report.json
python3 scanner.py 192.168.1.1-50 --profile web -o web-hosts.csv
```

### 4. Full 1–65535 Port Sweep
```bash
python3 scanner.py 127.0.0.1 --profile full -c 800 -t 0.5
```

### Available Port Presets (`--profile`)
- `quick` — Top 25 essential ports (`21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017`, etc.)
- `common` — Top ~96 commonly exposed TCP services *(default)*
- `web` — HTTP/HTTPS & dev servers (`80, 443, 3000, 5173, 8000, 8080, 8443, 9000`, etc.)
- `database` — SQL & NoSQL ports (`1433, 1521, 3306, 5432, 6379, 9200, 27017`, etc.)
- `full` — Complete range `1–65535`

---

## 📦 Building Executables Locally

- **Windows (`.exe`)**: run [`build_windows.bat`](build_windows.bat)
- **macOS / Linux**: run [`./build_unix.sh`](build_unix.sh) or `python3 build_executable.py --mode all`

Automated cross-platform builds run on every push via [`.github/workflows/build-binaries.yml`](.github/workflows/build-binaries.yml).

---

## ❓ Frequently Asked Questions (FAQ)

### How do I check if a port is open on my IP address or local network?
Run `python3 scanner.py --gui` and click **«Вся сеть»** (or **«Этот ПК»**), or run `python3 scanner.py --lan --profile quick` in your terminal. Open ports are displayed along with response latency in milliseconds and the detected service banner.

### Do I need to install Nmap, Npcap, or Java?
No. **Open Port Scanner** uses native OS TCP sockets via Python's standard `asyncio` library (or standalone compiled `.exe`/binary releases) and requires zero third-party packages or kernel drivers.

### How does 1-click LAN scanning avoid VPN virtual subnets?
The subnet detector checks active OS network interfaces (`ipconfig` on Windows, `ifconfig` on macOS, `ip` on Linux) and routing tables, ignoring loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and virtual TUN fake-IP blocks (`198.18.0.0/15`).

### Is it legal to use a port scanner?
Yes. Scanning **your own devices, localhost, home Wi-Fi, or authorized corporate servers** for diagnostics and security auditing is completely legal. Never scan external third-party networks without explicit permission.

---

## 🤝 Contributing

Contributions, bug reports, and feature ideas are welcome! Check the [Issues page](https://github.com/open-port-tools/port-scanner/issues) or pick up a `good first issue`.

Run the test suite locally:
```bash
python3 -m unittest discover -s tests -v
```

## ⭐ Support the Project

**Found this tool useful?** Please consider giving the repository a **Star ⭐** in the top-right corner! It helps more developers discover the project and motivates further development.

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
