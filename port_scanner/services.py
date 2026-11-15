"""Well-known port metadata, scan profiles, and target/port parsing helpers."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from typing import Any

# 120+ well-known TCP services mapped to (service_name, description)
COMMON_SERVICES: dict[int, tuple[str, str]] = {
    7: ("echo", "Echo Protocol"),
    9: ("discard", "Discard Protocol"),
    13: ("daytime", "Daytime Protocol"),
    17: ("qotd", "Quote of the Day"),
    19: ("chargen", "Character Generator"),
    20: ("ftp-data", "FTP Data Transfer"),
    21: ("ftp", "File Transfer Protocol"),
    22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "Simple Mail Transfer Protocol"),
    26: ("rsftp", "Alternate SMTP"),
    37: ("time", "Time Protocol"),
    42: ("nameserver", "Host Name Server"),
    43: ("whois", "WHOIS Directory Service"),
    49: ("tacacs", "TACACS+ Login Host Protocol"),
    53: ("dns", "Domain Name System"),
    67: ("dhcps", "DHCP Server"),
    68: ("dhcpc", "DHCP Client"),
    69: ("tftp", "Trivial File Transfer Protocol"),
    70: ("gopher", "Gopher Protocol"),
    79: ("finger", "Finger User Information"),
    80: ("http", "Hypertext Transfer Protocol"),
    81: ("http-alt", "HTTP Alternate / Admin"),
    88: ("kerberos", "Kerberos Authentication"),
    102: ("iso-tsap", "ISO-TSAP / S7comm"),
    109: ("pop2", "Post Office Protocol v2"),
    110: ("pop3", "Post Office Protocol v3"),
    111: ("rpcbind", "ONC RPC / Portmapper"),
    113: ("ident", "Ident Authentication Service"),
    115: ("sftp", "Simple File Transfer Protocol"),
    119: ("nntp", "Network News Transfer Protocol"),
    123: ("ntp", "Network Time Protocol"),
    135: ("msrpc", "Microsoft RPC Endpoint Mapper"),
    137: ("netbios-ns", "NetBIOS Name Service"),
    138: ("netbios-dgm", "NetBIOS Datagram Service"),
    139: ("netbios-ssn", "NetBIOS Session Service"),
    143: ("imap", "Internet Message Access Protocol"),
    161: ("snmp", "Simple Network Management Protocol"),
    162: ("snmptrap", "SNMP Trap"),
    177: ("xdmcp", "X Display Manager Control Protocol"),
    179: ("bgp", "Border Gateway Protocol"),
    194: ("irc", "Internet Relay Chat"),
    199: ("smux", "SNMP Unix Multiplexer"),
    264: ("bgmp", "Check Point Topology"),
    389: ("ldap", "Lightweight Directory Access Protocol"),
    443: ("https", "HTTP over TLS/SSL"),
    444: ("snpp", "Simple Network Paging Protocol"),
    445: ("microsoft-ds", "SMB / CIFS File Sharing"),
    464: ("kpasswd", "Kerberos Password Change"),
    465: ("smtps", "SMTP over TLS"),
    497: ("retrospect", "Retrospect Backup"),
    500: ("isakmp", "IKE / IPsec Key Exchange"),
    502: ("modbus", "Modbus TCP Industrial Protocol"),
    512: ("exec", "Remote Process Execution"),
    513: ("login", "Remote Login (rlogin)"),
    514: ("shell", "Remote Shell / Syslog"),
    515: ("printer", "LPD Print Spooler"),
    520: ("efs", "Extended File Name Server"),
    543: ("klogin", "Kerberos Login"),
    544: ("kshell", "Kerberos Remote Shell"),
    548: ("afp", "Apple Filing Protocol"),
    554: ("rtsp", "Real Time Streaming Protocol"),
    587: ("submission", "SMTP Mail Submission"),
    593: ("http-rpc-epmap", "DCOM over HTTP"),
    623: ("ipmi", "IPMI Remote Management"),
    631: ("ipp", "Internet Printing Protocol (CUPS)"),
    636: ("ldaps", "LDAP over TLS/SSL"),
    646: ("ldp", "Label Distribution Protocol"),
    691: ("msexch-routing", "MS Exchange Routing"),
    873: ("rsync", "rsync File Synchronization"),
    902: ("vmware-authd", "VMware ESXi Authentication"),
    989: ("ftps-data", "FTP Data over TLS"),
    990: ("ftps", "FTP Control over TLS"),
    993: ("imaps", "IMAP over TLS/SSL"),
    995: ("pop3s", "POP3 over TLS/SSL"),
    1025: ("nfs-or-iis", "Microsoft RPC / NFS"),
    1080: ("socks", "SOCKS Proxy"),
    1099: ("rmiregistry", "Java RMI Registry"),
    1194: ("openvpn", "OpenVPN"),
    1433: ("ms-sql-s", "Microsoft SQL Server"),
    1434: ("ms-sql-m", "Microsoft SQL Monitor"),
    1521: ("oracle", "Oracle Database Listener"),
    1720: ("h323q931", "H.323 Call Signaling"),
    1723: ("pptp", "Point-to-Point Tunneling Protocol"),
    1883: ("mqtt", "MQTT Message Broker"),
    1900: ("upnp", "UPnP / SSDP"),
    2000: ("cisco-sccp", "Cisco Skinny Client Control"),
    2049: ("nfs", "Network File System"),
    2082: ("cpanel", "cPanel HTTP"),
    2083: ("cpanel-ssl", "cPanel HTTPS"),
    2121: ("ccproxy-ftp", "Alternate FTP Proxy"),
    2181: ("zookeeper", "Apache ZooKeeper"),
    2375: ("docker", "Docker REST API (Unencrypted)"),
    2376: ("docker-tls", "Docker REST API (TLS)"),
    2379: ("etcd-client", "etcd Client API"),
    2380: ("etcd-peer", "etcd Peer Communication"),
    3000: ("dev-http", "Node.js / Grafana / Rails Dev Server"),
    3128: ("squid-http", "Squid HTTP Proxy"),
    3268: ("globalcatLDAP", "Active Directory Global Catalog"),
    3269: ("globalcatLDAPssl", "Active Directory Global Catalog SSL"),
    3306: ("mysql", "MySQL / MariaDB Database"),
    3389: ("ms-wbt-server", "Remote Desktop Protocol (RDP)"),
    3690: ("svn", "Subversion Version Control"),
    4000: ("remoteanything", "Dev Web Server / Phoenix"),
    4200: ("angular-cli", "Angular Dev Server"),
    4369: ("epmd", "Erlang Port Mapper Daemon"),
    4444: ("krb524", "Metasploit / Selenium Grid"),
    4500: ("nat-t-ike", "IPsec NAT-T"),
    4848: ("glassfish", "GlassFish Admin Console"),
    5000: ("upnp-or-flask", "Flask / Docker Registry / Synology"),
    5001: ("commplex-link", "Synology HTTPS / iPerf3"),
    5060: ("sip", "Session Initiation Protocol"),
    5061: ("sips", "SIP over TLS"),
    5173: ("vite", "Vite Development Server"),
    5432: ("postgresql", "PostgreSQL Database"),
    5601: ("kibana", "Kibana Analytics UI"),
    5672: ("amqp", "RabbitMQ AMQP"),
    5800: ("vnc-http", "VNC over HTTP"),
    5900: ("vnc", "Virtual Network Computing (VNC)"),
    5901: ("vnc-1", "VNC Display 1"),
    5984: ("couchdb", "Apache CouchDB"),
    5985: ("wsman", "WinRM HTTP"),
    5986: ("wsmans", "WinRM HTTPS"),
    6000: ("x11", "X Window System"),
    6379: ("redis", "Redis Key-Value Store"),
    6443: ("kubernetes-api", "Kubernetes API Server"),
    6667: ("irc", "IRC Server"),
    7000: ("afs3-fileserver", "Cassandra / AirPlay / Dev"),
    7001: ("afs3-callback", "WebLogic / Cassandra TLS"),
    7070: ("realserver", "AnyDesk / RTSP Alternate"),
    8000: ("http-alt", "Django / Python / Alternate HTTP"),
    8008: ("http-alt", "HTTP Alternate"),
    8080: ("http-proxy", "HTTP Proxy / Tomcat / Jenkins"),
    8081: ("blackice-icecap", "HTTP Alternate / Nexus"),
    8088: ("radan-http", "HTTP Alternate / YARN"),
    8086: ("influxdb", "InfluxDB HTTP API"),
    8161: ("activemq", "Apache ActiveMQ Console"),
    8200: ("vault", "HashiCorp Vault API"),
    8443: ("https-alt", "HTTPS Alternate"),
    8500: ("consul", "HashiCorp Consul UI/API"),
    8888: ("sun-answerbook", "Jupyter Notebook / HTTP Alt"),
    9000: ("cslistener", "SonarQube / Portainer / PHP-FPM"),
    9001: ("tor-orport", "Supervisor / MinIO Console"),
    9042: ("cassandra", "Apache Cassandra CQL"),
    9090: ("zeus-admin", "Prometheus / Cockpit Web UI"),
    9092: ("kafka", "Apache Kafka Broker"),
    9100: ("jetdirect", "HP JetDirect Raw Printing / Node Exporter"),
    9200: ("elasticsearch", "Elasticsearch HTTP API"),
    9300: ("vrace", "Elasticsearch Transport"),
    9443: ("tungsten-https", "VMware / Portainer HTTPS"),
    9999: ("abyss", "Urchin / Debug Console"),
    10000: ("snet-sensor-mgmt", "Webmin Admin Interface"),
    11211: ("memcache", "Memcached"),
    15672: ("rabbitmq-mgmt", "RabbitMQ Management UI"),
    27017: ("mongodb", "MongoDB Database"),
    27018: ("mongodb-shard", "MongoDB Shard Server"),
    28017: ("mongodb-web", "MongoDB Web Status"),
    32400: ("plex", "Plex Media Server"),
    50000: ("ibm-db2", "IBM DB2 / SAP / Jenkins Agent"),
    50070: ("hdfs-namenode", "Hadoop HDFS NameNode UI"),
}

TLS_LIKELY_PORTS: frozenset[int] = frozenset(
    {443, 465, 636, 989, 990, 993, 995, 2083, 2376, 3269, 5061, 5986, 6443, 8443, 9443}
)

HTTP_LIKELY_PORTS: frozenset[int] = frozenset(
    {
        80,
        81,
        591,
        631,
        2082,
        3000,
        4000,
        4200,
        4848,
        5000,
        5001,
        5173,
        5601,
        5800,
        7000,
        8000,
        8008,
        8080,
        8081,
        8086,
        8088,
        8161,
        8200,
        8500,
        8888,
        9000,
        9090,
        9200,
        10000,
        15672,
        28017,
        32400,
        50070,
    }
)

_QUICK_PORTS: list[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    27017,
]

_COMMON_PORTS: list[int] = sorted(
    set(_QUICK_PORTS)
    | {
        20,
        26,
        43,
        49,
        69,
        79,
        81,
        88,
        113,
        119,
        123,
        161,
        179,
        199,
        389,
        465,
        500,
        502,
        512,
        513,
        514,
        515,
        548,
        554,
        587,
        631,
        636,
        873,
        902,
        989,
        990,
        1025,
        1080,
        1099,
        1194,
        1723,
        1883,
        2049,
        2082,
        2083,
        2121,
        2181,
        2375,
        2376,
        2379,
        3000,
        3128,
        3268,
        3269,
        3690,
        4000,
        4200,
        4444,
        4848,
        5000,
        5001,
        5060,
        5173,
        5601,
        5672,
        5800,
        5901,
        5984,
        5985,
        5986,
        6000,
        6443,
        6667,
        7000,
        7001,
        7070,
        8000,
        8008,
        8081,
        8086,
        8088,
        8161,
        8200,
        8500,
        8888,
        9000,
        9001,
        9042,
        9090,
        9092,
        9100,
        9200,
        9300,
        9443,
        9999,
        10000,
        11211,
        15672,
        27018,
        28017,
        32400,
        50000,
    }
)

_WEB_PORTS: list[int] = [
    80,
    81,
    443,
    3000,
    4000,
    4200,
    5000,
    5173,
    7000,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
    9090,
    9443,
]

_DATABASE_PORTS: list[int] = [
    1433,
    1521,
    3306,
    5432,
    5984,
    6379,
    7000,
    7001,
    8086,
    9042,
    9200,
    9300,
    11211,
    27017,
    27018,
    28017,
    50000,
]

PROFILES: dict[str, list[int]] = {
    "quick": _QUICK_PORTS,
    "common": _COMMON_PORTS,
    "web": _WEB_PORTS,
    "database": _DATABASE_PORTS,
    "full": list(range(1, 65536)),
}


def identify_service(port: int) -> str:
    """Return a concise service name for a TCP port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port][0]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def describe_service(port: int) -> str:
    """Return a human-friendly description for a TCP port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port][1]
    name = identify_service(port)
    return name if name != "unknown" else "Unregistered / Custom Service"


def parse_ports(spec: str | None = None, profile: str = "common") -> list[int]:
    """
    Parse a port specification string or fall back to a named profile.

    Supports:
    - Profile names: ``quick``, ``common``, ``web``, ``database``, ``full``
    - Single ports: ``80,443,8080``
    - Ranges: ``1-1024``
    - Mixed: ``22,80,443,8000-8100``
    """
    raw = (spec or "").strip()
    if not raw:
        key = profile.strip().lower()
        if key not in PROFILES:
            valid = ", ".join(sorted(PROFILES))
            raise ValueError(f"Unknown profile '{profile}'. Valid profiles: {valid}")
        return list(PROFILES[key])

    lower_raw = raw.lower()
    if lower_raw in PROFILES:
        return list(PROFILES[lower_raw])

    ports: set[int] = set()
    tokens = [t.strip() for t in re.split(r"[\s,;]+", raw) if t.strip()]
    if not tokens:
        raise ValueError("Port specification is empty.")

    for token in tokens:
        if token.lower() in PROFILES:
            ports.update(PROFILES[token.lower()])
            continue

        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError(f"Invalid port range: '{token}'")
            start = int(parts[0])
            end = int(parts[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(
                    f"Port range out of bounds (1-65535, start<=end): '{token}'"
                )
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port value: '{token}'")
            port = int(token)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of bounds (1-65535): {port}")
            ports.add(port)

    return sorted(ports)


def _expand_ip_range(token: str) -> list[str]:
    """Expand `192.168.1.1-20` or `192.168.1.1-192.168.1.20` into IP strings."""
    left, right = token.split("-", 1)
    start_ip = ipaddress.ip_address(left.strip())
    if start_ip.version != 4:
        raise ValueError(f"IP range syntax is only supported for IPv4: '{token}'")

    right_clean = right.strip()
    if "." not in right_clean and right_clean.isdigit():
        last_octet = int(right_clean)
        if not (0 <= last_octet <= 255):
            raise ValueError(f"Invalid ending octet in IP range: '{token}'")
        prefix = ".".join(left.strip().split(".")[:3])
        end_ip = ipaddress.ip_address(f"{prefix}.{last_octet}")
    else:
        end_ip = ipaddress.ip_address(right_clean)

    if end_ip.version != 4 or int(end_ip) < int(start_ip):
        raise ValueError(f"Invalid IP range bounds: '{token}'")

    count = int(end_ip) - int(start_ip) + 1
    if count > 65536:
        raise ValueError(f"IP range too large ({count} hosts, max 65536): '{token}'")

    return [str(ipaddress.IPv4Address(int(start_ip) + i)) for i in range(count)]


_FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")
_LINK_LOCAL_NET = ipaddress.ip_network("169.254.0.0/16")
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def _is_usable_lan_ip(addr: ipaddress.IPv4Address) -> bool:
    """Return True if an IPv4 address belongs to a real private LAN interface."""
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return False
    if addr in _LINK_LOCAL_NET or addr in _FAKE_IP_NET:
        return False
    return addr.is_private


def _ip_priority(addr: ipaddress.IPv4Address) -> tuple[int, str]:
    """Sort key preferring 192.168.x.x > 10.x.x.x > 172.16-31.x.x > other private."""
    s = str(addr)
    if s.startswith("192.168."):
        return (0, s)
    if s.startswith("10."):
        return (1, s)
    if addr not in _CGNAT_NET:
        return (2, s)
    return (3, s)


def _compute_scan_cidr(ip_str: str, prefixlen: int | None = None) -> str:
    """Compute a practical LAN CIDR block (clamped to /24 for large subnets)."""
    eff_prefix = 24 if prefixlen is None or prefixlen < 24 or prefixlen > 30 else prefixlen
    net = ipaddress.ip_network(f"{ip_str}/{eff_prefix}", strict=False)
    return str(net)


def detect_local_networks() -> dict[str, Any]:
    """
    Detect active local IPv4 interfaces and their /24 LAN CIDRs across Windows, macOS, and Linux.

    Filters out loopback (127.0.0.0/8), link-local (169.254.0.0/16), and VPN fake-IP
    ranges (198.18.0.0/15).
    """
    discovered: dict[str, int] = {}

    def _record(ip_text: str, prefixlen: int | None = None) -> None:
        try:
            addr = ipaddress.IPv4Address(ip_text.strip())
        except ValueError:
            return
        if not _is_usable_lan_ip(addr):
            return
        s = str(addr)
        eff = 24 if prefixlen is None else prefixlen
        if s not in discovered or prefixlen is not None:
            discovered[s] = eff

    # 1. OS interface listing (most accurate, yields real netmask)
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["ipconfig"], text=True, errors="ignore", timeout=2.0
            )
            current_ip: str | None = None
            for line in out.splitlines():
                ip_m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
                if ip_m:
                    current_ip = ip_m.group(1)
                    _record(current_ip, 24)
                    continue
                mask_m = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
                if mask_m and current_ip:
                    try:
                        net = ipaddress.IPv4Network(
                            f"0.0.0.0/{mask_m.group(1)}", strict=False
                        )
                        _record(current_ip, net.prefixlen)
                    except ValueError:
                        pass
                    current_ip = None
        elif sys.platform == "darwin":
            out = subprocess.check_output(
                ["ifconfig"], text=True, errors="ignore", timeout=2.0
            )
            for line in out.splitlines():
                m = re.search(
                    r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]+)",
                    line,
                )
                if m:
                    mask_int = int(m.group(2), 16)
                    prefix = bin(mask_int).count("1")
                    _record(m.group(1), prefix)
        else:
            # Linux: prefer `ip -4 -o addr show`, fall back to `ifconfig`
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show"],
                    text=True,
                    errors="ignore",
                    timeout=2.0,
                )
                for m in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out):
                    _record(m.group(1), int(m.group(2)))
            except (OSError, subprocess.SubprocessError):
                out = subprocess.check_output(
                    ["ifconfig"], text=True, errors="ignore", timeout=2.0
                )
                for m in re.finditer(r"\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", out):
                    _record(m.group(1), 24)
    except (OSError, subprocess.SubprocessError):
        pass

    # 2. UDP route probes (no packets sent; checks OS routing table)
    for probe_host in ("192.168.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((probe_host, 80))
            _record(sock.getsockname()[0], 24)
        except OSError:
            pass
        finally:
            sock.close()

    # 3. Hostname lookup fallback
    try:
        for info in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM
        ):
            _record(str(info[4][0]), 24)
    except OSError:
        pass

    ordered_ips = sorted(
        discovered.keys(), key=lambda ip: _ip_priority(ipaddress.IPv4Address(ip))
    )
    candidates: list[dict[str, str]] = []
    seen_cidrs: set[str] = set()
    for ip_str in ordered_ips:
        cidr = _compute_scan_cidr(ip_str, discovered[ip_str])
        if cidr not in seen_cidrs:
            seen_cidrs.add(cidr)
            candidates.append({"ip": ip_str, "cidr": cidr})

    if not candidates:
        return {"local_ip": "", "lan_cidr": "", "candidates": []}

    return {
        "local_ip": candidates[0]["ip"],
        "lan_cidr": candidates[0]["cidr"],
        "candidates": candidates,
    }


def parse_targets(spec: str) -> list[str]:
    """
    Parse target hostnames, IP addresses, CIDR blocks, IPv4 ranges, or `lan` keyword.

    Examples:
    - ``127.0.0.1``
    - ``lan`` (auto-detected local /24 network)
    - ``scanme.nmap.org, localhost``
    - ``192.168.1.0/24``
    - ``192.168.1.1-25``
    - ``192.168.1.10-192.168.1.20``
    """
    raw = (spec or "").strip()
    if not raw:
        raise ValueError("Target specification cannot be empty.")

    tokens = [t.strip() for t in re.split(r"[\s,;]+", raw) if t.strip()]
    targets: list[str] = []
    seen: set[str] = set()

    def _add(item: str) -> None:
        if item not in seen:
            seen.add(item)
            targets.append(item)

    for token in tokens:
        if token.lower() in ("lan", "local", "subnet"):
            net_info = detect_local_networks()
            lan_cidr = net_info.get("lan_cidr", "")
            if not lan_cidr:
                raise ValueError(
                    "Could not detect an active local network. Enter a subnet explicitly (e.g. 192.168.1.0/24)."
                )
            token = lan_cidr

        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR target '{token}': {exc}") from exc
            if net.num_addresses > 65536:
                raise ValueError(
                    f"CIDR network '{token}' expands to {net.num_addresses} hosts (max 65536)."
                )
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            for addr in hosts:
                _add(str(addr))
            continue

        # Check IPv4 dash range (must start with an IPv4 address before the dash)
        if "-" in token:
            left = token.split("-", 1)[0]
            try:
                ipaddress.IPv4Address(left)
                is_ipv4_range = True
            except ValueError:
                is_ipv4_range = False

            if is_ipv4_range:
                for addr in _expand_ip_range(token):
                    _add(addr)
                continue

        # Strip optional brackets for IPv6 literals like [::1]
        cleaned = token.strip("[]")
        _add(cleaned)

    return targets
