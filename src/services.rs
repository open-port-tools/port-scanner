use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::Command;

const MAX_RANGE_HOSTS: usize = 4096;

/// Information about detected local IPv4 LAN interfaces and default `/24` target range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetInfo {
    pub local_ips: Vec<String>,
    pub primary_ip: String,
    pub cidr: String,
    pub host_count: usize,
    pub hosts: Vec<String>,
    pub all_cidrs: Vec<String>,
}

const PROFILE_QUICK: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017,
];

const PROFILE_WEB: &[u16] = &[
    80, 81, 3000, 3001, 4000, 4200, 5000, 5173, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9443, 10000,
];

const PROFILE_DATABASE: &[u16] = &[
    1433, 1521, 3306, 5432, 5433, 5984, 6379, 6380, 7474, 7687, 8529, 9042, 9200, 9300, 11211,
    27017, 28017,
];

const PROFILE_COMMON: &[u16] = &[
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 179,
    389, 443, 445, 465, 500, 514, 515, 548, 554, 587, 631, 636, 873, 902, 990, 993, 995, 1025,
    1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3001, 3128,
    3306, 3389, 3690, 4000, 4200, 4369, 4443, 5000, 5001, 5173, 5432, 5601, 5672, 5900, 5984, 5985,
    5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8883, 8888, 9000, 9042, 9090, 9092, 9100,
    9200, 9300, 9418, 9443, 10000, 11211, 15672, 27017, 50000,
];

/// Preset metadata for UI and validation.
#[derive(Debug, Clone, Copy)]
pub struct ProfileInfo {
    pub id: &'static str,
    pub label: &'static str,
}

pub const PROFILES: &[ProfileInfo] = &[
    ProfileInfo {
        id: "quick",
        label: "Быстрый (25)",
    },
    ProfileInfo {
        id: "common",
        label: "Стандартный (96)",
    },
    ProfileInfo {
        id: "web",
        label: "Веб (19)",
    },
    ProfileInfo {
        id: "database",
        label: "Базы данных (17)",
    },
    ProfileInfo {
        id: "full",
        label: "Все (1–65535)",
    },
];

/// Map a TCP port number to its standard well-known service name.
pub fn identify_service(port: u16) -> &'static str {
    match port {
        20 => "FTP-Data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        81 => "HTTP-Alt",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPCbind",
        119 => "NNTP",
        123 => "NTP",
        135 => "MSRPC",
        137 => "NetBIOS-NS",
        138 => "NetBIOS-DGM",
        139 => "NetBIOS-SSN",
        143 => "IMAP",
        161 => "SNMP",
        162 => "SNMP-Trap",
        179 => "BGP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        500 => "ISAKMP",
        512 => "exec",
        513 => "login",
        514 => "Syslog/Shell",
        515 => "LPD",
        548 => "AFP",
        554 => "RTSP",
        587 => "SMTP-Submission",
        631 => "IPP/CUPS",
        636 => "LDAPS",
        873 => "Rsync",
        902 => "VMware-ESXi",
        990 => "FTPS",
        993 => "IMAPS",
        995 => "POP3S",
        1025 => "NFS/IIS",
        1080 => "SOCKS",
        1194 => "OpenVPN",
        1433 => "MSSQL",
        1434 => "MSSQL-Monitor",
        1521 => "Oracle-DB",
        1723 => "PPTP",
        1883 => "MQTT",
        2049 => "NFS",
        2082 => "cPanel",
        2083 => "cPanel-SSL",
        2181 => "ZooKeeper",
        2375 => "Docker-TCP",
        2376 => "Docker-TLS",
        3000 => "Dev-HTTP",
        3001 => "Dev-HTTP-Alt",
        3128 => "Squid-Proxy",
        3306 => "MySQL",
        3389 => "RDP",
        3690 => "SVN",
        4000 => "Dev-Server",
        4200 => "Angular-CLI",
        4369 => "Erlang-EPMD",
        4443 => "HTTPS-Alt",
        5000 => "Flask/UPnP/Registry",
        5001 => "Synology/Dev",
        5173 => "Vite-Dev",
        5432 => "PostgreSQL",
        5433 => "PostgreSQL-Alt",
        5601 => "Kibana",
        5672 => "AMQP/RabbitMQ",
        5900 => "VNC",
        5984 => "CouchDB",
        5985 => "WinRM-HTTP",
        5986 => "WinRM-HTTPS",
        6379 => "Redis",
        6380 => "Redis-TLS",
        6443 => "Kubernetes-API",
        7001 => "WebLogic/Control",
        7474 => "Neo4j-HTTP",
        7687 => "Neo4j-Bolt",
        8000 => "HTTP-Dev",
        8008 => "HTTP-Alt",
        8080 => "HTTP-Proxy",
        8081 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        8529 => "ArangoDB",
        8883 => "MQTT-TLS",
        8888 => "Jupyter/HTTP-Alt",
        9000 => "PHP-FPM/SonarQube",
        9042 => "Cassandra",
        9090 => "Prometheus/Cockpit",
        9092 => "Kafka",
        9100 => "JetDirect",
        9200 => "Elasticsearch",
        9300 => "Elasticsearch-Node",
        9418 => "Git",
        9443 => "HTTPS-Alt",
        10000 => "Webmin",
        11211 => "Memcached",
        15672 => "RabbitMQ-Mgmt",
        27017 => "MongoDB",
        28017 => "MongoDB-HTTP",
        50000 => "SAP/Jenkins-Agent",
        _ => "unknown",
    }
}

/// Parse an explicit port specification (`"22,80,8000-8080"`, `"all"`) or resolve a named profile.
pub fn parse_ports(spec: Option<&str>, profile: &str) -> Result<Vec<u16>, String> {
    if let Some(raw) = spec {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if matches!(trimmed.to_ascii_lowercase().as_str(), "all" | "full") {
                return Ok((1..=65535).collect());
            }
            let mut ports = HashSet::new();
            for part in trimmed.split(',') {
                let token = part.trim();
                if token.is_empty() {
                    continue;
                }
                if let Some((start_s, end_s)) = token.split_once('-') {
                    let start: u32 = start_s
                        .trim()
                        .parse()
                        .map_err(|_| format!("Invalid port range token: {token}"))?;
                    let end: u32 = end_s
                        .trim()
                        .parse()
                        .map_err(|_| format!("Invalid port range token: {token}"))?;
                    if start < 1 || end > 65535 || start > end {
                        return Err(format!("Port range out of bounds (1-65535): {token}"));
                    }
                    for p in start..=end {
                        ports.insert(p as u16);
                    }
                } else {
                    let port: u32 = token
                        .parse()
                        .map_err(|_| format!("Invalid port number: {token}"))?;
                    if !(1..=65535).contains(&port) {
                        return Err(format!("Port out of bounds (1-65535): {token}"));
                    }
                    ports.insert(port as u16);
                }
            }
            if ports.is_empty() {
                return Err("No valid ports specified.".to_string());
            }
            let mut out: Vec<u16> = ports.into_iter().collect();
            out.sort_unstable();
            return Ok(out);
        }
    }

    match profile.trim().to_ascii_lowercase().as_str() {
        "quick" => Ok(PROFILE_QUICK.to_vec()),
        "common" => Ok(PROFILE_COMMON.to_vec()),
        "web" => Ok(PROFILE_WEB.to_vec()),
        "database" => Ok(PROFILE_DATABASE.to_vec()),
        "full" => Ok((1..=65535).collect()),
        other => Err(format!(
            "Unknown profile '{other}'. Expected quick, common, web, database, or full."
        )),
    }
}

/// Returns true if an IPv4 address should be excluded from auto-detected local LAN candidates.
pub fn is_ignored_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        // RFC 2544 / VPN TUN fake-IP pool (e.g. clash / Shadowrocket / WireGuard helpers)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
}

fn ipv4_priority(ip: Ipv4Addr) -> u8 {
    let o = ip.octets();
    if o[0] == 192 && o[1] == 168 {
        0
    } else if o[0] == 10 {
        1
    } else if o[0] == 172 && (16..=31).contains(&o[1]) {
        2
    } else if ip.is_private() {
        3
    } else {
        4
    }
}

fn netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn parse_hex_netmask(token: &str) -> Option<Ipv4Addr> {
    let hex = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X"))?;
    let val = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(val))
}

fn cidr_to_range(net_ip: Ipv4Addr, prefix: u8) -> Result<(u32, u32), String> {
    if prefix > 32 {
        return Err(format!("Invalid CIDR prefix '/{prefix}'"));
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let network = u32::from(net_ip) & mask;
    let broadcast = network | !mask;
    Ok((network, broadcast))
}

fn expand_cidr_hosts(ip: Ipv4Addr, prefix: u8, usable_only: bool) -> Result<Vec<String>, String> {
    let (network, broadcast) = cidr_to_range(ip, prefix)?;
    let total = (broadcast - network) as usize + 1;
    let (start, end) = if usable_only && prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };
    let count = (end.saturating_sub(start)) as usize + 1;
    if count > MAX_RANGE_HOSTS || total > MAX_RANGE_HOSTS * 2 {
        return Err(format!(
            "CIDR range /{prefix} is too large ({count} hosts, max {MAX_RANGE_HOSTS})"
        ));
    }
    Ok((start..=end)
        .map(|addr| Ipv4Addr::from(addr).to_string())
        .collect())
}

fn effective_lan_subnet(ip: Ipv4Addr, prefix_hint: Option<u8>) -> (String, Vec<String>) {
    // Cap large/unknown subnets (like /16) to the host's /24 block for fast interactive LAN discovery.
    let prefix = match prefix_hint {
        Some(p) if (24..=30).contains(&p) => p,
        _ => 24,
    };
    let (network, _) = cidr_to_range(ip, prefix).unwrap_or((u32::from(ip), u32::from(ip)));
    let cidr = format!("{}/{prefix}", Ipv4Addr::from(network));
    let hosts = expand_cidr_hosts(ip, prefix, true).unwrap_or_else(|_| vec![ip.to_string()]);
    (cidr, hosts)
}

fn push_candidate(
    candidates: &mut Vec<(Ipv4Addr, Option<u8>)>,
    seen: &mut HashSet<Ipv4Addr>,
    ip: Ipv4Addr,
    prefix: Option<u8>,
) {
    if is_ignored_ipv4(ip) {
        return;
    }
    if seen.insert(ip) {
        candidates.push((ip, prefix));
    } else if prefix.is_some() {
        for item in candidates.iter_mut() {
            if item.0 == ip && item.1.is_none() {
                item.1 = prefix;
            }
        }
    }
}

fn probe_udp_candidates(candidates: &mut Vec<(Ipv4Addr, Option<u8>)>, seen: &mut HashSet<Ipv4Addr>) {
    let targets = [
        "192.168.0.1:80",
        "192.168.1.1:80",
        "10.0.0.1:80",
        "172.16.0.1:80",
        "8.8.8.8:80",
    ];
    for remote in targets {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(remote).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    if let IpAddr::V4(ip) = addr.ip() {
                        push_candidate(candidates, seen, ip, None);
                    }
                }
            }
        }
    }
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn parse_ifconfig_output(
    text: &str,
    candidates: &mut Vec<(Ipv4Addr, Option<u8>)>,
    seen: &mut HashSet<Ipv4Addr>,
) {
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("inet ") || trimmed.contains("inet6") {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(inet_idx) = parts.iter().position(|&p| p == "inet") else {
            continue;
        };
        let Some(ip_token) = parts.get(inet_idx + 1) else {
            continue;
        };
        let (ip_str, cidr_prefix) = match ip_token.split_once('/') {
            Some((a, b)) => (a, b.parse::<u8>().ok()),
            None => (*ip_token, None),
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        let mut prefix = cidr_prefix;
        if prefix.is_none() {
            if let Some(nm_idx) = parts.iter().position(|&p| p == "netmask") {
                if let Some(mask_tok) = parts.get(nm_idx + 1) {
                    let mask = parse_hex_netmask(mask_tok)
                        .or_else(|| mask_tok.parse::<Ipv4Addr>().ok());
                    prefix = mask.map(netmask_to_prefix);
                }
            }
        }
        push_candidate(candidates, seen, ip, prefix);
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_ip_addr_output(
    text: &str,
    candidates: &mut Vec<(Ipv4Addr, Option<u8>)>,
    seen: &mut HashSet<Ipv4Addr>,
) {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|&p| p == "inet") {
            if let Some(cidr_tok) = parts.get(idx + 1) {
                if let Some((ip_s, pfx_s)) = cidr_tok.split_once('/') {
                    if let (Ok(ip), Ok(pfx)) = (ip_s.parse::<Ipv4Addr>(), pfx_s.parse::<u8>()) {
                        push_candidate(candidates, seen, ip, Some(pfx));
                    }
                }
            }
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_ipconfig_output(
    text: &str,
    candidates: &mut Vec<(Ipv4Addr, Option<u8>)>,
    seen: &mut HashSet<Ipv4Addr>,
) {
    let mut last_ip: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some((_, rhs)) = line.split_once(':') {
            let candidate = rhs.split('(').next().unwrap_or("").trim();
            if let Ok(addr) = candidate.parse::<Ipv4Addr>() {
                if lower.contains("subnet mask") || lower.contains("маска подсети") {
                    if let Some(ip) = last_ip.take() {
                        push_candidate(candidates, seen, ip, Some(netmask_to_prefix(addr)));
                    }
                } else if lower.contains("ipv4") || lower.contains("ip-адрес") || lower.contains("ip address") {
                    last_ip = Some(addr);
                    push_candidate(candidates, seen, addr, None);
                }
            }
        }
    }
}

fn collect_interface_candidates() -> Vec<(Ipv4Addr, Option<u8>)> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("ipconfig").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_ipconfig_output(&text, &mut candidates, &mut seen);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("ip").args(["-4", "-o", "addr", "show"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_ip_addr_output(&text, &mut candidates, &mut seen);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        for cmd in ["/sbin/ifconfig", "ifconfig"] {
            if let Ok(out) = Command::new(cmd).output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    parse_ifconfig_output(&text, &mut candidates, &mut seen);
                    break;
                }
            }
        }
    }

    probe_udp_candidates(&mut candidates, &mut seen);
    candidates
}

/// Detect active local IPv4 network(s), filtering out loopback, link-local, and `198.18.0.0/15` VPN pools.
pub fn detect_local_networks() -> LocalNetInfo {
    let mut candidates = collect_interface_candidates();
    candidates.sort_by_key(|(ip, _)| (ipv4_priority(*ip), u32::from(*ip)));

    if candidates.is_empty() {
        return LocalNetInfo {
            local_ips: Vec::new(),
            primary_ip: String::new(),
            cidr: String::new(),
            host_count: 0,
            hosts: Vec::new(),
            all_cidrs: Vec::new(),
        };
    }

    let mut local_ips = Vec::with_capacity(candidates.len());
    let mut all_cidrs = Vec::new();
    let mut cidr_seen = HashSet::new();
    let mut primary_cidr = String::new();
    let mut primary_hosts = Vec::new();

    for (idx, (ip, pfx)) in candidates.iter().enumerate() {
        local_ips.push(ip.to_string());
        let (cidr, hosts) = effective_lan_subnet(*ip, *pfx);
        if idx == 0 {
            primary_cidr = cidr.clone();
            primary_hosts = hosts;
        }
        if cidr_seen.insert(cidr.clone()) {
            all_cidrs.push(cidr);
        }
    }

    LocalNetInfo {
        primary_ip: local_ips[0].clone(),
        local_ips,
        cidr: primary_cidr,
        host_count: primary_hosts.len(),
        hosts: primary_hosts,
        all_cidrs,
    }
}

fn parse_ipv4_dash_range(token: &str) -> Result<Option<Vec<String>>, String> {
    let Some((left, right)) = token.split_once('-') else {
        return Ok(None);
    };
    let Ok(start_ip) = left.trim().parse::<Ipv4Addr>() else {
        return Ok(None);
    };
    let right_trim = right.trim();
    let end_ip = if let Ok(full_end) = right_trim.parse::<Ipv4Addr>() {
        full_end
    } else if let Ok(last_octet) = right_trim.parse::<u8>() {
        let mut o = start_ip.octets();
        o[3] = last_octet;
        Ipv4Addr::from(o)
    } else {
        return Err(format!("Invalid IPv4 range endpoint: {token}"));
    };

    let start_u32 = u32::from(start_ip);
    let end_u32 = u32::from(end_ip);
    if start_u32 > end_u32 {
        return Err(format!("Start IP is greater than end IP in '{token}'"));
    }
    let count = (end_u32 - start_u32) as usize + 1;
    if count > MAX_RANGE_HOSTS {
        return Err(format!(
            "IP range '{token}' expands to {count} hosts (max {MAX_RANGE_HOSTS})"
        ));
    }
    Ok(Some(
        (start_u32..=end_u32)
            .map(|a| Ipv4Addr::from(a).to_string())
            .collect(),
    ))
}

/// Expand hostnames, IPv4 addresses, CIDR blocks (`192.168.0.0/24`), dash ranges (`192.168.0.1-50`),
/// or `"lan"` into a deduplicated list of target host strings.
pub fn parse_targets(spec: &str) -> Result<Vec<String>, String> {
    let mut result = VecDeque::new();
    let mut seen = HashSet::new();
    let mut push_unique = |host: String| {
        if seen.insert(host.clone()) {
            result.push_back(host);
        }
    };

    for raw in spec.split([',', ' ', '\t', '\n', '\r']) {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if matches!(lower.as_str(), "lan" | "local" | "network" | "auto") {
            let info = detect_local_networks();
            if info.hosts.is_empty() {
                return Err(
                    "Could not detect an active local IPv4 LAN subnet. Enter a target or CIDR explicitly."
                        .to_string(),
                );
            }
            for host in info.hosts {
                push_unique(host);
            }
            continue;
        }

        if let Some((ip_part, pfx_part)) = token.split_once('/') {
            let ip: Ipv4Addr = ip_part
                .trim()
                .parse()
                .map_err(|_| format!("Invalid IPv4 CIDR target: {token}"))?;
            let prefix: u8 = pfx_part
                .trim()
                .parse()
                .map_err(|_| format!("Invalid CIDR prefix: {token}"))?;
            for host in expand_cidr_hosts(ip, prefix, true)? {
                push_unique(host);
            }
            continue;
        }

        if let Some(range_hosts) = parse_ipv4_dash_range(token)? {
            for host in range_hosts {
                push_unique(host);
            }
            continue;
        }

        push_unique(token.to_string());
    }

    if result.is_empty() {
        return Err("No valid targets specified.".to_string());
    }
    Ok(result.into_iter().collect())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn profile_counts_match_labels() {
        assert_eq!(PROFILE_QUICK.len(), 25);
        assert_eq!(PROFILE_COMMON.len(), 96);
        assert_eq!(PROFILE_WEB.len(), 19);
        assert_eq!(PROFILE_DATABASE.len(), 17);
    }

    #[test]
    fn ignores_vpn_fake_ip_and_loopback() {
        assert!(is_ignored_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_ignored_ipv4(Ipv4Addr::new(169, 254, 10, 5)));
        assert!(is_ignored_ipv4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_ignored_ipv4(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_ignored_ipv4(Ipv4Addr::new(192, 168, 0, 172)));
        assert!(!is_ignored_ipv4(Ipv4Addr::new(10, 0, 0, 15)));
    }

    #[test]
    fn parses_ifconfig_and_ipconfig_filters_fake_ip() {
        let ifcfg = "utun4: flags=8051\n\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xffff0000\nen0: flags=8863\n\tinet 192.168.0.172 netmask 0xffffff00 broadcast 192.168.0.255";
        let mut cands = Vec::new();
        let mut seen = HashSet::new();
        parse_ifconfig_output(ifcfg, &mut cands, &mut seen);
        assert_eq!(cands, vec![(Ipv4Addr::new(192, 168, 0, 172), Some(24))]);

        let ipcfg = "Wireless LAN adapter Wi-Fi:\n   IPv4 Address. . . . . . . . . . . : 10.1.2.44(Preferred)\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0";
        let mut wcands = Vec::new();
        let mut wseen = HashSet::new();
        parse_ipconfig_output(ipcfg, &mut wcands, &mut wseen);
        assert_eq!(wcands, vec![(Ipv4Addr::new(10, 1, 2, 44), Some(24))]);

        let ip_addr = "2: eth0    inet 192.168.50.10/24 brd 192.168.50.255 scope global eth0";
        let mut lcands = Vec::new();
        let mut lseen = HashSet::new();
        parse_ip_addr_output(ip_addr, &mut lcands, &mut lseen);
        assert_eq!(lcands, vec![(Ipv4Addr::new(192, 168, 50, 10), Some(24))]);
    }
}
