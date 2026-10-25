use crate::{Result, output::Template};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

pub const DEFAULT_FORMAT: &str = "$remote_addr:$remote_port - [$time_iso8601] $protocol in_bytes=$bytes_received out_bytes=$bytes_sent session_time=$session_time server=$server_addr:$server_port";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Address(pub [u8; 16]);
impl Address {
    pub fn v4(a: [u8; 4]) -> Self {
        Self(Ipv4Addr::from(a).to_ipv6_mapped().octets())
    }
    pub fn v6(a: [u8; 16]) -> Self {
        Self(a)
    }
    pub fn ip(self) -> IpAddr {
        let a = Ipv6Addr::from(self.0);
        a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a))
    }
    pub fn is_v4(self) -> bool {
        matches!(self.ip(), IpAddr::V4(_))
    }
    pub fn is_unspecified(self) -> bool {
        self.ip().is_unspecified()
    }
    pub fn loopback(self) -> bool {
        self.ip().is_loopback()
    }
}
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ip().fmt(f)
    }
}
impl std::str::FromStr for Address {
    type Err = std::net::AddrParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.parse::<IpAddr>()? {
            IpAddr::V4(a) => Self::v4(a.octets()),
            IpAddr::V6(a) => Self::v6(a.octets()),
        })
    }
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub proto: u8,
    pub addr: Address,
    pub ports: Vec<(u16, u16)>,
}
#[derive(Debug)]
pub struct Rules {
    pub groups: Vec<Rule>,
    pub local: HashSet<Address>,
}
impl Rules {
    pub fn matches(&self, ip: Address, port: u16, proto: u8) -> bool {
        self.groups.iter().any(|r| {
            r.proto == proto
                && (r.addr == ip
                    || (r.addr.is_unspecified()
                        && r.addr.is_v4() == ip.is_v4()
                        && (ip.loopback() || self.local.contains(&ip))))
                && r.ports.iter().any(|&(a, b)| a <= port && port <= b)
        })
    }
    pub fn parse(env: &BTreeMap<String, String>, local: HashSet<Address>) -> Result<Self> {
        let mut groups: BTreeMap<(u8, Address), Vec<(u16, u16)>> = BTreeMap::new();
        for (key, val) in env.iter().filter(|(k, _)| k.starts_with("LISTEN_")) {
            if key.len() == 7 || !key[7..].bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("invalid rule name: {key}").into());
            }
            let parts: Vec<_> = val.split_whitespace().collect();
            if parts.len() < 3 {
                return Err(format!("{key}: expected tcp|udp IP port[,port-range]").into());
            }
            let proto = match parts[0].to_ascii_lowercase().as_str() {
                "tcp" => 6,
                "udp" => 17,
                _ => return Err(format!("{key}: invalid protocol").into()),
            };
            let ip = parts[1];
            if ip.contains('%') {
                return Err(format!("{key}: scoped address unsupported").into());
            }
            let addr: Address = if ip.starts_with('[') && ip.ends_with(']') {
                let a = ip[1..ip.len() - 1].parse::<Ipv6Addr>()?;
                Address::v6(a.octets())
            } else {
                ip.parse()?
            };
            // Keep spaces around numbers/hyphens, but never concatenate digits.
            let portspec = parts[2..].join(" ");
            for item in portspec.split(',') {
                let nums: Vec<_> = item.split('-').map(str::trim).collect();
                if nums.is_empty()
                    || nums.len() > 2
                    || nums
                        .iter()
                        .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
                {
                    return Err(format!("{key}: invalid port/range {item:?}").into());
                }
                let start: u16 = nums[0].parse()?;
                let end = if nums.len() == 2 {
                    nums[1].parse()?
                } else {
                    start
                };
                if start == 0 || end < start {
                    return Err(format!("{key}: invalid range").into());
                }
                groups.entry((proto, addr)).or_default().push((start, end));
            }
        }
        if groups.is_empty() {
            return Err("at least one LISTEN_<number> required".into());
        }
        let groups = groups
            .into_iter()
            .map(|((proto, addr), mut ports)| {
                ports.sort_unstable();
                let mut merged: Vec<(u16, u16)> = Vec::new();
                for (a, b) in ports {
                    if let Some(last) = merged.last_mut() {
                        if u32::from(a) <= u32::from(last.1) + 1 {
                            last.1 = last.1.max(b);
                            continue;
                        }
                    }
                    merged.push((a, b));
                }
                Rule {
                    proto,
                    addr,
                    ports: merged,
                }
            })
            .collect();
        Ok(Self { groups, local })
    }
}
#[derive(Debug)]
pub struct Config {
    pub rules: Rules,
    pub template: Template,
    pub log_file: String,
    pub log_rotate_suffix: String,
    pub interface: String,
    pub tz: String,
    pub ignore_checksums: bool,
    pub udp_timeout: u64,
    pub shutdown_timeout: u32,
    pub pcap_buffer_mb: i32,
    pub max_sessions: usize,
    pub max_fragments: usize,
    pub fragment_bytes: usize,
    pub stats_interval: u64,
}
fn number(env: &BTreeMap<String, String>, key: &str, default: u64, max: u64) -> Result<u64> {
    match env.get(key) {
        None => Ok(default),
        Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            let v: u64 = s.parse()?;
            if v >= 1 && v <= max {
                Ok(v)
            } else {
                Err(format!("{key}: expected 1..{max}").into())
            }
        }
        _ => Err(format!("{key}: expected integer 1..{max}").into()),
    }
}
impl Config {
    pub fn parse(env: &BTreeMap<String, String>, local: HashSet<Address>) -> Result<Self> {
        let get = |k: &str, d: &str| env.get(k).cloned().unwrap_or_else(|| d.into());
        let interface = get("CAPTURE_INTERFACE", "eth0");
        if interface.is_empty()
            || interface.starts_with('-')
            || !interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:@-".contains(&b))
        {
            return Err("CAPTURE_INTERFACE: invalid interface".into());
        }
        let tz = get("TZ", "UTC");
        if tz.is_empty()
            || tz.starts_with('/')
            || tz.split('/').any(|s| s == ".." || s == ".")
            || !Path::new("/usr/share/zoneinfo").join(&tz).is_file()
        {
            return Err("TZ: unknown IANA timezone".into());
        }
        let log_file = get("LOG_FILE", "/dev/stdout");
        if log_file.is_empty() || log_file.contains(['\0', '\r', '\n']) {
            return Err("LOG_FILE: invalid path".into());
        }
        let log_rotate_suffix = get("LOG_ROTATE_SUFFIX", crate::rotation::DEFAULT_SUFFIX);
        crate::rotation::validate_suffix(&log_rotate_suffix)?;
        let ignore_checksums = match get("IGNORE_CHECKSUMS", "true")
            .to_ascii_lowercase()
            .as_str()
        {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => return Err("IGNORE_CHECKSUMS: expected true/false/1/0".into()),
        };
        if env.get("PCAP_BUFFER_MB").is_some_and(|s| s.len() > 4) {
            return Err("PCAP_BUFFER_MB: at most four digits".into());
        }
        Ok(Self {
            rules: Rules::parse(env, local)?,
            template: Template::parse(&get("LOG_FORMAT", DEFAULT_FORMAT))?,
            log_file,
            log_rotate_suffix,
            interface,
            tz,
            ignore_checksums,
            udp_timeout: number(env, "UDP_INACTIVITY_TIMEOUT", 60, 86400)? * 1_000_000,
            shutdown_timeout: number(env, "SHUTDOWN_TIMEOUT", 15, 86400)? as u32,
            pcap_buffer_mb: number(env, "PCAP_BUFFER_MB", 8, 1024)? as i32,
            max_sessions: number(env, "MAX_SESSIONS", 100_000, 10_000_000)? as usize,
            max_fragments: number(env, "MAX_FRAGMENTS", 128, 65536)? as usize,
            fragment_bytes: number(env, "FRAGMENT_CACHE_MB", 8, 1024)? as usize * 1024 * 1024,
            stats_interval: number(env, "STATS_INTERVAL", 60, 86400)? * 1_000_000,
        })
    }
    pub fn from_env() -> Result<Self> {
        let env = std::env::vars().collect();
        let mut c = Self::parse(&env, HashSet::new())?;
        if c.rules.groups.iter().any(|r| r.addr.is_unspecified()) {
            c.rules.local = local_addresses()?;
        }
        Ok(c)
    }
}
pub fn local_addresses() -> Result<HashSet<Address>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs owns an initialized linked list until freeifaddrs.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut p = head;
        let mut result = HashSet::new();
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                let addr = match (*a).sa_family as i32 {
                    libc::AF_INET => Some(Address::v4(
                        (*(a as *const libc::sockaddr_in))
                            .sin_addr
                            .s_addr
                            .to_ne_bytes(),
                    )),
                    libc::AF_INET6 => Some(Address::v6(
                        (*(a as *const libc::sockaddr_in6)).sin6_addr.s6_addr,
                    )),
                    _ => None,
                };
                if let Some(a) = addr {
                    if !a.is_unspecified() {
                        result.insert(a);
                    }
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(head);
        if result.is_empty() {
            Err("local address discovery returned no addresses; refusing wildcard".into())
        } else {
            Ok(result)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn env(s: &[(&str, &str)]) -> BTreeMap<String, String> {
        s.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    #[test]
    fn rules_merge_direction() {
        let r = Rules::parse(
            &env(&[
                ("LISTEN_9", "tcp 0.0.0.0 80-81,82,80"),
                ("LISTEN_2", "tcp 127.0.0.1 90"),
            ]),
            HashSet::new(),
        )
        .unwrap();
        assert!(r.matches("127.2.3.4".parse().unwrap(), 82, 6));
        assert!(r.matches("127.0.0.1".parse().unwrap(), 80, 6));
        assert!(!r.matches("1.2.3.4".parse().unwrap(), 80, 6));
        assert!(!r.matches("127.0.0.1".parse().unwrap(), 80, 17));
        assert_eq!(r.groups[0].ports, vec![(80, 82)]);
    }
    #[test]
    fn ipv6_mapped() {
        assert_eq!(
            "::ffff:1.2.3.4".parse::<Address>().unwrap(),
            "1.2.3.4".parse().unwrap()
        );
        let r = Rules::parse(&env(&[("LISTEN_1", "udp [::] 1234")]), HashSet::new()).unwrap();
        assert!(r.matches("::1".parse().unwrap(), 1234, 17));
        assert!(!r.matches("127.0.0.1".parse().unwrap(), 1234, 17));
    }
    #[test]
    fn invalid_config() {
        for (k, v) in [
            ("LISTEN_x", "tcp 1.2.3.4 80"),
            ("LISTEN_1", "tcp 1.2.3.4 0"),
            ("LISTEN_1", "tcp 1.2.3.4 8 0"),
            ("LISTEN_1", "tcp 1.2.3.4 90-80"),
            ("LISTEN_1", "icmp 1.2.3.4 80"),
        ] {
            assert!(Rules::parse(&env(&[(k, v)]), HashSet::new()).is_err());
        }
    }
    #[test]
    fn defaults_and_limits() {
        let e = env(&[("LISTEN_1", "udp 1.2.3.4 80")]);
        let c = Config::parse(&e, HashSet::new()).unwrap();
        assert_eq!(c.log_file, "/dev/stdout");
        assert_eq!(c.log_rotate_suffix, ".%Y%m%d");
        let mut custom = e.clone();
        custom.insert("LOG_FILE".into(), "/logs/access.log".into());
        custom.insert("LOG_ROTATE_SUFFIX".into(), ".%Y-%m-%d.bak".into());
        let custom = Config::parse(&custom, HashSet::new()).unwrap();
        assert_eq!(custom.log_file, "/logs/access.log");
        assert_eq!(custom.log_rotate_suffix, ".%Y-%m-%d.bak");
        assert_eq!(c.pcap_buffer_mb, 8);
        assert_eq!(c.udp_timeout, 60_000_000);
        assert!(c.ignore_checksums);
        for (k, v) in [
            ("PCAP_BUFFER_MB", "0"),
            ("PCAP_BUFFER_MB", "1025"),
            ("SHUTDOWN_TIMEOUT", "0"),
            ("IGNORE_CHECKSUMS", "yes"),
            ("TZ", "../../etc/passwd"),
            ("LOG_FORMAT", "$bad"),
            ("LOG_ROTATE_SUFFIX", ""),
            ("LOG_ROTATE_SUFFIX", "/%Y%m%d"),
            ("LOG_ROTATE_SUFFIX", "%Q"),
            ("LOG_ROTATE_SUFFIX", "%"),
            ("LOG_ROTATE_SUFFIX", "%n"),
            ("LOG_ROTATE_SUFFIX", ".bad\n"),
        ] {
            let mut e = e.clone();
            e.insert(k.into(), v.into());
            assert!(Config::parse(&e, HashSet::new()).is_err(), "{k}");
        }
    }
}
#[cfg(test)]mod discovery_tests {
    #[test]fn real_namespace_discovery_is_not_all_hosts(){let addresses=super::local_addresses().unwrap();assert!(addresses.contains(&"127.0.0.1".parse().unwrap()));assert!(!addresses.iter().any(|a|a.is_unspecified()));}
}
