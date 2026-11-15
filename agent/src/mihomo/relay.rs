//! Proxy servers past the TUN: the addresses of the active config's proxy
//! servers, for LAN clients that run their own proxy client (Surge, Clash,
//! honk, …) against the same servers.
//!
//! Through the TUN such a connection is accepted by mihomo's stack and dialled
//! again from the router: it costs mihomo CPU, never gets IPA offload, and the
//! client cannot see the server's IPv4 address failing, so its own
//! IPv4-to-IPv6 fallback never runs. Sent past the TUN (see
//! `service::relay_add`), the flow is plain forwarded traffic again.
//!
//! Two modes (`settings.node_bypass`):
//! - on (default): every global unicast address of every proxy server, like
//!   ShellCrash's "node bypass". A node that moves to a new address is
//!   followed at the next lookup, with nothing to edit in the rules.
//! - off: only addresses the active config already sends DIRECT by an IP
//!   rule: the first `IP-CIDR`/`IP-CIDR6` rule that matches, inline or inside
//!   a rule set, must target `DIRECT`. An address shared with other sites (a
//!   node behind a CDN) is not listed like that, so it stays in the TUN, where
//!   those sites are still routed by their names. Rules the agent cannot
//!   evaluate for an address (`GEOIP`, `IP-ASN`, binary `mrs` rule sets) and
//!   rules on names or processes are skipped.
//!
//! Names are resolved through mihomo (`/dns/query`), the resolver LAN clients
//! get their answers from. A query that fails keeps that name's addresses from
//! the previous lookup, so one DNS hiccup does not drop a node.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use super::controller::{segment, Controller};

/// Caps that keep one check bounded however large the config is.
const MAX_HOSTS: usize = 64;
const MAX_ADDRESSES: usize = 256;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const QTYPES: [&str; 2] = ["A", "AAAA"];

/// Last good answer per (server name, query type).
pub type Cache = HashMap<(String, &'static str), Vec<IpAddr>>;

/// The addresses to send past the TUN, the answers to remember for the next
/// lookup, and whether every query was answered (a failed one fell back to
/// the cache).
pub struct Found {
    pub addresses: Vec<IpAddr>,
    pub cache: Cache,
    pub complete: bool,
}

/// One query's outcome: `Some(addresses)` for an answer (NOERROR, maybe
/// empty), `None` when it failed (controller error, SERVFAIL, NXDOMAIN, …).
type Lookup<'a> = dyn FnMut(&str, &str) -> Option<Vec<IpAddr>> + 'a;

/// Look up the active config's proxy servers; with `all` keep every global
/// unicast address, otherwise only those its rules send DIRECT by address.
pub fn find(config: &Value, dir: &Path, all: bool, previous: &Cache) -> Found {
    let ctl = Controller;
    let mut query = |host: &str, qtype: &str| {
        let path = format!("/dns/query?name={}&type={qtype}", segment(host));
        let reply = ctl.request("GET", &path, None, QUERY_TIMEOUT).ok()?;
        let v = reply.ok().then(|| reply.json().ok()).flatten()?;
        (v["Status"].as_u64() == Some(0)).then(|| answers(&v))
    };
    let (candidates, cache, complete) = gather(&servers(config, dir), previous, &mut query);
    let candidates = candidates.into_iter().filter(bypassable);
    let picked: BTreeSet<IpAddr> = if all {
        candidates.collect()
    } else {
        direct_by_address(config, dir, candidates)
    };
    Found {
        addresses: picked.into_iter().take(MAX_ADDRESSES).collect(),
        cache,
        complete,
    }
}

/// Resolve `hosts` (literal addresses pass through) with `lookup`. A failed
/// query uses that name's entry in `previous`; the returned cache holds only
/// the names asked about now.
fn gather(
    hosts: &BTreeSet<String>,
    previous: &Cache,
    lookup: &mut Lookup<'_>,
) -> (BTreeSet<IpAddr>, Cache, bool) {
    let mut addresses = BTreeSet::new();
    let mut cache = Cache::new();
    let mut complete = true;
    for host in hosts.iter().take(MAX_HOSTS) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            addresses.insert(ip);
            continue;
        }
        for qtype in QTYPES {
            let key = (host.clone(), qtype);
            let got = match lookup(host, qtype) {
                Some(ips) => ips,
                None => {
                    complete = false;
                    match previous.get(&key) {
                        Some(ips) => ips.clone(),
                        None => continue,
                    }
                }
            };
            addresses.extend(got.iter().copied());
            cache.insert(key, got);
        }
    }
    (addresses, cache, complete)
}

/// `server` of every proxy in the config and in its proxy providers' files.
pub fn servers(config: &Value, dir: &Path) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let mut take = |proxies: &Value| {
        for p in proxies.as_array().into_iter().flatten() {
            if let Some(s) = p["server"].as_str() {
                let s = s.trim().trim_start_matches('[').trim_end_matches(']');
                if !s.is_empty() {
                    hosts.insert(s.to_ascii_lowercase());
                }
            }
        }
    };
    take(&config["proxies"]);
    for provider in config["proxy-providers"].as_object().into_iter().flatten() {
        let Some(path) = provider.1["path"].as_str() else {
            continue;
        };
        if let Some(v) = fs::read(dir.join(path))
            .ok()
            .and_then(|b| super::profile::parse_yaml(&b).ok())
        {
            take(&v["proxies"]);
        }
    }
    hosts
}

/// Addresses in a `/dns/query` reply (A and AAAA records only).
fn answers(reply: &Value) -> Vec<IpAddr> {
    reply["Answer"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| matches!(a["type"].as_u64(), Some(1) | Some(28)))
        .filter_map(|a| a["data"].as_str()?.parse().ok())
        .collect()
}

/// Global unicast only: private, shared, loopback, link-local, multicast and
/// the TUN's own 198.18.0.0/15 never leave through the WAN anyway.
pub fn bypassable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

/// An address prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    len: u8,
}

impl Net {
    /// `1.2.3.0/24`, `2001:db8::/32`, or a bare address (a host prefix).
    pub fn parse(text: &str) -> Option<Net> {
        let text = text.trim().trim_matches(|c| c == '\'' || c == '"');
        let (addr, len) = match text.split_once('/') {
            Some((a, l)) => (a.parse::<IpAddr>().ok()?, Some(l.parse::<u8>().ok()?)),
            None => (text.parse::<IpAddr>().ok()?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = len.unwrap_or(max);
        (len <= max).then_some(Net { addr, len })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(*ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(*ip) & mask
            }
            _ => false,
        }
    }
}

/// The `candidates` whose first matching IP rule targets DIRECT. Rules are
/// read in order and a rule set's file only while some candidate is still
/// undecided, so large lists after the deciding rule are never parsed.
pub fn direct_by_address(
    config: &Value,
    dir: &Path,
    candidates: impl IntoIterator<Item = IpAddr>,
) -> BTreeSet<IpAddr> {
    let mut undecided: Vec<IpAddr> = candidates.into_iter().collect();
    let mut direct = BTreeSet::new();
    for rule in config["rules"].as_array().into_iter().flatten() {
        if undecided.is_empty() {
            break;
        }
        let Some(rule) = rule.as_str() else { continue };
        let parts: Vec<&str> = rule.split(',').map(str::trim).collect();
        let (Some(kind), Some(payload), Some(target)) = (parts.first(), parts.get(1), parts.get(2))
        else {
            continue;
        };
        let nets = match kind.to_ascii_uppercase().as_str() {
            "IP-CIDR" | "IP-CIDR6" => Net::parse(payload).into_iter().collect(),
            "RULE-SET" => provider_nets(config, dir, payload),
            _ => continue,
        };
        undecided.retain(|ip| {
            if !nets.iter().any(|n| n.contains(ip)) {
                return true;
            }
            if *target == "DIRECT" {
                direct.insert(*ip);
            }
            false
        });
    }
    direct
}

/// The IP prefixes in rule set `name`: `IP-CIDR`/`IP-CIDR6` lines of a
/// classical set, every line of an ipcidr set; none for a domain set or a
/// file that cannot be read.
fn provider_nets(config: &Value, dir: &Path, name: &str) -> Vec<Net> {
    let def = &config["rule-providers"][name];
    let behavior = def["behavior"].as_str().unwrap_or("");
    if behavior == "domain" {
        return Vec::new();
    }
    let lines: Vec<String> = if let Some(inline) = def["payload"].as_array() {
        inline
            .iter()
            .filter_map(|l| l.as_str().map(str::to_string))
            .collect()
    } else {
        let Some(path) = def["path"].as_str() else {
            return Vec::new();
        };
        let Ok(bytes) = fs::read(dir.join(path)) else {
            return Vec::new();
        };
        match def["format"].as_str().unwrap_or("yaml") {
            "text" => String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_string)
                .collect(),
            "yaml" => super::profile::parse_yaml(&bytes)
                .ok()
                .and_then(|v| v["payload"].as_array().cloned())
                .into_iter()
                .flatten()
                .filter_map(|l| l.as_str().map(str::to_string))
                .collect(),
            _ => return Vec::new(),
        }
    };
    lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .filter_map(|l| {
            if behavior == "ipcidr" {
                return Net::parse(l);
            }
            let mut fields = l.split(',').map(str::trim);
            match fields.next()?.to_ascii_uppercase().as_str() {
                "IP-CIDR" | "IP-CIDR6" => Net::parse(fields.next()?),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn prefixes_parse_and_match_by_family() {
        let n = Net::parse("203.0.113.0/24").unwrap();
        assert!(n.contains(&ip("203.0.113.10")));
        assert!(!n.contains(&ip("198.51.100.1")));
        assert!(!n.contains(&ip("::1")));
        let host = Net::parse("'2001:db8:2::11'").unwrap();
        assert!(host.contains(&ip("2001:db8:2::11")));
        assert!(!host.contains(&ip("2001:db8:2::1")));
        assert!(Net::parse("0.0.0.0/0").unwrap().contains(&ip("8.8.8.8")));
        assert!(Net::parse("::/0").unwrap().contains(&ip("2001:db8::1")));
        assert!(Net::parse("1.2.3.4/33").is_none());
        assert!(Net::parse("example.com").is_none());
    }

    #[test]
    fn only_global_unicast_is_bypassable() {
        for a in ["203.0.113.10", "2001:db8:1::dc"] {
            assert!(bypassable(&ip(a)), "{a}");
        }
        for a in [
            "10.0.0.1",
            "192.168.0.1",
            "172.16.5.5",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.6.116",
            "198.19.0.1",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "fd00::1",
            "fe80::1",
            "::1",
            "::ffff:1.2.3.4",
            "ff02::1",
        ] {
            assert!(!bypassable(&ip(a)), "{a}");
        }
    }

    #[test]
    fn first_matching_ip_rule_decides() {
        let dir = std::env::temp_dir().join(format!("relay-test-{}", std::process::id()));
        fs::create_dir_all(dir.join("rules")).unwrap();
        fs::write(
            dir.join("rules/proxy.list"),
            "# proxied\nDOMAIN,mail.example.com\nIP-ASN,64496,no-resolve\nIP-CIDR6,2001:db8:3::1/128,no-resolve\n",
        )
        .unwrap();
        fs::write(
            dir.join("rules/direct.list"),
            "DOMAIN-SUFFIX,example.org\nIP-CIDR,203.0.113.10/32,no-resolve\n\
             IP-CIDR6,2001:db8:2::11/128,no-resolve\nIP-CIDR6,2001:db8:3::1/128\n",
        )
        .unwrap();
        fs::write(
            dir.join("rules/ai.yaml"),
            "payload:\n  - 'IP-CIDR,192.0.2.0/24'\n",
        )
        .unwrap();
        let config = json!({
            "rule-providers": {
                "ai": {"behavior": "classical", "format": "yaml", "path": "./rules/ai.yaml"},
                "proxy": {"behavior": "classical", "format": "text", "path": "./rules/proxy.list"},
                "direct": {"behavior": "classical", "format": "text", "path": "./rules/direct.list"},
                "cdn": {"behavior": "ipcidr", "type": "inline", "payload": ["104.16.0.0/13"]},
                "names": {"behavior": "domain", "format": "text", "path": "./rules/missing.list"},
                "huge": {"behavior": "classical", "format": "text", "path": "./rules/never-read.list"}
            },
            "rules": [
                "RULE-SET,ai,AI",
                "GEOIP,US,美国",
                "RULE-SET,names,节点选择",
                "RULE-SET,proxy,节点选择,no-resolve",
                "IP-CIDR,104.16.0.0/13,DIRECT,no-resolve",
                "RULE-SET,cdn,节点选择",
                "RULE-SET,direct,DIRECT,no-resolve",
                "RULE-SET,huge,DIRECT",
                "MATCH,DIRECT"
            ]
        });
        let got = direct_by_address(
            &config,
            &dir,
            [
                ip("203.0.113.10"),
                ip("2001:db8:2::11"),
                ip("2001:db8:3::1"),
                ip("192.0.2.10"),
                ip("104.17.1.1"),
                ip("9.9.9.9"),
            ],
        );
        // Proxied before DIRECT, AI-routed, unlisted (MATCH is not an IP rule):
        // all stay in the TUN. The inline DIRECT CIDR is honoured.
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            vec![ip("104.17.1.1"), ip("203.0.113.10"), ip("2001:db8:2::11"),]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn servers_come_from_proxies_and_provider_files() {
        let dir = std::env::temp_dir().join(format!("relay-servers-{}", std::process::id()));
        fs::create_dir_all(dir.join("providers")).unwrap();
        fs::write(
            dir.join("providers/sub.yaml"),
            "proxies:\n  - {name: a, type: ss, server: Relay-A.example.net}\n  - {name: b, type: ss, server: '[2001:db8::7]'}\n",
        )
        .unwrap();
        let config = json!({
            "proxies": [
                {"name": "DIRECT-v4", "type": "direct"},
                {"name": "x", "type": "vless", "server": "relay-b.example.net"},
                {"name": "y", "type": "ss", "server": "203.0.113.10"}
            ],
            "proxy-providers": {"sub": {"type": "http", "path": "./providers/sub.yaml"},
                                "gone": {"type": "file", "path": "./providers/none.yaml"}}
        });
        let got: Vec<String> = servers(&config, &dir).into_iter().collect();
        assert_eq!(
            got,
            [
                "2001:db8::7",
                "203.0.113.10",
                "relay-a.example.net",
                "relay-b.example.net"
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_query_keeps_the_previous_answer() {
        let hosts: BTreeSet<String> =
            ["relay-a.example.net", "relay-b.example.net", "203.0.113.10"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let mut previous = Cache::new();
        previous.insert(
            ("relay-a.example.net".into(), "A"),
            vec![ip("198.51.100.1")],
        );
        previous.insert(
            ("relay-a.example.net".into(), "AAAA"),
            vec![ip("2001:db8:a::1")],
        );
        previous.insert(("gone.example.net".into(), "A"), vec![ip("198.51.100.99")]);
        // relay-a: A answers with a new address, AAAA fails. relay-b: A answers
        // empty (no record), AAAA fails with nothing cached.
        let mut lookup = |host: &str, qtype: &str| match (host, qtype) {
            ("relay-a.example.net", "A") => Some(vec![ip("198.51.100.2")]),
            ("relay-b.example.net", "A") => Some(vec![]),
            _ => None,
        };
        let (got, cache, complete) = gather(&hosts, &previous, &mut lookup);
        assert!(!complete);
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            vec![ip("198.51.100.2"), ip("203.0.113.10"), ip("2001:db8:a::1")]
        );
        // New answers replace old ones; names no longer in the config are dropped.
        assert_eq!(
            cache[&("relay-a.example.net".to_string(), "A")],
            vec![ip("198.51.100.2")]
        );
        assert_eq!(
            cache[&("relay-a.example.net".to_string(), "AAAA")],
            vec![ip("2001:db8:a::1")]
        );
        assert_eq!(
            cache[&("relay-b.example.net".to_string(), "A")],
            Vec::<IpAddr>::new()
        );
        assert!(!cache.contains_key(&("relay-b.example.net".to_string(), "AAAA")));
        assert!(!cache.contains_key(&("gone.example.net".to_string(), "A")));

        let mut all_ok = |_: &str, _: &str| Some(vec![]);
        let (_, _, complete) = gather(&hosts, &cache, &mut all_ok);
        assert!(complete);
    }

    #[test]
    fn dns_answers_keep_address_records_only() {
        let reply = json!({"Status": 0, "Answer": [
            {"type": 5, "data": "alias.example.com."},
            {"type": 1, "data": "198.51.100.53"},
            {"type": 28, "data": "2001:db8:1::dc"}
        ]});
        assert_eq!(
            answers(&reply),
            vec![ip("198.51.100.53"), ip("2001:db8:1::dc")]
        );
        assert!(answers(&json!({"Status": 3})).is_empty());
    }
}
