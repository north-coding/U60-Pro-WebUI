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
//! With `settings.node_bypass` on (the default), every global unicast address
//! of every proxy server is taken, like ShellCrash's "node bypass": a node that
//! moves to a new address is followed at the next lookup. Off, nothing is
//! looked up and every node address stays in the TUN like other traffic. (Off
//! used to keep the addresses the rules send DIRECT by IP; that mode went on
//! 2026-11-16, once the devices that run their own proxy client skipped the
//! TUN by MAC address and the user asked for the TUN to carry everything else.)
//!
//! Names are resolved through mihomo (`/dns/query`), the resolver LAN clients
//! get their answers from. A query that fails keeps that name's addresses from
//! the previous lookup, so one DNS hiccup does not drop a node. mihomo answers
//! from an expired cache entry with every TTL set to 1 and refreshes it in the
//! background (`Resolver::ExchangeContext`); a lookup every 10 minutes nearly
//! always lands on such an entry, so a TTL-1 answer is asked again after a
//! second, until the refreshed one arrives. Without that, a node that moved
//! stayed on its old address for a whole cycle or more (2026-11-15).

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
/// Re-asks of a stale (TTL 1) answer, and the wait before each.
const STALE_RETRIES: usize = 2;
const STALE_WAIT: Duration = Duration::from_secs(1);
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

/// Look up the active config's proxy servers and keep every global unicast
/// address.
pub fn find(config: &Value, dir: &Path, previous: &Cache) -> Found {
    let ctl = Controller;
    let ask = |host: &str, qtype: &str| -> Option<Value> {
        let path = format!("/dns/query?name={}&type={qtype}", segment(host));
        let reply = ctl.request("GET", &path, None, QUERY_TIMEOUT).ok()?;
        reply.ok().then(|| reply.json().ok()).flatten()
    };
    let mut query = |host: &str, qtype: &str| {
        fresh_answer(&mut |h, t| ask(h, t), host, qtype, &mut || {
            std::thread::sleep(STALE_WAIT)
        })
    };
    let (candidates, cache, complete) = gather(&servers(config, dir), previous, &mut query);
    let picked: BTreeSet<IpAddr> = candidates.into_iter().filter(bypassable).collect();
    Found {
        addresses: picked.into_iter().take(MAX_ADDRESSES).collect(),
        cache,
        complete,
    }
}

/// One query through `ask`, asked again (after `wait`) while mihomo answers
/// from an expired cache entry. `None` when it failed or did not say NOERROR.
fn fresh_answer(
    ask: &mut dyn FnMut(&str, &str) -> Option<Value>,
    host: &str,
    qtype: &str,
    wait: &mut dyn FnMut(),
) -> Option<Vec<IpAddr>> {
    let mut reply = ask(host, qtype)?;
    for _ in 0..STALE_RETRIES {
        if !stale(&reply) {
            break;
        }
        wait();
        match ask(host, qtype) {
            Some(r) => reply = r,
            None => break,
        }
    }
    (reply["Status"].as_u64() == Some(0)).then(|| answers(&reply))
}

/// mihomo's mark for an answer served from an expired cache entry: records,
/// and every one of them with TTL 1 (or less).
fn stale(reply: &Value) -> bool {
    let records = reply["Answer"].as_array().map_or(&[][..], Vec::as_slice);
    !records.is_empty()
        && records
            .iter()
            .all(|a| a["TTL"].as_u64().is_some_and(|t| t <= 1))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
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
    fn a_stale_answer_is_asked_again_until_it_is_refreshed() {
        let reply = |ttl: u64, ip: &str| json!({"Status": 0, "Answer": [{"type": 1, "TTL": ttl, "data": ip}]});
        // Expired entry first, the refreshed one on the second ask.
        let mut replies = vec![reply(1, "203.0.113.7"), reply(60, "203.0.113.8")].into_iter();
        let mut waits = 0;
        let got = fresh_answer(
            &mut |_, _| replies.next(),
            "relay-a.example.net",
            "A",
            &mut || waits += 1,
        );
        assert_eq!(got, Some(vec![ip("203.0.113.8")]));
        assert_eq!(waits, 1);
        // A record whose real TTL is 1 costs only the retries, then is used.
        let mut waits = 0;
        let got = fresh_answer(
            &mut |_, _| Some(reply(1, "203.0.113.9")),
            "h",
            "A",
            &mut || waits += 1,
        );
        assert_eq!(got, Some(vec![ip("203.0.113.9")]));
        assert_eq!(waits, STALE_RETRIES);
        // A fresh answer, an empty one and an NXDOMAIN are not asked again.
        for r in [
            reply(30, "203.0.113.1"),
            json!({"Status": 0}),
            json!({"Status": 3}),
        ] {
            let mut asks = 0;
            let _ = fresh_answer(
                &mut |_, _| {
                    asks += 1;
                    Some(r.clone())
                },
                "h",
                "A",
                &mut || {},
            );
            assert_eq!(asks, 1);
        }
        assert_eq!(
            fresh_answer(&mut |_, _| Some(json!({"Status": 3})), "h", "A", &mut || {}),
            None
        );
        // A retry that fails keeps the stale answer rather than nothing.
        let mut first = Some(reply(1, "203.0.113.7"));
        let got = fresh_answer(&mut |_, _| first.take(), "h", "A", &mut || {});
        assert_eq!(got, Some(vec![ip("203.0.113.7")]));
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
