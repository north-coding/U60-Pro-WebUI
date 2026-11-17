//! mihomo process lifecycle, runtime firewall rules for the TUN, and cleanup.
//!
//! All newly managed Mihomo data lives below /data/u60-pro-managed/mihomo,
//! separate from the abandoned legacy /data/mihomo tree. The process is
//! started by the agent, while runtime routes remain owned by Mihomo and are
//! never swept by generic priority or table cleanup.

use std::fs::{self, OpenOptions};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::process::BoundedCommand;

use super::config::{LAN_BRIDGE, TUN_DEVICE};
use super::paths;

pub const DIR: &str = paths::MIHOMO_DIR;
pub const BINARY: &str = paths::MIHOMO_BINARY;
pub const CONFIG: &str = paths::MIHOMO_CONFIG;
pub const STAGED: &str = paths::MIHOMO_STAGED_CONFIG;
pub const LOG: &str = paths::MIHOMO_LOG;
const PIDFILE: &str = paths::MIHOMO_PID;
const LOG_CAP: u64 = 1024 * 1024;
const FW_COMMENT: &str = "mihomo-tun";
/// sing-tun's default ip rule priority range and route table.
const RULE_PREFS: std::ops::RangeInclusive<u32> = 9000..=9099;
const ROUTE_TABLE: &str = "2022";

pub struct Process {
    child: Option<Child>,
    pub pid: u32,
    pub started: Instant,
}

#[derive(Default)]
pub struct FirewallLease {
    rules: Vec<OwnedFirewallRule>,
}

#[derive(PartialEq, Eq)]
struct OwnedFirewallRule {
    bin: &'static str,
    rule: Vec<&'static str>,
}

impl FirewallLease {
    pub fn extend(&mut self, other: Self) {
        for rule in other.rules {
            if !self.rules.contains(&rule) {
                self.rules.push(rule);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[derive(Default)]
pub struct BypassLease {
    set: bool,
    mark_rule: bool,
    ip_rule: bool,
}

impl BypassLease {
    pub fn extend(&mut self, other: Self) {
        self.set |= other.set;
        self.mark_rule |= other.mark_rule;
        self.ip_rule |= other.ip_rule;
    }

    pub fn is_empty(&self) -> bool {
        !(self.set || self.mark_rule || self.ip_rule)
    }
}

pub fn installed() -> bool {
    Path::new(BINARY).is_file()
}

/// `Mihomo Meta v1.19.32 linux arm64 …` → `v1.19.32`.
pub fn version() -> Option<String> {
    let out = Command::new(BINARY).arg("-v").bounded_output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .find(|w| w.starts_with('v') && w.chars().nth(1).is_some_and(|c| c.is_ascii_digit()))
        .map(str::to_string)
}

/// `mihomo -t`: parses the config and loads rule data without starting
/// listeners or fetching subscriptions.
pub fn test_config(path: &str) -> Result<(), String> {
    let out = Command::new(BINARY)
        .args(["-t", "-d", DIR, "-f", path])
        .bounded_output()
        .map_err(|e| format!("could not run mihomo -t: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Err(last_error_line(&text, true).unwrap_or_else(|| "mihomo rejected the configuration".into()))
}

/// The most useful line of mihomo output: the last `level=error`/`fatal`
/// message, else (when `any_line`) the last non-empty line.
pub fn last_error_line(text: &str, any_line: bool) -> Option<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let pick = lines
        .iter()
        .rev()
        .find(|l| l.contains("level=error") || l.contains("level=fatal"))
        .or_else(|| if any_line { lines.last() } else { None })?;
    let msg = pick
        .split_once("msg=")
        .map(|(_, m)| m.trim_matches('"').replace("\\\"", "\""))
        .unwrap_or_else(|| pick.to_string());
    Some(msg.chars().take(300).collect())
}

pub fn log_tail_error() -> Option<String> {
    let text = fs::read_to_string(LOG).ok()?;
    let start = text.len().saturating_sub(16 * 1024);
    let tail = text.get(start..).unwrap_or(&text);
    last_error_line(tail, false)
}

pub fn spawn() -> Result<Process, String> {
    if !installed() {
        return Err(format!("mihomo is not installed (expected {BINARY})"));
    }
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG)
        .map_err(|e| format!("cannot open {LOG}: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("cannot open {LOG}: {e}"))?;
    let mut cmd = Command::new(BINARY);
    cmd.args(["-d", DIR, "-f", CONFIG])
        .env("GOMEMLIMIT", "160MiB")
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err);
    // Own session: an agent restart (deploy, crash) must not take mihomo with it.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("failed to start mihomo: {e}"))?;
    let pid = child.id();
    let _ = fs::write(PIDFILE, format!("{pid}\n"));
    Ok(Process {
        child: Some(child),
        pid,
        started: Instant::now(),
    })
}

/// Re-attach to a mihomo started by a previous agent instance.
pub fn adopt() -> Option<Process> {
    let pid: u32 = fs::read_to_string(PIDFILE).ok()?.trim().parse().ok()?;
    if !pid_is_mihomo(pid) {
        let _ = fs::remove_file(PIDFILE);
        return None;
    }
    let started = process_age(pid)
        .and_then(|age| Instant::now().checked_sub(age))
        .unwrap_or_else(Instant::now);
    Some(Process {
        child: None,
        pid,
        started,
    })
}

fn pid_is_mihomo(pid: u32) -> bool {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let first = cmdline.split(|&b| b == 0).next().unwrap_or(&[]);
    if first != BINARY.as_bytes() {
        return false;
    }
    // A zombie still has a cmdline-less /proc entry; treat it as dead.
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let state = stat
        .rsplit(')')
        .next()
        .and_then(|s| s.split_whitespace().next());
    !matches!(state, Some("Z") | Some("X") | None)
}

fn process_age(pid: u32) -> Option<Duration> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit(')').next()?;
    // Field 22 overall is starttime; after ") " the first field is #3.
    let start_ticks: f64 = after.split_whitespace().nth(19)?.parse().ok()?;
    let uptime: f64 = fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    if hz <= 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(
        (uptime - start_ticks / hz).max(0.0),
    ))
}

impl Process {
    pub fn alive(&mut self) -> bool {
        if let Some(child) = self.child.as_mut() {
            if !matches!(child.try_wait(), Ok(None)) {
                return false;
            }
        }
        pid_is_mihomo(self.pid)
    }

    pub fn rss_bytes(&self) -> Option<u64> {
        let status = fs::read_to_string(format!("/proc/{}/status", self.pid)).ok()?;
        let kb: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }

    /// SIGTERM, wait up to 5 s, then SIGKILL. A forced exit can leave TUN
    /// routing resources; the next start detects them and fails closed.
    pub fn terminate(mut self) -> bool {
        let pid = self.pid as libc::pid_t;
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !self.alive() {
                let _ = fs::remove_file(PIDFILE);
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        unsafe { libc::kill(pid, libc::SIGKILL) };
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
        let _ = fs::remove_file(PIDFILE);
        true
    }
}

// ── Runtime firewall for the TUN ─────────────────────────────────────────────
//
// ZTE's fw3 only forwards lan→wan(rmnet) and only accepts INPUT from lo/br-lan,
// so LAN traffic routed into the TUN is rejected without these. They are
// inserted at the top of the chains, tagged, and never written to config.

fn fw_rules() -> [Vec<&'static str>; 3] {
    [
        vec!["FORWARD", "-i", LAN_BRIDGE, "-o", TUN_DEVICE],
        vec!["FORWARD", "-i", TUN_DEVICE, "-o", LAN_BRIDGE],
        vec!["INPUT", "-i", TUN_DEVICE],
    ]
}

fn fw(bin: &str, op: &str, rule: &[&str]) -> bool {
    let mut args: Vec<&str> = vec![op, rule[0]];
    if op == "-I" {
        args.push("1");
    }
    args.extend_from_slice(&rule[1..]);
    args.extend_from_slice(&["-m", "comment", "--comment", FW_COMMENT, "-j", "ACCEPT"]);
    Command::new(bin)
        .args(&args)
        .bounded_output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn firewall_present() -> bool {
    ["iptables", "ip6tables"]
        .iter()
        .all(|bin| fw_rules().iter().all(|rule| fw(bin, "-C", rule)))
}

pub fn firewall_add() -> Result<FirewallLease, String> {
    let mut lease = FirewallLease::default();
    for bin in ["iptables", "ip6tables"] {
        for rule in fw_rules() {
            if fw(bin, "-C", &rule) {
                continue;
            }
            if !fw(bin, "-I", &rule) {
                firewall_remove(lease);
                return Err(format!(
                    "{bin}: could not insert {} accept for the TUN",
                    rule[0]
                ));
            }
            lease.rules.push(OwnedFirewallRule {
                bin,
                rule: rule.into_iter().collect(),
            });
        }
    }
    Ok(lease)
}

pub fn firewall_remove(lease: FirewallLease) {
    for owned in lease.rules.into_iter().rev() {
        let _ = fw(owned.bin, "-D", &owned.rule);
    }
}

fn routing_conflicts(
    rule4: &str,
    rule6: &str,
    routes4: &str,
    routes6: &str,
    tun_active: bool,
) -> Vec<String> {
    let mut conflicts = Vec::new();
    for (family, rules) in [("IPv4", rule4), ("IPv6", rule6)] {
        for line in rules.lines() {
            let Some(priority) = line
                .split(':')
                .next()
                .and_then(|p| p.trim().parse::<u32>().ok())
            else {
                continue;
            };
            if RULE_PREFS.contains(&priority) {
                conflicts.push(format!("{family} rule priority {priority}"));
            }
        }
    }
    for (family, routes) in [("IPv4", routes4), ("IPv6", routes6)] {
        if routes.lines().any(|line| !line.trim().is_empty()) {
            conflicts.push(format!("{family} route table {ROUTE_TABLE} is not empty"));
        }
    }
    if tun_active {
        conflicts.push(format!("interface {TUN_DEVICE} already exists"));
    }
    conflicts
}

fn validate_routing_state(
    tun_enabled: bool,
    rule4: &str,
    rule6: &str,
    routes4: &str,
    routes6: &str,
    tun_active: bool,
) -> Result<(), String> {
    let conflicts = routing_conflicts(rule4, rule6, routes4, routes6, tun_active);
    if conflicts.is_empty() {
        return Ok(());
    }
    let context = if tun_enabled {
        "before enabling TUN"
    } else {
        "while TUN is disabled"
    };
    Err(format!(
        "unowned TUN routing state exists {context} ({}); inspect it before starting Mihomo",
        conflicts.join(", ")
    ))
}

/// Read-only preflight. Runtime routes and the TUN device have no durable
/// ownership record, so a possible leftover is a conflict, never a cleanup
/// target. This deliberately fails closed after a force-killed process in
/// either proxy mode so a TUN fallback cannot start on stale routing state.
pub fn preflight_routing(tun_enabled: bool) -> Result<(), String> {
    let read = |family: &str, kind: &str, table: Option<&str>| {
        let mut command = Command::new("ip");
        command.args([family, kind, "show"]);
        if let Some(table) = table {
            command.args(["table", table]);
        }
        let output = command
            .bounded_output()
            .map_err(|e| format!("cannot inspect {family} {kind}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "cannot inspect {family} {kind}; refusing TUN start"
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    };

    let rule4 = read("-4", "rule", None)?;
    let rule6 = read("-6", "rule", None)?;
    let routes4 = read("-4", "route", Some(ROUTE_TABLE))?;
    let routes6 = read("-6", "route", Some(ROUTE_TABLE))?;
    validate_routing_state(
        tun_enabled,
        &rule4,
        &rule6,
        &routes4,
        &routes6,
        tun_active(),
    )
}

// ── Mainland bypass for the TUN ──────────────────────────────────────────────
//
// TUN costs about one CPU core per 100 Mbit/s here (measured 2026-10-06), and
// mainland destinations go DIRECT anyway. LAN packets to mainland IPv4 ranges
// (an ipset loaded from CN_LIST) get a mark, and one ip rule ahead of
// sing-tun's (8999 < 9000) sends marked packets through the main table, so
// they keep the stock path and IPA offload. Runtime only, like the accepts.

pub const CN_LIST: &str = paths::MIHOMO_CN_LIST;
const CN_SET: &str = "mihomo-cn";
const BYPASS_MARK: &str = "0x10000000/0x10000000";
const BYPASS_PREF: &str = "8999";
const BYPASS_RULE_SUFFIX: &str = "from all fwmark 0x10000000/0x10000000 lookup main";

pub fn bypass_available() -> bool {
    Path::new(CN_LIST).exists()
}

/// IPv4 prefixes from the list (one CIDR per line; IPv6 and junk skipped).
pub fn cn_prefixes(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            let Some((addr, len)) = l.split_once('/') else {
                return false;
            };
            addr.parse::<std::net::Ipv4Addr>().is_ok()
                && len.parse::<u8>().is_ok_and(|n| (1..=32).contains(&n))
        })
        .collect()
}

fn bypass_mark_rule(op: &str) -> bool {
    let mut args = vec!["-t", "mangle", op, "PREROUTING"];
    if op == "-I" {
        args.push("1");
    }
    args.extend_from_slice(&[
        "-i",
        LAN_BRIDGE,
        "-m",
        "set",
        "--match-set",
        CN_SET,
        "dst",
        "-m",
        "comment",
        "--comment",
        FW_COMMENT,
        "-j",
        "MARK",
        "--set-xmark",
        BYPASS_MARK,
    ]);
    Command::new("iptables")
        .args(&args)
        .bounded_output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn bypass_rule_state() -> Result<(usize, usize), String> {
    Command::new("ip")
        .args(["-4", "rule", "show"])
        .bounded_output()
        .map_err(|e| format!("cannot inspect IPv4 rules: {e}"))
        .and_then(|o| {
            if !o.status.success() {
                return Err("cannot inspect IPv4 rules; refusing bypass change".into());
            }
            Ok(parse_bypass_rule_state(&String::from_utf8_lossy(&o.stdout)))
        })
}

fn parse_bypass_rule_state(listing: &str) -> (usize, usize) {
    let mut exact = 0;
    let mut priority_count = 0;
    for line in listing.lines() {
        let Some((priority, rule)) = line.split_once(':') else {
            continue;
        };
        if priority.trim() == BYPASS_PREF {
            priority_count += 1;
            if rule.split_whitespace().collect::<Vec<_>>().join(" ") == BYPASS_RULE_SUFFIX {
                exact += 1;
            }
        }
    }
    (exact, priority_count)
}

fn set_present() -> bool {
    Command::new("ipset")
        .args(["list", "-n", CN_SET])
        .bounded_output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn bypass_present() -> bool {
    set_present()
        && bypass_mark_rule("-C")
        && bypass_rule_state()
            .is_ok_and(|(exact, priority_count)| exact == 1 && priority_count == 1)
}

/// Load the set (only when missing: a reload costs ~6000 entries) and insert
/// the mark rule and the ip rule. Returns the number of prefixes loaded.
pub fn bypass_add() -> Result<(usize, BypassLease), String> {
    let mut loaded = 0;
    let mut lease = BypassLease::default();
    if !set_present() {
        let text = fs::read_to_string(CN_LIST).map_err(|e| format!("{CN_LIST}: {e}"))?;
        let prefixes = cn_prefixes(&text);
        if prefixes.len() < 1000 {
            return Err(format!(
                "{CN_LIST} holds only {} IPv4 prefixes; refusing a partial list",
                prefixes.len()
            ));
        }
        let maxelem = (prefixes.len() * 2).max(16384).to_string();
        let created = Command::new("ipset")
            .args([
                "create", CN_SET, "hash:net", "family", "inet", "maxelem", &maxelem,
            ])
            .bounded_output()
            .map_err(|e| format!("ipset create: {e}"))?;
        if !created.status.success() {
            return Err(
                "ipset create refused the name or configuration; refusing to reuse it".into(),
            );
        }
        lease.set = true;
        let mut script = String::new();
        for p in &prefixes {
            script.push_str(&format!("add {CN_SET} {p} -exist\n"));
        }
        let out = match process_runner::output(
            Command::new("ipset").arg("restore"),
            Some(script.as_bytes()),
            Duration::from_secs(20),
            64 * 1024,
        ) {
            Ok(out) => out,
            Err(e) => {
                bypass_remove(lease);
                return Err(format!("ipset restore: {e}"));
            }
        };
        if !out.status.success() {
            bypass_remove(lease);
            return Err(format!(
                "ipset restore: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        loaded = prefixes.len();
    }
    if !bypass_mark_rule("-C") {
        if !bypass_mark_rule("-I") {
            bypass_remove(lease);
            return Err("iptables: could not insert the mainland mark rule".into());
        }
        lease.mark_rule = true;
    }
    let (exact_rules, priority_count) = match bypass_rule_state() {
        Ok(state) => state,
        Err(error) => {
            bypass_remove(lease);
            return Err(error);
        }
    };
    if (exact_rules == 0 && priority_count > 0) || exact_rules != priority_count || exact_rules > 1
    {
        bypass_remove(lease);
        return Err(
            "IPv4 rule priority 8999 is occupied or duplicated; refusing the bypass".into(),
        );
    }
    if exact_rules == 0 {
        let ok = Command::new("ip")
            .args([
                "-4",
                "rule",
                "add",
                "pref",
                BYPASS_PREF,
                "fwmark",
                BYPASS_MARK,
                "lookup",
                "main",
            ])
            .bounded_output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            bypass_remove(lease);
            return Err("ip rule: could not add the mainland bypass rule".into());
        }
        lease.ip_rule = true;
    }
    Ok((loaded, lease))
}

pub fn bypass_remove(lease: BypassLease) {
    if lease.mark_rule && !bypass_mark_rule("-D") {
        eprintln!("[mihomo] owned mainland mark rule was already absent");
    }
    if lease.ip_rule {
        match bypass_rule_state() {
            Ok((1, 1)) => {
                let _ = Command::new("ip")
                    .args([
                        "-4",
                        "rule",
                        "del",
                        "pref",
                        BYPASS_PREF,
                        "fwmark",
                        BYPASS_MARK,
                        "lookup",
                        "main",
                    ])
                    .bounded_output()
                    .map(|o| o.status.success());
            }
            Ok((0, _)) => {}
            _ => eprintln!("[mihomo] bypass rule ownership is ambiguous; leaving it in place"),
        }
    }
    if lease.set {
        // The set is destroyed only when this process created it. If another
        // rule still references it, ipset refuses the operation.
        let _ = Command::new("ipset")
            .args(["destroy", CN_SET])
            .bounded_output();
    }
}

/// Does mihomo's LAN controller at `addr` accept `secret`? `None` when it
/// cannot be asked. A hot reload does not replace the controller's secret, so
/// this catches a running mihomo still using an older one.
pub fn controller_accepts(addr: &str, secret: &str) -> Option<bool> {
    use std::io::{Read, Write};
    let sock: std::net::SocketAddr = addr.parse().ok()?;
    let mut stream = std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(2)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let request = format!(
        "GET /version HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut head = [0u8; 64];
    let n = stream.read(&mut head).ok()?;
    let status = String::from_utf8_lossy(&head[..n])
        .split_whitespace()
        .nth(1)?
        .to_string();
    Some(status == "200")
}

/// metacubexd is installed (scripts/deploy-mihomo.sh) and served at `/ui`.
pub fn ui_installed() -> bool {
    Path::new(super::config::UI_DIR).join("index.html").exists()
}

pub fn tun_active() -> bool {
    Path::new("/sys/class/net").join(TUN_DEVICE).exists()
}

pub fn truncate_log_if_large() {
    if fs::metadata(LOG)
        .map(|m| m.len() > LOG_CAP)
        .unwrap_or(false)
    {
        if let Ok(file) = OpenOptions::new().write(true).open(LOG) {
            let _ = file.set_len(0);
        }
    }
}

/// Mainland endpoints that answer 204; rule presets and typical provider
/// configs send them DIRECT, so a failure through mihomo means mihomo itself
/// stopped forwarding rather than a node being down.
const PROBE_URLS: &[&str] = &[
    "http://connectivitycheck.platform.hicloud.com/generate_204",
    "http://connect.rom.miui.com/generate_204",
];

/// One HTTP 204 check, through `proxy` (e.g. `http://192.168.0.1:7890`) or direct.
pub fn probe_204(proxy: Option<&str>) -> bool {
    PROBE_URLS.iter().any(|url| {
        let mut cmd = Command::new("/usr/bin/curl");
        cmd.args([
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--max-time",
            "5",
        ]);
        if let Some(p) = proxy {
            cmd.args(["--proxy", p]);
        } else {
            cmd.arg("--noproxy").arg("*");
        }
        cmd.arg(url);
        process_runner::output(&mut cmd, None, Duration::from_secs(8), 1024)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "204")
            .unwrap_or(false)
    })
}

/// Endpoints outside the mainland that answer 204 over HTTPS. Through the
/// mixed port they follow the proxy rules, so a failure means the selected
/// node path is broken (not mihomo itself).
const ROUTE_PROBE_URLS: &[&str] = &[
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
];

/// One HTTPS 204 check through the proxy's own routing (mixed port).
pub fn probe_route(proxy: &str) -> bool {
    ROUTE_PROBE_URLS.iter().any(|url| {
        let mut cmd = Command::new("/usr/bin/curl");
        cmd.args([
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--max-time",
            "8",
            "--proxy",
            proxy,
            url,
        ]);
        process_runner::output(&mut cmd, None, Duration::from_secs(11), 1024)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "204")
            .unwrap_or(false)
    })
}

/// True once `ip` is assigned locally, i.e. mihomo can bind its listener.
pub fn address_ready(ip: &str) -> bool {
    std::net::TcpListener::bind((ip, 0)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cn_list_keeps_ipv4_prefixes_only() {
        let text =
            "1.0.1.0/24\n 1.0.2.0/23 \n2400:3200::/32\n# comment\n10.0.0.0/33\nbad\n0.0.0.0/0\n";
        assert_eq!(cn_prefixes(text), ["1.0.1.0/24", "1.0.2.0/23"]);
    }

    #[test]
    fn picks_last_error_message() {
        let log = "time=\"t\" level=info msg=\"Start\"\n\
                   time=\"t\" level=error msg=\"initial proxy provider sub-x error: Get \\\"https://h/x\\\": EOF\"\n\
                   time=\"t\" level=info msg=\"done\"\n";
        assert_eq!(
            last_error_line(log, false).unwrap(),
            "initial proxy provider sub-x error: Get \"https://h/x\": EOF"
        );
        assert_eq!(
            last_error_line("plain failure\n\n", true).unwrap(),
            "plain failure"
        );
        assert!(last_error_line("level=warning msg=\"x\"\n", false).is_none());
        assert!(last_error_line("\n \n", true).is_none());
    }

    #[test]
    fn firewall_rules_cover_both_directions_and_input() {
        let rules = fw_rules();
        assert_eq!(rules[0], vec!["FORWARD", "-i", "br-lan", "-o", "mihomo"]);
        assert_eq!(rules[1], vec!["FORWARD", "-i", "mihomo", "-o", "br-lan"]);
        assert_eq!(rules[2], vec!["INPUT", "-i", "mihomo"]);
    }

    #[test]
    fn tun_preflight_rejects_routes_rules_and_existing_device_without_deleting() {
        assert_eq!(
            routing_conflicts(
                "0: from all lookup local\n10000: from all lookup main\n",
                "0: from all lookup local\n",
                "",
                "",
                false,
            ),
            Vec::<String>::new()
        );
        assert!(routing_conflicts(
            "9000: from all lookup 2022\n",
            "0: from all lookup local\n",
            "",
            "",
            false,
        )
        .iter()
        .any(|entry| entry == "IPv4 rule priority 9000"));
        assert!(routing_conflicts(
            "0: from all lookup local\n",
            "9099: from all lookup 2022\n",
            "",
            "",
            false,
        )
        .iter()
        .any(|entry| entry == "IPv6 rule priority 9099"));
        assert!(
            routing_conflicts("", "", "default dev mihomo\n", "", false,)
                .iter()
                .any(|entry| entry == "IPv4 route table 2022 is not empty")
        );
        assert!(routing_conflicts("", "", "", "", true)
            .iter()
            .any(|entry| entry == "interface mihomo already exists"));
    }

    #[test]
    fn both_proxy_modes_fail_closed_on_unowned_tun_state() {
        let clean = (
            "0: from all lookup local\n10000: from all lookup main\n",
            "0: from all lookup local\n",
            "",
            "",
            false,
        );
        assert!(validate_routing_state(true, clean.0, clean.1, clean.2, clean.3, clean.4).is_ok());
        assert!(validate_routing_state(false, clean.0, clean.1, clean.2, clean.3, clean.4).is_ok());

        let stale = (
            "9000: from all lookup 2022\n",
            "0: from all lookup local\n",
            "",
            "",
            false,
        );
        let tun_error =
            validate_routing_state(true, stale.0, stale.1, stale.2, stale.3, stale.4).unwrap_err();
        let non_tun_error =
            validate_routing_state(false, stale.0, stale.1, stale.2, stale.3, stale.4).unwrap_err();
        assert!(tun_error.contains("before enabling TUN"));
        assert!(non_tun_error.contains("while TUN is disabled"));
    }

    #[test]
    fn bypass_rule_priority_requires_exact_signature() {
        assert_eq!(
            parse_bypass_rule_state(
                "0: from all lookup local\n8999: from all fwmark 0x10000000/0x10000000 lookup main\n"
            ),
            (1, 1)
        );
        assert_eq!(
            parse_bypass_rule_state("8999: from all lookup 2022\n"),
            (0, 1)
        );
        assert_eq!(
            parse_bypass_rule_state("9000: from all lookup 2022\n"),
            (0, 0)
        );
    }

    #[test]
    fn existing_bypass_signature_does_not_create_an_ownership_lease() {
        let listing = "8999: from all fwmark 0x10000000/0x10000000 lookup main\n";
        assert_eq!(parse_bypass_rule_state(listing), (1, 1));
        assert!(BypassLease::default().is_empty());
        assert!(FirewallLease::default().is_empty());
    }

    #[test]
    fn manager_reads_only_its_new_mihomo_pid_path() {
        assert_eq!(PIDFILE, paths::MIHOMO_PID);
        assert_ne!(PIDFILE, "/var/run/mihomo.pid");
    }
}
