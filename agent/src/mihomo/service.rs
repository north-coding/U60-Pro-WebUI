//! mihomo process lifecycle, runtime firewall rules for the TUN, and cleanup.
//!
//! All newly managed Mihomo data lives below /data/u60-pro-managed/mihomo,
//! separate from the abandoned legacy /data/mihomo tree. The process is
//! started by the agent, while runtime routes remain owned by Mihomo and are
//! never swept by generic priority or table cleanup.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::process::BoundedCommand;

use super::config::{LAN_BRIDGE, TUN_DEVICE};
use super::ownership::{self, FileIdentity, OwnerRecord, Phase, ProcessEvidence};
use super::paths;

pub const DIR: &str = paths::MIHOMO_DIR;
pub const BINARY: &str = paths::MIHOMO_BINARY;
pub const CONFIG: &str = paths::MIHOMO_CONFIG;
pub const STAGED: &str = paths::MIHOMO_STAGED_CONFIG;
pub const LOG: &str = paths::MIHOMO_LOG;
const PIDFILE: &str = paths::MIHOMO_PID;
const LOCKFILE: &str = paths::MIHOMO_LOCK;
const LOG_CAP: u64 = 1024 * 1024;
const FW_COMMENT: &str = "mihomo-tun";
/// sing-tun's default ip rule priority range and route table.
const RULE_PREFS: std::ops::RangeInclusive<u32> = 9000..=9099;
const ROUTE_TABLE: &str = "2022";

pub struct Process {
    child: Option<Child>,
    pub pid: u32,
    pub started: Instant,
    owner: OwnerRecord,
    owner_file: FileIdentity,
    pidfd: OwnedFd,
}

pub struct ManagerLock {
    _file: File,
}

pub enum Recovery {
    Stopped,
    Running(Box<Process>),
    Blocked(String),
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
    ownership::validate_binary(Path::new(BINARY)).is_ok()
}

/// Read-only indicator for a record that proxy-only mode will not adopt or
/// overwrite. The caller should report the state as unverified.
pub fn managed_pid_record_present() -> bool {
    fs::symlink_metadata(PIDFILE).is_ok()
}

/// Validate existing proxy-only state without following symlinks or repairing
/// unknown ownership. A missing Mihomo directory is allowed until a mutation
/// needs to write its first managed config.
pub fn validate_proxy_only_paths() -> Result<(), String> {
    let root = Path::new(DIR)
        .parent()
        .ok_or_else(|| "managed Mihomo path has no runtime root".to_string())?;
    validate_managed_tree(root, Path::new(DIR), Path::new(paths::MIHOMO_STATE))?;
    for path in [
        paths::MIHOMO_CONFIG,
        paths::MIHOMO_STAGED_CONFIG,
        paths::MIHOMO_LOG,
        paths::MIHOMO_PID,
    ] {
        validate_optional_private_file(Path::new(path))?;
    }
    for path in [paths::MIHOMO_PROVIDERS, paths::MIHOMO_PROFILES] {
        validate_optional_private_directory(Path::new(path))?;
    }
    if Path::new(BINARY).exists() {
        ownership::validate_binary(Path::new(BINARY))?;
    }
    validate_controller_socket_path()
}

/// Create only the exact Mihomo runtime directory under an already validated
/// managed root, with private permissions for the Unix controller socket.
pub fn ensure_proxy_only_runtime_dir() -> Result<(), String> {
    let root = Path::new(DIR)
        .parent()
        .ok_or_else(|| "managed Mihomo path has no runtime root".to_string())?;
    ensure_private_directory(root, Path::new(DIR))
}

/// Serialize every Agent instance which can manage the new Mihomo runtime.
/// The kernel releases this advisory lock if the Agent crashes; the lock file
/// itself is stable and is never deleted as stale state.
pub fn acquire_manager_lock() -> Result<ManagerLock, String> {
    acquire_lock_at(Path::new(LOCKFILE))
}

fn acquire_lock_at(lock_path: &Path) -> Result<ManagerLock, String> {
    let parent = lock_path
        .parent()
        .ok_or_else(|| "managed Mihomo lock path has no parent".to_string())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("managed Mihomo directory is unavailable: {error}"))?;
    validate_private_directory(parent, &parent_metadata)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)
        .map_err(|error| format!("cannot open managed Mihomo lock: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect managed Mihomo lock: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err("managed Mihomo lock has unexpected type, owner, links, or permissions".into());
    }
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err("another Agent instance already owns the managed Mihomo lifecycle".into());
        }
        return Err(format!("cannot lock managed Mihomo lifecycle: {error}"));
    }
    Ok(ManagerLock { _file: file })
}

/// Refuse coexistence with the observed legacy installation. This is a
/// read-only exclusion gate, never proof that a PID may be signalled.
fn check_legacy_mihomo_absent(proc_root: &Path, legacy_binary: &Path) -> Result<(), String> {
    fn disappeared(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    }

    let legacy_identity = match fs::metadata(legacy_binary) {
        Ok(metadata) => Some(FileIdentity::from_metadata(&metadata)),
        Err(error) if disappeared(&error) => None,
        Err(error) => {
            return Err(format!(
                "cannot inspect the legacy Mihomo executable: {error}"
            ))
        }
    };
    let legacy_dir = legacy_binary
        .parent()
        .ok_or("legacy Mihomo executable has no parent")?;
    let launcher = legacy_dir.join("start-mihomo.sh");
    let config = legacy_dir.join("config.yaml");
    let deleted_name = format!("{} (deleted)", legacy_binary.display());
    let scan_error = |error| format!("cannot check for legacy Mihomo in procfs: {error}");
    for entry in fs::read_dir(proc_root).map_err(scan_error)? {
        let entry = entry.map_err(scan_error)?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let exe = entry.path().join("exe");
        let path = match fs::read_link(&exe) {
            Ok(path) => path,
            Err(error) if disappeared(&error) => continue,
            Err(error) => return Err(scan_error(error)),
        };
        if path == legacy_binary || path == Path::new(&deleted_name) {
            return Err("legacy Mihomo is still running; cutover is blocked".into());
        }
        if let Some(legacy_identity) = legacy_identity {
            match fs::metadata(&exe) {
                Ok(metadata) if FileIdentity::from_metadata(&metadata) == legacy_identity => {
                    return Err(
                        "a process is using the legacy Mihomo executable; cutover is blocked"
                            .into(),
                    );
                }
                Ok(_) => {}
                Err(error) if disappeared(&error) => {}
                Err(error) => return Err(scan_error(error)),
            }
        }
        let cmdline = match fs::read(entry.path().join("cmdline")) {
            Ok(cmdline) => cmdline,
            Err(error) if disappeared(&error) => continue,
            Err(error) => return Err(scan_error(error)),
        };
        let mut args = cmdline.split(|byte| *byte == 0);
        let first = args.next().unwrap_or_default();
        let legacy_launcher = launcher.as_os_str().as_bytes();
        if first == legacy_binary.as_os_str().as_bytes() || first == legacy_launcher {
            return Err(
                "legacy Mihomo startup or process is still present; cutover is blocked".into(),
            );
        }
        let mut previous = first;
        for arg in args {
            if arg == legacy_launcher
                || (previous == b"-d" && arg == legacy_dir.as_os_str().as_bytes())
                || (previous == b"-f" && arg == config.as_os_str().as_bytes())
                || arg.strip_prefix(b"-d=") == Some(legacy_dir.as_os_str().as_bytes())
                || arg.strip_prefix(b"-f=") == Some(config.as_os_str().as_bytes())
            {
                return Err(
                    "a process claims the legacy Mihomo runtime; cutover is blocked".into(),
                );
            }
            previous = arg;
        }
    }
    Ok(())
}

pub fn preflight_single_mihomo() -> Result<(), String> {
    check_legacy_mihomo_absent(Path::new("/proc"), Path::new("/data/mihomo/mihomo"))
}

pub fn preflight_legacy_controller(ip: &str) -> Result<(), String> {
    preflight_proxy_port(ip, 9090)
        .map_err(|error| format!("legacy LAN controller port must be free before cutover: {error}"))
}

/// Recover only a process whose durable record, PID start ticks, executable,
/// arguments, owner token, and binary identity all agree.
pub fn recover_proxy_only_process() -> Recovery {
    if let Err(error) = preflight_single_mihomo() {
        return Recovery::Blocked(error);
    }
    match ownership::inspect_owner(
        Path::new(PIDFILE),
        Path::new("/proc"),
        Path::new(BINARY),
        Path::new(DIR),
        Path::new(CONFIG),
    ) {
        ownership::Inspection::Stopped => Recovery::Stopped,
        ownership::Inspection::Blocked(reason) => Recovery::Blocked(reason),
        ownership::Inspection::Owned {
            record: record_box,
            mut file_identity,
            process: process_box,
            record_needs_completion,
        } => {
            let record = *record_box;
            let process = *process_box;
            if record_needs_completion {
                match ownership::complete_owner_file(Path::new(PIDFILE), file_identity, &record) {
                    Ok(identity) => file_identity = identity,
                    Err(error) => return Recovery::Blocked(error),
                }
            }
            let pidfd = match open_verified_pidfd(&record, process.pid) {
                Ok(pidfd) => pidfd,
                Err(error) => return Recovery::Blocked(error),
            };
            match ownership::inspect_process(Path::new("/proc"), process.pid) {
                Ok(current) if ownership::matches_record(&record, &current, record.start_ticks) => {
                    let started = process_age(process.pid)
                        .and_then(|age| Instant::now().checked_sub(age))
                        .unwrap_or_else(Instant::now);
                    Recovery::Running(Box::new(Process {
                        child: None,
                        pid: process.pid,
                        started,
                        owner: record,
                        owner_file: file_identity,
                        pidfd,
                    }))
                }
                Ok(_) => Recovery::Blocked(
                    "Mihomo identity changed while recovery was being verified".into(),
                ),
                Err(error) => {
                    Recovery::Blocked(format!("cannot recheck recovered Mihomo process: {error}"))
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn open_verified_pidfd(record: &OwnerRecord, pid: u32) -> Result<OwnedFd, String> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
    if fd < 0 {
        return Err(format!(
            "cannot safely recover Mihomo: pidfd_open failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    let current = ownership::inspect_process(Path::new("/proc"), pid)
        .map_err(|error| format!("cannot verify process after pidfd_open: {error}"))?;
    if !ownership::matches_record(record, &current, record.start_ticks) {
        return Err("Mihomo process identity changed during pidfd recovery".into());
    }
    Ok(pidfd)
}

#[cfg(not(target_os = "linux"))]
fn open_verified_pidfd(_record: &OwnerRecord, _pid: u32) -> Result<OwnedFd, String> {
    Err("safe Mihomo adoption requires Linux pidfd support".into())
}

fn validate_optional_private_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600 =>
        {
            Err(format!(
                "managed file {} has unexpected type, owner, links, or permissions",
                path.display()
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect managed file {}: {error}",
            path.display()
        )),
    }
}

fn validate_optional_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect managed directory {}: {error}",
            path.display()
        )),
    }
}

fn validate_controller_socket_path() -> Result<(), String> {
    let path = Path::new(paths::MIHOMO_CONTROLLER_SOCKET);
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_socket()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0 =>
        {
            Err("managed Mihomo controller socket has unexpected type, owner, links, or permissions".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect managed controller socket: {error}")),
    }
}

fn validate_managed_tree(root: &Path, mihomo_dir: &Path, state_file: &Path) -> Result<(), String> {
    if mihomo_dir.parent() != Some(root) || state_file.parent() != Some(mihomo_dir) {
        return Err("managed Mihomo paths do not match the declared directory layout".into());
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("managed runtime root is unavailable: {error}"))?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.uid() != unsafe { libc::geteuid() }
        || root_metadata.mode() & 0o7777 != 0o700
    {
        return Err("managed runtime root has unexpected type or owner".into());
    }

    let directory_metadata = match fs::symlink_metadata(mihomo_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect managed Mihomo directory: {error}")),
    };
    validate_private_directory(mihomo_dir, &directory_metadata)?;

    validate_optional_private_file(state_file)
}

fn ensure_private_directory(root: &Path, mihomo_dir: &Path) -> Result<(), String> {
    if mihomo_dir.parent() != Some(root) {
        return Err("managed Mihomo directory is outside the declared runtime root".into());
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("managed runtime root is unavailable: {error}"))?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.uid() != unsafe { libc::geteuid() }
        || root_metadata.mode() & 0o7777 != 0o700
    {
        return Err("managed runtime root has unexpected type or owner".into());
    }
    match fs::symlink_metadata(mihomo_dir) {
        Ok(metadata) => validate_private_directory(mihomo_dir, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(mihomo_dir)
                .map_err(|error| format!("cannot create managed Mihomo directory: {error}"))?;
            let metadata = fs::symlink_metadata(mihomo_dir)
                .map_err(|error| format!("cannot verify managed Mihomo directory: {error}"))?;
            validate_private_directory(mihomo_dir, &metadata)
        }
        Err(error) => Err(format!("cannot inspect managed Mihomo directory: {error}")),
    }
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(format!(
            "managed directory {} has unexpected type, owner, or permissions",
            path.display()
        ));
    }
    Ok(())
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
    ensure_proxy_only_runtime_dir()?;
    let binary = ownership::validate_binary(Path::new(BINARY))?;
    let boot_id = ownership::read_boot_id(Path::new("/proc"))?;
    validate_optional_private_file(Path::new(LOG))?;
    let prior_log_identity = match fs::symlink_metadata(LOG) {
        Ok(metadata) => Some(FileIdentity::from_metadata(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot inspect {LOG}: {error}")),
    };
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(LOG)
        .map_err(|e| format!("cannot open {LOG}: {e}"))?;
    let log_metadata = log
        .metadata()
        .map_err(|e| format!("cannot inspect {LOG}: {e}"))?;
    if !log_metadata.is_file()
        || log_metadata.uid() != unsafe { libc::geteuid() }
        || log_metadata.nlink() != 1
        || log_metadata.mode() & 0o7777 != 0o600
        || prior_log_identity
            .is_some_and(|identity| identity != FileIdentity::from_metadata(&log_metadata))
    {
        return Err(format!(
            "managed Mihomo log {LOG} changed or has unexpected ownership/permissions"
        ));
    }
    let log_err = log
        .try_clone()
        .map_err(|e| format!("cannot open {LOG}: {e}"))?;
    let owner_token = random_owner_token()?;
    let owner = ownership::starting_record(
        Path::new(BINARY),
        &binary,
        Path::new(DIR),
        Path::new(CONFIG),
        owner_token.clone(),
        boot_id,
    );
    let mut owner_file = ownership::reserve_owner_file(Path::new(PIDFILE), &owner)?;
    let mut cmd = Command::new(BINARY);
    cmd.args(["-d", DIR, "-f", CONFIG])
        .env("GOMEMLIMIT", "160MiB")
        .env(ownership::OWNER_TOKEN_ENV, owner_token)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err);
    // Own session: an agent restart (deploy, crash) must not take mihomo with it.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = ownership::remove_owner_file(Path::new(PIDFILE), owner_file);
            return Err(format!("failed to start mihomo: {error}"));
        }
    };
    let pid = child.id();
    let evidence = match wait_for_process_evidence(pid) {
        Ok(evidence) if ownership::matches_record(&owner, &evidence, None) => evidence,
        Ok(_) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = ownership::remove_owner_file(Path::new(PIDFILE), owner_file);
            return Err(
                "new Mihomo process failed executable/argument ownership verification".into(),
            );
        }
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = ownership::remove_owner_file(Path::new(PIDFILE), owner_file);
            return Err(error);
        }
    };
    let pidfd = match open_verified_pidfd(&owner, pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = ownership::remove_owner_file(Path::new(PIDFILE), owner_file);
            return Err(error);
        }
    };
    let mut owner = owner;
    owner.phase = Phase::Running;
    owner.pid = Some(pid);
    owner.start_ticks = Some(evidence.start_ticks);
    owner_file = match ownership::complete_owner_file(Path::new(PIDFILE), owner_file, &owner) {
        Ok(identity) => identity,
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = ownership::remove_owner_file(Path::new(PIDFILE), owner_file);
            return Err(error);
        }
    };
    Ok(Process {
        child: Some(child),
        pid,
        started: Instant::now(),
        owner,
        owner_file,
        pidfd,
    })
}

fn random_owner_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| format!("secure process owner token generation failed: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn wait_for_process_evidence(pid: u32) -> Result<ProcessEvidence, String> {
    let mut last_error = None;
    for _ in 0..20 {
        match ownership::inspect_process(Path::new("/proc"), pid) {
            Ok(process) => return Ok(process),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "cannot verify new Mihomo process: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "process identity unavailable".into())
    ))
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
    pub fn verify_alive(&mut self) -> Result<bool, String> {
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(None) => {}
                Ok(Some(_)) => {
                    self.remove_verified_owner_record()?;
                    return Ok(false);
                }
                Err(error) => return Err(format!("cannot inspect Mihomo child process: {error}")),
            }
        }
        if pidfd_exited(self.pidfd.as_raw_fd())? {
            self.remove_verified_owner_record()?;
            return Ok(false);
        }
        let process = ownership::inspect_process(Path::new("/proc"), self.pid)
            .map_err(|error| format!("cannot verify managed Mihomo process: {error}"))?;
        if !ownership::matches_record(&self.owner, &process, self.owner.start_ticks) {
            return Err(
                "managed Mihomo PID no longer matches its recorded start identity; lifecycle blocked"
                    .into(),
            );
        }
        Ok(true)
    }

    pub fn alive(&mut self) -> bool {
        self.verify_alive().unwrap_or(false)
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

    /// Clear this manager's PID record only after its child handle confirms
    /// that the process exited. Used for a failed immediate start.
    pub fn clear_pidfile_if_child_exited(&mut self) {
        if self
            .child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(Some(_))))
        {
            let _ = self.remove_verified_owner_record();
        }
    }

    /// SIGTERM, wait up to 5 s, then SIGKILL. A forced exit can leave TUN
    /// routing resources; the next start detects them and fails closed.
    pub fn terminate(&mut self) -> Result<bool, String> {
        if self.process_exited()? {
            self.remove_verified_owner_record()?;
            return Ok(false);
        }
        self.signal(libc::SIGTERM)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.process_exited()? {
                self.remove_verified_owner_record()?;
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if self.process_exited()? {
            self.remove_verified_owner_record()?;
            return Ok(false);
        }
        self.signal(libc::SIGKILL)?;
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.process_exited()? {
                self.remove_verified_owner_record()?;
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err("managed Mihomo did not exit after SIGKILL; ownership record retained".into())
    }

    fn process_exited(&mut self) -> Result<bool, String> {
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(true),
                Ok(None) => {}
                Err(error) => return Err(format!("cannot inspect Mihomo child process: {error}")),
            }
        }
        pidfd_exited(self.pidfd.as_raw_fd())
    }

    fn signal(&self, number: libc::c_int) -> Result<(), String> {
        let process = ownership::inspect_process(Path::new("/proc"), self.pid)
            .map_err(|error| format!("cannot re-verify managed Mihomo before stop: {error}"))?;
        if !ownership::matches_record(&self.owner, &process, self.owner.start_ticks) {
            return Err("managed Mihomo identity changed; refusing to signal it".into());
        }
        send_pidfd_signal(self.pidfd.as_raw_fd(), number)
    }

    fn remove_verified_owner_record(&mut self) -> Result<(), String> {
        ownership::remove_owner_file(Path::new(PIDFILE), self.owner_file)
    }
}

fn pidfd_exited(fd: libc::c_int) -> Result<bool, String> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(format!(
            "cannot inspect managed Mihomo pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(result > 0 && descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

fn send_pidfd_signal(fd: libc::c_int, signal: libc::c_int) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            return Ok(());
        }
        return Err(format!(
            "could not signal verified Mihomo pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, signal);
        Err("safe managed Mihomo signaling requires Linux pidfd support".into())
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

/// Fail before writing a candidate config when its client-facing listener is
/// already owned by another service. This is a read-only bind probe; start
/// still relies on Mihomo's actual bind result to close the race.
pub fn preflight_proxy_port(ip: &str, port: u16) -> Result<(), String> {
    let address = ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "managed Mihomo listener address is not IPv4".to_string())?;
    if port == 0 {
        return Err("managed Mihomo listener port must be nonzero".into());
    }
    std::net::TcpListener::bind((address, port))
        .map(drop)
        .map_err(|error| {
            format!("managed Mihomo listener {address}:{port} is unavailable: {error}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn legacy_mihomo_blocks_start_and_recovery_even_without_listeners() {
        let root = std::env::temp_dir().join(format!("u60-legacy-{}", std::process::id()));
        let proc_root = root.join("proc");
        let legacy = root.join("legacy-mihomo");
        let proc_pid = proc_root.join("41");
        fs::create_dir_all(&proc_pid).unwrap();
        fs::write(&legacy, b"synthetic executable").unwrap();
        let exe = proc_pid.join("exe");
        let alias = root.join("other-name");
        fs::write(&alias, b"different executable").unwrap();
        std::os::unix::fs::symlink(&alias, &exe).unwrap();
        assert!(check_legacy_mihomo_absent(&proc_root, &legacy).is_ok());
        fs::remove_file(&exe).unwrap();
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&legacy, &alias).unwrap();
        std::os::unix::fs::symlink(&alias, &exe).unwrap();
        assert!(check_legacy_mihomo_absent(&proc_root, &legacy).is_err());
        fs::remove_file(&exe).unwrap();
        fs::remove_file(&legacy).unwrap();
        std::os::unix::fs::symlink(format!("{} (deleted)", legacy.display()), &exe).unwrap();
        assert!(check_legacy_mihomo_absent(&proc_root, &legacy).is_err());
        fs::remove_file(&exe).unwrap();
        std::os::unix::fs::symlink(&legacy, &exe).unwrap();
        assert!(check_legacy_mihomo_absent(&proc_root, &legacy).is_err());
        fs::remove_file(&exe).unwrap();
        std::os::unix::fs::symlink(&alias, &exe).unwrap();
        let cmdline = proc_pid.join("cmdline");
        fs::write(&cmdline, [legacy.as_os_str().as_bytes(), b"\0"].concat()).unwrap();
        assert!(check_legacy_mihomo_absent(&proc_root, &legacy).is_err());
        fs::write(&cmdline, b"unrelated\0").unwrap();
        assert!(check_legacy_mihomo_absent(&proc_root, &legacy).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn proxy_only_runtime_paths_require_owned_private_paths() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "u60-managed-paths-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mihomo_dir = root.join("mihomo");
        let state_file = mihomo_dir.join("manager.json");
        assert!(validate_managed_tree(&root, &mihomo_dir, &state_file).is_ok());

        ensure_private_directory(&root, &mihomo_dir).unwrap();
        assert_eq!(fs::metadata(&mihomo_dir).unwrap().mode() & 0o777, 0o700);
        fs::write(&state_file, b"{}\n").unwrap();
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_managed_tree(&root, &mihomo_dir, &state_file).is_ok());

        let managed_log = mihomo_dir.join("mihomo.log");
        fs::write(&managed_log, b"log\n").unwrap();
        fs::set_permissions(&managed_log, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_optional_private_file(&managed_log).is_ok());
        fs::set_permissions(&managed_log, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_optional_private_file(&managed_log).is_err());
        fs::remove_file(&managed_log).unwrap();
        let linked_log = mihomo_dir.join("linked.log");
        std::os::unix::fs::symlink(&managed_log, &linked_log).unwrap();
        assert!(validate_optional_private_file(&linked_log).is_err());
        fs::remove_file(&linked_log).unwrap();

        let profiles = mihomo_dir.join("profiles");
        fs::create_dir(&profiles).unwrap();
        fs::set_permissions(&profiles, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_optional_private_directory(&profiles).is_ok());
        fs::remove_dir(&profiles).unwrap();
        std::os::unix::fs::symlink(&mihomo_dir, &profiles).unwrap();
        assert!(validate_optional_private_directory(&profiles).is_err());
        fs::remove_file(&profiles).unwrap();

        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_managed_tree(&root, &mihomo_dir, &state_file).is_err());
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&state_file).unwrap();
        let external_state = root.join("outside.json");
        fs::write(&external_state, b"{}\n").unwrap();
        std::os::unix::fs::symlink(&external_state, &state_file).unwrap();
        assert!(validate_managed_tree(&root, &mihomo_dir, &state_file).is_err());
        fs::remove_file(&state_file).unwrap();
        fs::remove_dir(&mihomo_dir).unwrap();
        fs::create_dir(&mihomo_dir).unwrap();
        fs::set_permissions(&mihomo_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_managed_tree(&root, &mihomo_dir, &state_file).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn proxy_listener_preflight_detects_existing_port_owner() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(preflight_proxy_port("127.0.0.1", port).is_err());
        drop(listener);
        assert!(preflight_proxy_port("127.0.0.1", port).is_ok());
        assert!(preflight_proxy_port("not-an-ip", port).is_err());
        assert!(preflight_proxy_port("127.0.0.1", 0).is_err());
    }

    #[test]
    fn lifecycle_lock_serializes_concurrent_manager_instances_and_releases_on_drop() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "u60-manager-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("manager.lock");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut attempts = Vec::new();
        for _ in 0..2 {
            let barrier = std::sync::Arc::clone(&barrier);
            let path = path.clone();
            attempts.push(std::thread::spawn(move || {
                barrier.wait();
                let lock = acquire_lock_at(&path);
                let acquired = lock.is_ok();
                barrier.wait();
                drop(lock);
                acquired
            }));
        }
        barrier.wait();
        barrier.wait();
        let acquired = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .filter(|acquired| *acquired)
            .count();
        assert_eq!(acquired, 1);
        assert!(acquire_lock_at(&path).is_ok());
        let _ = fs::remove_dir_all(root);
    }

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
