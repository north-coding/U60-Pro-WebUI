//! Durable evidence for the one Mihomo process owned by the proxy-only Agent.
//!
//! The record is deliberately small and lives beside the managed runtime. A
//! PID alone is never sufficient to adopt or signal a process.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const OWNER_TOKEN_ENV: &str = "U60_MIHOMO_OWNER_TOKEN";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

impl FileIdentity {
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Starting,
    Running,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecord {
    pub schema: u8,
    pub phase: Phase,
    pub pid: Option<u32>,
    pub start_ticks: Option<u64>,
    pub executable: String,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable_sha256: String,
    pub runtime_dir: String,
    pub config: String,
    pub owner_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessEvidence {
    pub pid: u32,
    pub uid: u32,
    pub start_ticks: u64,
    pub executable: PathBuf,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub command_line: Vec<String>,
    pub owner_token: Option<String>,
}

#[derive(Debug)]
pub enum Inspection {
    Stopped,
    Owned {
        record: Box<OwnerRecord>,
        file_identity: FileIdentity,
        process: Box<ProcessEvidence>,
        record_needs_completion: bool,
    },
    Blocked(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryIdentity {
    pub device: u64,
    pub inode: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BinarySnapshot {
    device: u64,
    inode: u64,
    size: u64,
    uid: u32,
    mode: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl BinarySnapshot {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

pub fn validate_binary(path: &Path) -> Result<BinaryIdentity, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("managed Mihomo binary is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("managed Mihomo binary must be a regular, non-symbolic-link file".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("cannot read managed Mihomo binary: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect managed Mihomo binary: {error}"))?;
    let initial = BinarySnapshot::from_metadata(&opened);
    if metadata.file_type().is_symlink()
        || !opened.is_file()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.nlink() != 1
        || opened.mode() & 0o111 == 0
        || BinarySnapshot::from_metadata(&metadata) != initial
    {
        return Err("managed Mihomo binary has unexpected type, owner, links, or mode".into());
    }

    let mut elf_header = [0u8; 20];
    file.read_exact(&mut elf_header)
        .map_err(|error| format!("managed Mihomo binary has no complete ELF header: {error}"))?;
    let little_endian = elf_header[5] == 1;
    let machine = if little_endian {
        u16::from_le_bytes([elf_header[18], elf_header[19]])
    } else {
        u16::from_be_bytes([elf_header[18], elf_header[19]])
    };
    if &elf_header[..4] != b"\x7fELF"
        || elf_header[4] != 2
        || !matches!(elf_header[5], 1 | 2)
        || machine != 183
    {
        return Err("managed Mihomo binary must be a 64-bit AArch64 ELF executable".into());
    }

    // The header was read for validation, but it remains part of the binary's
    // identity. Hash those exact bytes before continuing from the current fd
    // offset so the digest covers the executable from byte zero to EOF.
    let mut hasher = Sha256::new();
    hasher.update(elf_header);
    let mut total_bytes = elf_header.len() as u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash managed Mihomo binary: {error}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total_bytes = total_bytes.saturating_add(count as u64);
    }
    if total_bytes != initial.size {
        return Err("managed Mihomo binary size changed while it was being hashed".into());
    }
    verify_binary_unchanged(path, &file, initial)?;
    Ok(BinaryIdentity {
        device: initial.device,
        inode: initial.inode,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn verify_binary_unchanged(
    path: &Path,
    file: &File,
    initial: BinarySnapshot,
) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot recheck managed Mihomo binary: {error}"))?;
    let current_path = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot recheck managed Mihomo binary path: {error}"))?;
    if current_path.file_type().is_symlink()
        || !current_path.is_file()
        || BinarySnapshot::from_metadata(&opened) != initial
        || BinarySnapshot::from_metadata(&current_path) != initial
    {
        return Err("managed Mihomo binary changed while its identity was being checked".into());
    }
    Ok(())
}

pub fn starting_record(
    executable: &Path,
    binary: &BinaryIdentity,
    runtime_dir: &Path,
    config: &Path,
    owner_token: String,
) -> OwnerRecord {
    OwnerRecord {
        schema: 1,
        phase: Phase::Starting,
        pid: None,
        start_ticks: None,
        executable: executable.to_string_lossy().into_owned(),
        executable_device: binary.device,
        executable_inode: binary.inode,
        executable_sha256: binary.sha256.clone(),
        runtime_dir: runtime_dir.to_string_lossy().into_owned(),
        config: config.to_string_lossy().into_owned(),
        owner_token,
    }
}

pub fn create_record(path: &Path, record: &OwnerRecord) -> Result<FileIdentity, String> {
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("cannot reserve managed Mihomo owner record: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("cannot persist managed Mihomo owner record: {error}"))?;
    let identity = FileIdentity::from_metadata(
        &file
            .metadata()
            .map_err(|error| format!("cannot verify owner record: {error}"))?,
    );
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot sync owner record directory: {error}"))?;
    }
    Ok(identity)
}

pub fn replace_record(
    path: &Path,
    old_identity: FileIdentity,
    record: &OwnerRecord,
) -> Result<FileIdentity, String> {
    verify_record_file(path, old_identity)?;
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    crate::storage::atomic_write(path, &bytes)
        .map_err(|error| format!("cannot update managed Mihomo owner record: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot verify updated owner record: {error}"))?;
    Ok(FileIdentity::from_metadata(&metadata))
}

pub fn remove_record(path: &Path, identity: FileIdentity) -> Result<(), String> {
    verify_record_file(path, identity)?;
    fs::remove_file(path)
        .map_err(|error| format!("cannot remove verified stale owner record: {error}"))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot sync owner record removal: {error}"))?;
    }
    Ok(())
}

fn verify_record_file(path: &Path, expected: FileIdentity) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect Mihomo owner record: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || FileIdentity::from_metadata(&metadata) != expected
    {
        return Err("Mihomo owner record changed or has unexpected ownership/permissions".into());
    }
    Ok(())
}

pub fn inspect_owner(
    record_path: &Path,
    proc_root: &Path,
    executable: &Path,
    runtime_dir: &Path,
    config: &Path,
) -> Inspection {
    let loaded = match read_record(record_path) {
        Ok(record) => record,
        Err(error) => return Inspection::Blocked(error),
    };
    let Some((mut record, file_identity)) = loaded else {
        return match scan_runtime_claims(proc_root, executable, runtime_dir, config) {
            Ok(found) if found.is_empty() => Inspection::Stopped,
            Ok(_) => Inspection::Blocked("an unrecorded process uses the managed Mihomo executable/runtime; refusing adoption".into()),
            Err(error) => Inspection::Blocked(error),
        };
    };

    if record.schema != 1
        || record.executable != executable.to_string_lossy()
        || record.runtime_dir != runtime_dir.to_string_lossy()
        || record.config != config.to_string_lossy()
        || record.owner_token.len() != 64
        || !record
            .owner_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Inspection::Blocked(
            "Mihomo owner record does not match the managed runtime".into(),
        );
    }
    let binary = match validate_binary(executable) {
        Ok(identity) => identity,
        Err(error) => return Inspection::Blocked(error),
    };
    if binary.device != record.executable_device
        || binary.inode != record.executable_inode
        || binary.sha256 != record.executable_sha256
    {
        return Inspection::Blocked(
            "managed Mihomo binary identity changed since the owner record was written".into(),
        );
    }

    match record.phase {
        Phase::Running => {
            let (Some(pid), Some(start_ticks)) = (record.pid, record.start_ticks) else {
                return Inspection::Blocked("running Mihomo owner record is incomplete".into());
            };
            match inspect_process(proc_root, pid) {
                Ok(process) if matches_record(&record, &process, Some(start_ticks)) => {
                    match scan_runtime_claims(proc_root, executable, runtime_dir, config) {
                        Ok(found)
                            if found.len() == 1
                                && found[0].pid == pid
                                && found[0].owner_token.as_deref() == Some(&record.owner_token) =>
                        {
                            Inspection::Owned {
                                record: Box::new(record),
                                file_identity,
                                process: Box::new(process),
                                record_needs_completion: false,
                            }
                        }
                        Ok(_) => Inspection::Blocked(
                            "multiple or conflicting processes claim the managed Mihomo runtime".into(),
                        ),
                        Err(error) => Inspection::Blocked(error),
                    }
                }
                Ok(_) => Inspection::Blocked("Mihomo PID exists but its start identity, executable, arguments, or owner token does not match".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match scan_runtime_claims(proc_root, executable, runtime_dir, config) {
                        Ok(found) if found.is_empty() => match remove_record(record_path, file_identity) {
                            Ok(()) => Inspection::Stopped,
                            Err(error) => Inspection::Blocked(error),
                        },
                        Ok(_) => Inspection::Blocked(
                            "the recorded Mihomo PID is gone but another matching process remains".into(),
                        ),
                        Err(error) => Inspection::Blocked(error),
                    }
                }
                Err(error) => Inspection::Blocked(format!("cannot verify managed Mihomo process: {error}")),
            }
        }
        Phase::Starting => {
            if record.pid.is_some() || record.start_ticks.is_some() {
                return Inspection::Blocked(
                    "starting Mihomo owner record has unexpected process identity".into(),
                );
            }
            match scan_runtime_claims(proc_root, executable, runtime_dir, config) {
                Ok(found) if found.is_empty() => match remove_record(record_path, file_identity) {
                    Ok(()) => Inspection::Stopped,
                    Err(error) => Inspection::Blocked(error),
                },
                Ok(mut found) if found.len() == 1 => {
                    let process = found.remove(0);
                    if !matches_record(&record, &process, None) {
                        return Inspection::Blocked("starting record token belongs to a process with an unexpected identity".into());
                    }
                    record.phase = Phase::Running;
                    record.pid = Some(process.pid);
                    record.start_ticks = Some(process.start_ticks);
                    Inspection::Owned {
                        record: Box::new(record),
                        file_identity,
                        process: Box::new(process),
                        record_needs_completion: true,
                    }
                }
                Ok(_) => {
                    Inspection::Blocked("multiple processes claim one Mihomo owner token".into())
                }
                Err(error) => Inspection::Blocked(error),
            }
        }
    }
}

pub fn finish_record(
    path: &Path,
    old_identity: FileIdentity,
    record: &OwnerRecord,
) -> Result<FileIdentity, String> {
    replace_record(path, old_identity, record)
}

fn read_record(path: &Path) -> Result<Option<(OwnerRecord, FileIdentity)>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect Mihomo owner record: {error}")),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 4096
    {
        return Err("Mihomo owner record has unexpected type, owner, links, size, or mode".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("cannot read Mihomo owner record: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect Mihomo owner record: {error}"))?;
    if FileIdentity::from_metadata(&metadata) != FileIdentity::from_metadata(&opened)
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.mode() & 0o7777 != 0o600
        || opened.len() > 4096
    {
        return Err("Mihomo owner record changed while being read".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read Mihomo owner record: {error}"))?;
    let record = serde_json::from_slice(&bytes).map_err(|error| {
        format!("Mihomo owner record is malformed or from an unknown version: {error}")
    })?;
    Ok(Some((record, FileIdentity::from_metadata(&metadata))))
}

pub fn inspect_process(proc_root: &Path, pid: u32) -> std::io::Result<ProcessEvidence> {
    let base = proc_root.join(pid.to_string());
    let metadata = fs::metadata(&base)?;
    let executable = fs::read_link(base.join("exe"))?;
    let executable_metadata = fs::metadata(base.join("exe"))?;
    let command_line = fs::read(base.join("cmdline"))?
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    let environ = fs::read(base.join("environ"))?;
    let owner_token = environ
        .split(|byte| *byte == 0)
        .find_map(|entry| entry.strip_prefix(format!("{OWNER_TOKEN_ENV}=").as_bytes()))
        .map(|value| String::from_utf8_lossy(value).into_owned());
    let stat = fs::read_to_string(base.join("stat"))?;
    let suffix = stat
        .rsplit_once(')')
        .map(|(_, suffix)| suffix)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid /proc stat")
        })?;
    let fields: Vec<&str> = suffix.split_whitespace().collect();
    if fields
        .first()
        .is_some_and(|state| matches!(*state, "Z" | "X"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "process has exited",
        ));
    }
    let start_ticks = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing process start time",
            )
        })?;
    Ok(ProcessEvidence {
        pid,
        uid: metadata.uid(),
        start_ticks,
        executable,
        executable_device: executable_metadata.dev(),
        executable_inode: executable_metadata.ino(),
        command_line,
        owner_token,
    })
}

pub fn matches_record(
    record: &OwnerRecord,
    process: &ProcessEvidence,
    expected_start: Option<u64>,
) -> bool {
    process.uid == unsafe { libc::geteuid() }
        && process.executable == Path::new(&record.executable)
        && process.executable_device == record.executable_device
        && process.executable_inode == record.executable_inode
        && expected_start.is_none_or(|start| process.start_ticks == start)
        && process.owner_token.as_deref() == Some(record.owner_token.as_str())
        && process.command_line
            == [
                record.executable.clone(),
                "-d".to_string(),
                record.runtime_dir.clone(),
                "-f".to_string(),
                record.config.clone(),
            ]
}

/// Find every process that could be using the managed binary or claiming the
/// managed runtime in argv. A matching binary with different argv (or the
/// expected argv with a different executable) is a conflict, never ignored.
fn scan_runtime_claims(
    proc_root: &Path,
    executable: &Path,
    runtime_dir: &Path,
    config: &Path,
) -> Result<Vec<ProcessEvidence>, String> {
    let entries = fs::read_dir(proc_root)
        .map_err(|error| format!("cannot inspect process table: {error}"))?;
    let expected_args = vec![
        executable.to_string_lossy().into_owned(),
        "-d".into(),
        runtime_dir.to_string_lossy().into_owned(),
        "-f".into(),
        config.to_string_lossy().into_owned(),
    ];
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inspect process table: {error}"))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        match inspect_process(proc_root, pid) {
            Ok(process)
                if process.executable == executable || process.command_line == expected_args =>
            {
                found.push(process)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot verify every process while checking for an unowned Mihomo instance: {error}"
                ))
            }
        }
    }
    Ok(found)
}

pub fn reserve_owner_file(path: &Path, record: &OwnerRecord) -> Result<FileIdentity, String> {
    create_record(path, record)
}

pub fn complete_owner_file(
    path: &Path,
    identity: FileIdentity,
    record: &OwnerRecord,
) -> Result<FileIdentity, String> {
    finish_record(path, identity, record)
}

pub fn remove_owner_file(path: &Path, identity: FileIdentity) -> Result<(), String> {
    remove_record(path, identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn scratch(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "u60-owner-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn fake_binary(path: &Path, machine: u16) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn proc_entry(proc_root: &Path, pid: u32, binary: &Path, token: &str, start_ticks: u64) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        symlink(binary, dir.join("exe")).unwrap();
        fs::write(
            dir.join("cmdline"),
            format!("{}\0-d\0/data/u60-pro-managed/mihomo\0-f\0/data/u60-pro-managed/mihomo/config.yaml\0", binary.display()),
        )
        .unwrap();
        fs::write(
            dir.join("environ"),
            format!("PATH=/bin\0{OWNER_TOKEN_ENV}={token}\0"),
        )
        .unwrap();
        let fields = (0..18).map(|_| "0").collect::<Vec<_>>().join(" ");
        fs::write(
            dir.join("stat"),
            format!("{pid} (mihomo) S {fields} {start_ticks} 0\n"),
        )
        .unwrap();
    }

    #[test]
    fn binary_validation_requires_owned_aarch64_elf_and_rejects_links() {
        let root = scratch("binary");
        let binary = root.join("mihomo");
        fake_binary(&binary, 183);
        assert!(validate_binary(&binary).is_ok());
        let wrong = root.join("wrong");
        fake_binary(&wrong, 62);
        assert!(validate_binary(&wrong).is_err());
        let link = root.join("link");
        symlink(&binary, &link).unwrap();
        assert!(validate_binary(&link).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn binary_sha256_covers_the_whole_file_including_valid_elf_header_bytes() {
        let root = scratch("full-binary-hash");
        let binary = root.join("mihomo");
        fake_binary(&binary, 183);

        let original = fs::read(&binary).unwrap();
        let identity = validate_binary(&binary).unwrap();
        assert_eq!(
            identity.sha256,
            format!("{:x}", Sha256::digest(&original)),
            "digest must equal an independent whole-file SHA-256 calculation"
        );

        let mut changed_header = original;
        changed_header[7] = 3; // A valid ELF OSABI value; architecture stays AArch64.
        fs::write(&binary, &changed_header).unwrap();
        let changed = validate_binary(&binary).unwrap();
        assert_ne!(identity.sha256, changed.sha256);
        assert_eq!(
            changed.sha256,
            format!("{:x}", Sha256::digest(&changed_header))
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn binary_validation_rejects_malformed_elf_headers_and_wrong_architecture() {
        let root = scratch("malformed-binary");
        let binary = root.join("mihomo");
        fake_binary(&binary, 62);
        assert!(validate_binary(&binary).is_err());

        fs::write(&binary, b"not an ELF executable with a long enough header").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_binary(&binary).is_err());

        fs::write(&binary, b"\x7fELF\x02\x01\x01").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_binary(&binary).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn binary_validation_rechecks_open_file_metadata_and_current_path() {
        let root = scratch("changed-binary");
        let binary = root.join("mihomo");
        fake_binary(&binary, 183);

        let file = OpenOptions::new().read(true).open(&binary).unwrap();
        let before = BinarySnapshot::from_metadata(&file.metadata().unwrap());
        let mut writer = OpenOptions::new().write(true).open(&binary).unwrap();
        writer.seek(SeekFrom::Start(40)).unwrap();
        writer.write_all(&[1]).unwrap();
        writer.sync_all().unwrap();
        assert!(verify_binary_unchanged(&binary, &file, before).is_err());

        drop(writer);
        drop(file);
        fake_binary(&binary, 183);
        let file = OpenOptions::new().read(true).open(&binary).unwrap();
        let before = BinarySnapshot::from_metadata(&file.metadata().unwrap());
        let replacement = root.join("replacement");
        fake_binary(&replacement, 183);
        fs::rename(&replacement, &binary).unwrap();
        assert!(verify_binary_unchanged(&binary, &file, before).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn durable_owner_record_recovers_only_the_same_pid_start_executable_args_and_token() {
        let root = scratch("recover");
        let binary = root.join("mihomo");
        let proc_root = root.join("proc");
        let record_path = root.join("mihomo.pid");
        let token = "ab".repeat(32);
        fake_binary(&binary, 183);
        let identity = validate_binary(&binary).unwrap();
        let mut record = starting_record(&binary, &identity, token.clone());
        let record_identity = create_record(&record_path, &record).unwrap();
        proc_entry(&proc_root, 41, &binary, &token, 12345);

        let process = inspect_process(&proc_root, 41).unwrap();
        assert!(matches_record(&record, &process, None));
        record.phase = Phase::Running;
        record.pid = Some(41);
        record.start_ticks = Some(12345);
        let identity = replace_record(&record_path, record_identity, &record).unwrap();
        match inspect_owner(
            &record_path,
            &proc_root,
            &binary,
            Path::new("/data/u60-pro-managed/mihomo"),
            Path::new("/data/u60-pro-managed/mihomo/config.yaml"),
        ) {
            Inspection::Owned {
                process,
                file_identity,
                record_needs_completion: false,
                ..
            } => {
                assert_eq!(process.pid, 41);
                assert_eq!(process.start_ticks, 12345);
                assert_eq!(file_identity, identity);
            }
            other => panic!("expected exact owner recovery, got {other:?}"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pid_reuse_and_executable_mismatch_block_without_deleting_record() {
        let root = scratch("reuse");
        let binary = root.join("mihomo");
        let other = root.join("other");
        let proc_root = root.join("proc");
        let record_path = root.join("mihomo.pid");
        let token = "cd".repeat(32);
        fake_binary(&binary, 183);
        fake_binary(&other, 183);
        let identity = validate_binary(&binary).unwrap();
        let mut record = starting_record(&binary, &identity, token.clone());
        record.phase = Phase::Running;
        record.pid = Some(41);
        record.start_ticks = Some(12345);
        create_record(&record_path, &record).unwrap();

        proc_entry(&proc_root, 41, &binary, &token, 67890);
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));
        fs::remove_dir_all(&proc_root).unwrap();
        proc_entry(&proc_root, 41, &other, &token, 12345);
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));
        assert!(record_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_and_corrupt_records_are_distinguished() {
        let root = scratch("stale");
        let binary = root.join("mihomo");
        let proc_root = root.join("proc");
        let record_path = root.join("mihomo.pid");
        fake_binary(&binary, 183);
        fs::create_dir_all(&proc_root).unwrap();
        let identity = validate_binary(&binary).unwrap();
        let mut record = starting_record(&binary, &identity, "ef".repeat(32));
        record.phase = Phase::Running;
        record.pid = Some(99999);
        record.start_ticks = Some(10);
        create_record(&record_path, &record).unwrap();
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Stopped
        ));
        fs::write(&record_path, b"not-json").unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));
        assert!(record_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unrecorded_and_wrong_token_processes_block_starting_record_recovery() {
        let root = scratch("unowned");
        let binary = root.join("mihomo");
        let proc_root = root.join("proc");
        let record_path = root.join("mihomo.pid");
        let token = "12".repeat(32);
        fake_binary(&binary, 183);
        let identity = validate_binary(&binary).unwrap();

        proc_entry(&proc_root, 41, &binary, &token, 10);
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));

        let record = starting_record(&binary, &identity, token.clone());
        create_record(&record_path, &record).unwrap();
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Owned { .. }
        ));
        fs::remove_dir_all(&proc_root).unwrap();
        proc_entry(&proc_root, 42, &binary, &"34".repeat(32), 11);
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));
        assert!(record_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unrecorded_project_binary_with_unexpected_runtime_args_blocks_start() {
        let root = scratch("unexpected-args");
        let binary = root.join("mihomo");
        let proc_root = root.join("proc");
        let record_path = root.join("mihomo.pid");
        fake_binary(&binary, 183);
        proc_entry(&proc_root, 41, &binary, &"ab".repeat(32), 10);
        fs::write(
            proc_root.join("41/cmdline"),
            format!(
                "{}\0-d\0/var/tmp/other\0-f\0/tmp/other.yaml\0",
                binary.display()
            ),
        )
        .unwrap();

        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_pid_record_is_not_removed_when_another_runtime_process_exists() {
        let root = scratch("stale-other");
        let binary = root.join("mihomo");
        let proc_root = root.join("proc");
        let record_path = root.join("mihomo.pid");
        fake_binary(&binary, 183);
        let identity = validate_binary(&binary).unwrap();
        let mut record = starting_record(&binary, &identity, "56".repeat(32));
        record.phase = Phase::Running;
        record.pid = Some(41);
        record.start_ticks = Some(10);
        create_record(&record_path, &record).unwrap();
        proc_entry(&proc_root, 42, &binary, &"78".repeat(32), 11);
        assert!(matches!(
            inspect_owner(
                &record_path,
                &proc_root,
                &binary,
                Path::new("/data/u60-pro-managed/mihomo"),
                Path::new("/data/u60-pro-managed/mihomo/config.yaml")
            ),
            Inspection::Blocked(_)
        ));
        assert!(record_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    fn starting_record(
        binary_path: &Path,
        identity: &BinaryIdentity,
        token: String,
    ) -> OwnerRecord {
        OwnerRecord {
            schema: 1,
            phase: Phase::Starting,
            pid: None,
            start_ticks: None,
            executable: binary_path.to_string_lossy().into_owned(),
            executable_device: identity.device,
            executable_inode: identity.inode,
            executable_sha256: identity.sha256.clone(),
            runtime_dir: "/data/u60-pro-managed/mihomo".into(),
            config: "/data/u60-pro-managed/mihomo/config.yaml".into(),
            owner_token: token,
        }
    }
}
