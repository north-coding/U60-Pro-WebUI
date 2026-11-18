use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::auth::AuthState;
use crate::mihomo::{Manager, PROXY_AUTH_PASSWORD, PROXY_AUTH_SALT};
use crate::server;

const PASSWORD_LENGTH: usize = 43;

pub struct ProxyOnlyState {
    pub auth: AuthState,
    pub mihomo: Arc<Manager>,
    pub shutdown: Arc<AtomicBool>,
    pub https_origin: Option<String>,
}

pub fn run(bind: SocketAddr, https_origin: Option<String>) -> Result<(), String> {
    validate_password_file_env(std::env::var_os("ZTE_AGENT_PASSWORD_FILE").as_deref())?;
    validate_auth_directories()?;
    let password = read_password_file(Path::new(PROXY_AUTH_PASSWORD))?;
    validate_password(&password)?;

    // Validate the existing Mihomo-owned state before creating auth material.
    let mihomo = Arc::new(Manager::new_proxy_only()?);
    let auth = AuthState::new_with_salt_path(Path::new(PROXY_AUTH_SALT))?;
    auth.set_password(&password);
    let state = Arc::new(ProxyOnlyState {
        auth,
        mihomo,
        shutdown: Arc::new(AtomicBool::new(false)),
        https_origin,
    });
    eprintln!(
        "[agent] starting isolated proxy-management API on {bind}; legacy router initialization is disabled"
    );
    server::start_proxy_only(bind, state)
}

fn validate_password_file_env(value: Option<&OsStr>) -> Result<(), String> {
    let value = value.ok_or_else(|| "managed proxy-only password file is required".to_string())?;
    if Path::new(value) != Path::new(PROXY_AUTH_PASSWORD) {
        return Err("proxy-only password file must use the managed auth path".into());
    }
    Ok(())
}

fn read_password_file(path: &Path) -> Result<String, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("managed Agent password file is unavailable: {error}"))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() != (PASSWORD_LENGTH + 1) as u64
    {
        return Err(
            "managed Agent password file has unexpected type, owner, links, size, or mode".into(),
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("cannot read managed Agent password file: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot inspect managed Agent password file: {error}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.uid() != unsafe { libc::geteuid() }
        || after.nlink() != 1
        || after.mode() & 0o7777 != 0o600
        || after.len() != (PASSWORD_LENGTH + 1) as u64
    {
        return Err("managed Agent password file changed while being opened".into());
    }
    let mut bytes = Vec::with_capacity(after.len() as usize);
    (&file)
        .take((PASSWORD_LENGTH + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read managed Agent password file: {error}"))?;
    let after_read = file
        .metadata()
        .map_err(|error| format!("cannot inspect managed Agent password file: {error}"))?;
    let current_path = fs::symlink_metadata(path).map_err(|error| {
        format!("managed Agent password file changed while being read: {error}")
    })?;
    let same_identity = |left: &fs::Metadata, right: &fs::Metadata| {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
            && left.nlink() == right.nlink()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    };
    if !same_identity(&after, &after_read) || !same_identity(&after, &current_path) {
        return Err("managed Agent password file changed while being read".into());
    }
    if bytes.len() != PASSWORD_LENGTH + 1
        || bytes.last() != Some(&b'\n')
        || bytes[..PASSWORD_LENGTH]
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
    {
        return Err("managed Agent password file must contain one 32-byte base64url secret".into());
    }
    let password = String::from_utf8(bytes[..PASSWORD_LENGTH].to_vec())
        .map_err(|_| "managed Agent password file is malformed".to_string())?;
    validate_password(&password)?;
    Ok(password)
}

fn validate_auth_directories() -> Result<(), String> {
    for (path, expected_mode) in [
        (Path::new("/data"), None),
        (Path::new("/data/u60-pro-managed"), Some(0o700)),
        (
            Path::new(PROXY_AUTH_PASSWORD).parent().unwrap(),
            Some(0o700),
        ),
    ] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("managed authentication directory is unavailable: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || expected_mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode)
        {
            return Err(format!(
                "managed authentication directory {} has unexpected type, owner, or permissions",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() != PASSWORD_LENGTH
        || !password.is_ascii()
        || password
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
        || !matches!(
            password.as_bytes().last(),
            Some(
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            )
        )
    {
        return Err("proxy-only password must be a 32-byte base64url secret".into());
    }
    Ok(())
}

#[cfg(test)]
impl ProxyOnlyState {
    pub(crate) fn new_for_test(
        password: &str,
        salt_path: &Path,
        state_path: std::path::PathBuf,
    ) -> Result<Self, String> {
        validate_password(password)?;
        let auth = AuthState::new_with_salt_path(salt_path)?;
        auth.set_password(password);
        Ok(Self {
            auth,
            mihomo: Arc::new(Manager::new_proxy_only_for_test(state_path)),
            shutdown: Arc::new(AtomicBool::new(false)),
            https_origin: None,
        })
    }

    pub(crate) fn new_for_test_with_origin(
        password: &str,
        salt_path: &Path,
        state_path: std::path::PathBuf,
        https_origin: Option<String>,
    ) -> Result<Self, String> {
        let mut state = Self::new_for_test(password, salt_path, state_path)?;
        state.https_origin = https_origin;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        read_password_file, validate_password, validate_password_file_env, PASSWORD_LENGTH,
    };
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    #[test]
    fn proxy_only_requires_a_32_byte_base64url_secret() {
        let strong = "A".repeat(PASSWORD_LENGTH);
        assert!(validate_password(&strong).is_ok());
        assert!(validate_password("secret").is_err());
        assert!(validate_password(&"x".repeat(PASSWORD_LENGTH - 1)).is_err());
        assert!(validate_password(&format!("{}!", "x".repeat(PASSWORD_LENGTH - 1))).is_err());
        assert!(validate_password(&"x".repeat(PASSWORD_LENGTH + 1)).is_err());
        assert!(validate_password(&format!("{}B", "A".repeat(PASSWORD_LENGTH - 1))).is_err());
        assert!(validate_password(&format!("{}é", "x".repeat(PASSWORD_LENGTH - 2))).is_err());
    }

    #[test]
    fn proxy_only_requires_the_managed_owner_only_password_file() {
        assert!(validate_password_file_env(None).is_err());
        assert!(validate_password_file_env(Some(std::ffi::OsStr::new("/tmp/password"))).is_err());
        assert!(
            validate_password_file_env(Some(std::ffi::OsStr::new(super::PROXY_AUTH_PASSWORD)))
                .is_ok()
        );
    }

    #[test]
    fn managed_password_file_requires_private_regular_single_line_content() {
        let root = std::env::temp_dir().join(format!("u60-password-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let password = root.join("password");
        let strong = "A".repeat(PASSWORD_LENGTH);
        fs::write(&password, format!("{strong}\n")).unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(&password).unwrap(), strong);

        fs::set_permissions(&password, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_password_file(&password).is_err());
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&password, b"secret\nextra\n").unwrap();
        assert!(read_password_file(&password).is_err());
        fs::write(&password, format!("{}!\n", "A".repeat(PASSWORD_LENGTH - 1))).unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_password_file(&password).is_err());
        fs::write(&password, format!("{}B\n", "A".repeat(PASSWORD_LENGTH - 1))).unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_password_file(&password).is_err());
        fs::write(&password, format!("{}\r\n", "A".repeat(PASSWORD_LENGTH))).unwrap();
        assert!(read_password_file(&password).is_err());

        let link = root.join("password-link");
        symlink(&password, &link).unwrap();
        assert!(read_password_file(&link).is_err());
        assert!(read_password_file(Path::new("/path/that/does/not/exist")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
