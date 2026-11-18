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

pub struct ProxyOnlyState {
    pub auth: AuthState,
    pub mihomo: Arc<Manager>,
    pub shutdown: Arc<AtomicBool>,
    pub https_origin: Option<String>,
}

pub fn run(bind: SocketAddr, https_origin: Option<String>) -> Result<(), String> {
    let password = match std::env::var_os("ZTE_AGENT_PASSWORD_FILE") {
        Some(path) if Path::new(&path) == Path::new(PROXY_AUTH_PASSWORD) => {
            validate_auth_directories()?;
            read_password_file(Path::new(PROXY_AUTH_PASSWORD))?
        }
        Some(_) => return Err("proxy-only password file must use the managed auth path".into()),
        None => std::env::var("ZTE_AGENT_PASSWORD")
            .map_err(|_| "managed password file or ZTE_AGENT_PASSWORD is required".to_string())?,
    };
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

fn read_password_file(path: &Path) -> Result<String, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("managed Agent password file is unavailable: {error}"))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > 513
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
        || after.mode() & 0o7777 != 0o600
        || after.len() > 513
    {
        return Err("managed Agent password file changed while being opened".into());
    }
    let mut bytes = Vec::with_capacity(after.len() as usize);
    file.take(514)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read managed Agent password file: {error}"))?;
    if bytes.len() > 513 {
        return Err("managed Agent password file is too long".into());
    }
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.pop();
    }
    if bytes.iter().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
        return Err("managed Agent password file must contain one line".into());
    }
    String::from_utf8(bytes).map_err(|_| "managed Agent password file is not UTF-8".into())
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
    if password.is_empty() {
        return Err("ZTE_AGENT_PASSWORD must not be empty".into());
    }
    if password.len() > 512 {
        return Err("ZTE_AGENT_PASSWORD is too long".into());
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
    use super::{read_password_file, validate_password};
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    #[test]
    fn proxy_only_requires_a_nonempty_bounded_password() {
        assert!(validate_password("").is_err());
        assert!(validate_password("secret").is_ok());
        assert!(validate_password(&"x".repeat(513)).is_err());
    }

    #[test]
    fn managed_password_file_requires_private_regular_single_line_content() {
        let root = std::env::temp_dir().join(format!("u60-password-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let password = root.join("password");
        fs::write(&password, b"synthetic_secret\r\n").unwrap();
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(&password).unwrap(), "synthetic_secret");

        fs::set_permissions(&password, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_password_file(&password).is_err());
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&password, b"secret\nextra\n").unwrap();
        assert!(read_password_file(&password).is_err());

        let link = root.join("password-link");
        symlink(&password, &link).unwrap();
        assert!(read_password_file(&link).is_err());
        assert!(read_password_file(Path::new("/path/that/does/not/exist")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
