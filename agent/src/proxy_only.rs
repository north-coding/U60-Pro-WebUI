use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::auth::AuthState;
use crate::mihomo::{Manager, PROXY_AUTH_SALT};
use crate::server;

pub struct ProxyOnlyState {
    pub auth: AuthState,
    pub mihomo: Arc<Manager>,
}

pub fn run(bind: SocketAddr) -> Result<(), String> {
    let password = std::env::var("ZTE_AGENT_PASSWORD")
        .map_err(|_| "ZTE_AGENT_PASSWORD is required in proxy-only mode".to_string())?;
    validate_password(&password)?;

    // Validate the existing Mihomo-owned state before creating auth material.
    let mihomo = Arc::new(Manager::new_proxy_only()?);
    let auth = AuthState::new_with_salt_path(Path::new(PROXY_AUTH_SALT))?;
    auth.set_password(&password);
    let state = Arc::new(ProxyOnlyState { auth, mihomo });
    eprintln!(
        "[agent] starting isolated proxy-management API on {bind}; legacy router initialization is disabled"
    );
    server::start_proxy_only(bind, state)
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::validate_password;

    #[test]
    fn proxy_only_requires_a_nonempty_bounded_password() {
        assert!(validate_password("").is_err());
        assert!(validate_password("secret").is_ok());
        assert!(validate_password(&"x".repeat(513)).is_err());
    }
}
