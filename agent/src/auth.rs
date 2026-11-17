use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::util::MutexExt;

const SALT_PATH: &str = "/data/.zte-agent-salt";
const TOKEN_TTL_SECS: u64 = 3600;
const MAX_TOKENS: usize = 10;
const HASH_ITERATIONS: u32 = 10_000;
const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOGIN_LOCKOUT_SECS: u64 = 30;
/// Forget a client's failure history after this long without a failed attempt,
/// so the map can't accumulate one row per IP that ever mistyped a password.
const LOGIN_ATTEMPT_TTL_SECS: u64 = 3600;

pub struct AuthState {
    password_hash: Mutex<Option<String>>,
    pin_hash: Mutex<Option<String>>,
    salt: Mutex<Vec<u8>>,
    tokens: Mutex<Vec<Token>>,
    failed_logins: Mutex<HashMap<String, LoginAttempt>>,
}

struct Token {
    value: String,
    expires: u64,
}

struct LoginAttempt {
    count: u32,
    locked_until: u64,
    last_attempt: u64,
}

impl AuthState {
    pub fn new() -> Self {
        let salt = load_or_create_salt();
        Self::from_salt(salt)
    }

    /// Create the password-only proxy auth state with its salt in the managed
    /// runtime tree. Unlike legacy `new()`, failures are fatal to startup.
    pub fn new_with_salt_path(path: &Path) -> Result<Self, String> {
        let salt = load_or_create_salt_at(path)?;
        Ok(Self::from_salt(salt))
    }

    fn from_salt(salt: Vec<u8>) -> Self {
        Self {
            password_hash: Mutex::new(None),
            pin_hash: Mutex::new(None),
            salt: Mutex::new(salt),
            tokens: Mutex::new(Vec::new()),
            failed_logins: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_password(&self, password: &str) {
        let salt = self.salt.safe_lock();
        let hash = iterated_hash(&salt, password);
        *self.password_hash.safe_lock() = Some(hash);
    }

    pub fn set_pin(&self, pin: &str) -> Result<(), String> {
        validate_pin(pin)?;
        let salt = self.salt.safe_lock();
        let hash = iterated_hash(&salt, pin);
        *self.pin_hash.safe_lock() = Some(hash);
        Ok(())
    }

    pub fn has_pin(&self) -> bool {
        self.pin_hash.safe_lock().is_some()
    }

    pub fn has_password(&self) -> bool {
        self.password_hash.safe_lock().is_some()
    }

    pub fn login_password(&self, password: &str, client_ip: &str) -> LoginResult {
        self.login_against(password, &self.password_hash, client_ip)
    }

    pub fn login_pin(&self, pin: &str, client_ip: &str) -> LoginResult {
        if validate_pin(pin).is_err() {
            self.record_failed_login(client_ip, epoch_secs());
            return LoginResult::Invalid;
        }
        self.login_against(pin, &self.pin_hash, client_ip)
    }

    fn login_against(
        &self,
        credential: &str,
        stored_hash: &Mutex<Option<String>>,
        client_ip: &str,
    ) -> LoginResult {
        let now = epoch_secs();

        {
            let mut attempts = self.failed_logins.safe_lock();
            if let Some(attempt) = attempts.get(client_ip) {
                if attempt.count >= MAX_LOGIN_ATTEMPTS {
                    if now < attempt.locked_until {
                        return LoginResult::Locked {
                            retry_after_secs: attempt.locked_until - now,
                        };
                    }
                    // Lockout expired — clear the counter and let this attempt run.
                    // Only clear here: clearing on every unlocked attempt (as this
                    // used to) reset `count` to 1 each time, so the threshold was
                    // never reached and the lockout never armed.
                    attempts.remove(client_ip);
                }
            }
        }

        let salt = self.salt.safe_lock();
        let hash = iterated_hash(&salt, credential);
        let stored = stored_hash.safe_lock();
        if stored.as_deref() != Some(&hash) {
            drop(stored);
            drop(salt);
            self.record_failed_login(client_ip, now);
            return LoginResult::Invalid;
        }
        drop(stored);
        drop(salt);

        {
            let mut attempts = self.failed_logins.safe_lock();
            attempts.remove(client_ip);
        }

        let mut random_bytes = [0u8; 16];
        read_urandom(&mut random_bytes);

        let token_bytes = {
            let mut hasher = Sha256::new();
            hasher.update(random_bytes);
            hasher.update(hash.as_bytes());
            hasher.update(now.to_le_bytes());
            let digest = hasher.finalize();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&digest[..16]);
            arr
        };
        let token = hex_encode(&token_bytes);

        let mut tokens = self.tokens.safe_lock();
        tokens.retain(|t| t.expires > now);
        if tokens.len() >= MAX_TOKENS {
            tokens.remove(0);
        }
        tokens.push(Token {
            value: token.clone(),
            expires: now + TOKEN_TTL_SECS,
        });

        LoginResult::Ok { token }
    }

    fn record_failed_login(&self, client_ip: &str, now: u64) {
        let mut attempts = self.failed_logins.safe_lock();
        attempts.retain(|_, a| {
            now < a.locked_until || now.saturating_sub(a.last_attempt) < LOGIN_ATTEMPT_TTL_SECS
        });
        let entry = attempts
            .entry(client_ip.to_string())
            .or_insert(LoginAttempt {
                count: 0,
                locked_until: 0,
                last_attempt: now,
            });
        entry.count += 1;
        entry.last_attempt = now;
        if entry.count >= MAX_LOGIN_ATTEMPTS {
            entry.locked_until = now + LOGIN_LOCKOUT_SECS;
        }
    }

    /// Validate a bearer token, sliding its expiry forward on success. Without
    /// the slide a dashboard left open is logged out mid-poll on the hour.
    pub fn validate(&self, token: &str) -> bool {
        let now = epoch_secs();
        let mut tokens = self.tokens.safe_lock();
        tokens.retain(|t| t.expires > now);
        match tokens.iter_mut().find(|t| t.value == token) {
            Some(t) => {
                t.expires = now + TOKEN_TTL_SECS;
                true
            }
            None => false,
        }
    }
}

pub enum LoginResult {
    Ok { token: String },
    Invalid,
    Locked { retry_after_secs: u64 },
}

fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err("PIN must be exactly 6 digits".into());
    }
    Ok(())
}

fn iterated_hash(salt: &[u8], password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let mut digest = hasher.finalize();
    for _ in 1..HASH_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(digest);
        digest = hasher.finalize();
    }
    hex_encode(&digest)
}

fn load_or_create_salt() -> Vec<u8> {
    if let Ok(salt_hex) = fs::read_to_string(SALT_PATH) {
        if let Ok(salt) = hex_decode(salt_hex.trim()) {
            if salt.len() >= 16 {
                return salt;
            }
        }
    }
    let mut salt = vec![0u8; 32];
    read_urandom(&mut salt);
    let _ = fs::write(SALT_PATH, hex_encode(&salt));
    salt
}

fn load_or_create_salt_at(path: &Path) -> Result<Vec<u8>, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "authentication salt path has no parent".to_string())?;
    if path == Path::new(crate::mihomo::PROXY_AUTH_SALT) {
        let data_dir = Path::new("/data");
        let data_metadata = fs::symlink_metadata(data_dir)
            .map_err(|error| format!("data partition is unavailable: {error}"))?;
        if data_metadata.file_type().is_symlink() || !data_metadata.is_dir() {
            return Err("data partition path is not a real directory".into());
        }
        let managed_root = Path::new(crate::mihomo::PROXY_AUTH_DIR)
            .parent()
            .ok_or_else(|| "managed authentication directory has no runtime root".to_string())?;
        let metadata = fs::symlink_metadata(managed_root)
            .map_err(|error| format!("managed runtime root is unavailable: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("managed runtime root has unexpected type or owner".into());
        }
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() } =>
        {
            return Err("authentication directory has unexpected type or owner".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect authentication directory: {error}")),
    }
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create authentication directory: {error}"))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot secure authentication directory: {error}"))?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("authentication salt is not a regular file".into());
        }
        // Reject a salt owned by another uid instead of silently trusting it.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("authentication salt has an unexpected owner".into());
        }
        if metadata.nlink() != 1 {
            return Err("authentication salt is unexpectedly shared".into());
        }
        if metadata.mode() & 0o7777 != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot secure authentication salt: {error}"))?;
        }
        if let Ok(salt_hex) = fs::read_to_string(path) {
            if let Ok(salt) = hex_decode(salt_hex.trim()) {
                if salt.len() >= 16 {
                    return Ok(salt);
                }
            }
        }
    }

    let mut salt = vec![0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| std::io::Read::read_exact(&mut random, &mut salt))
        .map_err(|error| format!("secure random source is unavailable: {error}"))?;
    if salt.iter().all(|byte| *byte == 0) {
        return Err("secure random source is unavailable".into());
    }
    crate::storage::atomic_write(path, hex_encode(&salt).as_bytes())
        .map_err(|error| format!("cannot persist authentication salt: {error}"))?;
    Ok(salt)
}

fn read_urandom(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(buf);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
    if !hex.len().is_multiple_of(2) {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: &str = "192.168.0.42";

    fn authed() -> AuthState {
        let auth = AuthState::new();
        auth.set_password("correct-horse");
        auth
    }

    fn token_of(result: LoginResult) -> String {
        match result {
            LoginResult::Ok { token } => token,
            LoginResult::Invalid => panic!("expected success, got Invalid"),
            LoginResult::Locked { .. } => panic!("expected success, got Locked"),
        }
    }

    #[test]
    fn lockout_arms_after_max_attempts() {
        let auth = authed();
        for i in 0..MAX_LOGIN_ATTEMPTS {
            assert!(
                matches!(auth.login_password("wrong", IP), LoginResult::Invalid),
                "attempt {i} should be Invalid, not locked yet"
            );
        }
        // Armed: even the correct password is refused while locked out.
        assert!(matches!(
            auth.login_password("correct-horse", IP),
            LoginResult::Locked { .. }
        ));
    }

    #[test]
    fn lockout_is_scoped_to_the_client_ip() {
        let auth = authed();
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            let _ = auth.login_password("wrong", IP);
        }
        assert!(matches!(
            auth.login_password("wrong", IP),
            LoginResult::Locked { .. }
        ));
        // A different client is unaffected.
        let _ = token_of(auth.login_password("correct-horse", "192.168.0.99"));
    }

    #[test]
    fn successful_login_clears_failure_count() {
        let auth = authed();
        for _ in 0..MAX_LOGIN_ATTEMPTS - 1 {
            let _ = auth.login_password("wrong", IP);
        }
        let _ = token_of(auth.login_password("correct-horse", IP));

        // Counter reset, so we get a fresh full budget of attempts.
        for i in 0..MAX_LOGIN_ATTEMPTS {
            assert!(
                matches!(auth.login_password("wrong", IP), LoginResult::Invalid),
                "attempt {i} after reset should be Invalid"
            );
        }
    }

    #[test]
    fn validate_slides_token_expiry() {
        let auth = authed();
        let token = token_of(auth.login_password("correct-horse", IP));

        // Age the token to one second short of expiry.
        {
            let mut tokens = auth.tokens.safe_lock();
            tokens[0].expires = epoch_secs() + 1;
        }

        assert!(auth.validate(&token));
        let expires = auth.tokens.safe_lock()[0].expires;
        assert!(
            expires >= epoch_secs() + TOKEN_TTL_SECS - 2,
            "validate() should push expiry back out to the full TTL"
        );
    }

    #[test]
    fn validate_rejects_expired_and_unknown_tokens() {
        let auth = authed();
        let token = token_of(auth.login_password("correct-horse", IP));
        assert!(!auth.validate("not-a-real-token"));

        auth.tokens.safe_lock()[0].expires = epoch_secs() - 1;
        assert!(!auth.validate(&token));
    }

    #[test]
    fn proxy_only_salt_is_persisted_under_a_private_synthetic_root() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "u60-auth-salt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let salt_path = root.join("auth/salt");
        let auth = AuthState::new_with_salt_path(&salt_path).unwrap();
        auth.set_password("synthetic-password");
        assert!(matches!(
            auth.login_password("synthetic-password", IP),
            LoginResult::Ok { .. }
        ));
        assert_eq!(
            std::fs::metadata(salt_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&salt_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let reloaded = AuthState::new_with_salt_path(&salt_path).unwrap();
        reloaded.set_password("synthetic-password");
        assert!(matches!(
            reloaded.login_password("synthetic-password", IP),
            LoginResult::Ok { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
