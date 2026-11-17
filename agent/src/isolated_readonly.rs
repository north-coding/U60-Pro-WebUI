//! Explicit, loopback-only, no-device-state read-only prototype.
//!
//! This module intentionally must not import AppState, legacy server handlers,
//! device services or subprocess/file APIs. The only permitted effect is binding
//! a fixed local HTTP listener and returning static, non-sensitive responses.

use std::ffi::{OsStr, OsString};

use tiny_http::{Header, Method, Response, Server};

pub const LOOPBACK_BIND: &str = "127.0.0.1:19090";
const HEALTH_PATH: &str = "/healthz";
const HEALTH_BODY: &str = r#"{"mode":"isolated-readonly-prototype","ready_for_deployment":false,"device_state":"unread"}"#;
const NOT_FOUND_BODY: &str = r#"{"error":"not-found"}"#;
const METHOD_NOT_ALLOWED_BODY: &str = r#"{"error":"method-not-allowed"}"#;

#[derive(Debug, PartialEq, Eq)]
pub enum StartupMode {
    Legacy,
    IsolatedReadonly,
}

/// Reject invalid or extra arguments before any legacy initialization.
pub fn select_mode(args: impl IntoIterator<Item = OsString>) -> Result<StartupMode, &'static str> {
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (None, None) => Ok(StartupMode::Legacy),
        (Some(arg), None) if arg == OsStr::new("--isolated-readonly") => {
            Ok(StartupMode::IsolatedReadonly)
        }
        _ => Err("Usage: zte-agent [--isolated-readonly]; other options are not supported"),
    }
}

/// Response policy is testable without starting a listener or touching a device.
fn route(method: &Method, path: &str) -> (u16, &'static str) {
    if *method != Method::Get {
        return (405, METHOD_NOT_ALLOWED_BODY);
    }
    if path == HEALTH_PATH {
        return (200, HEALTH_BODY);
    }
    (404, NOT_FOUND_BODY)
}

/// This path never constructs AppState and never enters the legacy server.
pub fn run() -> Result<(), String> {
    let listener = Server::http(LOOPBACK_BIND)
        .map_err(|err| format!("isolated loopback listener unavailable: {err}"))?;

    eprintln!(
        "[isolated-readonly-prototype] listening on {LOOPBACK_BIND}; no device data or mutation APIs"
    );
    for request in listener.incoming_requests() {
        let (status, body) = route(request.method(), request.url());
        let response = Response::from_string(body)
            .with_status_code(status)
            .with_header(
                Header::from_bytes("Content-Type", "application/json").expect("static header"),
            )
            .with_header(Header::from_bytes("Cache-Control", "no-store").expect("static header"))
            .with_header(
                Header::from_bytes("X-Content-Type-Options", "nosniff").expect("static header"),
            );
        if let Err(err) = request.respond(response) {
            eprintln!("[isolated-readonly-prototype] response error: {err}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn exact_opt_in_selects_readonly() {
        assert_eq!(
            select_mode(args(&["--isolated-readonly"])),
            Ok(StartupMode::IsolatedReadonly)
        );
    }

    #[test]
    fn no_arguments_preserves_legacy_selection() {
        assert_eq!(select_mode(args(&[])), Ok(StartupMode::Legacy));
    }

    #[test]
    fn unexpected_or_extra_arguments_fail_closed() {
        for a in [
            args(&["--help"]),
            args(&["--isolated-readonly", "--legacy"]),
            args(&["--unknown"]),
            args(&["--isolated-readonly", "--isolated-readonly"]),
        ] {
            assert!(select_mode(a).is_err());
        }
    }

    #[test]
    fn fixed_loopback_port_is_not_lan_or_wildcard() {
        assert_eq!(LOOPBACK_BIND, "127.0.0.1:19090");
    }

    #[test]
    fn only_health_get_is_allowed() {
        assert_eq!(route(&Method::Get, HEALTH_PATH), (200, HEALTH_BODY));
        assert_eq!(route(&Method::Get, "/"), (404, NOT_FOUND_BODY));
        assert_eq!(
            route(&Method::Get, "/api/system/info"),
            (404, NOT_FOUND_BODY)
        );
        assert_eq!(
            route(&Method::Post, HEALTH_PATH),
            (405, METHOD_NOT_ALLOWED_BODY)
        );
        assert_eq!(
            route(&Method::Put, HEALTH_PATH),
            (405, METHOD_NOT_ALLOWED_BODY)
        );
        assert_eq!(
            route(&Method::Delete, "/api/reboot"),
            (405, METHOD_NOT_ALLOWED_BODY)
        );
        assert_eq!(
            route(&Method::Options, HEALTH_PATH),
            (405, METHOD_NOT_ALLOWED_BODY)
        );
    }

    #[test]
    fn health_makes_no_device_readiness_claim() {
        assert!(HEALTH_BODY.contains(r#""ready_for_deployment":false"#));
        assert!(HEALTH_BODY.contains(r#""device_state":"unread""#));
        assert!(!HEALTH_BODY.contains("192.168.0.1"));
        assert!(!HEALTH_BODY.contains("/data/mihomo"));
    }
}
