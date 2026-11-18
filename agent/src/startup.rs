use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupMode {
    Legacy,
    ProxyOnly {
        bind: SocketAddr,
        https_origin: Option<String>,
    },
}

/// Parse all arguments before main performs any legacy initialization.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<StartupMode, String> {
    let args: Vec<String> = args.into_iter().collect();
    if args.is_empty() {
        return Ok(StartupMode::Legacy);
    }

    let mut proxy_only = false;
    let mut bind = None;
    let mut https_origin = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--proxy-only" if !proxy_only => proxy_only = true,
            "--proxy-only" => return Err("duplicate --proxy-only".into()),
            "--proxy-bind" => {
                if bind.is_some() {
                    return Err("duplicate --proxy-bind".into());
                }
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--proxy-bind requires an IPv4 address and port".to_string())?;
                bind = Some(parse_ipv4_socket(value)?);
                i += 1;
            }
            "--proxy-https-origin" => {
                if https_origin.is_some() {
                    return Err("duplicate --proxy-https-origin".into());
                }
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--proxy-https-origin requires one HTTPS origin".to_string())?;
                https_origin = Some(parse_https_origin(value)?);
                i += 1;
            }
            "--proxy-lan-confirm" => {
                return Err(
                    "LAN binding is disabled until a secure HTTPS management path is available"
                        .into(),
                )
            }
            unknown => return Err(format!("unsupported argument '{unknown}'")),
        }
        i += 1;
    }

    if !proxy_only {
        return Err("proxy options require --proxy-only".into());
    }

    let bind = bind.unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090)));
    let ip = match bind.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => return Err("proxy-only accepts IPv4 bind addresses only".into()),
    };

    if !ip.is_loopback() {
        return Err("proxy-only management is loopback-only until HTTPS is provided".into());
    }

    Ok(StartupMode::ProxyOnly { bind, https_origin })
}

pub fn parse_https_origin(value: &str) -> Result<String, String> {
    let authority = value
        .strip_prefix("https://")
        .ok_or_else(|| "proxy HTTPS origin must start with lowercase https://".to_string())?;
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@' | b' ' | b'\\' | b'[' | b']'))
        || authority.contains('%')
    {
        return Err("proxy HTTPS origin must be a bare hostname or IPv4 origin".into());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let parsed = port
                .parse::<u16>()
                .map_err(|_| "proxy HTTPS origin port must be between 1 and 65535".to_string())?;
            if parsed == 0 || parsed.to_string() != port || parsed == 443 {
                return Err(
                    "proxy HTTPS origin port must be canonical; omit the default 443".into(),
                );
            }
            host
        }
        Some(_) => return Err("proxy HTTPS origin does not support IPv6 literals".into()),
        None => authority,
    };
    if host.is_empty()
        || host != host.to_ascii_lowercase()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("proxy HTTPS origin host is not a canonical DNS name or IPv4 address".into());
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && host.parse::<std::net::Ipv4Addr>().is_err()
    {
        return Err("proxy HTTPS origin IPv4 address is invalid".into());
    }
    Ok(value.to_string())
}

fn parse_ipv4_socket(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "--proxy-bind must be an IPv4 address and port".to_string())?;
    if !address.is_ipv4() || address.port() != 9090 {
        return Err("--proxy-bind must use IPv4 port 9090".into());
    }
    Ok(address)
}

pub fn dispatch<T>(
    mode: StartupMode,
    legacy: impl FnOnce() -> T,
    proxy_only: impl FnOnce(SocketAddr, Option<String>) -> T,
) -> T {
    match mode {
        StartupMode::Legacy => legacy(),
        StartupMode::ProxyOnly { bind, https_origin } => proxy_only(bind, https_origin),
    }
}

#[cfg(test)]
mod tests {
    use super::{dispatch, parse, parse_https_origin, StartupMode};
    use std::cell::Cell;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn zero_arguments_select_unchanged_legacy_dispatch() {
        assert_eq!(parse(Vec::<String>::new()).unwrap(), StartupMode::Legacy);
        let legacy_calls = Cell::new(0);
        let proxy_calls = Cell::new(0);
        dispatch(
            StartupMode::Legacy,
            || legacy_calls.set(legacy_calls.get() + 1),
            |_, _| proxy_calls.set(proxy_calls.get() + 1),
        );
        assert_eq!(legacy_calls.get(), 1);
        assert_eq!(proxy_calls.get(), 0);
    }

    #[test]
    fn proxy_only_dispatch_never_runs_legacy_initialization() {
        let legacy_calls = Cell::new(0);
        let proxy_calls = Cell::new(0);
        let mode = parse(args(&["--proxy-only"])).unwrap();
        dispatch(
            mode,
            || legacy_calls.set(legacy_calls.get() + 1),
            |_, _| proxy_calls.set(proxy_calls.get() + 1),
        );
        assert_eq!(legacy_calls.get(), 0);
        assert_eq!(proxy_calls.get(), 1);
    }

    #[test]
    fn proxy_only_defaults_to_loopback_and_rejects_unsafe_or_conflicting_args() {
        assert_eq!(
            parse(args(&["--proxy-only"])).unwrap(),
            StartupMode::ProxyOnly {
                bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090)),
                https_origin: None,
            }
        );
        assert!(parse(args(&["--unknown"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-only"])).is_err());
        assert!(parse(args(&["--proxy-bind", "127.0.0.1:9090"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-bind"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-bind", "127.0.0.1:9999"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-bind", "0.0.0.0:9090"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-lan-confirm"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-bind", "192.168.0.1:9090"])).is_err());
        assert!(parse(args(&["--proxy-only", "--proxy-https-origin"])).is_err());
        assert!(parse(args(&[
            "--proxy-only",
            "--proxy-https-origin",
            "https://u60.local",
            "--proxy-https-origin",
            "https://u60.local"
        ]))
        .is_err());
        assert!(parse(args(&[
            "--proxy-only",
            "--proxy-bind",
            "192.168.0.1:9090",
            "--proxy-lan-confirm"
        ]))
        .unwrap_err()
        .contains("HTTPS"));
    }

    #[test]
    fn https_origin_must_be_exact_canonical_and_https_only() {
        for valid in [
            "https://u60.local",
            "https://192.168.0.1",
            "https://router.home.arpa:8443",
            "https://localhost:45443",
        ] {
            assert_eq!(parse_https_origin(valid).unwrap(), valid);
        }
        for invalid in [
            "http://u60.local",
            "https://",
            "https://u60.local/",
            "https://u60.local/path",
            "https://user@u60.local",
            "https://*.home.arpa",
            "https://U60.local",
            "https://u60.local:0",
            "https://u60.local:0443",
            "https://u60.local:443",
            "https://999.1.1.1",
            "https://[::1]",
        ] {
            assert!(parse_https_origin(invalid).is_err(), "accepted {invalid}");
        }
        assert_eq!(
            parse(args(&[
                "--proxy-only",
                "--proxy-https-origin",
                "https://u60.home.arpa:8443"
            ]))
            .unwrap(),
            StartupMode::ProxyOnly {
                bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090)),
                https_origin: Some("https://u60.home.arpa:8443".into()),
            }
        );
    }
}
