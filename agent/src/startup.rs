use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupMode {
    Legacy,
    ProxyOnly { bind: SocketAddr },
}

/// Parse all arguments before main performs any legacy initialization.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<StartupMode, String> {
    let args: Vec<String> = args.into_iter().collect();
    if args.is_empty() {
        return Ok(StartupMode::Legacy);
    }

    let mut proxy_only = false;
    let mut bind = None;
    let mut lan_confirmed = false;
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
            "--proxy-lan-confirm" if !lan_confirmed => lan_confirmed = true,
            "--proxy-lan-confirm" => return Err("duplicate --proxy-lan-confirm".into()),
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

    if ip.is_loopback() {
        if lan_confirmed {
            return Err("--proxy-lan-confirm is only valid for a private LAN address".into());
        }
    } else if !ip.is_private() || !lan_confirmed {
        return Err("a private LAN bind requires --proxy-lan-confirm".into());
    }

    Ok(StartupMode::ProxyOnly { bind })
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
    proxy_only: impl FnOnce(SocketAddr) -> T,
) -> T {
    match mode {
        StartupMode::Legacy => legacy(),
        StartupMode::ProxyOnly { bind } => proxy_only(bind),
    }
}

#[cfg(test)]
mod tests {
    use super::{dispatch, parse, StartupMode};
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
            |_| proxy_calls.set(proxy_calls.get() + 1),
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
            |_| proxy_calls.set(proxy_calls.get() + 1),
        );
        assert_eq!(legacy_calls.get(), 0);
        assert_eq!(proxy_calls.get(), 1);
    }

    #[test]
    fn proxy_only_defaults_to_loopback_and_rejects_unsafe_or_conflicting_args() {
        assert_eq!(
            parse(args(&["--proxy-only"])).unwrap(),
            StartupMode::ProxyOnly {
                bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090))
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
        assert!(parse(args(&[
            "--proxy-only",
            "--proxy-bind",
            "192.168.0.1:9090",
            "--proxy-lan-confirm"
        ]))
        .is_ok());
    }
}
