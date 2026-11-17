use crate::process::BoundedCommand;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, thread};

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::at_cmd;
use crate::backup;
use crate::cell;
use crate::client_traffic;
use crate::clients;
use crate::connection_logger;
use crate::device_ext;
use crate::handlers::{self, AppState};
use crate::netselect;
use crate::netsvc;
use crate::network_ext;
use crate::proxy_only::ProxyOnlyState;
use crate::router;
use crate::schedule;
use crate::signal_logger;
use crate::sim;
use crate::sms;
use crate::sms_forward;
use crate::usb;
use crate::wifi;
use crate::wwan;

/// How long a worker blocks before re-checking whether the listener died.
/// Also bounds how long a rebuild waits for the other workers to drain.
const WORKER_POLL: Duration = Duration::from_millis(500);
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

pub fn start(threads: usize, state: Arc<AppState>) {
    // Seed the CPU tracker with a baseline
    state.cpu.seed();

    // tiny_http's accept thread exits permanently on its first accept() error
    // — plausible here via EMFILE, ENOBUFS under memory pressure, or interface
    // churn. That used to leave every worker blocked forever on a listener that
    // would never yield another request, with the process still alive and
    // nothing to restart it. Supervise instead: a worker that sees the failure
    // flags it, all workers drain, and we rebuild the listener.
    let mut retry = RETRY_MIN;
    loop {
        let bind = state.binding.address();
        let generation = state.binding.generation.load(Ordering::Acquire);
        let server = match Server::http(&bind) {
            Ok(s) => {
                retry = RETRY_MIN;
                Arc::new(s)
            }
            Err(e) => {
                eprintln!(
                    "[server] bind {bind} failed: {e}; retrying in {}s",
                    retry.as_secs()
                );
                std::thread::sleep(retry);
                retry = (retry * 2).min(RETRY_MAX);
                continue;
            }
        };

        let dead = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for _ in 0..threads {
            let server = Arc::clone(&server);
            let state = Arc::clone(&state);
            let dead = Arc::clone(&dead);
            handles.push(std::thread::spawn(move || loop {
                if state.binding.generation.load(Ordering::Acquire) != generation {
                    dead.store(true, Ordering::Relaxed);
                }
                if dead.load(Ordering::Relaxed) {
                    return;
                }
                match server.recv_timeout(WORKER_POLL) {
                    Ok(Some(request)) => handle_request(request, &state),
                    // Idle timeout — loop round and re-check `dead`.
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[server] listener failed: {e}");
                        dead.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }

        eprintln!("[server] listener down, rebuilding in {}s", retry.as_secs());
        std::thread::sleep(retry);
        retry = (retry * 2).min(RETRY_MAX);
    }
}

/// Minimal API listener used only by `--proxy-only`. It constructs no legacy
/// AppState and dispatches only the explicit proxy-management allowlist.
pub fn start_proxy_only(bind: SocketAddr, state: Arc<ProxyOnlyState>) -> Result<(), String> {
    let server = Server::http(bind.to_string())
        .map_err(|error| format!("could not bind proxy-only API on {bind}: {error}"))?;
    eprintln!("[proxy-only] API listening on {bind}");
    state.mihomo.start_watchdog();

    let server = Arc::new(server);
    let failed = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        let failed = Arc::clone(&failed);
        workers.push(thread::spawn(move || loop {
            if failed.load(Ordering::Relaxed) {
                return;
            }
            match server.recv_timeout(WORKER_POLL) {
                Ok(Some(request)) => handle_proxy_only_request(request, &state, bind),
                Ok(None) => {}
                Err(error) => {
                    eprintln!("[proxy-only] listener failed: {error}");
                    failed.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
    Err(format!("proxy-only listener on {bind} stopped"))
}

fn proxy_only_methods(path: &str) -> Option<&'static [&'static str]> {
    match path {
        "/api/auth/login" => Some(&["POST"]),
        "/api/proxy/status" => Some(&["GET"]),
        "/api/proxy/settings" => Some(&["PUT"]),
        "/api/proxy/service" => Some(&["POST"]),
        "/api/proxy/subscriptions" => Some(&["GET", "POST", "PUT"]),
        "/api/proxy/subscriptions/delete" | "/api/proxy/subscriptions/update" => Some(&["POST"]),
        "/api/proxy/groups" => Some(&["GET", "PUT"]),
        "/api/proxy/delay" => Some(&["POST"]),
        _ => None,
    }
}

fn proxy_only_origin_allowed(origin: &str, bind: SocketAddr) -> bool {
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@' | b' ' | b'\\'))
    {
        return false;
    }
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') || port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
            return false;
        }
        (host, port.parse::<u16>().ok())
    } else {
        (authority, None)
    };

    let bound_ip = match bind.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => return false,
    };
    if bound_ip.is_loopback() {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback())
    } else {
        host.parse::<std::net::Ipv4Addr>().ok() == Some(bound_ip) && port == Some(8080)
    }
}

fn proxy_only_request_header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv(name))
        .map(|header| header.value.as_str())
}

fn handle_proxy_only_request(mut request: Request, state: &ProxyOnlyState, bind: SocketAddr) {
    let method = request.method().clone();
    let method_name = method.as_str();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or(&url);
    let Some(allowed_methods) = proxy_only_methods(path) else {
        respond_proxy_only(
            request,
            404,
            json!({"ok": false, "error": "not found"}),
            None,
        );
        return;
    };

    let origin = proxy_only_request_header(&request, "Origin").map(str::to_string);
    let origin_ref = origin.as_deref();
    if let Some(origin) = origin_ref {
        if !proxy_only_origin_allowed(origin, bind) {
            respond_proxy_only(
                request,
                403,
                json!({"ok": false, "error": "origin is not allowed"}),
                None,
            );
            return;
        }
    }

    if method == Method::Options {
        let requested = proxy_only_request_header(&request, "Access-Control-Request-Method");
        let requested_headers =
            proxy_only_request_header(&request, "Access-Control-Request-Headers").unwrap_or("");
        let headers_allowed = requested_headers.split(',').all(|header| {
            matches!(
                header.trim().to_ascii_lowercase().as_str(),
                "" | "authorization" | "content-type" | "x-confirm"
            )
        });
        if origin_ref.is_none()
            || !headers_allowed
            || !requested.is_some_and(|name| allowed_methods.contains(&name))
        {
            respond_proxy_only(
                request,
                403,
                json!({"ok": false, "error": "preflight request is not allowed"}),
                None,
            );
            return;
        }
        let response = proxy_only_cors_response(Response::empty(204), origin_ref, allowed_methods);
        let _ = request.respond(response);
        return;
    }

    if !allowed_methods.contains(&method_name) {
        let response = proxy_only_response(
            Response::from_string(json!({"ok": false, "error": "method not allowed"}).to_string())
                .with_status_code(405),
            origin_ref,
        )
        .with_header(Header::from_bytes("Allow", allowed_methods.join(", ")).unwrap());
        let _ = request.respond(response);
        return;
    }

    let client_ip = request
        .remote_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    let login = path == "/api/auth/login";
    if !login {
        if !state.auth.has_password() {
            respond_proxy_only(
                request,
                403,
                json!({"ok": false, "error": "no password configured"}),
                origin_ref,
            );
            return;
        }
        let valid = proxy_only_request_header(&request, "Authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| state.auth.validate(token));
        if !valid {
            respond_proxy_only(
                request,
                401,
                json!({"ok": false, "error": "unauthorized"}),
                origin_ref,
            );
            return;
        }
    }

    if path == "/api/proxy/subscriptions/delete"
        && proxy_only_request_header(&request, "X-Confirm") != Some("true")
    {
        respond_proxy_only(
            request,
            400,
            json!({"ok": false, "error": "destructive action requires X-Confirm: true header"}),
            origin_ref,
        );
        return;
    }

    let mut body = Vec::new();
    let read_result = {
        let mut reader = request.as_reader();
        std::io::Read::take(&mut reader, 1024 * 1024 + 1).read_to_end(&mut body)
    };
    if let Err(error) = read_result {
        respond_proxy_only(
            request,
            400,
            json!({"ok": false, "error": format!("failed to read body: {error}")}),
            origin_ref,
        );
        return;
    }
    if body.len() > 1024 * 1024 {
        respond_proxy_only(
            request,
            413,
            json!({"ok": false, "error": "request body exceeds 1 MiB"}),
            origin_ref,
        );
        return;
    }

    let (status, response_body) = if login {
        handlers::proxy_login(&state.auth, &body, &client_ip)
    } else {
        proxy_only_route(&method, path, &state.mihomo, &body)
    };
    respond_proxy_only(request, status, response_body, origin_ref);
}

fn proxy_only_route(
    method: &Method,
    path: &str,
    mihomo: &crate::mihomo::Manager,
    body: &[u8],
) -> (u16, Value) {
    match (method, path) {
        (&Method::Get, "/api/proxy/status") => mihomo.status(),
        (&Method::Put, "/api/proxy/settings") => mihomo.settings_set(body),
        (&Method::Post, "/api/proxy/service") => mihomo.service(body),
        (&Method::Get, "/api/proxy/subscriptions") => mihomo.subscriptions(),
        (&Method::Post, "/api/proxy/subscriptions") => mihomo.subscription_add(body),
        (&Method::Put, "/api/proxy/subscriptions") => mihomo.subscription_edit(body),
        (&Method::Post, "/api/proxy/subscriptions/delete") => mihomo.subscription_delete(body),
        (&Method::Post, "/api/proxy/subscriptions/update") => mihomo.subscription_refresh(body),
        (&Method::Get, "/api/proxy/groups") => mihomo.groups(),
        (&Method::Put, "/api/proxy/groups") => mihomo.group_select(body),
        (&Method::Post, "/api/proxy/delay") => mihomo.delay(body),
        _ => (404, json!({"ok": false, "error": "not found"})),
    }
}

fn proxy_only_response(
    response: Response<std::io::Cursor<Vec<u8>>>,
    origin: Option<&str>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = response
        .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap());
    if let Some(origin) = origin {
        response = response
            .with_header(Header::from_bytes("Access-Control-Allow-Origin", origin).unwrap())
            .with_header(Header::from_bytes("Vary", "Origin").unwrap());
    }
    response
}

fn proxy_only_cors_response<R: Read>(
    mut response: Response<R>,
    origin: Option<&str>,
    allowed_methods: &[&str],
) -> Response<R> {
    if let Some(origin) = origin {
        response = response
            .with_header(Header::from_bytes("Access-Control-Allow-Origin", origin).unwrap())
            .with_header(Header::from_bytes("Vary", "Origin").unwrap());
    }
    response
        .with_header(
            Header::from_bytes("Access-Control-Allow-Methods", allowed_methods.join(", ")).unwrap(),
        )
        .with_header(
            Header::from_bytes(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, X-Confirm",
            )
            .unwrap(),
        )
        .with_header(Header::from_bytes("Access-Control-Max-Age", "600").unwrap())
}

fn respond_proxy_only(request: Request, status: u16, body: Value, origin: Option<&str>) {
    let response = Response::from_string(body.to_string()).with_status_code(status);
    let _ = request.respond(proxy_only_response(response, origin));
}

const DESTRUCTIVE_PATHS: &[&str] = &[
    "/api/device/reboot",
    "/api/device/shutdown",
    "/api/system/kill-bloat",
    "/api/proxy/subscriptions/delete",
    "/api/system/restore",
];

fn cors_headers(origin: Option<&str>) -> Vec<Header> {
    let allowed = origin
        .and_then(|o| is_lan_origin(o).then_some(o))
        .unwrap_or("");
    vec![
        Header::from_bytes("Access-Control-Allow-Origin", allowed).unwrap(),
        Header::from_bytes(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .unwrap(),
        Header::from_bytes(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, X-Confirm",
        )
        .unwrap(),
        Header::from_bytes("Access-Control-Max-Age", "86400").unwrap(),
    ]
}

fn is_lan_origin(origin: &str) -> bool {
    if !origin.starts_with("http://") {
        return false;
    }
    let host = &origin[7..];
    let host = host.split(':').next().unwrap_or(host);
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse().ok()).collect();
    if octets.len() != 4 {
        return false;
    }
    octets[0] == 10
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
}

fn handle_request(mut request: Request, state: &AppState) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or(&url).to_string();
    let origin = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Origin"))
        .map(|h| h.value.as_str().to_string());
    let origin_ref = origin.as_deref();
    let client_ip = request
        .remote_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let user_agent = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.as_str().to_string());
    let user_agent_ref = user_agent.as_deref();

    if method == Method::Options {
        let mut response = Response::empty(200);
        for h in cors_headers(origin_ref) {
            response = response.with_header(h);
        }
        let _ = request.respond(response);
        return;
    }

    // Proxy auto-config for LAN devices. Public by design: browsers and OSes
    // fetch it without credentials, and it only names the proxy address.
    if method == Method::Get && path == "/proxy.pac" {
        let response = Response::from_string(state.mihomo.pac())
            .with_header(
                Header::from_bytes("Content-Type", "application/x-ns-proxy-autoconfig").unwrap(),
            )
            .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
        let _ = request.respond(response);
        return;
    }

    // The LAN confirmation nonce authorises only the pending change. It lets
    // the browser prove connectivity without sending its session bearer token
    // to a new IP that might already be occupied by another host.
    let needs_auth =
        path != "/api/auth/login" && !(method == Method::Post && path == "/api/router/lan/confirm");
    if needs_auth {
        let authorized = request
            .headers()
            .iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "authorization")
            .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
            .map(|token| state.auth.validate(token))
            .unwrap_or(false);

        if !state.auth.has_password() {
            respond(
                request,
                403,
                json!({"ok": false, "error": "no password configured. Set ZTE_AGENT_PASSWORD environment variable."}),
                origin_ref,
            );
            return;
        } else if !authorized {
            respond(
                request,
                401,
                json!({"ok": false, "error": "unauthorized"}),
                origin_ref,
            );
            return;
        }
    }

    if DESTRUCTIVE_PATHS.contains(&path.as_str()) {
        let confirmed = request
            .headers()
            .iter()
            .any(|h| h.field.equiv("X-Confirm") && h.value.as_str() == "true");
        if !confirmed {
            respond(
                request,
                400,
                json!({"ok": false, "error": "destructive action requires X-Confirm: true header"}),
                origin_ref,
            );
            return;
        }
    }

    if method == Method::Get {
        let download = match (&method, path.as_str()) {
            (&Method::Get, "/api/logger/signal/download") => {
                Some((signal_logger::LOG_PATH, "signal_log.csv"))
            }
            (&Method::Get, "/api/logger/connection/download") => {
                Some((connection_logger::LOG_PATH, "connection_log.csv"))
            }
            _ => None,
        };
        if let Some((path, name)) = download {
            match crate::logging::open_download(path) {
                Ok((file, len)) => {
                    use std::io::Read;
                    let mut response = Response::new(
                        tiny_http::StatusCode(200),
                        vec![],
                        file.take(len),
                        Some(len as usize),
                        None,
                    )
                    .with_header(
                        Header::from_bytes("Content-Type", "text/csv; charset=utf-8").unwrap(),
                    )
                    .with_header(
                        Header::from_bytes(
                            "Content-Disposition",
                            format!("attachment; filename=\"{name}\""),
                        )
                        .unwrap(),
                    )
                    .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
                    for header in cors_headers(origin_ref) {
                        response = response.with_header(header);
                    }
                    let _ = request.respond(response);
                }
                Err(_) => respond(
                    request,
                    404,
                    json!({"ok": false, "error": "no readable log file"}),
                    origin_ref,
                ),
            }
            return;
        }
    }

    let mut body = Vec::new();
    let mut reader = request.as_reader();
    let mut limited = std::io::Read::take(&mut reader, 1024 * 1024 + 1);
    if let Err(e) = std::io::Read::read_to_end(&mut limited, &mut body) {
        respond(
            request,
            400,
            json!({"ok": false, "error": format!("failed to read body: {e}")}),
            origin_ref,
        );
        return;
    }

    if body.len() > 1024 * 1024 {
        respond(
            request,
            413,
            json!({"ok": false, "error": "request body exceeds 1 MiB"}),
            origin_ref,
        );
        return;
    }

    let (status, body_json) = route(&method, &path, state, &body, &client_ip, user_agent_ref);
    respond(request, status, body_json, origin_ref);
}

pub fn route(
    method: &Method,
    path: &str,
    state: &AppState,
    body: &[u8],
    client_ip: &str,
    user_agent: Option<&str>,
) -> (u16, Value) {
    match (method, path) {
        // Auth
        (&Method::Post, "/api/auth/login") => handlers::login(state, body, client_ip, user_agent),
        // Batch — the dashboard's heartbeat; feeds Home, Signal and Modem/Data
        (&Method::Get, "/api/dashboard") => handlers::dashboard(state),
        // Device / system
        (&Method::Get, "/api/device") => handlers::device(state),
        (&Method::Get, "/api/cpu") => handlers::cpu(state),
        (&Method::Get, "/api/memory") => handlers::memory(state),
        (&Method::Get, "/api/system/top") => handlers::system_top(state),
        (&Method::Post, "/api/system/kill-bloat") => handlers::system_kill_bloat(state, body),
        (&Method::Post, "/api/system/restart-agent") => device_ext::agent_restart(state),
        (&Method::Post, "/api/device/reboot") => device_ext::device_reboot(state),
        (&Method::Post, "/api/device/shutdown") => device_ext::device_shutdown(state),
        (&Method::Get, "/api/device/battery-info") => network_ext::network_battery_ubus(state),
        (&Method::Get, "/api/device/thermal/all") => device_ext::device_thermal_all(state),
        (&Method::Get, "/api/device/battery/detail") => device_ext::device_battery_detail(state),
        (&Method::Get, "/api/device/charger") => device_ext::device_charger(state),
        (&Method::Get, "/api/device/sleep") => schedule::sleep_get(state),
        (&Method::Put, "/api/device/sleep") => schedule::sleep_set(state, body),
        (&Method::Get, "/api/device/reboot-schedule") => schedule::reboot_schedule_get(state),
        (&Method::Put, "/api/device/reboot-schedule") => schedule::reboot_schedule_set(state, body),
        (&Method::Get, "/api/device/charge-control") => device_ext::charge_control_get(state),
        (&Method::Put, "/api/device/charge-control") => device_ext::charge_control_set(state, body),
        // Network
        (&Method::Get, "/api/network/clients") => network_ext::network_clients(state),
        // WiFi
        (&Method::Get, "/api/wifi/status") => wifi::wifi_status(state),
        (&Method::Put, "/api/wifi/settings") => wifi::wifi_set(state, body),
        // Modem
        (&Method::Put, "/api/data-usage/reset-day") => {
            handlers::data_usage_reset_day_set(state, body)
        }
        (&Method::Get, "/api/modem/capabilities") => cell::modem_capabilities(state),
        (&Method::Get, "/api/router/watchdog") => netsvc::watchdog_get(state),
        (&Method::Put, "/api/router/watchdog") => netsvc::watchdog_set(state, body),
        (&Method::Get, "/api/router/firewall") => netsvc::firewall_get(state),
        (&Method::Put, "/api/router/firewall") => netsvc::firewall_set(state, body),
        (&Method::Get, "/api/router/port-forwards") => netsvc::port_rules_get(state),
        (&Method::Post, "/api/router/port-forwards") => netsvc::port_rule_add(state, body),
        (&Method::Put, "/api/router/port-forwards") => netsvc::port_rules_switch(state, body),
        (&Method::Post, "/api/router/port-forwards/delete") => {
            netsvc::port_rule_delete(state, body)
        }
        (&Method::Get, "/api/router/dhcp-bindings") => netsvc::bindings_get(state),
        (&Method::Post, "/api/router/dhcp-bindings") => netsvc::binding_add(state, body),
        (&Method::Put, "/api/router/dhcp-bindings") => netsvc::bindings_switch(state, body),
        (&Method::Post, "/api/router/dhcp-bindings/delete") => netsvc::binding_delete(state, body),
        (&Method::Get, "/api/system/time") => netsvc::time_get(state),
        (&Method::Get, "/api/network/clients/traffic") => client_traffic::get(state),
        (&Method::Post, "/api/network/clients/traffic/reset") => client_traffic::reset(state),
        (&Method::Get, "/api/cell/operators") => netselect::get(state),
        (&Method::Post, "/api/cell/operators/scan") => netselect::scan(state),
        (&Method::Post, "/api/cell/operators/select") => netselect::select(state, body),
        (&Method::Post, "/api/cell/operators/auto") => netselect::auto(state),
        (&Method::Get, "/api/system/backup") => backup::export(state),
        (&Method::Post, "/api/system/restore") => backup::restore(state, body),
        (&Method::Get, "/api/sms/forward") => sms_forward::get(state),
        (&Method::Put, "/api/sms/forward") => sms_forward::set(state, body),
        (&Method::Post, "/api/sms/forward/test") => sms_forward::test(state),
        (&Method::Put, "/api/network/clients/name") => clients::name_set(state, body),
        (&Method::Post, "/api/network/clients/kick") => clients::kick_post(state, body),
        (&Method::Get, "/api/network/blocklist") => clients::blocklist_get(state),
        (&Method::Put, "/api/network/blocklist") => clients::blocklist_set(state, body),
        (&Method::Get, "/api/modem/data") => wwan::data_get(state),
        (&Method::Put, "/api/modem/data") => wwan::data_set(state, body),
        (&Method::Get, "/api/data-usage/limit") => wwan::limit_get(state),
        (&Method::Put, "/api/data-usage/limit") => wwan::limit_set(state, body),
        (&Method::Put, "/api/modem/network-mode") => cell::modem_network_mode_set(state, body),
        // SMS
        (&Method::Get, "/api/sms/capabilities") => sms::sms_capabilities(state),
        (&Method::Post, "/api/sms/list") => sms::sms_list(state, body),
        (&Method::Post, "/api/sms/send") => sms::sms_send(state, body),
        (&Method::Post, "/api/sms/delete") => sms::sms_delete(state, body),
        (&Method::Post, "/api/sms/read") => sms::sms_mark_read(state, body),
        // SIM
        (&Method::Get, "/api/sim/info") => sim::sim_info(state),
        (&Method::Get, "/api/sim/imei") => sim::sim_imei(state),
        // Cell / band lock
        (&Method::Post, "/api/cell/lock/nr") => cell::cell_lock_nr(state, body),
        (&Method::Post, "/api/cell/lock/lte") => cell::cell_lock_lte(state, body),
        (&Method::Post, "/api/cell/lock/reset") => cell::cell_lock_reset(state),
        (&Method::Post, "/api/cell/band/nr") => cell::cell_band_nr(state, body),
        (&Method::Post, "/api/cell/band/lte") => cell::cell_band_lte(state, body),
        (&Method::Post, "/api/cell/band/reset") => cell::cell_band_reset(state),
        // Router
        (&Method::Get, "/api/router/dns") => router::router_dns_get(state),
        (&Method::Put, "/api/router/dns") => router::router_dns_set(state, body),
        (&Method::Get, "/api/router/lan") => router::router_lan_get(state),
        (&Method::Put, "/api/router/lan") => router::router_lan_set(state, body),
        (&Method::Post, "/api/router/lan/confirm") => router::router_lan_confirm(state, body),
        (&Method::Get, "/api/router/apn/mode") => router::router_apn_mode_get(state),
        (&Method::Put, "/api/router/apn/mode") => router::router_apn_mode_set(state, body),
        (&Method::Get, "/api/router/apn/profiles") => router::router_apn_profiles_get(state),
        (&Method::Put, "/api/router/apn/profiles") => router::router_apn_profiles_edit(state, body),
        (&Method::Post, "/api/router/apn/profiles") => router::router_apn_profiles_add(state, body),
        (&Method::Post, "/api/router/apn/profiles/delete") => {
            router::router_apn_profiles_delete(state, body)
        }
        (&Method::Post, "/api/router/apn/profiles/activate") => {
            router::router_apn_profiles_activate(state, body)
        }
        // USB
        (&Method::Get, "/api/usb/status") => usb::usb_status(state),
        (&Method::Put, "/api/usb/mode") => usb::usb_mode_set(state, body),
        (&Method::Put, "/api/usb/default") => usb::usb_default_set(state, body),
        (&Method::Put, "/api/usb/powerbank") => usb::usb_powerbank_set(state, body),
        // TTL clamping
        (&Method::Get, "/api/ttl/status") => ttl_status(),
        (&Method::Put, "/api/ttl/set") => ttl_set(body),
        (&Method::Delete, "/api/ttl/clear") => ttl_clear(),
        // AT console
        (&Method::Post, "/api/at/send") => at_console(state, body),
        (&Method::Get, "/api/at/port") => at_port(state),
        // Signal logger
        (&Method::Post, "/api/logger/signal/start") => signal_logger::start_logging(state, body),
        (&Method::Post, "/api/logger/signal/stop") => signal_logger::stop_logging(state),
        (&Method::Get, "/api/logger/signal/status") => signal_logger::status(state),
        // Connection logger
        (&Method::Post, "/api/logger/connection/start") => {
            connection_logger::start_logging(state, body)
        }
        (&Method::Post, "/api/logger/connection/stop") => connection_logger::stop_logging(state),
        (&Method::Get, "/api/logger/connection/status") => connection_logger::status(state),
        // Proxy (mihomo)
        (&Method::Get, "/api/proxy/status") => state.mihomo.status(),
        (&Method::Put, "/api/proxy/settings") => state.mihomo.settings_set(body),
        (&Method::Post, "/api/proxy/service") => state.mihomo.service(body),
        (&Method::Get, "/api/proxy/subscriptions") => state.mihomo.subscriptions(),
        (&Method::Post, "/api/proxy/subscriptions") => state.mihomo.subscription_add(body),
        (&Method::Put, "/api/proxy/subscriptions") => state.mihomo.subscription_edit(body),
        (&Method::Post, "/api/proxy/subscriptions/delete") => {
            state.mihomo.subscription_delete(body)
        }
        (&Method::Post, "/api/proxy/subscriptions/update") => {
            state.mihomo.subscription_refresh(body)
        }
        (&Method::Get, "/api/proxy/groups") => state.mihomo.groups(),
        (&Method::Put, "/api/proxy/groups") => state.mihomo.group_select(body),
        (&Method::Post, "/api/proxy/delay") => state.mihomo.delay(body),
        // Fallback
        _ => (404, json!({"ok": false, "error": "not found"})),
    }
}

// --- AT console ---

fn at_console(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let command = match parsed["command"].as_str() {
        Some(c) if !c.is_empty() => c,
        _ => return (400, json!({"ok": false, "error": "missing 'command'"})),
    };
    let timeout = parsed["timeout"].as_u64().unwrap_or(2).min(30);

    if !is_at_command_allowed(command) {
        return (
            403,
            json!({"ok": false, "error": "command not allowed. Only read-only AT commands are permitted."}),
        );
    }

    match at_cmd::send(&state.at_port, command, timeout) {
        Ok(resp) => (200, json!({"ok": true, "data": {"response": resp.trim()}})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

const AT_BLOCKED_PREFIXES: &[&str] = &[
    "AT+CFUN",
    "AT^",
    "AT$QCRMCALL",
    "AT+CLCK",
    "AT+CMGD",
    "AT+CMGF=1;+CMGS",
    "AT+CGDCONT=",
    "AT+CGACT=",
];

const AT_ALLOWED_EXACT: &[&str] = &[
    "AT",
    "ATI",
    "AT+CSQ",
    "AT+COPS?",
    "AT+COPS=?",
    "AT+CGDCONT?",
    "AT+CREG?",
    "AT+CGREG?",
    "AT+CEREG?",
    "AT+CGPADDR",
    "AT+CGACT?",
    "AT+CLAC",
    "AT+CGSN",
    "AT+CGMI",
    "AT+CGMM",
    "AT+CGMR",
    "AT+QENG=\"SERVINGCELL\"",
    "AT+QNWINFO",
    "AT+QRSRP",
    "AT+QRSRQ",
    "AT+QINISTAT",
    "AT+QSPN",
    "AT+QCIDINCOMING",
    "AT+CGCONTRDP",
];

fn is_at_command_allowed(cmd: &str) -> bool {
    let upper = cmd.trim().to_uppercase();
    if upper.is_empty() {
        return false;
    }
    for prefix in AT_BLOCKED_PREFIXES {
        if upper.starts_with(prefix) {
            return false;
        }
    }
    AT_ALLOWED_EXACT.contains(&upper.as_str())
}

/// GET /api/at/port — report the detected AT serial port (if any)
fn at_port(state: &AppState) -> (u16, Value) {
    match state.at_port.detect_serialized() {
        Some(port) => (
            200,
            json!({"ok": true, "data": {"port": port, "available": true}}),
        ),
        None => (
            200,
            json!({"ok": true, "data": {"port": null, "available": false}}),
        ),
    }
}

// --- TTL handlers ---

fn ttl_status() -> (u16, Value) {
    let ipv4 = std::process::Command::new("iptables")
        .args(["-t", "mangle", "-L", "PREROUTING", "-n"])
        .bounded_output();
    let ipv6 = std::process::Command::new("ip6tables")
        .args(["-t", "mangle", "-L", "PREROUTING", "-n"])
        .bounded_output();
    let mut active = false;
    let mut ttl_value: u32 = 0;
    if let Ok(out) = &ipv4 {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("TTL set to") {
                active = true;
                if let Some(v) = line.rsplit("TTL set to ").next() {
                    ttl_value = v.trim().parse().unwrap_or(0);
                }
                break;
            }
        }
    }
    let mut hl_active = false;
    if let Ok(out) = &ipv6 {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("HL set to") {
                hl_active = true;
                if ttl_value == 0 {
                    if let Some(v) = line.rsplit("HL set to ").next() {
                        ttl_value = v.trim().parse().unwrap_or(0);
                    }
                }
                break;
            }
        }
    }
    (
        200,
        json!({"ok": true, "data": {
            "active": active,
            "ipv6_active": hl_active,
            "ttl_value": ttl_value,
        }}),
    )
}

fn ttl_set(body: &[u8]) -> (u16, Value) {
    let val: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let ttl = match val.get("ttl").and_then(|v| v.as_u64()) {
        Some(v) if (1..=255).contains(&v) => v as u32,
        _ => return (400, json!({"ok": false, "error": "ttl must be 1-255"})),
    };
    // Clear existing rules first
    let _ = std::process::Command::new("sh").args(["-c",
        "iptables -t mangle -S PREROUTING 2>/dev/null | grep 'TTL --ttl-set' | while read -r rule; do iptables -t mangle $(echo \"$rule\" | sed 's/-A/-D/'); done"
    ]).bounded_output();
    let _ = std::process::Command::new("sh").args(["-c",
        "ip6tables -t mangle -S PREROUTING 2>/dev/null | grep 'HL --hl-set' | while read -r rule; do ip6tables -t mangle $(echo \"$rule\" | sed 's/-A/-D/'); done"
    ]).bounded_output();
    // Add new rules
    let r4 = std::process::Command::new("iptables")
        .args([
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            "br-lan",
            "-j",
            "TTL",
            "--ttl-set",
            &ttl.to_string(),
        ])
        .bounded_output();
    let r6 = std::process::Command::new("ip6tables")
        .args([
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            "br-lan",
            "-j",
            "HL",
            "--hl-set",
            &ttl.to_string(),
        ])
        .bounded_output();
    let ok4 = r4.map(|o| o.status.success()).unwrap_or(false);
    let ok6 = r6.map(|o| o.status.success()).unwrap_or(false);
    // Persist to start_ttl.sh
    let script = format!(
        "#!/bin/sh\niptables  -t mangle -C PREROUTING -i br-lan -j TTL --ttl-set {ttl} 2>/dev/null ||   iptables  -t mangle -A PREROUTING -i br-lan -j TTL --ttl-set {ttl}\nip6tables -t mangle -C PREROUTING -i br-lan -j HL  --hl-set  {ttl} 2>/dev/null ||   ip6tables -t mangle -A PREROUTING -i br-lan -j HL  --hl-set  {ttl}\n"
    );
    let _ = std::fs::write("/data/local/tmp/start_ttl.sh", script);
    if ok4 || ok6 {
        (
            200,
            json!({"ok": true, "data": {"ttl": ttl, "ipv4": ok4, "ipv6": ok6}}),
        )
    } else {
        (
            500,
            json!({"ok": false, "error": format!("ipv4={ok4} ipv6={ok6}")}),
        )
    }
}

fn ttl_clear() -> (u16, Value) {
    let _ = std::process::Command::new("sh").args(["-c",
        "iptables -t mangle -S PREROUTING 2>/dev/null | grep 'TTL --ttl-set' | while read -r rule; do iptables -t mangle $(echo \"$rule\" | sed 's/-A/-D/'); done"
    ]).bounded_output();
    let _ = std::process::Command::new("sh").args(["-c",
        "ip6tables -t mangle -S PREROUTING 2>/dev/null | grep 'HL --hl-set' | while read -r rule; do ip6tables -t mangle $(echo \"$rule\" | sed 's/-A/-D/'); done"
    ]).bounded_output();
    // Remove persistence script content (keep file but make it a no-op)
    let _ = std::fs::write(
        "/data/local/tmp/start_ttl.sh",
        "#!/bin/sh\n# TTL disabled\n",
    );
    (200, json!({"ok": true}))
}

fn respond(request: Request, status: u16, body: Value, origin: Option<&str>) {
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let content_type = Header::from_bytes("Content-Type", "application/json").unwrap();
    let mut response = Response::from_string(body_str)
        .with_status_code(status)
        .with_header(content_type);
    for h in cors_headers(origin) {
        response = response.with_header(h);
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::{handle_proxy_only_request, is_at_command_allowed};
    use crate::proxy_only::ProxyOnlyState;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use tiny_http::Server;

    struct SmokeServer {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        root: std::path::PathBuf,
    }

    impl Drop for SmokeServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn smoke_server() -> SmokeServer {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "u60-proxy-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let state_file = root.join("mihomo/manager.json");
        std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();
        let saved_state = serde_json::json!({
            "settings": {
                "enabled": false,
                "mode": "rule",
                "preset": "bypass_cn",
                "tun": false,
                "cn_bypass": true,
                "mixed_port": 7890,
                "profile": null
            },
            "subscriptions": [{
                "id": "a1b2c3d4",
                "name": "synthetic-provider",
                "url": "https://provider.invalid/synthetic-token",
                "enabled": true,
                "interval_hours": 0,
                "fetched": null
            }],
            "secret": "synthetic-controller-secret"
        });
        let bytes = serde_json::to_vec_pretty(&saved_state).unwrap();
        crate::storage::atomic_write(&state_file, &bytes).unwrap();
        let state = Arc::new(
            ProxyOnlyState::new_for_test("synthetic-password", &root.join("auth/salt"), state_file)
                .unwrap(),
        );
        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let address = server.server_addr().to_ip().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_server = Arc::clone(&server);
        let worker_state = Arc::clone(&state);
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                match worker_server.recv_timeout(Duration::from_millis(25)) {
                    Ok(Some(request)) => handle_proxy_only_request(request, &worker_state, address),
                    Ok(None) => {}
                    Err(_) => return,
                }
            }
        });
        SmokeServer {
            address,
            stop,
            worker: Some(worker),
            root,
        }
    }

    fn http(
        address: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, String, String) {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        )
        .unwrap();
        for (name, value) in headers {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
        stream.write_all(b"\r\n").unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let response = String::from_utf8_lossy(&response).into_owned();
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
        (status, headers.to_string(), body.to_string())
    }

    #[test]
    fn at_allowlist_is_exact_and_read_only() {
        assert!(is_at_command_allowed("AT"));
        assert!(is_at_command_allowed("at+csq"));
        assert!(is_at_command_allowed("AT+QENG=\"servingcell\""));
        assert!(!is_at_command_allowed("AT+CSQ=1"));
        assert!(!is_at_command_allowed("AT+FOO"));
        assert!(!is_at_command_allowed("AT+CFUN=1"));
        assert!(!is_at_command_allowed("AT^RESET"));
    }

    #[test]
    fn proxy_only_http_authenticates_and_serves_synthetic_subscription_state() {
        let server = smoke_server();

        assert_eq!(
            http(server.address, "GET", "/api/proxy/subscriptions", &[], "").0,
            401
        );
        assert_eq!(
            http(server.address, "POST", "/api/proxy/service", &[], "{}").0,
            401
        );
        assert_eq!(
            http(
                server.address,
                "POST",
                "/api/auth/login",
                &[("Content-Type", "application/json")],
                r#"{"password":"wrong"}"#,
            )
            .0,
            401
        );
        let (status, _, login_body) = http(
            server.address,
            "POST",
            "/api/auth/login",
            &[("Content-Type", "application/json")],
            r#"{"password":"synthetic-password"}"#,
        );
        assert_eq!(status, 200);
        let token = serde_json::from_str::<serde_json::Value>(&login_body).unwrap()["data"]
            ["token"]
            .as_str()
            .unwrap()
            .to_string();
        let authorization = format!("Bearer {token}");

        let (status, _, subscriptions_body) = http(
            server.address,
            "GET",
            "/api/proxy/subscriptions",
            &[("Authorization", &authorization)],
            "",
        );
        assert_eq!(status, 200);
        let subscriptions = serde_json::from_str::<serde_json::Value>(&subscriptions_body).unwrap();
        assert_eq!(subscriptions["data"]["subscriptions"][0]["id"], "a1b2c3d4");
        assert_eq!(
            subscriptions["data"]["subscriptions"][0]["name"],
            "synthetic-provider"
        );

        assert_eq!(
            http(
                server.address,
                "GET",
                "/api/wifi/status",
                &[("Authorization", &authorization)],
                "",
            )
            .0,
            404
        );
        assert_eq!(
            http(
                server.address,
                "PUT",
                "/api/proxy/status",
                &[("Authorization", &authorization)],
                "{}",
            )
            .0,
            405
        );
        assert_eq!(
            http(
                server.address,
                "GET",
                "/api/proxy/subscriptions",
                &[("Authorization", "Bearer invalid-token")],
                "",
            )
            .0,
            401
        );
        assert_eq!(
            http(
                server.address,
                "POST",
                "/api/proxy/service",
                &[
                    ("Authorization", &authorization),
                    ("Content-Type", "application/json"),
                ],
                r#"{"action":"unsupported"}"#,
            )
            .0,
            400
        );
        assert_eq!(
            http(
                server.address,
                "POST",
                "/api/auth/login",
                &[("Content-Type", "application/json")],
                r#"{"pin":"123456"}"#,
            )
            .0,
            400
        );
    }

    #[test]
    fn proxy_only_http_restricts_cross_origin_and_preflight_methods() {
        let server = smoke_server();
        let (status, headers, _) = http(
            server.address,
            "GET",
            "/api/proxy/subscriptions",
            &[("Origin", "https://untrusted.example")],
            "",
        );
        assert_eq!(status, 403);
        assert!(!headers.contains("Access-Control-Allow-Origin"));

        let (status, headers, _) = http(
            server.address,
            "OPTIONS",
            "/api/proxy/status",
            &[
                ("Origin", "http://localhost:3000"),
                ("Access-Control-Request-Method", "DELETE"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
            "",
        );
        assert_eq!(status, 403);
        assert!(!headers.contains("Access-Control-Allow-Credentials"));

        let (status, headers, _) = http(
            server.address,
            "OPTIONS",
            "/api/proxy/status",
            &[
                ("Origin", "http://localhost:3000"),
                ("Access-Control-Request-Method", "GET"),
                (
                    "Access-Control-Request-Headers",
                    "authorization, content-type",
                ),
            ],
            "",
        );
        assert_eq!(status, 204);
        assert!(headers.contains("Access-Control-Allow-Origin: http://localhost:3000"));
        assert!(!headers.contains("Access-Control-Allow-Credentials"));
    }

    #[test]
    fn proxy_only_lan_origin_must_match_the_webui_host_and_port() {
        let bind = "192.168.0.1:9090".parse().unwrap();
        assert!(super::proxy_only_origin_allowed(
            "http://192.168.0.1:8080",
            bind
        ));
        assert!(!super::proxy_only_origin_allowed(
            "http://192.168.0.1:9090",
            bind
        ));
        assert!(!super::proxy_only_origin_allowed(
            "http://192.168.0.2:8080",
            bind
        ));
    }
}
