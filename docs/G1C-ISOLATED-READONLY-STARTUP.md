# G1-C — Explicit Loopback-Only Read-Only Agent Prototype

Date: 2026-11-17
Parent: G1-B Draft PR #3, exact baseline `764fce6d9a42cd440d2d03321475256564674204`
Status: OFFLINE PROTOTYPE — **NOT AUTHORIZED FOR DEVICE DEPLOYMENT**

## Scope and rationale

Peter's existing `zte-agent` startup calls destructive or device-mutating routines before serving HTTP: cleanup/migration, AppState construction, event bus, charge and Mihomo background services, TTL shell script, USB enforcement, LAN recovery and legacy binding. Switching port or data directory is **not enough** to run it safely in parallel with the Owner's B31 U60 and legacy /data/mihomo.

G1-C introduces a separate explicitly selected bootstrap branch to demonstrate a minimally scoped no-device API while preserving the original zero-argument legacy behavior unchanged. It is a stepping stone for hardening, **not** the full router-management UI.

## Prototype contract

- The exact command `zte-agent --isolated-readonly` chooses the new path **before** `diag_log::init()`, `migrate_drop_removed_features()`, `AppState::new()`, background service starts, shell scripts, USB operations, LAN recovery or `server::start()`.
- Missing flags follow the existing unsafe legacy startup (preserved solely for upstream compatibility; **never run it on the Owner's U60**). Unknown or extra flags return an error before any legacy initialization.
- The isolated module does not access persistent files, /data/mihomo, SIM/eSIM/APN, USB/ECM, UCI, FOTA, network management APIs, Dropbear, or subprocesses.
- It binds **only** to `127.0.0.1:19090`, with no environment override and no LAN/WAN listener. A bind failure exits; there is no fallback to a default or shared port.
- Only `GET /healthz` returns fixed non-sensitive JSON (`mode=isolated-readonly-prototype`, `ready_for_deployment=false`, `device_state=unread`). Other GET paths return 404. All other methods, including OPTIONS, POST, PUT and DELETE, return 405. Responses include `Content-Type: application/json`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`; no CORS.
- No shell, auto-start, installer, write handler, router discovery, transparent proxy, Mihomo manager, WebUI dashboard or subscription editing is enabled.
- This loopback-only endpoint requires no auth because it provides only unchanging public non-sensitive text. It must **not** be exposed on LAN, extended to real device data, or granted any mutation capability without a new authenticated security design and independent review.

## Verification on Mac Dev only

1. Exact main() branch order and lack of unsafe imports in `agent/src/isolated_readonly.rs` must be checked on the candidate diff.
2. Pure Rust unit tests cover argument routing, invalid/extra flags, fixed bind address, path+method allowlist and no device-ready claim.
3. Run native `cargo test --locked -p zte-agent` and format checks with the existing U60 project-local Rust toolchain; arm64-musl `cargo check --locked -p zte-agent --target aarch64-unknown-linux-musl` is a type check, **not a linked device binary**.
4. An optional controlled Mac Dev local process/HTTP smoke test may run only with `--isolated-readonly`, with cleanup and no U60 contact. Never invoke the no-flag binary in an integration test.
5. Keep PR Draft/unmerged. Artifact Ledger tracks contract, interrupted Codex session, local tests and mock listener evidence.

## Explicit remaining deployment blockers

- A static loopback-only prototype is **not** a functional WebUI, full read-only device status API, authenticated management service, or real parallel Mihomo instance.
- No verified instance-scoped files/paths, handler-level read-only allowlist, suitable LAN authentication or WebUI connectivity, host-key-pinned SSH transport, installer transaction, actual filesystem rollback, ARM64 linkage, B31 firmware compatibility, or USB-ECM behavior.
- Existing deployment scripts still use `StrictHostKeyChecking=accept-new` and shared paths; none may be used against the Owner device as-is.
- Before any on-device read-only validation: separate explicit Owner authorization; before any installation or startup: separate Owner deployment authorization, independently reviewed exact diff, safe rollback, verified host key and complete route/firewall/DNS/USB preservation evidence.
