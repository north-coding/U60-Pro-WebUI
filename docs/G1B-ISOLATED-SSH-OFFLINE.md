# G1-B — Offline SSH-isolation / coexistence design

**Status:** PLAN-ONLY, mock-tested. **NOT AUTHORIZED FOR DEVICE DEPLOYMENT.**
**Baseline:** G1-A Draft PR #2 (stacked on G0 Draft PR #1).
**Target:** Owner's ZTE U60 Pro / MU5250, firmware `BD_CNMU5250V1.0.0B31`.
**Host:** Mac Dev. No interaction with the actual router in this phase.

## What is actually implemented

`scripts/u60_isolated_ssh_plan.py` is a standard-library Python **local snapshot reader**. It imports G1-A's offline snapshot validation, checks that model/firmware/timestamp/SSH/ECM evidence is well-formed, checks reported port observations, and prints sanitized planning diagnostics. It has no SSH, ADB, shell, HTTP, socket, subprocess, file-writing, or device-management capability.

Example local-only usage (with an intentionally synthetic JSON fixture):

```text
python3 scripts/u60_isolated_ssh_plan.py local-synthetic-snapshot.json
```

A local fixture that passes gives **CONDITIONAL CANDIDATE (not device-ready)**; it is not a permission to install or evidence of the actual router state. Invalid/missing evidence gives BLOCKED. Every handled CLI path prints `NOT AUTHORIZED FOR DEVICE DEPLOYMENT`.

The tool is **not** an SSH installer, not an automated preflight collector, not a rollback program, and does not create a deployment package. Its in-memory transaction test only checks logical reversal, not actual remote filesystem recovery.

## Proposed isolation layout (candidates, not deployed)

| Role | Candidate | Hard boundary |
| --- | --- | --- |
| New Agent listener | TCP 19090 | Must be unoccupied on real device and supported across *all* Agent URLs/bindings |
| New Dashboard | TCP 18080 | Do not disturb stock Web UI / existing dashboard |
| Future new Mihomo listener | TCP 17890 | Not started or configured during G1-B |
| New installation root | `/data/u60-webui-isolated` | Dedicated subdirectories for binary, UI, runtime state, snapshots and staged releases |
| Existing system | `/data/mihomo`, `/data/zte-agent`, `/data/www.current` | Never overwrite or delete |
| Existing startup | `/etc/rc.local` | Read-only, capture hash, no registration or edit |
| Existing SSH | Root SSH on 2222 / Dropbear | Preserve keys, host key, service and access |

These names/ports are provisional. They must be revalidated before any real device step. G1-B requires candidate ports 19090/18080/17890 to be observed as free in the **local snapshot**, and requires observation records for legacy 7890/8080/9090; legacy occupancy is **allowed**. Missing or unverified observations block. The local snapshot is not a substitute for G2 actual read-only checks.

### Why G1-A CLEAR is not a gate for coexistence

G1-A intentionally blocks whenever legacy 7890/8080/9090 are occupied or `/data/mihomo` exists. Those may be the Owner's normal, protected running configuration. G1-B **does not** reuse G1-A's collision decision. It reuses only its strict input validator and tests new candidate resources independently. No old process needs to be stopped to make a planning test pass.

## Mandatory code changes still outstanding before any runnable parallel installation

Existing Peter deployment / runtime code is **not safely isolated**:

- `scripts/deploy-components.py` currently uses SSH `StrictHostKeyChecking=accept-new`. A future Owner-authorized transport must require an already pinned and independently verified host key (`StrictHostKeyChecking=yes` and a deliberately selected known-hosts entry); no key copying or Trust On First Use.
- Deployment code installs to `/data/zte-agent`, `/data/www.current`, and `/data/local/tmp/start_zte_agent.sh`, and manipulates `rc.local`; hardening can change Dropbear, stock UI, FOTA and USB startup behavior. **None of those commands may be reused as-is.**
- `agent/src/lan.rs` supports `ZTE_AGENT_BIND`, but default/rebind behavior references 9090, and other source files reference 9090 directly. Web UI requests and health checks also require per-instance port configuration before use.
- `agent/src/mihomo/service.rs`, `config.rs`, `profile.rs`, and `mod.rs` contain fixed `/data/mihomo` runtime paths, controller socket, state and provider paths. Merely relocating the executable would not isolate data or operations.
- Proxy management, transparent routing, firewall/DNS/IPv6/TUN, USB controls, update/reboot actions and any ability to kill named processes must be disabled or safely instance-scoped before a parallel Agent may start. No assumption that a read-only UI makes an Agent read-only.
- **Critical startup side effects:** `agent/src/main.rs` calls `diag_log::init`, `migrate_drop_removed_features` (which may update dnsmasq/UCI and delete legacy `/data/local/tmp` state), `AppState::new`, `event_bus.start`, `charge_limit.start`, `mihomo.start_watchdog`, `sms_forward::start`, `client_traffic::start`, the persisted `start_ttl.sh`, `usb::enforce_usb_mode_on_boot`, and `state.lan.recover` *before* serving requests. Some paths may alter USB, TTL, DNS, Mihomo, LAN or persistence without any web API request. Binding to a new port **does not prevent these mutations**. The current Rust Agent must not be started on the Owner device until a verified fail-closed, isolated, no-write startup path and write-disabled API surface exist; compile, mock-test and independently review the exact candidate first.
- The historical Mac Dev tool inventory has no Rust/Cargo. ARM64 binaries, startup behavior, UI and integration **have not been compiled or validated** in this phase.

No real SSH write/installer entrypoint is included until these issues are corrected and reviewed. Do not run `setup.sh`, `deploy.sh`, `deploy-dashboard.sh`, `scripts/zharden.sh`, or `scripts/deploy-mihomo.sh` against Owner hardware.

## Intended future install transaction — design only

1. **G2 read-only gate (requires explicit Owner authorization):** verify device identity and B31 firmware, SSH key-only login via existing verified management path, pinned host key, existing ECM and stock UI, `/data/mihomo`/processes, full `rc.local` hash, all relevant listeners, filesystem free space/mount behavior, existing routes/firewall/DNS, and current firmware services. Collect sanitized evidence with no secrets. Abort if host identity changes or any safety fact is unavailable.
2. **Separate deployment approval:** verify isolated binaries and their signatures/hashes, exact source version, runtime paths and target ports. Require tested Agent write-safety isolation, independent security review, an exact recovery plan, and sufficient writable storage. A local plan alone never grants this approval.
3. **Stage:** create only a unique private directory under the new root, with `0700` permissions; hash-verify artifacts and preserve the previous isolated release. Do not touch legacy files, startup or services.
4. **Validate:** verify contents, environment, dedicated listeners, no route/firewall/DNS changes, and no access to legacy Mihomo data. Preserve backups of *only* owned isolated assets.
5. **Activate manually:** later, after approval, run the new instance without boot persistence and without taking over any client proxy; check authenticated health and accessibility.
6. **Rollback:** stop only the exact new instance PID; restore the previous isolated release using an owned transaction journal, remove only newly staged isolated artifacts, and reverify original Dropbear, ECM, stock UI, old Mihomo, DNS/route/firewall, and `rc.local` checksum. Do not use global `killall zte-agent` or delete any owner data. If recovery evidence fails, stop and escalate; no destructive cleanup.

### Required negative tests before device stage

Reject: missing/stale/unrecognized B31 evidence; host-key mismatch; disconnected ECM; occupied/unobserved candidate ports; missing observations of legacy ports; insufficient space; symlinks escaping the isolated root; concurrent/pending transaction; insufficient permissions; interrupted upload; invalid hashes; failed health checks; startup/kill side effects; write outside owned directory; rollback failure. Test with a mock filesystem/transport and failure injection, then independently review the exact implementation.

**G1-B current mock:** Python tests cover schema, stale/unknown/occupied observations, preservation of legacy state, no execution and *in-memory* reverse-order transaction simulation. They do **not** verify actual SSH installation, real filesystem rollback, Rust binaries, network proxies or the hardware.

## Lifecycle

- G0 PR #1 remains Draft / unmerged.
- G1-A PR #2 remains Draft / unmerged and based on G0.
- G1-B is a new stacked Draft-only candidate; no automatic merges.
- No GitHub Actions / CI. Tests are local. No installation, OTA, route replacement or production change without Owner decision.
