# G0 Read-only baseline and deployment gate — 2026-11-17

**Project:** north-coding/U60-Pro-WebUI
**Owner device:** ZTE U60 Pro / MU5250, reported firmware `BD_CNMU5250V1.0.0B31`
**Scope:** source and offline testing only. **No router access or mutation occurred.**

## 1. Reproducible provenance

| Role | Ref | SHA / details |
|---|---|---|
| Fork to develop | `north-coding/U60-Pro-WebUI` | `main` initially identical to Peter |
| Product source | `peter5842/U60-Pro-WebUI` | `069bf9840eff1a70dd17809fecbf30af8975e6c5` |
| Parent upstream | `dklasens/MU5250-OpenUI` | `v2.5` points to `6aa3bf3e769a013354f15d4a27859cbe9c8ea00e` |
| Common ancestor (fork vs v2.5) | local Git merge-base | `f95e4f4ab7dadca75dcf3df00d4f9a8e16c1aeaf` |
| Local feature branch | `feat/g0-audit-ssh-preflight-20261117` | isolated worktree, no main changes |

Compared with this ancestor, Peter has 25 branch-only commits / 146 changed paths and dklasens v2.5 has 7 branch-only commits / 110 changed paths; 20 paths overlap. Overlap includes `agent/src/server.rs`, `agent/src/network_ext.rs`, `agent/src/router.rs`, `agent/src/handlers.rs`, `agent/src/wifi.rs`, `web-app/src/data/api.ts`, `web-app/src/types.ts`, `Cargo.lock`. **No wholesale merge or automatic cherry-pick.**

## 2. Code evidence versus unverified claims

**Source-confirmed:** Peter contains a Rust device API (`agent/`), a browser dashboard (`web-app/`), and subscription/selection/TUN code (`agent/src/mihomo/`, `web-app/src/features/proxy/`). `agent/src/mihomo/config.rs` creates settings, subscriptions and TUN configuration; `service.rs` manages Mihomo runtime firewall, TUN route and bypass rules. `scripts/deploy-mihomo.sh` stages downloaded files under `/data/mihomo`. `scripts/device/transaction.sh` provides deployment snapshots including `/etc/rc.local`.

**Project claims requiring owner-device validation:** complete B31 support, router-wide proxy reliability, WAN/SSH survival, watchdog recovery, domestic throughput hardware offload. Tests on another MU5250 or HK firmware do not prove these on the owner's B31.

**Source-confirmed limitations:** managed config sets `ipv6: false` and `dns.ipv6: false` (`agent/src/mihomo/config.rs`); mainland fast-path bypass handles IPv4 prefixes (`agent/src/mihomo/service.rs`); firewall code handles both iptables/ip6tables, but that alone does **not** establish IPv6 leak prevention or UDP correctness. The `/api/proxy` of other UFI projects is unrelated to a transparent proxy and must not be conflated.

**Upstream v2.5 relevance:** the 7 upstream-only commits include handling stalled uploads/panics and in-flight uploads, Metrics source freshness, and removable-eUICC/eSIM support. These require **targeted security review and behavior tests** against Peter's changed server/network code, not blanket merge. ESim is explicitly out of the current proxy objective; do not import it by default.

## 3. Known conflicts and scope of uncertainty

| Surface | Peter's source assumption | Owner's previously observed state | Gate |
|---|---|---|---|
| SSH | Root `2222`, own Dropbear startup | Existing working key-only Root SSH; do not replace keys/service | Preserve byte-for-byte, never reprovision |
| USB | Stock USB ECM and special firmware behavior | Mac USB ECM `en12`, `192.168.0.45`; 2/2 Ping after a prior ADB incident | **No** live `usb_op`, ConfigFS, ADB or gadget changes |
| Agent API | `192.168.0.1:9090` | Prior independent Mihomo controller/Zashboard on 9090 | Must move new API to a verified free port or deliberately design migration |
| Mihomo files | `/data/mihomo` | Existing separate Mihomo binary, config, rules, provider storage | No overwrites; isolate new state until complete and tested |
| Proxy ports | controller `9097`, mixed listener configurable (historically 7890) | Existing mixed 7890 and old dashboard; live status not currently measured | No duplicate listeners, ownership-based checks |
| Browser page | `:8080` | Occupancy unverified on owner device | Check later read-only, choose collision-free port |
| Boot hooks | `/etc/rc.local` | Existing custom startup and SSH hooks; exact current content not captured in this G0 | Backup/hash, minimal append only in separately approved G1/G2 |
| Cellular/eSIM | Device command handlers exist | Stock eSIM/APN/SIM must remain unchanged | No related writes or replacement |
| Firewall/routing | Temporary TUN and iptables/IP rules | Older proxy rules may remain; no live verification this run | Do not mutate until owner-authorized isolated proxy window |

Historical owner facts are not assumed to reflect today's process/port state. We have NOT inspected the live router.

## 4. Local validation

The Owner's existing decision excludes GitHub Actions/CI. All tests, builds, and reviews use the authorized local development and reviewer environments; GitHub is for version control and Draft PRs only.

Mac Dev was missing Rust/Cargo (and no Rust toolchain was installed in G0). Therefore no local Rust build/test or ARM64 execution is claimed. Local Python validation:

- `python3 -m unittest discover -s tests -q`: **71/71 PASS** after a small test-only correction in `tests/test_mock_agent.py`. Previous test incorrectly failed when a registered delete endpoint legitimately returned `404 no such rule`.
- `python3 scripts/check-api-contract.py`: **PASS**; agent/dashboard/mock all report 111 routes across 90 paths.
- `python3 scripts/check-device-secrets.py`: **PASS** for its tracked-secret scan scope.
- `git diff --check`: **PASS**.
- Node/npm dashboard and Playwright checks **not locally executed** in G0; remain pending authorized local-only validation.

Passing a source/mocked test does not establish any specific hardware or firewall behavior.

## 5. Minimum G1 SSH installer contract (design only, NOT implemented)

1. **Preflight first, read-only:** exact MU5250+B31 identity, root SSH verified with the owner's own key/host-key pinning, `/data` free space, process/listen ports, `/data/mihomo` ownership, `/etc/rc.local` checksum, relevant network state. Never reveal secrets/IMEI/ICCID.
2. **Non-disruptive staging:** build and verify signed/checksummed ARM64 artifacts on a development host; stage new agent/dashboard in independent namespaced `/data` paths and unused ports. Do not use `setup.sh`/unlock/hardening as a shortcut; do not touch working SSH or USB.
3. **Explicit port/path adaptation:** current hardcoded agent 9090 and Mihomo `/data/mihomo` conflict with owner legacy installation. Resolve in source and isolated tests **before** any live deployment. No forced killing or overwriting legacy processes/config.
4. **No immediate boot persistence:** start only the new independent UI/agent under supervision, prove health/login/read-only telemetry, and verify old 80/9090/SSH/ECM still work. On failure, stop only newly owned processes and remove only owned staged files.
5. **Separately approved persistence:** preserve exact `rc.local` file content/ownership/mode, refuse unknown or edited boot state, syntax-check before activation, retain recovery snapshot and verify after controlled reboot only when approved.
6. **Separately approved proxy migration:** inspect current routes/DNS/iptables/ip6tables, preserve original configs, staged TUN fail-safe and rollback. Verify real iPhone IPv4/IPv6/DNS/UDP and mainland direct / overseas proxy behavior before considering old Mihomo cleanup. Never treat subscriber fetch or node test success as sufficient.

## 6. Decision

**GO** to private fork, test-only patch, Draft PR, and local-only tests/review. No GitHub Actions/CI.
**NO-GO** to device install, upstream v2.5 merge, SSH service reprovision, transparent proxy activation or removal of old Mihomo.

Potential future tasks after G0: review/port narrowly justified upstream security changes, design isolated configurable Agent port and independent Mihomo data directory, and implement/test a guarded SSH preflight. All real router actions remain subject to an explicit owner-approved execution window.
