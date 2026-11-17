# G1-D — Isolated Mihomo config preview (offline only)

**Date:** 2026-11-17
**Base:** G1-C Draft PR #4, commit `d74c0ed62445ec07af32b413e03eb904c71867b3`
**Status:** PURE IN-MEMORY RENDERER ONLY — **NOT AUTHORIZED FOR DEVICE STARTUP OR DEPLOYMENT**

## Why this slice

The original WebUI already includes adding, editing, deleting, and manually updating subscriptions, node selection, and rule-mode controls. The blocker is the backend: the current `mihomo::Manager` is firmly tied to the existing `/data/mihomo` and starts background tasks and potentially modifies router DNS, routes and USB from the legacy Agent. Reimplementing the frontend would not fix coexistence.

G1-D adds `mihomo::config::render_isolated_preview(&State)`. It reuses the existing **pure** managed subscription/group/rule renderer to prepare a candidate config *without* file reads or writes, network requests, process creation, firewall, DNS/UCI/USB operations, or starting Mihomo. The safe G1-C `--isolated-readonly` process and existing legacy runtime are unchanged. The new function is deliberately **not wired to the server, any API or deployment script**.

## In-memory candidate contract

- Fixed isolated mixed port `17890`, `allow-lan=false`, `bind-address=127.0.0.1`; no TCP controller; only candidate Unix controller path `/data/u60-webui-isolated/runtime/mihomo.sock`.
- No TUN/transparent proxy, iptables, routing marks, public listener/UI or DNS listener. DNS and NTP are disabled; geodata auto-update disabled; selection persistence disabled.
- Managed subscription providers and existing groups/rules are retained. Each provider interval is set to 0, and automated health checks are disabled. **This does not guarantee that Mihomo will avoid network requests when a config is eventually launched. In particular, enabled HTTP providers may still fetch at startup. Therefore the rendered config is NOT approved for actual Mihomo execution.**
- Input state is not modified. Reject full-provider profile-mode import, TUN, unsupported/duplicate IDs, unsafe IDs, invalid subscription URLs/names/update intervals, and too many subscriptions before rendering.
- Subscription URLs can include embedded provider account tokens; generated configs are secret-bearing and **must not be logged, included in PRs, or served via an unauthenticated HTTP endpoint**.
- The legacy `render(...)` behavior remains unchanged and is still device-unsafe without G1-D/G1-C isolation.

## Local verification

Mac Dev project-local Rust 1.100.0, no on-device access:
- `cargo test --locked -p zte-agent`: **129 pass / 4 ignored** (5 additional focused tests).
- `cargo fmt --all -- --check`, ARM64 musl `cargo check --locked -p zte-agent --target aarch64-unknown-linux-musl`: PASS, only a type check, not a runnable ARM64 binary.
- Scoped strict Clippy, exempting only two pre-existing Rust 1.100 `clippy::manual_is_multiple_of` findings in unchanged files: PASS.
- Python offline snapshot regression: **98/98 PASS**, synthetic/no-router evidence only.
- No WebUI/frontend changes; its existing subscription flows remain unmodified.

## Remaining gates

**G1-E or later:** Design and independently review a dedicated isolated storage root, runtime path mapping for all Mihomo artifacts, controller + HTTP authentication for managing the instance, explicit refresh behavior that never changes the existing Mihomo, parser/profile-mode restrictions, safe API transaction and rollback, background process ownership, OS/DNS/route/firewall/USB preservation, and a physical-device read-only baseline after a separate Owner approval. Do not start Mihomo with this preview or touch existing `/data/mihomo`, legacy 7890/9090, `rc.local`, Dropbear, or cellular settings. No real U60 SSH access, deployment, merging or GitHub CI authorized in G1-D.
