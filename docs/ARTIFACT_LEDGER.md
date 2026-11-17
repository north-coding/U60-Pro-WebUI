# U60 Pro — Development Artifact Ledger

Owner: north-coding. Development host: Mac Dev only. This ledger tracks **temporary development/review evidence**. It does not authorize deleting any file.

| Path (Mac Dev) | Task | Purpose / retention reason | Status | Cleanup checkpoint |
|---|---|---|---|---|
| `/Users/north/Developer/U60-Pro-WebUI` | G0 | Canonical clean `main` checkout; preserve as project state | RETAIN | Project retirement / Owner-approved migration |
| `/Users/north/Developer/Worktrees/u60-pro-webui-g0-20261117` | G0 | PR #1 exact candidate and source review | PENDING_CLEANUP | After PR #1 disposition and dependent worktree rebase |
| `/Users/north/Developer/Worktrees/u60-pro-webui-g1a-20261117` | G1-A | Offline preflight implementation and review candidate | PENDING_CLEANUP | After G1-A Draft PR disposition |
| `/tmp/u60-g0-task-20261117.md` | G0 | Original agent scope and safety contract | PENDING_CLEANUP | After PR #1 completion and evidence archival |
| `/tmp/u60-g0-codex-console-20261117.log` | G0 | Agent execution record, interrupted source review | PENDING_CLEANUP | After PR #1 completion and evidence archival |
| `/tmp/u60-g0-final-result-20261117.txt` | G0 | Consolidated test/repo result (historical; superseded CI plan) | PENDING_CLEANUP | After PR #1 completion and evidence archival |
| `/tmp/u60-g0-python-tests-20261117.log` | G0 | Initial test failure record | PENDING_CLEANUP | After PR #1 completion and evidence archival |
| `/tmp/u60-g0-tests-after-fix-20261117.log` | G0 | Regression retest evidence | PENDING_CLEANUP | After PR #1 completion and evidence archival |
| `/tmp/u60-g0-pr-body.md` | G0 | Historical Draft PR text | PENDING_CLEANUP | After PR #1 completion |
| `/tmp/u60-g1a-contract-20261117.md` | G1-A | First task contract, stopped for excessive scope | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-codex-20261117.log` | G1-A | Stopped broad agent attempt | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-focused-20261117.md` | G1-A | Narrow task contract | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-focused-codex-20261117.log` | G1-A | Implementation agent evidence | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-remediation-20261117.md` | G1-A | Focused reviewer-driven remediation instructions | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-remediation-codex-20261117.log` | G1-A | Remediation implementation evidence | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-all-py-tests-20261117.log` | G1-A | Host-side 80/80 Python test evidence | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-after-rebase-tests-20261117.log` | G1-A | Final host-side Python 80/80 tests after branch rebase | PENDING_CLEANUP | After G1-A PR completion |
| `/tmp/u60-g1a-pr-body-20261117.md` | G1-A | Draft PR #2 description and scope | PENDING_CLEANUP | After PR #2 completion |

| `/Users/north/Developer/Worktrees/u60-pro-webui-g1b-20261117` | G1-B | Isolated offline coexistence planner, synthetic tests and architecture; stacked on G1-A | RETAIN / DRAFT_CANDIDATE | After G1-B PR lifecycle decision |
| `/tmp/u60-g1a-focused-notice-contract-20261117.md` | G1-A | Scoped CLI authorization notice task | PENDING_CLEANUP | After PR #2 lifecycle decision |
| `/tmp/u60-g1a-focused-notice-codex-20261117.log` | G1-A | Implementation agent record and sandbox limitation | PENDING_CLEANUP | After PR #2 lifecycle decision |
| `/tmp/u60-g1a-full-local-after-notice-20261117.log` | G1-A | 81/81 host-side Python test evidence | PENDING_CLEANUP | After PR #2 lifecycle decision |
| `/tmp/u60-g1b-offline-contract-20261117.md` | G1-B | Scoped design / offline implementation task contract | PENDING_CLEANUP | After G1-B PR lifecycle decision |
| `/tmp/u60-g1b-offline-codex-20261117.log` | G1-B | Partial agent execution evidence; session terminated after prolonged inactivity; resulting files separately verified | PENDING_CLEANUP | After G1-B PR lifecycle decision |
| `/tmp/u60-g1b-local-tests-20261117.log` | G1-B | Local offline and regression test evidence (when generated) | PENDING_CLEANUP | After G1-B PR lifecycle decision |

| `/tmp/u60-g1b-focused-review-20261117.md` | G1-B | Focused ChatGPT exact-diff/surrounding-source review; startup side-effect finding and disposition | PENDING_CLEANUP | After Draft PR #3 final review |
| `/tmp/u60-g1b-review-remediate-task-20261117.md` | G1-B | Scoped Codex follow-up contract for review finding | PENDING_CLEANUP | After PR #3 lifecycle decision |
| `/tmp/u60-g1b-review-remediate-codex-20261117.log` | G1-B | Interrupted overbroad source scan; no edits; preserved for cost/traceability | PENDING_CLEANUP | After PR #3 lifecycle decision |
| `/tmp/u60-g1b-reviewed-local-tests-20261117.log` | G1-B | Post-remediation local test and safety check record | PENDING_CLEANUP | After PR #3 lifecycle decision |
| `/tmp/u60-g1b-draft-pr-body-20261117.md` | G1-B | Draft PR #3 description and review disposition | PENDING_CLEANUP | After PR #3 lifecycle decision |

| `/Users/north/Developer/U60-BuildTools` | G1-C | Project-local verified Rust 1.100.0 minimal toolchain, ARM64 musl std target, Cargo cache, native/target check outputs and validation logs; no global PATH changes | RETAIN / PENDING_CLEANUP | After G1-C build and review evidence retention decision |
| `/Users/north/Developer/Worktrees/u60-pro-webui-g1b-20261117/web-app/node_modules` | G1-C | Locked npm install (241 packages), needed for local UI verification | PENDING_CLEANUP | Once G1-C UI build validation no longer needs incremental tests |
| `/Users/north/Developer/Worktrees/u60-pro-webui-g1b-20261117/web-app/dist` | G1-C | Regenerable local TypeScript/Vite build output | PENDING_CLEANUP | After G1-C UI build evidence archived |
| `/tmp/u60-g1c-frontend-local-20261117.log` | G1-C | npm ci/build/lint/275 Node tests evidence for G1-B head 9deff002 | PENDING_CLEANUP | After G1-C local validation report finalized |

| `/Users/north/Developer/Worktrees/u60-pro-webui-g1c-20261117` | G1-C | Isolated loopback-only read-only startup prototype; stacked on Draft PR #3 | RETAIN / DRAFT_CANDIDATE | G1-C local and independent review complete |
| `/tmp/u60-g1c-isolated-readonly-contract-20261117.md` | G1-C | Bounded Codex implementation task contract | PENDING_CLEANUP | G1-C PR lifecycle decision |
| `/tmp/u60-g1c-isolated-readonly-codex-20261117.log` | G1-C | Interrupted Codex read-heavy execution, no code edits; retained as actual invocation evidence | PENDING_CLEANUP | G1-C PR lifecycle decision |
| `/tmp/u60-g1c-rust-native-20261117.log` | G1-C | Native 124 pass, 4 ignored Rust tests for isolated prototype | PENDING_CLEANUP | G1-C review completion |
| `/tmp/u60-g1c-verify-20261117.log` | G1-C | Native 124-pass Rust, ARM64 musl check, clippy-scoped, Mac binary link and 98 Python regression evidence | PENDING_CLEANUP | G1-C review completion |
| `/tmp/u60-g1c-loopback-smoke-20261117.py` | G1-C | Mac Dev-only isolated binary HTTP/CLI/port-conflict smoke harness, never legacy startup | PENDING_CLEANUP | After G1-C exact candidate review |
| `/tmp/u60-g1c-loopback-smoke-20261117.log` | G1-C | Successful real Mac Dev loopback process verification and termination evidence | PENDING_CLEANUP | After G1-C exact candidate review |
| `/tmp/u60-g1c-focused-review-20261117.md` | G1-C | Focused ChatGPT exact-diff security review with remaining independent-review gate | PENDING_CLEANUP | After G1-C PR lifecycle decision |
| `/tmp/u60-g1c-review-prompt-20261117.md` | G1-C | Separate read-only Codex reviewer instruction, no modification scope | PENDING_CLEANUP | After G1-C PR lifecycle decision |
| `/tmp/u60-g1c-review-codex-20261117.log` | G1-C | Separate read-only reviewer transcript, if executed; no external paid reviewer permitted | PENDING_CLEANUP | After G1-C PR lifecycle decision |
| `/tmp/u60-g1c-pr-body-20261117.md` | G1-C | Draft PR #4 scope, test evidence and security gates | PENDING_CLEANUP | After G1-C PR lifecycle decision |

| `/Users/north/Developer/Worktrees/u60-pro-webui-g1d-20261117` | G1-D | Pure isolated Mihomo managed-config preview, stacked on G1-C Draft | RETAIN / DRAFT_CANDIDATE | G1-D review and PR lifecycle decision |
| `/tmp/u60-g1d-codex-task-20261117.md` | G1-D | Scoped implementation contract for ChatGPT-subscription Codex | PENDING_CLEANUP | G1-D PR lifecycle decision |
| `/tmp/u60-g1d-codex-20261117.log` | G1-D | Codex partial implementation transcript; 115s bound expired and orchestrator completed tests/hardening | PENDING_CLEANUP | G1-D PR lifecycle decision |
| `/tmp/u60-g1d-rust-20261117.log` | G1-D | Native 129 passing Rust tests, 4 ignored | PENDING_CLEANUP | G1-D review completion |
| `/tmp/u60-g1d-arm64-20261117.log` | G1-D | aarch64-unknown-linux-musl Rust type check only | PENDING_CLEANUP | G1-D review completion |
| `/tmp/u60-g1d-clippy-20261117.log` | G1-D | Clippy scoped exception for two preexisting style lints | PENDING_CLEANUP | G1-D review completion |
| `/tmp/u60-g1d-python-20261117.log` | G1-D | Offline Python regression test evidence | PENDING_CLEANUP | G1-D review completion |
| `/tmp/u60-g1d-pr-body-20261117.md` | G1-D | Draft PR summary, boundaries and test evidence | PENDING_CLEANUP | G1-D PR lifecycle decision |

Next review: after G1-D exact-diff offline source review; before any on-device test, live Mihomo process, or device-facing SSH installer work. Only the Owner-approved lifecycle may authorize deleting authoritative evidence or worktrees with unresolved recovery value. **No cleanup performed in G0/G1-A.**

No GitHub Actions/CI is authorized; local tests and proportionate independent review are the evidence source.
