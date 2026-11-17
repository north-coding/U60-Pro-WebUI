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

Next review: after G1-B offline focused audit; before any G1-B device-facing SSH installer work. Only the Owner-approved lifecycle may authorize deleting authoritative evidence or worktrees with unresolved recovery value. **No cleanup performed in G0/G1-A.**

No GitHub Actions/CI is authorized; local tests and proportionate independent review are the evidence source.
