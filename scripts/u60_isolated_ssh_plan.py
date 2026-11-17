#!/usr/bin/env python3
"""Offline-only coexistence plan from a local G1-A snapshot."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any

if __package__:
    from . import u60_offline_preflight as preflight
else:
    import u60_offline_preflight as preflight


AUTHORIZATION_NOTICE = "NOT AUTHORIZED FOR DEVICE DEPLOYMENT"
ISOLATED_ROOT = "/data/u60-webui-isolated"
CANDIDATE_PORTS = (
    (19090, "Agent"),
    (18080, "Dashboard"),
    (17890, "Future proxy"),
)
LEGACY_PORTS = frozenset((7890, 8080, 9090))
ALLOWED_PORTS = LEGACY_PORTS | frozenset(port for port, _label in CANDIDATE_PORTS)


def evaluate_snapshot(snapshot: Any, now: datetime | None = None) -> dict[str, Any]:
    """Return sanitized planning decisions; no empty blocker list means readiness."""
    # Reuse G1-A's exact-field, duplicate-port, sensitive-name, and value checks.
    data = preflight._validate_snapshot(snapshot)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    collected_at = datetime.fromisoformat(data["collected_at"].replace("Z", "+00:00"))
    collected_at = collected_at.astimezone(timezone.utc)

    blockers: list[str] = []
    if data["model"] != preflight.EXPECTED_MODEL:
        blockers.append("Snapshot model is not supported.")
    if data["firmware"] != preflight.EXPECTED_FIRMWARE:
        blockers.append("Snapshot firmware is not supported.")
    if collected_at > current:
        blockers.append("Snapshot timestamp is in the future.")
    elif current - collected_at > preflight.MAX_SNAPSHOT_AGE:
        blockers.append("Snapshot is stale.")

    ports = {entry["port"]: entry for entry in data["ports"]}
    if set(ports) - ALLOWED_PORTS:
        raise preflight.SnapshotError("Invalid snapshot: unexpected port observation.")

    for port in sorted(LEGACY_PORTS):
        entry = ports.get(port)
        if entry is None:
            blockers.append(f"Legacy port {port} observation is missing.")
        elif not entry["observed"]:
            blockers.append(f"Legacy port {port} observation is unverified.")

    for port, label in CANDIDATE_PORTS:
        entry = ports.get(port)
        if entry is None:
            blockers.append(f"Candidate port {port} observation is missing.")
        elif not entry["observed"]:
            blockers.append(f"Candidate port {port} observation is unverified.")
        elif entry["state"] != "free":
            blockers.append(f"Candidate port {port} is occupied.")

    if not data["ssh_verified_key_only"]:
        blockers.append("SSH key-only access is not verified.")
    if not data["ecm_active"]:
        blockers.append("ECM is not active.")

    return {
        "blockers": blockers,
        "candidate_ports": CANDIDATE_PORTS,
        "rc_local_sha256": data["rc_local_sha256"].lower(),
        "rc_local_custom_hooks": data["rc_local_custom_hooks"],
        "mihomo_data_present": data["mihomo_data_present"],
    }


def _print_header() -> None:
    print(f"*** {AUTHORIZATION_NOTICE} ***")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    _print_header()
    if len(args) != 1:
        print("Usage: u60_isolated_ssh_plan.py SNAPSHOT.json", file=sys.stderr)
        print("Offline plan: BLOCKED (one local snapshot path is required).")
        return 2

    try:
        snapshot = preflight._load_snapshot(args[0])
        plan = evaluate_snapshot(snapshot)
    except preflight.SnapshotError as exc:
        print("Offline plan: BLOCKED")
        print(f"- {exc}")
        return 2

    if plan["blockers"]:
        print("Offline plan: BLOCKED")
        for blocker in plan["blockers"]:
            print(f"- {blocker}")
        print("No device readiness is established; resolve evidence gaps in a separately reviewed phase.")
        return 1

    print("Offline plan only: CONDITIONAL CANDIDATE (not device-ready)")
    print(f"- Proposed isolated root: {ISOLATED_ROOT} (not created).")
    for port, label in plan["candidate_ports"]:
        print(f"- {label} candidate port {port}: observed free in this local snapshot; revalidate later.")
    print(
        "- Legacy ports 7890, 8080, and 9090 are outside the candidate check; "
        "occupancy is tolerated and no legacy process stop is planned."
    )
    print(
        f"- Preserve the recorded rc.local SHA-256 ({plan['rc_local_sha256']}) "
        f"and its custom-hook state ({'present' if plan['rc_local_custom_hooks'] else 'not reported'})."
    )
    print(
        f"- Preserve recorded /data/mihomo state "
        f"({'present' if plan['mihomo_data_present'] else 'not present'}); do not require it to be empty."
    )
    print("- STOP: The unmodified Rust Agent startup can modify USB, TTL, DNS, Mihomo, LAN, and device state; do not launch it.")
    print("- STOP: Runtime paths/ports are not isolated, and existing SSH deployment uses unpinned accept-new host keys.")
    print("- No files are transferred, no shell or change instructions are generated, and no device is contacted.")
    print("- This local result is not device-readiness evidence; later on-device revalidation is required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
