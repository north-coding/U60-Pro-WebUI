#!/usr/bin/env python3
"""Offline, fail-closed preflight for synthetic or locally collected evidence."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
MAX_SNAPSHOT_AGE = timedelta(hours=24)
TARGET_PORTS = (9090, 8080, 7890)
EXPECTED_MODEL = "ZTE MU5250"
EXPECTED_FIRMWARE = "BD_CNMU5250V1.0.0B31"
AUTHORIZATION_NOTICE = "NOT AUTHORIZED FOR DEVICE DEPLOYMENT"

TOP_LEVEL_FIELDS = {
    "schema_version",
    "model",
    "firmware",
    "collected_at",
    "ports",
    "mihomo_data_present",
    "rc_local_sha256",
    "rc_local_custom_hooks",
    "ssh_verified_key_only",
    "ecm_active",
}
PORT_FIELDS = {"port", "state", "owners", "observed"}
SENSITIVE_FIELD = re.compile(
    r"(?:password|passwd|token|secret|credential|authorization|auth|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|imei|imsi|iccid|"
    r"msisdn|serial(?:number)?)",
    re.IGNORECASE,
)
SENSITIVE_KEY_FIELD = re.compile(r"(?:^|[^a-z0-9])key(?:$|[^a-z0-9])", re.IGNORECASE)
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


class SnapshotError(ValueError):
    """A sanitized, user-safe snapshot validation error."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("Invalid snapshot: duplicate fields.")
        result[key] = value
    return result


def _reject_non_json_constant(_value: str) -> None:
    raise SnapshotError("Invalid snapshot: unsupported JSON value.")


def _check_sensitive_field_names(value: Any) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                # This one field records a boolean status, not key material.
                if key != "ssh_verified_key_only" and (
                    SENSITIVE_FIELD.search(key) or SENSITIVE_KEY_FIELD.search(key)
                ):
                    raise SnapshotError("Invalid snapshot: suspect sensitive field.")
                pending.append(child)
        elif isinstance(current, list):
            pending.extend(current)


def _require_exact_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) - expected:
        raise SnapshotError("Invalid snapshot: unknown fields.")
    if expected - set(value):
        raise SnapshotError("Invalid snapshot: required evidence is missing.")


def _require_bool(value: Any) -> bool:
    if type(value) is not bool:
        raise SnapshotError("Invalid snapshot: invalid evidence value.")
    return value


def _validate_snapshot(snapshot: Any) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise SnapshotError("Invalid snapshot: expected a JSON object.")

    _check_sensitive_field_names(snapshot)
    _require_exact_fields(snapshot, TOP_LEVEL_FIELDS)

    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != SCHEMA_VERSION:
        raise SnapshotError("Invalid snapshot: unsupported schema.")
    if not isinstance(snapshot["model"], str) or not snapshot["model"].strip():
        raise SnapshotError("Invalid snapshot: invalid evidence value.")
    if not isinstance(snapshot["firmware"], str) or not snapshot["firmware"].strip():
        raise SnapshotError("Invalid snapshot: invalid evidence value.")
    if not isinstance(snapshot["collected_at"], str):
        raise SnapshotError("Invalid snapshot: invalid timestamp.")
    try:
        collected_at = datetime.fromisoformat(snapshot["collected_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotError("Invalid snapshot: invalid timestamp.") from exc
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise SnapshotError("Invalid snapshot: timestamp must include a timezone.")

    if not isinstance(snapshot["rc_local_sha256"], str) or not SHA256.fullmatch(
        snapshot["rc_local_sha256"]
    ):
        raise SnapshotError("Invalid snapshot: invalid evidence value.")

    for field in (
        "mihomo_data_present",
        "rc_local_custom_hooks",
        "ssh_verified_key_only",
        "ecm_active",
    ):
        _require_bool(snapshot[field])

    ports = snapshot["ports"]
    if not isinstance(ports, list):
        raise SnapshotError("Invalid snapshot: invalid port evidence.")
    seen: set[int] = set()
    for entry in ports:
        if not isinstance(entry, dict):
            raise SnapshotError("Invalid snapshot: invalid port evidence.")
        _require_exact_fields(entry, PORT_FIELDS)
        port = entry["port"]
        if type(port) is not int or not 1 <= port <= 65535 or port in seen:
            raise SnapshotError("Invalid snapshot: invalid port evidence.")
        seen.add(port)
        if entry["state"] not in ("free", "occupied"):
            raise SnapshotError("Invalid snapshot: invalid port evidence.")
        if type(entry["observed"]) is not bool:
            raise SnapshotError("Invalid snapshot: invalid port evidence.")
        owners = entry["owners"]
        if not isinstance(owners, list) or any(
            not isinstance(owner, str) or not owner.strip() for owner in owners
        ):
            raise SnapshotError("Invalid snapshot: invalid port evidence.")
        if (entry["state"] == "free" and owners) or (
            entry["state"] == "occupied" and not owners
        ):
            raise SnapshotError("Invalid snapshot: invalid port evidence.")

    return snapshot


def evaluate_snapshot(snapshot: Any, now: datetime | None = None) -> list[str]:
    """Return stable, sanitized blockers; an empty list means offline checks pass."""
    data = _validate_snapshot(snapshot)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    collected_at = datetime.fromisoformat(data["collected_at"].replace("Z", "+00:00"))
    collected_at = collected_at.astimezone(timezone.utc)

    blockers: list[str] = []
    if data["model"] != EXPECTED_MODEL:
        blockers.append("Snapshot model is not supported.")
    if data["firmware"] != EXPECTED_FIRMWARE:
        blockers.append("Snapshot firmware is not supported.")
    if collected_at > current:
        blockers.append("Snapshot timestamp is in the future.")
    elif current - collected_at > MAX_SNAPSHOT_AGE:
        blockers.append("Snapshot is stale.")

    port_evidence = {entry["port"]: entry for entry in data["ports"]}
    for port in TARGET_PORTS:
        entry = port_evidence.get(port)
        if entry is None:
            blockers.append(f"Port {port} observation is missing.")
        elif not entry["observed"]:
            blockers.append(f"Port {port} observation is unverified.")
        elif entry["state"] == "occupied":
            blockers.append(f"Port {port} collision detected.")

    if data["mihomo_data_present"]:
        blockers.append("Existing /data/mihomo content is present.")
    if data["rc_local_custom_hooks"]:
        blockers.append("Existing custom rc.local hooks are present.")
    if not data["ssh_verified_key_only"]:
        blockers.append("SSH key-only access is not verified.")
    if not data["ecm_active"]:
        blockers.append("ECM is not active.")
    return blockers


def _load_snapshot(path: str) -> Any:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SnapshotError("Invalid snapshot: unable to read local JSON file.") from exc
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except SnapshotError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SnapshotError("Invalid snapshot: malformed JSON.") from exc


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: u60_offline_preflight.py SNAPSHOT.json", file=sys.stderr)
        return 2

    try:
        snapshot = _load_snapshot(args[0])
        blockers = evaluate_snapshot(snapshot)
    except SnapshotError as exc:
        print(str(exc))
        print(AUTHORIZATION_NOTICE)
        return 2

    if blockers:
        print("Offline preflight: BLOCKED")
        for blocker in blockers:
            print(f"- {blocker}")
        print(AUTHORIZATION_NOTICE)
        return 1

    print("Offline preflight: CLEAR")
    print("- Evidence checks passed.")
    print(AUTHORIZATION_NOTICE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
