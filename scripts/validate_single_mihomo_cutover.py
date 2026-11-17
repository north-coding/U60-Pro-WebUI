#!/usr/bin/env python3
"""Validate an offline single-Mihomo cutover inventory and print a dry-run plan.

This tool reads local JSON only. It has no device transport and no mutation
mode; its output is a candidate list for owner review, never a deployment plan.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
RC_LOCAL_PATH = "/etc/rc.local"
APPROVED_RC_ENTRY = "sh /data/local/tmp/start_zte_agent.sh"
OWNER_CLASSES = {
    "stock_zte_protected",
    "project_owned",
    "mihomo_owned",
    "unknown",
}
SERVICE_STATES = {"stopped", "running", "unknown"}


def canonical_absolute_path(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or value == "/"
        or "\\" in value
    ):
        return False
    if any(char in value for char in "*?[]"):
        return False
    path = PurePosixPath(value)
    return ".." not in path.parts and "." not in path.parts and path.as_posix() == value


def under(path: PurePosixPath, parent: PurePosixPath) -> bool:
    return path != parent and parent in path.parents


def validate(manifest: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    candidates = manifest.get("candidate_cleanup_targets", [])
    target_by_path = {item["path"]: item for item in candidates}
    protected_values = set(manifest.get("protected_paths", []))
    for component in manifest.get("protected_components", []):
        if component.get("classification") != "stock_zte_protected":
            blockers.append(f"protected component has invalid classification: {component.get('id')}")
        protected_values.update(component.get("paths", []))
    protected = {PurePosixPath(item) for item in protected_values}
    protected_prefixes = {
        PurePosixPath(item) for item in manifest.get("protected_path_prefixes", [])
    }

    if manifest.get("schema_version") != 1:
        blockers.append("unsupported manifest schema")
    if manifest.get("execution_mode") != "dry-run-only" or manifest.get(
        "device_mutations_supported"
    ) is not False:
        blockers.append("manifest must explicitly disable device mutations")
    routing_policy = manifest.get("routing_policy", {})
    if routing_policy.get("automatic_cleanup_targets") != []:
        blockers.append("manifest must not authorize automatic route cleanup")
    if routing_policy.get("check_before_both_tun_and_non_tun_starts") is not True:
        blockers.append("manifest must require a read-only routing check for both proxy modes")
    if len(target_by_path) != len(candidates):
        blockers.append("manifest contains duplicate candidate paths")
    for target in candidates:
        path_text = target.get("path")
        if not canonical_absolute_path(path_text):
            blockers.append(f"manifest contains a non-canonical target path: {path_text!r}")
            continue
        path = PurePosixPath(path_text)
        startup_entry = (
            target.get("kind") == "startup_entry"
            and path_text == RC_LOCAL_PATH
            and target.get("exact_entry") == APPROVED_RC_ENTRY
            and target.get("action") == "replace_exact_entry_only"
        )
        if target.get("kind") == "startup_entry" and not startup_entry:
            blockers.append(f"manifest startup entry is outside the exact allowlist: {path_text}")
        if any(path == p or under(path, p) for p in protected) and not startup_entry:
            blockers.append(f"manifest cleanup target overlaps a protected path: {path_text}")
        if any(path == p or under(path, p) for p in protected_prefixes):
            blockers.append(f"manifest target is under a protected system tree: {path_text}")
    if state.get("schema_version") != 1:
        blockers.append("unsupported inventory schema")
    for key in ("paths_inventory_complete", "services_inventory_complete", "routes_inventory_complete"):
        if state.get(key) is not True:
            blockers.append(f"inventory is incomplete: {key}")
    transition = state.get("transition")
    if not isinstance(transition, dict):
        transition = {}
        blockers.append("transition inventory is missing or malformed")
    if transition.get("interrupted") is not False:
        blockers.append("transition is interrupted or its state is unknown")
    if transition.get("phase") != "prepared_offline":
        blockers.append("transition is not at the prepared_offline checkpoint")
    for key in ("rollback_snapshot_complete", "rc_local_snapshot_complete"):
        if transition.get(key) is not True:
            blockers.append(f"transition is missing {key}")

    resources = state.get("paths")
    if not isinstance(resources, list):
        resources = []
        blockers.append("paths inventory is missing or malformed")
    path_records: dict[str, dict[str, Any]] = {}
    for resource in resources:
        if not isinstance(resource, dict):
            blockers.append("path inventory contains a malformed record")
            continue
        path_text = resource.get("path")
        if not canonical_absolute_path(path_text):
            blockers.append(f"unexpected or non-canonical path: {path_text!r}")
            continue
        if path_text in path_records:
            blockers.append(f"duplicate path inventory record: {path_text}")
            continue
        path_records[path_text] = resource
        path = PurePosixPath(path_text)

        target = target_by_path.get(path_text)
        parent_target = next(
            (
                item
                for item in candidates
                if item["kind"] == "directory"
                and under(path, PurePosixPath(item["path"]))
            ),
            None,
        )
        if target is None and parent_target is None:
            blockers.append(f"unexpected path is outside the allowlist: {path_text}")
            continue

        if any(path == p or under(path, p) for p in protected):
            # /etc/rc.local is protected as a file except for one exact entry.
            exact_entry = target and target.get("kind") == "startup_entry" and path_text == RC_LOCAL_PATH
            if not exact_entry:
                blockers.append(f"protected path appeared as a cleanup resource: {path_text}")
        if any(path == prefix or under(path, prefix) for prefix in protected_prefixes):
            blockers.append(f"path is under a protected system tree: {path_text}")

        expected = target or parent_target
        if target and resource.get("kind") != target["kind"]:
            blockers.append(f"resource kind mismatch for {path_text}")
        if resource.get("classification") not in OWNER_CLASSES:
            blockers.append(f"unknown ownership classification for {path_text}")
        if resource.get("classification") != expected["classification"]:
            blockers.append(f"ownership class mismatch for {path_text}")
        if resource.get("owner_id") != expected["owner_id"]:
            blockers.append(f"owner identity mismatch for {path_text}")
        if resource.get("present") is not True:
            blockers.append(f"inventory resource is not positively present: {path_text}")

        evidence = resource.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
            blockers.append(f"ownership evidence is malformed for {path_text}")
        if (
            evidence.get("method") != "owner_verified_exact_inventory"
            or evidence.get("path") != path_text
            or evidence.get("owner_id") != expected["owner_id"]
            or evidence.get("verified") is not True
        ):
            blockers.append(f"exact-path ownership evidence is missing for {path_text}")
        if resource.get("kind") == "file":
            if not SHA256.fullmatch(str(evidence.get("sha256", ""))):
                blockers.append(f"file hash evidence is missing or malformed for {path_text}")
        elif resource.get("kind") == "startup_entry":
            expected_entry = target.get("exact_entry") if target else None
            if expected_entry is None:
                blockers.append(f"startup entry is outside the exact allowlist: {path_text}")
            if evidence.get("exact_entry") != expected_entry:
                blockers.append(f"startup entry evidence does not match for {path_text}")
            if resource.get("exact_entry") != expected_entry:
                blockers.append(f"unexpected startup entry at {path_text}")
        elif resource.get("kind") == "directory":
            if resource.get("children_complete") is not True or not isinstance(
                resource.get("children"), list
            ):
                blockers.append(f"directory lacks a complete child inventory: {path_text}")
        elif resource.get("kind") != "symlink":
            blockers.append(f"unsupported resource kind for {path_text}")

    # A directory is eligible only when its enumerated direct children exactly
    # match the inventory and every descendant has the same verified owner.
    for root_text, root_record in path_records.items():
        if root_record.get("kind") != "directory":
            continue
        root_path = PurePosixPath(root_text)
        actual_children = sorted(
            path_text
            for path_text in path_records
            if PurePosixPath(path_text).parent == root_path
        )
        listed = root_record.get("children", [])
        if not isinstance(listed, list) or not all(canonical_absolute_path(item) for item in listed):
            blockers.append(f"directory child list is malformed: {root_text}")
            continue
        listed_children = sorted(listed)
        if root_record.get("children_complete") is True and actual_children != listed_children:
            blockers.append(f"directory child list is incomplete or unexpected: {root_text}")

    for target in candidates:
        if target["kind"] != "directory" or target["path"] in path_records:
            continue
        root = PurePosixPath(target["path"])
        if any(under(PurePosixPath(path_text), root) for path_text in path_records):
            blockers.append(f"directory root is missing from its child inventory: {target['path']}")

    services = state.get("services")
    if not isinstance(services, list):
        services = []
        blockers.append("service inventory is missing or malformed")
    managed = {item["name"]: item["owner_id"] for item in manifest.get("managed_services", [])}
    seen_services: set[str] = set()
    for service in services:
        if not isinstance(service, dict) or service.get("name") not in managed:
            blockers.append("service inventory contains an unknown service")
            continue
        if service["name"] in seen_services:
            blockers.append(f"duplicate service inventory record: {service['name']}")
        seen_services.add(service["name"])
        if service.get("owner_id") != managed[service["name"]]:
            blockers.append(f"service owner mismatch: {service['name']}")
        if service.get("state") not in SERVICE_STATES:
            blockers.append(f"invalid service state: {service['name']}")
        if service.get("state") != "stopped":
            blockers.append(f"service must be stopped before cutover planning: {service['name']}")
    for missing in sorted(set(managed) - seen_services):
        blockers.append(f"managed service inventory is missing: {missing}")

    routes = state.get("routes")
    if not isinstance(routes, list):
        routes = []
        blockers.append("route inventory is missing or malformed")
    low, high = manifest["routing_policy"]["conflict_rule_priority_range"]
    route_table = str(manifest["routing_policy"]["conflict_route_table"])
    for route in routes:
        if not isinstance(route, dict) or route.get("classification") not in OWNER_CLASSES:
            blockers.append("route inventory contains unknown ownership")
            continue
        if route.get("classification") == "unknown":
            blockers.append("route ownership is unknown")
        priority = route.get("priority")
        table = str(route.get("table", ""))
        if (isinstance(priority, int) and low <= priority <= high) or table == route_table:
            blockers.append("conflicting TUN route resource is present; no route deletion is planned")

    artifacts = state.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []
        blockers.append("artifact inventory is missing or malformed")
    artifact_by_id = {
        item.get("id"): item for item in artifacts if isinstance(item, dict) and item.get("id")
    }
    for required in manifest.get("required_artifacts", []):
        artifact = artifact_by_id.get(required["id"])
        if not artifact or artifact.get("present") is not True:
            blockers.append(f"required artifact is missing: {required['id']}")
            continue
        if not SHA256.fullmatch(str(artifact.get("sha256", ""))):
            blockers.append(f"artifact hash is missing or malformed: {required['id']}")
        if required.get("arch") and artifact.get("arch") != required["arch"]:
            blockers.append(f"artifact architecture mismatch: {required['id']}")

    checks = state.get("checks", {})
    if not isinstance(checks, dict):
        checks = {}
        blockers.append("preparation checks are missing or malformed")
    for check in manifest.get("offline_preparation_checks", []):
        if checks.get(check) is not True:
            blockers.append(f"offline preparation check failed: {check}")

    # De-duplicate in encounter order; one error per fact keeps the report short.
    blockers = list(dict.fromkeys(blockers))
    actions: list[dict[str, Any]] = []
    if not blockers:
        for target in candidates:
            record = path_records.get(target["path"])
            if record is not None:
                actions.append(
                    {
                        "id": target["id"],
                        "path": target["path"],
                        "action": target["action"],
                        "owner_id": target["owner_id"],
                        "requires_owner_review": True,
                        "execution_supported": False,
                    }
                )

    activation_checks = manifest.get("activation_checks", [])
    activation_confirmed = all(checks.get(check) is True for check in activation_checks)
    recovery_checks = manifest.get("failure_recovery_checks", [])
    recovery_confirmed = all(checks.get(check) is True for check in recovery_checks)
    return {
        "plan_id": manifest.get("plan_id"),
        "status": "blocked" if blockers else "offline_plan_only",
        "offline_only": True,
        "deployment_ready": False,
        "execution_supported": False,
        "activation_checks_confirmed": activation_confirmed,
        "pending_activation_checks": [check for check in activation_checks if checks.get(check) is not True],
        "failure_recovery_checks_confirmed": recovery_confirmed,
        "blockers": blockers,
        "candidate_actions": actions,
        "routing_cleanup_targets": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, help="local JSON inventory or synthetic fixture")
    parser.add_argument(
        "--manifest",
        default=str(Path(__file__).resolve().parents[1] / "docs/G2C-SINGLE-MIHOMO-CUTOVER-MANIFEST.json"),
        help="local cutover manifest JSON",
    )
    parser.add_argument("--dry-run", action="store_true", help="required; this tool never mutates")
    args = parser.parse_args()
    if not args.dry_run:
        parser.error("--dry-run is required; this validator has no mutation mode")
    try:
        with open(args.manifest, encoding="utf-8") as stream:
            manifest = json.load(stream)
        with open(args.state, encoding="utf-8") as stream:
            state = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "blocked", "blockers": [str(error)]}, indent=2))
        return 2
    if not isinstance(manifest, dict) or not isinstance(state, dict):
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "blockers": ["manifest and inventory must both be JSON objects"],
                },
                indent=2,
            )
        )
        return 2
    result = validate(manifest, state)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
