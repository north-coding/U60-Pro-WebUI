import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_single_mihomo_cutover as validator


MANIFEST_PATH = ROOT / "docs/G2C-SINGLE-MIHOMO-CUTOVER-MANIFEST.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def synthetic_inventory():
    paths = []
    for target in MANIFEST["candidate_cleanup_targets"]:
        record = {
            "path": target["path"],
            "kind": target["kind"],
            "classification": target["classification"],
            "owner_id": target["owner_id"],
            "present": True,
            "evidence": {
                "method": "owner_verified_exact_inventory",
                "verified": True,
                "path": target["path"],
                "owner_id": target["owner_id"],
            },
        }
        if target["kind"] == "file":
            record["evidence"]["sha256"] = "a" * 64
        elif target["kind"] == "directory":
            record["children_complete"] = True
            record["children"] = []
        elif target["kind"] == "startup_entry":
            record["exact_entry"] = target["exact_entry"]
            record["evidence"]["exact_entry"] = target["exact_entry"]
        paths.append(record)

    artifacts = [
        {
            "id": item["id"],
            "path": item["path"],
            "present": True,
            "sha256": "b" * 64,
            **({"arch": item["arch"]} if item["arch"] else {}),
        }
        for item in MANIFEST["required_artifacts"]
    ]
    checks = {name: True for name in MANIFEST["offline_preparation_checks"]}
    checks.update({name: False for name in MANIFEST["activation_checks"]})
    managed_runtime_paths = [
        {
            "path": item["path"],
            "kind": item["kind"],
            "classification": item["classification"],
            "owner_id": item["owner_id"],
            "present": True,
            "evidence": {
                "method": "owner_verified_exact_inventory",
                "verified": True,
                "path": item["path"],
                "owner_id": item["owner_id"],
            },
        }
        for item in MANIFEST["single_instance_storage"]["managed_runtime_paths"]
    ]
    return {
        "schema_version": 1,
        "source": "synthetic",
        "paths_inventory_complete": True,
        "services_inventory_complete": True,
        "routes_inventory_complete": True,
        "managed_runtime_inventory_complete": True,
        "paths": paths,
        "managed_runtime_paths": managed_runtime_paths,
        "services": [
            {"name": item["name"], "owner_id": item["owner_id"], "state": "stopped"}
            for item in MANIFEST["managed_services"]
        ],
        "routes": [],
        "artifacts": artifacts,
        "checks": checks,
        "transition": {
            "phase": "prepared_offline",
            "interrupted": False,
            "rollback_snapshot_complete": True,
            "rc_local_snapshot_complete": True,
        },
    }


class SingleMihomoCutoverValidator(unittest.TestCase):
    def report(self, state):
        return validator.validate(MANIFEST, state)

    def test_synthetic_inventory_yields_manual_dry_run_candidates_only(self):
        result = self.report(synthetic_inventory())
        self.assertEqual(result["status"], "offline_plan_only")
        self.assertTrue(result["offline_only"])
        self.assertFalse(result["deployment_ready"])
        self.assertFalse(result["execution_supported"])
        self.assertFalse(result["activation_checks_confirmed"])
        self.assertEqual(result["routing_cleanup_targets"], [])
        self.assertTrue(result["candidate_actions"])
        self.assertTrue(all(a["requires_owner_review"] for a in result["candidate_actions"]))
        self.assertTrue(all(not a["execution_supported"] for a in result["candidate_actions"]))

    def test_g2g_contract_is_synthetic_only_and_never_restores_legacy_startup(self):
        transaction = MANIFEST["startup_activation_transaction"]
        self.assertFalse(transaction["device_execution_enabled"])
        self.assertEqual(transaction["execution_mode"], "marked_temporary_synthetic_root_only")
        self.assertIn("never restore the abandoned legacy startup entry", transaction["rollback_policy"])
        self.assertIn("verify listener executable and process identity", transaction["health_check"]["device_gate"])
        self.assertFalse(MANIFEST["management_transport"]["forwarded_client_address_headers_trusted"])
        self.assertIn("deployment_blocker", MANIFEST["management_transport"]["source_aware_login_throttling"])

    def test_unknown_owner_blocks_all_candidates(self):
        state = synthetic_inventory()
        state["paths"][0]["classification"] = "unknown"
        result = self.report(state)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("ownership" in blocker for blocker in result["blockers"]))

    def test_malformed_transition_or_evidence_blocks_without_crashing(self):
        state = synthetic_inventory()
        state["transition"] = "interrupted"
        state["paths"][0]["evidence"] = []
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("transition inventory" in blocker for blocker in result["blockers"]))
        self.assertTrue(any("evidence is malformed" in blocker for blocker in result["blockers"]))

    def test_rc_local_allows_only_the_exact_project_startup_entry(self):
        state = synthetic_inventory()
        entry = next(item for item in state["paths"] if item["kind"] == "startup_entry")
        entry["exact_entry"] = "sh /tmp/unverified.sh"
        entry["evidence"]["exact_entry"] = "sh /tmp/unverified.sh"
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("unexpected startup entry" in blocker for blocker in result["blockers"]))

    def test_unexpected_path_blocks_all_candidates(self):
        state = synthetic_inventory()
        state["paths"].append(
            {
                "path": "/data/unknown-component",
                "kind": "file",
                "classification": "unknown",
                "owner_id": "unknown",
                "present": True,
                "evidence": {},
            }
        )
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("unexpected path" in blocker for blocker in result["blockers"]))

    def test_managed_runtime_path_overlapping_legacy_cleanup_blocks_plan(self):
        state = synthetic_inventory()
        manifest = copy.deepcopy(MANIFEST)
        managed = next(
            item
            for item in manifest["single_instance_storage"]["managed_runtime_paths"]
            if item["id"] == "managed-agent-binary"
        )
        managed["path"] = "/data/zte-agent"
        result = validator.validate(manifest, state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("overlaps legacy cleanup target" in blocker for blocker in result["blockers"]))

    def test_unknown_or_shared_managed_runtime_owner_blocks_plan(self):
        for ownership in ("unknown", "shared"):
            with self.subTest(ownership=ownership):
                state = synthetic_inventory()
                state["managed_runtime_paths"][0]["classification"] = ownership
                result = self.report(state)
                self.assertEqual(result["candidate_actions"], [])
                self.assertTrue(any("managed runtime" in blocker for blocker in result["blockers"]))

    def test_cleanup_inventory_cannot_alias_managed_runtime(self):
        state = synthetic_inventory()
        state["managed_runtime_paths"][0]["path"] = "/data/zte-agent"
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("overlaps a cleanup target" in blocker for blocker in result["blockers"]))

    def test_active_managed_service_blocks_cleanup_plan(self):
        state = synthetic_inventory()
        state["services"][1]["state"] = "running"
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("must be stopped" in blocker for blocker in result["blockers"]))

    def test_missing_artifact_blocks_cleanup_plan(self):
        state = synthetic_inventory()
        state["artifacts"] = [item for item in state["artifacts"] if item["id"] != "mihomo-binary"]
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("artifact is missing" in blocker for blocker in result["blockers"]))

    def test_interrupted_transition_blocks_cleanup_plan(self):
        state = synthetic_inventory()
        state["transition"]["interrupted"] = True
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("interrupted" in blocker for blocker in result["blockers"]))

    def test_conflicting_route_is_never_a_cleanup_target(self):
        state = synthetic_inventory()
        state["routes"] = [
            {"family": "ipv4", "priority": 9001, "table": "2022", "classification": "unknown"}
        ]
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertEqual(result["routing_cleanup_targets"], [])
        self.assertTrue(any("conflicting TUN route" in blocker for blocker in result["blockers"]))

    def test_incomplete_directory_inventory_blocks_whole_directory_action(self):
        state = synthetic_inventory()
        directory = next(item for item in state["paths"] if item["kind"] == "directory")
        directory["children_complete"] = False
        result = self.report(state)
        self.assertEqual(result["candidate_actions"], [])
        self.assertTrue(any("complete child inventory" in blocker for blocker in result["blockers"]))

    def test_cli_requires_explicit_dry_run(self):
        state_path = ROOT / "tests/.g2c-cutover-synthetic.json"
        try:
            state_path.write_text(json.dumps(synthetic_inventory()), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate_single_mihomo_cutover.py"),
                    "--state",
                    str(state_path),
                    "--manifest",
                    str(MANIFEST_PATH),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--dry-run is required", result.stderr)
        finally:
            state_path.unlink(missing_ok=True)

    def test_cli_dry_run_prints_non_executable_plan(self):
        state_path = ROOT / "tests/.g2c-cutover-synthetic.json"
        try:
            state_path.write_text(json.dumps(synthetic_inventory()), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate_single_mihomo_cutover.py"),
                    "--state",
                    str(state_path),
                    "--manifest",
                    str(MANIFEST_PATH),
                    "--dry-run",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(output["status"], "offline_plan_only")
            self.assertFalse(output["deployment_ready"])
            self.assertFalse(output["execution_supported"])
        finally:
            state_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
