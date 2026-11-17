import ast
import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import u60_isolated_ssh_plan as plan
from scripts import u60_offline_preflight as preflight


NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
REQUIRED_PORTS = (19090, 18080, 17890)
LEGACY_PORTS = (7890, 8080, 9090)


def clean_snapshot(now=NOW):
    ports = [
        {"port": port, "state": "free", "owners": [], "observed": True}
        for port in (*LEGACY_PORTS, *REQUIRED_PORTS)
    ]
    return {
        "schema_version": 1,
        "model": "ZTE MU5250",
        "firmware": "BD_CNMU5250V1.0.0B31",
        "collected_at": now.isoformat().replace("+00:00", "Z"),
        "ports": ports,
        "mihomo_data_present": False,
        "rc_local_sha256": hashlib.sha256(b"synthetic rc.local").hexdigest(),
        "rc_local_custom_hooks": False,
        "ssh_verified_key_only": True,
        "ecm_active": True,
    }


def port_entry(snapshot, port):
    return next(entry for entry in snapshot["ports"] if entry["port"] == port)


class IsolatedSshPlanTests(unittest.TestCase):
    def test_all_candidate_ports_must_be_observed_free(self):
        result = plan.evaluate_snapshot(clean_snapshot(), NOW)

        self.assertEqual(result["blockers"], [])
        self.assertEqual(tuple(port for port, _ in result["candidate_ports"]), REQUIRED_PORTS)

    def test_each_occupied_candidate_blocks_without_echoing_owner(self):
        for port in REQUIRED_PORTS:
            with self.subTest(port=port):
                snapshot = clean_snapshot()
                entry = port_entry(snapshot, port)
                entry.update(state="occupied", owners=["sensitive-owner-name"])

                result = plan.evaluate_snapshot(snapshot, NOW)

                self.assertEqual(result["blockers"], [f"Candidate port {port} is occupied."])
                self.assertNotIn("sensitive-owner-name", str(result))

    def test_unknown_candidate_observation_blocks(self):
        for port in REQUIRED_PORTS:
            with self.subTest(port=port):
                snapshot = clean_snapshot()
                port_entry(snapshot, port)["observed"] = False

                result = plan.evaluate_snapshot(snapshot, NOW)

                self.assertEqual(
                    result["blockers"],
                    [f"Candidate port {port} observation is unverified."],
                )

    def test_missing_candidate_observation_blocks(self):
        for port in REQUIRED_PORTS:
            with self.subTest(port=port):
                snapshot = clean_snapshot()
                snapshot["ports"] = [entry for entry in snapshot["ports"] if entry["port"] != port]

                result = plan.evaluate_snapshot(snapshot, NOW)

                self.assertEqual(
                    result["blockers"],
                    [f"Candidate port {port} observation is missing."],
                )

    def test_legacy_ports_may_be_occupied(self):
        snapshot = clean_snapshot()
        for port in LEGACY_PORTS:
            port_entry(snapshot, port).update(state="occupied", owners=[f"legacy-{port}"])

        result = plan.evaluate_snapshot(snapshot, NOW)

        self.assertEqual(result["blockers"], [])

    def test_missing_or_unverified_legacy_observations_block(self):
        for port in LEGACY_PORTS:
            with self.subTest(port=port):
                snapshot = clean_snapshot()
                snapshot["ports"] = [entry for entry in snapshot["ports"] if entry["port"] != port]
                self.assertIn(f"Legacy port {port} observation is missing.", plan.evaluate_snapshot(snapshot, NOW)["blockers"])
                snapshot = clean_snapshot()
                port_entry(snapshot, port)["observed"] = False
                self.assertIn(f"Legacy port {port} observation is unverified.", plan.evaluate_snapshot(snapshot, NOW)["blockers"])

    def test_mihomo_and_custom_rc_local_state_are_preserved_not_blocked(self):
        snapshot = clean_snapshot()
        snapshot["mihomo_data_present"] = True
        snapshot["rc_local_custom_hooks"] = True
        expected_sha = snapshot["rc_local_sha256"]

        result = plan.evaluate_snapshot(snapshot, NOW)

        self.assertEqual(result["blockers"], [])
        self.assertTrue(result["mihomo_data_present"])
        self.assertTrue(result["rc_local_custom_hooks"])
        self.assertEqual(result["rc_local_sha256"], expected_sha)

    def test_model_firmware_staleness_ecm_and_ssh_fail_closed(self):
        cases = (
            ("model", "not the target", "Snapshot model is not supported."),
            ("firmware", "not B31", "Snapshot firmware is not supported."),
            ("collected_at", (NOW - timedelta(hours=24, seconds=1)).isoformat(), "Snapshot is stale."),
            ("ecm_active", False, "ECM is not active."),
            ("ssh_verified_key_only", False, "SSH key-only access is not verified."),
        )
        for field, value, expected in cases:
            with self.subTest(field=field):
                snapshot = clean_snapshot()
                snapshot[field] = value
                self.assertIn(expected, plan.evaluate_snapshot(snapshot, NOW)["blockers"])

    def test_future_snapshot_blocks(self):
        snapshot = clean_snapshot(NOW + timedelta(seconds=1))
        self.assertEqual(
            plan.evaluate_snapshot(snapshot, NOW)["blockers"],
            ["Snapshot timestamp is in the future."],
        )

    def test_unexpected_and_duplicate_ports_fail_closed(self):
        snapshot = clean_snapshot()
        snapshot["ports"].append(
            {"port": 2222, "state": "free", "owners": [], "observed": True}
        )
        with self.assertRaisesRegex(preflight.SnapshotError, "unexpected port observation"):
            plan.evaluate_snapshot(snapshot, NOW)

        snapshot = clean_snapshot()
        snapshot["ports"].append(copy.deepcopy(port_entry(snapshot, 19090)))
        with self.assertRaisesRegex(preflight.SnapshotError, "invalid port evidence"):
            plan.evaluate_snapshot(snapshot, NOW)

    def test_unknown_state_and_unexpected_fields_fail_closed(self):
        snapshot = clean_snapshot()
        port_entry(snapshot, 19090)["state"] = "unknown"
        with self.assertRaisesRegex(preflight.SnapshotError, "invalid port evidence"):
            plan.evaluate_snapshot(snapshot, NOW)

        snapshot = clean_snapshot()
        snapshot["unrecognized"] = "sensitive-value"
        with self.assertRaisesRegex(preflight.SnapshotError, "unknown fields") as error:
            plan.evaluate_snapshot(snapshot, NOW)
        self.assertNotIn("sensitive-value", str(error.exception))

    def test_duplicate_json_keys_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text('{"model":"first","model":"second"}', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = plan.main([str(path)])

        self.assertEqual(result, 2)
        self.assertIn(plan.AUTHORIZATION_NOTICE, output.getvalue())
        self.assertIn("duplicate fields", output.getvalue())
        self.assertNotIn("first", output.getvalue())
        self.assertNotIn("second", output.getvalue())

    def test_sensitive_field_names_and_owner_values_are_never_emitted(self):
        snapshot = clean_snapshot()
        snapshot["api_token"] = "synthetic-secret"
        with self.assertRaisesRegex(preflight.SnapshotError, "suspect sensitive field") as error:
            plan.evaluate_snapshot(snapshot, NOW)
        self.assertNotIn("synthetic-secret", str(error.exception))

        snapshot = clean_snapshot()
        port_entry(snapshot, 19090).update(state="occupied", owners=["owner-has-secret"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = plan.main([str(path)])

        self.assertEqual(result, 1)
        self.assertIn(plan.AUTHORIZATION_NOTICE, output.getvalue())
        self.assertNotIn("owner-has-secret", output.getvalue())

    def test_success_and_handled_errors_always_show_notice_and_plan_never_claims_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(clean_snapshot(datetime.now(timezone.utc))), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = plan.main([str(path)])

        self.assertEqual(result, 0)
        self.assertIn(plan.AUTHORIZATION_NOTICE, output.getvalue())
        self.assertIn("CONDITIONAL CANDIDATE", output.getvalue())
        self.assertIn("not device-ready", output.getvalue())
        self.assertIn("Preserve the recorded rc.local SHA-256", output.getvalue())
        self.assertIn("Preserve recorded /data/mihomo state (not present)", output.getvalue())
        self.assertNotIn("ready for deployment", output.getvalue().lower())
        self.assertIn("Rust Agent startup can modify USB, TTL, DNS, Mihomo, LAN", output.getvalue())
        self.assertIn("do not launch it", output.getvalue())
        self.assertIn("unpinned accept-new host keys", output.getvalue())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = plan.main([])
        self.assertEqual(result, 2)
        self.assertIn(plan.AUTHORIZATION_NOTICE, output.getvalue())

    def test_planner_source_has_no_execution_network_or_write_capability(self):
        source = Path(plan.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_imports = {"subprocess", "socket", "urllib", "http", "ftplib"}
        forbidden_calls = {
            "Popen", "run", "call", "check_call", "check_output", "system", "popen",
            "urlopen", "connect", "create_connection", "sendto", "write_text", "write_bytes",
            "mkdir", "unlink", "rename", "remove", "rmdir",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse({alias.name.split(".", 1)[0] for alias in node.names} & forbidden_imports)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".", 1)[0], forbidden_imports)
            elif isinstance(node, ast.Call):
                called = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                self.assertNotIn(called, forbidden_calls)

        self.assertNotIn("192.168.0.1", source)

    def test_main_reads_snapshot_without_writing_or_using_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(clean_snapshot(datetime.now(timezone.utc))), encoding="utf-8")
            output = io.StringIO()
            with (
                mock.patch.object(Path, "write_text", side_effect=AssertionError("write attempted")),
                mock.patch.object(Path, "write_bytes", side_effect=AssertionError("write attempted")),
                mock.patch("socket.socket", side_effect=AssertionError("socket attempted")),
                mock.patch("subprocess.Popen", side_effect=AssertionError("process attempted")),
                contextlib.redirect_stdout(output),
            ):
                result = plan.main([str(path)])

        self.assertEqual(result, 0)

    def test_simulated_failure_rolls_back_in_memory_in_reverse_order(self):
        baseline = {
            "active_release": "legacy",
            "isolated_files": (),
            "legacy_mihomo": "preserved",
            "rc_local_sha256": "synthetic-baseline-hash",
        }
        transitions = (
            ("isolated_files", ("agent.fixture", "dashboard.fixture")),
            ("verified", True),
            ("active_release", "isolated-fixture"),
            ("health_check", False),
        )

        for fail_after in range(1, len(transitions) + 1):
            with self.subTest(fail_after=fail_after):
                state = copy.deepcopy(baseline)
                journal = []
                for key, value in transitions[:fail_after]:
                    journal.append((key, copy.deepcopy(state.get(key, None)), key in state))
                    state[key] = copy.deepcopy(value)
                # Injected failure is handled entirely in memory; undo the mock journal in reverse.
                while journal:
                    key, old_value, existed = journal.pop()
                    if existed:
                        state[key] = old_value
                    else:
                        del state[key]

                self.assertEqual(state, baseline)


if __name__ == "__main__":
    unittest.main()
