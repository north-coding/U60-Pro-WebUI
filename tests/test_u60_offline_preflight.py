import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts import u60_offline_preflight as preflight


NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


def clean_snapshot(now=NOW):
    return {
        "schema_version": 1,
        "model": "ZTE MU5250",
        "firmware": "BD_CNMU5250V1.0.0B31",
        "collected_at": now.isoformat().replace("+00:00", "Z"),
        "ports": [
            {"port": 9090, "state": "free", "owners": [], "observed": True},
            {"port": 8080, "state": "free", "owners": [], "observed": True},
            {"port": 7890, "state": "free", "owners": [], "observed": True},
        ],
        "mihomo_data_present": False,
        "rc_local_sha256": hashlib.sha256(b"synthetic rc.local").hexdigest(),
        "rc_local_custom_hooks": False,
        "ssh_verified_key_only": True,
        "ecm_active": True,
    }


class OfflinePreflightTests(unittest.TestCase):
    def test_invalid_argument_counts_print_authorization_notice(self):
        for args in ([], ["one.json", "two.json"]):
            with self.subTest(args=args):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = preflight.main(args)

                self.assertEqual(result, 2)
                self.assertIn("Usage: u60_offline_preflight.py SNAPSHOT.json", stderr.getvalue())
                self.assertIn(preflight.AUTHORIZATION_NOTICE, stdout.getvalue())

    def test_port_collisions_are_reported_without_owner_values(self):
        snapshot = clean_snapshot()
        snapshot["ports"] = [
            {"port": 9090, "state": "occupied", "owners": ["synthetic-agent"], "observed": True},
            {"port": 8080, "state": "occupied", "owners": ["synthetic-web"], "observed": True},
            {"port": 7890, "state": "occupied", "owners": ["synthetic-proxy"], "observed": True},
        ]

        blockers = preflight.evaluate_snapshot(snapshot, NOW)

        self.assertEqual(
            blockers,
            [
                "Port 9090 collision detected.",
                "Port 8080 collision detected.",
                "Port 7890 collision detected.",
            ],
        )
        self.assertNotIn("synthetic-agent", " ".join(blockers))

    def test_unknown_field_is_rejected(self):
        snapshot = clean_snapshot()
        snapshot["extra"] = "synthetic value"

        with self.assertRaisesRegex(preflight.SnapshotError, "unknown fields"):
            preflight.evaluate_snapshot(snapshot, NOW)

    def test_malformed_json_fails_without_echoing_input(self):
        payload = '{"password":"synthetic-secret",'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(payload, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = preflight.main([str(path)])

        self.assertEqual(result, 2)
        self.assertIn("malformed JSON", output.getvalue())
        self.assertNotIn("synthetic-secret", output.getvalue())
        self.assertIn(preflight.AUTHORIZATION_NOTICE, output.getvalue())

    def test_suspect_sensitive_field_is_rejected_without_echo(self):
        snapshot = clean_snapshot()
        snapshot["device"] = {"api_token": "synthetic-secret"}

        with self.assertRaisesRegex(preflight.SnapshotError, "suspect sensitive field") as error:
            preflight.evaluate_snapshot(snapshot, NOW)

        self.assertNotIn("api_token", str(error.exception))
        self.assertNotIn("synthetic-secret", str(error.exception))

    def test_clean_synthetic_fixture_is_clear_but_never_authorizes_deployment(self):
        snapshot = clean_snapshot(datetime.now(timezone.utc))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = preflight.main([str(path)])

        self.assertEqual(result, 0)
        self.assertIn("Offline preflight: CLEAR", output.getvalue())
        self.assertIn(preflight.AUTHORIZATION_NOTICE, output.getvalue())

    def test_stale_snapshot_blocks(self):
        snapshot = clean_snapshot(NOW - timedelta(hours=24, seconds=1))

        self.assertEqual(preflight.evaluate_snapshot(snapshot, NOW), ["Snapshot is stale."])

    def test_unsupported_firmware_blocks(self):
        snapshot = clean_snapshot()
        snapshot["firmware"] = "synthetic unsupported firmware"

        self.assertEqual(
            preflight.evaluate_snapshot(snapshot, NOW),
            ["Snapshot firmware is not supported."],
        )

    def test_missing_port_observation_does_not_mean_free(self):
        snapshot = clean_snapshot()
        snapshot["ports"] = [entry for entry in snapshot["ports"] if entry["port"] != 8080]

        self.assertEqual(
            preflight.evaluate_snapshot(snapshot, NOW),
            ["Port 8080 observation is missing."],
        )

    def test_missing_proxy_port_observation_does_not_mean_free(self):
        snapshot = clean_snapshot()
        snapshot["ports"] = [entry for entry in snapshot["ports"] if entry["port"] != 7890]

        self.assertEqual(
            preflight.evaluate_snapshot(snapshot, NOW),
            ["Port 7890 observation is missing."],
        )


if __name__ == "__main__":
    unittest.main()
