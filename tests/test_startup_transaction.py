from __future__ import annotations

import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import stat
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DEVICE_SCRIPTS = ROOT / "scripts/device"
sys.path.insert(0, str(DEVICE_SCRIPTS))
import proxy_credentials
import startup_transaction as startup


PASSWORD = "A" * proxy_credentials.PASSWORD_LENGTH
OLD_LINE = b"sh /data/local/tmp/start_zte_agent.sh\n"
NEW_LINE = b"sh /data/u60-pro-managed/agent/start-proxy-agent.sh start\n"


class StartupFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="u60-startup-transaction-")
        self.root = Path(self.temp.name) / "fixture"
        self.root.mkdir(mode=0o700)
        (self.root / startup.TEST_ROOT_MARKER).write_text("synthetic-only\n")
        (self.root / startup.TEST_ROOT_MARKER).chmod(0o600)
        for name in ("etc", "data"):
            (self.root / name).mkdir(mode=0o700)
        managed = self.root / startup.MANAGED_ROOT
        managed.mkdir(mode=0o700)
        self.agent_dir = managed / "agent"
        self.mihomo_dir = managed / "mihomo"
        self.auth_dir = managed / "auth"
        self.staging_dir = managed / "staging"
        for path in (self.agent_dir, self.mihomo_dir, self.auth_dir, self.staging_dir):
            path.mkdir(mode=0o700)
        self.rc = self.root / "etc/rc.local"
        self.original = b"#!/bin/sh\necho stock-before\n" + OLD_LINE + b"echo stock-after\n"
        self.safe = b"#!/bin/sh\necho stock-before\necho stock-after\n"
        self.rc.write_bytes(self.original)
        self.rc.chmod(0o755)
        self.password_file = self.auth_dir / "password"
        self.password_file.write_text(PASSWORD + "\n")
        self.password_file.chmod(0o600)
        self._artifact(self.agent_dir / "zte-agent", b"#!/bin/sh\nexit 0\n", "aarch64")
        self._artifact(self.mihomo_dir / "mihomo", b"#!/bin/sh\nexit 0\n", "aarch64")
        self._artifact(self.agent_dir / "start-proxy-agent.sh", (ROOT / "scripts/device/start-proxy-agent.sh").read_bytes())
        config = self.mihomo_dir / "config.yaml"
        config.write_text("mode: rule\n")
        config.chmod(0o600)
        self.tx = startup.StartupTransaction(self.root)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _artifact(path: Path, content: bytes, arch: str | None = None):
        path.write_bytes(content)
        path.chmod(0o700)
        digest = Path(str(path) + ".sha256")
        digest.write_text(hashlib.sha256(content).hexdigest() + "\n")
        digest.chmod(0o600)
        if arch:
            arch_file = Path(str(path) + ".arch")
            arch_file.write_text(arch + "\n")
            arch_file.chmod(0o600)

    def _activate(self, probe=lambda _deadline: True, **kwargs):
        self.tx.activate(lambda: None, probe, **kwargs)


class StartupTransactionTests(StartupFixture):
    def test_success_snapshots_all_bytes_and_changes_only_the_exact_project_entry(self):
        self._activate()
        current = self.rc.read_bytes()
        self.assertEqual(current, self.original.replace(OLD_LINE, NEW_LINE, 1))
        self.assertEqual(current.replace(NEW_LINE, OLD_LINE, 1), self.original)
        snapshot = self.tx.transaction / "original.rc.local"
        metadata = json.loads((self.tx.transaction / "metadata.json").read_text())
        state = json.loads((self.tx.transaction / "state.json").read_text())
        self.assertEqual(snapshot.read_bytes(), self.original)
        self.assertEqual(metadata["snapshot_sha256"], hashlib.sha256(self.original).hexdigest())
        self.assertEqual(state["phase"], "activated")
        self.assertEqual(state["rollback_policy"], "remove-only-new-proxy-entry")
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.tx.transaction.stat().st_mode & 0o777, 0o700)

    def test_health_failure_removes_new_entry_without_restoring_legacy_startup(self):
        with self.assertRaises(startup.ActivationFailed):
            self._activate(lambda _deadline: False, total_timeout=0.04, request_timeout=0.01, attempts=2, interval=0)
        self.assertEqual(self.rc.read_bytes(), self.safe)
        self.assertNotIn(OLD_LINE, self.rc.read_bytes())
        self.assertNotIn(NEW_LINE, self.rc.read_bytes())
        state = json.loads((self.tx.transaction / "state.json").read_text())
        self.assertEqual(state["phase"], "rolled_back")
        self.assertEqual((self.tx.transaction / "original.rc.local").read_bytes(), self.original)

    def test_activation_callback_failure_uses_the_same_fail_closed_rollback(self):
        with self.assertRaises(startup.ActivationFailed):
            self.tx.activate(lambda: (_ for _ in ()).throw(RuntimeError("synthetic launch failure")), lambda _d: True)
        self.assertEqual(self.rc.read_bytes(), self.safe)

    def test_missing_duplicate_modified_and_unexpected_project_entries_are_rejected(self):
        variants = [
            b"#!/bin/sh\necho stock\n",
            OLD_LINE + OLD_LINE,
            b"#!/bin/sh\n  " + OLD_LINE,
            b"#!/bin/sh\nsh /data/local/tmp/start_zte_agent.sh extra\n",
            b"#!/bin/sh\n" + NEW_LINE,
        ]
        for content in variants:
            with self.subTest(content=content):
                self.rc.write_bytes(content)
                before = self.rc.read_bytes()
                with self.assertRaises(startup.TransactionError):
                    self._activate()
                self.assertEqual(self.rc.read_bytes(), before)
                self.assertFalse(self.tx.transaction.exists())

    def test_wrong_owner_permissions_artifact_hash_or_target_path_blocks_before_replacement(self):
        with self.subTest("owner"):
            with self.assertRaises(startup.TransactionError):
                startup.StartupTransaction(self.root, expected_uid=os.geteuid() + 1)
            self.assertEqual(self.rc.read_bytes(), self.original)
        self.tx = startup.StartupTransaction(self.root)
        with self.subTest("auth mode"):
            self.password_file.chmod(0o640)
            with self.assertRaises(ValueError):
                self._activate()
            self.assertEqual(self.rc.read_bytes(), self.original)
            self.password_file.chmod(0o600)
        with self.subTest("artifact identity"):
            binary = self.agent_dir / "zte-agent"
            binary.write_bytes(b"replacement binary\n")
            with self.assertRaises(startup.TransactionError):
                self._activate()
            self.assertEqual(self.rc.read_bytes(), self.original)
        with self.subTest("symlink path"):
            self.mihomo_dir.rename(self.mihomo_dir.with_name("mihomo-real"))
            self.mihomo_dir.symlink_to(self.mihomo_dir.with_name("mihomo-real"), target_is_directory=True)
            with self.assertRaises(startup.TransactionError):
                self._activate()
            self.assertEqual(self.rc.read_bytes(), self.original)

    def test_interruption_after_replace_recovers_by_disabling_only_new_entry(self):
        def failpoint(point):
            if point == "after-replacement":
                raise startup.PowerLoss()

        with self.assertRaises(startup.PowerLoss):
            self._activate(failpoint=failpoint)
        self.assertIn(NEW_LINE, self.rc.read_bytes())
        self.assertEqual(self.tx.recover_pending(), "rolled_back")
        self.assertEqual(self.rc.read_bytes(), self.safe)
        self.assertNotIn(OLD_LINE, self.rc.read_bytes())

    def test_interruption_after_snapshot_leaves_startup_untouched_and_recovers(self):
        def failpoint(point):
            if point == "after-snapshot":
                raise startup.PowerLoss()

        with self.assertRaises(startup.PowerLoss):
            self._activate(failpoint=failpoint)
        self.assertEqual(self.rc.read_bytes(), self.original)
        self.assertEqual(self.tx.recover_pending(), "rolled_back")
        self.assertEqual(self.rc.read_bytes(), self.original)

    def test_mismatched_or_corrupted_snapshot_blocks_recovery_without_overwrite(self):
        def failpoint(point):
            if point == "after-replacement":
                raise startup.PowerLoss()

        with self.assertRaises(startup.PowerLoss):
            self._activate(failpoint=failpoint)
        snapshot = self.tx.transaction / "original.rc.local"
        snapshot.chmod(0o600)
        snapshot.write_bytes(b"tampered snapshot")
        snapshot.chmod(0o400)
        candidate = self.rc.read_bytes()
        with self.assertRaises(startup.TransactionError):
            self.tx.recover_pending()
        self.assertEqual(self.rc.read_bytes(), candidate)

    def test_partial_candidate_staging_is_removed_without_changing_rc_local(self):
        original_write = startup._write_new

        def partial_write(path, payload, mode, uid, gid=None):
            if path.parent.resolve() == self.tx.rc.parent and path.name.startswith(".u60-rc-"):
                path.write_bytes(payload[:8])
                path.chmod(mode)
                raise OSError("synthetic interrupted staging write")
            return original_write(path, payload, mode, uid, gid)

        with mock.patch.object(startup, "_write_new", side_effect=partial_write):
            with self.assertRaises(startup.ActivationFailed):
                self._activate()
        self.assertEqual(self.rc.read_bytes(), self.original)
        self.assertEqual(list((self.root / "etc").glob(".u60-rc-*")), [])
        self.assertEqual(json.loads((self.tx.transaction / "state.json").read_text())["phase"], "rolled_back")

    def test_replace_permission_error_does_not_change_startup_and_keeps_verified_snapshot(self):
        original_replace = startup.os.replace

        def reject_rc_replace(source, destination):
            if Path(destination).resolve() == self.tx.rc:
                raise PermissionError("synthetic permission error")
            return original_replace(source, destination)

        with mock.patch.object(startup.os, "replace", side_effect=reject_rc_replace):
            with self.assertRaises(startup.ActivationFailed):
                self._activate()
        self.assertEqual(self.rc.read_bytes(), self.original)
        self.assertEqual((self.tx.transaction / "original.rc.local").read_bytes(), self.original)
        self.assertEqual(json.loads((self.tx.transaction / "state.json").read_text())["phase"], "rolled_back")

    def test_state_persistence_failure_rolls_back_from_the_last_committed_state(self):
        original_write_state = self.tx._write_state

        def fail_activated_state(state):
            if state.get("phase") == "activated":
                raise OSError("synthetic state persistence failure")
            original_write_state(state)

        with mock.patch.object(self.tx, "_write_state", side_effect=fail_activated_state):
            with self.assertRaises(startup.ActivationFailed):
                self._activate()
        self.assertEqual(self.rc.read_bytes(), self.safe)
        self.assertEqual(json.loads((self.tx.transaction / "state.json").read_text())["phase"], "rolled_back")

    def test_rollback_failure_retains_candidate_snapshot_and_recovers_later(self):
        original_replace = startup.os.replace
        rc_replacements = 0

        def reject_second_rc_replace(source, destination):
            nonlocal rc_replacements
            if Path(destination).resolve() == self.tx.rc:
                rc_replacements += 1
                if rc_replacements == 2:
                    raise PermissionError("synthetic rollback failure")
            return original_replace(source, destination)

        with mock.patch.object(startup.os, "replace", side_effect=reject_second_rc_replace):
            with self.assertRaisesRegex(startup.TransactionError, "rollback did not complete"):
                self._activate(lambda _deadline: False, total_timeout=0.03, request_timeout=0.01, attempts=1, interval=0)
        self.assertIn(NEW_LINE, self.rc.read_bytes())
        self.assertEqual((self.tx.transaction / "original.rc.local").read_bytes(), self.original)
        self.assertEqual(json.loads((self.tx.transaction / "state.json").read_text())["phase"], "rollback_pending")
        self.assertEqual(self.tx.recover_pending(), "rolled_back")
        self.assertEqual(self.rc.read_bytes(), self.safe)

    def test_health_wait_is_deadline_bounded_and_attempts_are_capped(self):
        now = [0.0]
        deadlines = []

        def clock():
            return now[0]

        def slow_probe(deadline):
            deadlines.append(deadline)
            now[0] = deadline
            return False

        def sleep(duration):
            now[0] += duration

        result = startup.wait_authenticated_health(
            slow_probe,
            total_timeout=0.12,
            request_timeout=0.05,
            attempts=12,
            interval=0.01,
            monotonic=clock,
            sleep=sleep,
        )
        self.assertFalse(result)
        self.assertLessEqual(now[0], 0.12)
        self.assertLessEqual(len(deadlines), 3)
        self.assertTrue(all(deadline <= 0.12 for deadline in deadlines))

    def test_concurrent_transaction_lock_fails_closed(self):
        lock_fd = self.tx._lock()
        try:
            with self.assertRaisesRegex(startup.TransactionError, "another startup transaction"):
                self._activate()
        finally:
            os.close(lock_fd)

    def test_cli_refuses_non_synthetic_target_and_never_accepts_rc_local_argument(self):
        command = [sys.executable, str(DEVICE_SCRIPTS / "prepare-proxy-rc-local.py")]
        outside = subprocess.run(command + ["--test-root", "/etc", "--apply"], capture_output=True, text=True)
        self.assertNotEqual(outside.returncode, 0)
        self.assertIn("device execution is disabled", outside.stderr)
        with tempfile.TemporaryDirectory(prefix="u60-unmarked-root-") as temp:
            result = subprocess.run(command + ["--test-root", temp, "--rc-local", "/etc/rc.local", "--apply"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


class AuthenticatedHealthProbeTests(StartupFixture):
    def test_probe_uses_loopback_capability_login_and_authenticated_status(self):
        token = "B" * 64
        observed = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def send_json(self, status, value):
                payload = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                observed.append(("GET", self.path, self.headers.get("Authorization") is not None))
                if self.path == "/api/proxy/capabilities":
                    self.send_json(200, {"ok": True, "data": {"mode": "proxy_only", "auth_required": True}})
                elif self.path == "/api/proxy/status" and self.headers.get("Authorization") == f"Bearer {token}":
                    self.send_json(200, {"ok": True, "data": {"running": False, "enabled": False, "mode": "rule"}})
                else:
                    self.send_json(401, {"ok": False, "error": "unauthorized"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                observed.append(("POST", self.path, False))
                if self.path == "/api/auth/login" and body.get("password") == PASSWORD:
                    self.send_json(200, {"ok": True, "data": {"token": token}})
                else:
                    self.send_json(401, {"ok": False, "error": "unauthorized"})

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            probe = startup.LocalAgentHealthProbe(self.password_file, server.server_port)
            self.assertTrue(probe(time.monotonic() + 2))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        self.assertEqual(observed, [
            ("GET", "/api/proxy/capabilities", False),
            ("POST", "/api/auth/login", False),
            ("GET", "/api/proxy/status", True),
        ])

    def test_probe_rejects_missing_or_malformed_credentials_before_network(self):
        missing = self.auth_dir / "missing"
        with self.assertRaises(ValueError):
            startup.LocalAgentHealthProbe(missing, 9090)
        self.password_file.write_text("weak\n")
        self.password_file.chmod(0o600)
        with self.assertRaises(ValueError):
            startup.LocalAgentHealthProbe(self.password_file, 9090)

    def test_nonresponsive_loopback_endpoint_is_cancelled_at_request_deadline(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                hits.append(self.path)
                payload = json.dumps({"ok": True, "data": {"mode": "proxy_only", "auth_required": True}}).encode()
                response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n\r\n".encode() + payload
                try:
                    for byte in response:
                        self.wfile.write(bytes((byte,)))
                        self.wfile.flush()
                        time.sleep(0.02)
                except OSError:
                    pass

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started = time.monotonic()
        try:
            probe = startup.LocalAgentHealthProbe(self.password_file, server.server_port)
            healthy = startup.wait_authenticated_health(
                probe,
                total_timeout=0.12,
                request_timeout=0.04,
                attempts=1,
                interval=0,
            )
            elapsed = time.monotonic() - started
            self.assertFalse(healthy)
            self.assertLess(elapsed, 0.18)
            self.assertEqual(hits, ["/api/proxy/capabilities"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)


class CredentialProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="u60-proxy-credential-")
        self.root = Path(self.temp.name) / "fixture"
        self.root.mkdir(mode=0o700)
        marker = self.root / proxy_credentials.TEST_ROOT_MARKER
        marker.write_text("synthetic-only\n")
        marker.chmod(0o600)
        self.auth = self.root / "data/u60-pro-managed/auth"
        for directory in (self.root / "data", self.root / "data/u60-pro-managed", self.auth):
            directory.mkdir(mode=0o700)
        self.password = self.auth / "password"

    def tearDown(self):
        self.temp.cleanup()

    def test_provisions_random_canonical_secret_in_owner_only_file_without_output(self):
        proxy_credentials.provision_password(self.password, self.root)
        value = proxy_credentials.read_password_file(self.password)
        self.assertRegex(value, re.compile(r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"))
        self.assertEqual(self.password.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(self.password.stat().st_mode), 0o600)
        first = self.password.read_bytes()
        with self.assertRaises(ValueError):
            proxy_credentials.provision_password(self.password, self.root)
        self.assertEqual(self.password.read_bytes(), first)

    def test_provisioner_rejects_unmarked_root_and_outside_target(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        with self.assertRaises(ValueError):
            proxy_credentials.provision_password(outside / "password", outside)
        with self.assertRaises(ValueError):
            proxy_credentials.provision_password(self.password, self.root / "data")

    def test_cli_requires_synthetic_root_and_never_prints_generated_secret(self):
        command = [sys.executable, str(DEVICE_SCRIPTS / "provision-proxy-password.py")]
        missing_root = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(missing_root.returncode, 0)
        result = subprocess.run(command + ["--test-root", str(self.root)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        secret = proxy_credentials.read_password_file(self.password)
        self.assertNotIn(secret, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
