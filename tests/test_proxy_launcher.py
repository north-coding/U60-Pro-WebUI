import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts/device/start-proxy-agent.sh"
RC_PREP = ROOT / "scripts/device/prepare-proxy-rc-local.py"


class ProxyLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="u60-proxy-launcher-")
        self.root = Path(self.temp.name) / "managed"
        self.root.mkdir()
        self.root.chmod(0o700)
        for name in ("agent", "mihomo", "auth"):
            path = self.root / name
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        self.down = Path(self.temp.name) / "agent-down"
        self.down.touch()
        self._write_executable(
            self.root / "agent/zte-agent",
            "#!/bin/sh\nif [ \"${1:-}\" = --build-info ]; then echo 'zte-agent synthetic arch=aarch64'; exit 0; fi\nif [ -n \"${U60_PROXY_TEST_ENV_CAPTURE:-}\" ]; then printf '%s|%s|%s' \"${ZTE_AGENT_PASSWORD_FILE:-}\" \"${ZTE_AGENT_PASSWORD:+set}\" \"$*\" > \"$U60_PROXY_TEST_ENV_CAPTURE\"; fi\n[ -z \"${U60_TEST_DOWN_FLAG:-}\" ] || rm -f \"$U60_TEST_DOWN_FLAG\"\nexit 0\n",
        )
        self._write_executable(
            self.root / "mihomo/mihomo",
            "#!/bin/sh\nif [ \"${1:-}\" = -v ]; then echo 'Mihomo Meta v1.19.32 linux arm64'; exit 0; fi\n[ \"${1:-}\" != -t ] || [ \"${U60_TEST_CONFIG_FAIL:-0}\" != 1 ]\n",
        )
        password = self.root / "auth/password"
        password.write_text("synthetic_password_123\n")
        password.chmod(0o600)
        self.curl = Path(self.temp.name) / "curl-mock"
        self._write_executable(self.curl, self._curl_mock())
        self._write_hash_metadata(self.root / "agent/zte-agent")
        self._write_hash_metadata(self.root / "mihomo/mihomo")

    def tearDown(self):
        self.temp.cleanup()

    def _write_executable(self, path: Path, content: str):
        path.write_text(content)
        path.chmod(0o700)

    @staticmethod
    def _curl_mock():
        return r'''#!/usr/bin/python3
import os, pathlib, sys
args = sys.argv[1:]
url = args[-1]
down = pathlib.Path(os.environ["U60_TEST_DOWN_FLAG"])
if url.endswith("/api/proxy/capabilities"):
    if os.environ.get("U60_TEST_INCOMPATIBLE") == "1":
        print('{"ok":true,"data":{"mode":"full","auth_required":true,"features":["proxy_management"]}}')
        raise SystemExit(0)
    if down.exists():
        raise SystemExit(7)
    print('{"ok":true,"data":{"mode":"proxy_only","auth_required":true,"features":["proxy_management"]}}')
elif url.endswith("/api/auth/login"):
    body = sys.stdin.read()
    if 'synthetic_password_123' not in body:
        raise SystemExit(22)
    print('{"ok":true,"data":{"token":"' + 'a' * 64 + '"}}')
elif url.endswith("/api/proxy/agent/stop"):
    config = pathlib.Path(args[args.index("--config") + 1]).read_text()
    if "Bearer " + "a" * 64 not in config:
        raise SystemExit(22)
    if "X-Confirm: true" not in args:
        raise SystemExit(22)
    down.touch()
    print('{"ok":true,"data":{"stopping":true,"mihomo_preserved":true}}')
else:
    raise SystemExit(22)
'''

    def _write_hash_metadata(self, binary: Path):
        binary.with_name(binary.name + ".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest() + "\n")
        binary.with_name(binary.name + ".sha256").chmod(0o600)
        binary.with_name(binary.name + ".arch").write_text("aarch64\n")
        binary.with_name(binary.name + ".arch").chmod(0o600)

    def _env(self, **extra):
        return {
            **os.environ,
            "U60_PROXY_TEST_MODE": "1",
            "U60_PROXY_TEST_ROOT": str(self.root),
            "U60_PROXY_TEST_CURL_BIN": str(self.curl),
            "U60_PROXY_TEST_ARCH": "aarch64",
            "U60_TEST_DOWN_FLAG": str(self.down),
            **extra,
        }

    def _run(self, action: str, **extra):
        return subprocess.run(["/bin/sh", str(LAUNCHER), action], text=True, capture_output=True, env=self._env(**extra))

    def test_fresh_start_and_idempotent_start_use_explicit_proxy_only_entrypoint(self):
        capture = Path(self.temp.name) / "agent-env"
        first = self._run("start", U60_PROXY_TEST_ENV_CAPTURE=str(capture))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("ready on 127.0.0.1:9090", first.stdout)
        self.assertFalse(self.down.exists())
        self.assertEqual(
            capture.read_text(),
            f"{self.root}/auth/password||--proxy-only --proxy-bind 127.0.0.1:9090",
        )
        second = self._run("start")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("already running", second.stdout)

    def test_restart_preserves_managed_mihomo_for_verified_recovery(self):
        self.down.unlink()
        result = self._run("restart")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.down.exists())
        self.assertIn("remains available for recovery", result.stdout)

    def test_missing_credentials_bad_permissions_missing_binary_and_wrong_arch_fail_closed(self):
        password = self.root / "auth/password"
        password.unlink()
        self.assertNotEqual(self._run("start").returncode, 0)
        password.write_text("synthetic_password_123\n")
        password.chmod(0o644)
        self.assertNotEqual(self._run("start").returncode, 0)
        password.chmod(0o600)
        agent = self.root / "agent/zte-agent"
        agent.unlink()
        self.assertNotEqual(self._run("start").returncode, 0)
        self._write_executable(agent, "#!/bin/sh\nif [ \"${1:-}\" = --build-info ]; then echo 'zte-agent synthetic arch=aarch64'; exit 0; fi\nexit 0\n")
        self._write_hash_metadata(agent)
        agent.with_name(agent.name + ".arch").write_text("x86_64\n")
        agent.with_name(agent.name + ".arch").chmod(0o600)
        self.assertNotEqual(self._run("start").returncode, 0)
        agent.with_name(agent.name + ".arch").write_text("aarch64\n")
        agent.with_name(agent.name + ".arch").chmod(0o600)
        self._write_executable(agent, "#!/bin/sh\nif [ \"${1:-}\" = --build-info ]; then echo 'zte-agent synthetic arch=x86_64'; exit 0; fi\nexit 0\n")
        self._write_hash_metadata(agent)
        self.assertNotEqual(self._run("start").returncode, 0)

    def test_invalid_config_and_incompatible_api_never_start_agent(self):
        config = self.root / "mihomo/config.yaml"
        config.write_text("invalid\n")
        config.chmod(0o600)
        bad = self._run("start", U60_TEST_CONFIG_FAIL="1")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("config validation failed", bad.stderr)
        self.assertTrue(self.down.exists())
        config.unlink()
        incompatible = self._run("start", U60_TEST_INCOMPATIBLE="1")
        self.assertNotEqual(incompatible.returncode, 0)
        self.assertTrue(self.down.exists())

    def test_launcher_refuses_symlinked_managed_paths_without_following_them(self):
        linked = Path(self.temp.name) / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        result = subprocess.run(
            ["/bin/sh", str(LAUNCHER), "start"], text=True, capture_output=True,
            env={**self._env(), "U60_PROXY_TEST_ROOT": str(linked)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or linked", result.stderr)

    def test_launcher_rejects_symlinked_config_and_log_even_when_target_is_missing(self):
        missing = Path(self.temp.name) / "missing-target"
        config = self.root / "mihomo/config.yaml"
        config.symlink_to(missing)
        self.assertNotEqual(self._run("start").returncode, 0)
        config.unlink()
        log = self.root / "agent/agent.log"
        log.unlink(missing_ok=True)
        log.symlink_to(missing)
        self.assertNotEqual(self._run("start").returncode, 0)


class ProxyStartupEntryTests(unittest.TestCase):
    def test_default_dry_run_and_apply_change_only_the_exact_project_entry(self):
        with tempfile.TemporaryDirectory(prefix="u60-rc-local-") as temp:
            path = Path(temp) / "rc.local"
            original = b"#!/bin/sh\nstock-before\nsh /data/local/tmp/start_zte_agent.sh\nstock-after\n"
            path.write_bytes(original)
            path.chmod(0o755)
            dry = subprocess.run(["python3", str(RC_PREP), "--rc-local", str(path)], text=True, capture_output=True)
            self.assertEqual(dry.returncode, 0, dry.stderr)
            self.assertEqual(path.read_bytes(), original)
            applied = subprocess.run(["python3", str(RC_PREP), "--rc-local", str(path), "--apply"], text=True, capture_output=True)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            updated = path.read_bytes()
            self.assertIn(b"stock-before\n", updated)
            self.assertIn(b"stock-after\n", updated)
            self.assertIn(b"sh /data/u60-pro-managed/agent/start-proxy-agent.sh start\n", updated)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
            self.assertEqual(subprocess.run(["sh", "-n", str(path)]).returncode, 0)

    def test_missing_duplicate_or_symlinked_entry_is_never_rewritten(self):
        with tempfile.TemporaryDirectory(prefix="u60-rc-local-negative-") as temp:
            root = Path(temp)
            path = root / "rc.local"
            for content in (b"#!/bin/sh\nstock\n", b"sh /data/local/tmp/start_zte_agent.sh\nsh /data/local/tmp/start_zte_agent.sh\n"):
                path.write_bytes(content)
                result = subprocess.run(["python3", str(RC_PREP), "--rc-local", str(path), "--apply"], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(path.read_bytes(), content)
            target = root / "target"
            target.write_bytes(b"sh /data/local/tmp/start_zte_agent.sh\n")
            link = root / "link"
            link.symlink_to(target)
            result = subprocess.run(["python3", str(RC_PREP), "--rc-local", str(link), "--apply"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), b"sh /data/local/tmp/start_zte_agent.sh\n")


if __name__ == "__main__":
    unittest.main()
