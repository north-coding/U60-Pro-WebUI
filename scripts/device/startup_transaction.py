"""Fail-closed, synthetic-root-only startup transaction primitives.

This module deliberately has no device transport or device activation entrypoint.
Tests exercise the complete file transaction with disposable trees and injected
activation/health callbacks. A future device workflow needs separate approval
and a separately reviewed adapter.
"""

from __future__ import annotations

import fcntl
import hashlib
import errno
import json
import os
from pathlib import Path
import selectors
import secrets
import socket
import stat
import subprocess
import time
from typing import Callable

from proxy_credentials import read_password_file, validate_synthetic_test_root


OLD_ENTRY = b"sh /data/mihomo/start-mihomo.sh >/data/mihomo/autostart.log 2>&1 &"
NEW_ENTRY = b"sh /data/u60-pro-managed/agent/start-proxy-agent.sh start &"
TEST_ROOT_MARKER = ".u60-proxy-transaction-test-root"
DEVICE_RC_LOCAL = "/etc/rc.local"
MANAGED_ROOT = "data/u60-pro-managed"
MAX_RC_BYTES = 1024 * 1024
HEALTH_TIMEOUT_SECONDS = 8.0
HEALTH_REQUEST_TIMEOUT_SECONDS = 1.0
HEALTH_ATTEMPTS = 8
HEALTH_INTERVAL_SECONDS = 0.2


class TransactionError(RuntimeError):
    pass


class ActivationFailed(TransactionError):
    pass


class PowerLoss(BaseException):
    """Test-only interruption sentinel; intentionally bypasses rollback handlers."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _regular_file(path: Path, uid: int, mode: int | None = None, max_size: int = MAX_RC_BYTES) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TransactionError(f"required path is unavailable: {path.name}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_nlink != 1
        or metadata.st_size > max_size
        or metadata.st_mode & 0o7000
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
    ):
        raise TransactionError(f"file ownership, type, link count, mode, or size is invalid: {path.name}")
    return metadata


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_checked(path: Path, uid: int, mode: int | None = None, max_size: int = MAX_RC_BYTES) -> tuple[bytes, os.stat_result]:
    before = _regular_file(path, uid, mode, max_size)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise TransactionError(f"cannot safely open file: {path.name}") from error
    try:
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or _file_signature(before) != _file_signature(after)
            or after.st_uid != uid
            or after.st_nlink != 1
            or (mode is not None and stat.S_IMODE(after.st_mode) != mode)
            or after.st_size > max_size
        ):
            raise TransactionError(f"file changed while being inspected: {path.name}")
        chunks = bytearray()
        while len(chunks) <= max_size:
            block = os.read(fd, min(65536, max_size + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > max_size or len(chunks) != after.st_size:
            raise TransactionError(f"file size changed while being inspected: {path.name}")
        after_read = os.fstat(fd)
        try:
            path_after_read = path.lstat()
        except OSError as error:
            raise TransactionError(f"file path changed while being inspected: {path.name}") from error
        if _file_signature(after) != _file_signature(after_read) or _file_signature(after) != _file_signature(path_after_read):
            raise TransactionError(f"file changed while being read: {path.name}")
        return bytes(chunks), after
    finally:
        os.close(fd)


def _check_directory(path: Path, uid: int, mode: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TransactionError(f"required directory is unavailable: {path.name}") from error
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != mode:
        raise TransactionError(f"directory ownership, type, or mode is invalid: {path.name}")
    return metadata


def _write_new(path: Path, payload: bytes, mode: int, uid: int, gid: int | None = None) -> os.stat_result:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError as error:
        raise TransactionError(f"cannot create transaction file: {path.name}") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or metadata.st_nlink != 1:
            raise TransactionError(f"transaction file ownership is invalid: {path.name}")
        if gid is not None and metadata.st_gid != gid:
            os.fchown(fd, uid, gid)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise TransactionError(f"short transaction write: {path.name}")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, mode)
        os.fsync(fd)
        return os.fstat(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _entry_lines(content: bytes) -> list[bytes]:
    return content.splitlines(keepends=True)


def _entry_ending(line: bytes, entry: bytes) -> bytes | None:
    for ending in (b"\r\n", b"\n", b"\r", b""):
        if line == entry + ending:
            return ending
    return None


def transform_startup(content: bytes) -> tuple[bytes, bytes]:
    """Return candidate and fail-closed rollback bytes, changing only OLD_ENTRY."""
    lines = _entry_lines(content)
    owned_markers = (b"/data/mihomo", b"start-mihomo.sh", b"start_zte_agent.sh", b"start-proxy-agent.sh")
    mentions = [line for line in lines if any(marker in line for marker in owned_markers)]
    old = [index for index, line in enumerate(lines) if _entry_ending(line, OLD_ENTRY) is not None]
    if len(old) != 1 or len(mentions) != 1 or _entry_ending(mentions[0], OLD_ENTRY) is None:
        raise TransactionError("expected exactly one unchanged project-owned Mihomo startup entry")
    index = old[0]
    ending = _entry_ending(lines[index], OLD_ENTRY)
    assert ending is not None
    candidate_lines = list(lines)
    candidate_lines[index] = NEW_ENTRY + ending
    rollback_lines = list(lines)
    rollback_lines.pop(index)  # Preserve the original snapshot; leave the obsolete Mihomo disabled.
    candidate = b"".join(candidate_lines)
    rollback = b"".join(rollback_lines)
    return candidate, rollback


def startup_identity(content: bytes, metadata: os.stat_result) -> dict:
    return {
        "sha256": sha256_bytes(content),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "links": metadata.st_nlink,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def validate_startup_files(original: bytes, candidate: bytes, rollback: bytes) -> None:
    for label, content in (("original", original), ("candidate", candidate), ("rollback", rollback)):
        if b"\0" in content or subprocess.run(
            ["/bin/sh", "-n"], input=content, capture_output=True, timeout=2
        ).returncode:
            raise TransactionError(f"{label} startup file failed shell syntax validation")


def _verify_artifact(root: Path, relative: str, uid: int, arch: str | None) -> str:
    path = root / relative
    metadata = _regular_file(path, uid)
    if stat.S_IMODE(metadata.st_mode) not in {0o500, 0o550, 0o555, 0o700, 0o750, 0o755}:
        raise TransactionError(f"managed artifact permissions are invalid: {path.name}")
    binary, _ = _read_checked(path, uid, max_size=512 * 1024 * 1024)
    digest_path = Path(str(path) + ".sha256")
    digest_bytes, _ = _read_checked(digest_path, uid, 0o600, 128)
    expected = digest_bytes.decode("ascii", "strict").strip()
    actual = sha256_bytes(binary)
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected) or expected != actual:
        raise TransactionError(f"managed artifact digest mismatch: {path.name}")
    if arch is not None:
        arch_bytes, _ = _read_checked(Path(str(path) + ".arch"), uid, 0o600, 32)
        if arch_bytes not in (f"{arch}\n".encode(), arch.encode()):
            raise TransactionError(f"managed artifact architecture mismatch: {path.name}")
    return actual


class StartupTransaction:
    """One-time transaction rooted strictly inside a marked temporary test tree."""

    def __init__(self, test_root: Path, expected_uid: int | None = None):
        try:
            root = validate_synthetic_test_root(test_root)
        except ValueError as error:
            raise TransactionError(str(error)) from error
        except OSError as error:
            raise TransactionError("synthetic test root is unavailable") from error
        self.root = root
        self.uid = os.geteuid() if expected_uid is None else expected_uid
        marker = root / TEST_ROOT_MARKER
        marker_bytes, marker_meta = _read_checked(marker, self.uid, 0o600, 128)
        if marker_bytes != b"synthetic-only\n" or marker_meta.st_nlink != 1:
            raise TransactionError("synthetic test root marker is invalid")
        self.rc = root / "etc/rc.local"
        self.managed = root / MANAGED_ROOT
        self.agent = self.managed / "agent"
        self.mihomo = self.managed / "mihomo"
        self.auth = self.managed / "auth"
        self.staging = self.managed / "staging"
        self.transaction = self.staging / "startup-transaction"
        self.lock_path = self.staging / "startup-transaction.lock"

    def _validate_transaction_paths(self) -> None:
        _check_directory(self.root, self.uid, 0o700)
        _check_directory(self.root / "etc", self.uid, 0o700)
        _check_directory(self.root / "data", self.uid, 0o700)
        _check_directory(self.managed, self.uid, 0o700)
        _check_directory(self.staging, self.uid, 0o700)
        _regular_file(self.rc, self.uid)

    def _validate_layout(self) -> None:
        self._validate_transaction_paths()
        for path in (self.agent, self.mihomo, self.auth):
            _check_directory(path, self.uid, 0o700)
        read_password_file(self.auth / "password", self.uid)
        self._validate_artifacts()

    def _validate_artifacts(self) -> None:
        launcher = self.agent / "start-proxy-agent.sh"
        launcher_bytes, launcher_meta = _read_checked(launcher, self.uid, max_size=64 * 1024)
        if stat.S_IMODE(launcher_meta.st_mode) not in {0o500, 0o550, 0o555, 0o700, 0o750, 0o755}:
            raise TransactionError("managed launcher permissions are invalid")
        digest = _verify_artifact(self.managed, "agent/start-proxy-agent.sh", self.uid, None)
        if b"--proxy-only --proxy-bind 127.0.0.1:9090" not in launcher_bytes:
            raise TransactionError("managed launcher does not select the explicit loopback proxy-only mode")
        if any(forbidden in launcher_bytes for forbidden in (b"start_zte_agent.sh", b"/data/mihomo", b"killall ")):
            raise TransactionError("managed launcher contains a legacy fallback or uncontrolled cleanup")
        checked = subprocess.run(["sh", "-n"], input=launcher_bytes, check=False, capture_output=True, timeout=2)
        if checked.returncode:
            raise TransactionError("managed launcher failed shell syntax validation")
        if digest != sha256_bytes(launcher_bytes):
            raise TransactionError("managed launcher identity is malformed")
        _verify_artifact(self.managed, "agent/zte-agent", self.uid, "aarch64")
        _verify_artifact(self.managed, "mihomo/mihomo", self.uid, "aarch64")
        config = self.mihomo / "config.yaml"
        config_bytes, _ = _read_checked(config, self.uid, 0o600, 1024 * 1024)
        if not config_bytes.strip():
            raise TransactionError("fresh managed Mihomo config is empty")

    def _lock(self):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError as error:
            raise TransactionError("cannot create startup transaction lock") from error
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.uid or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise TransactionError("startup transaction lock ownership is invalid")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise TransactionError("another startup transaction is active") from error
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _write_state(self, state: dict) -> None:
        payload = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
        destination = self.transaction / "state.json"
        if destination.exists() or destination.is_symlink():
            _regular_file(destination, self.uid, 0o600, 16 * 1024)
        temp = self.transaction / (".state-" + secrets.token_hex(6))
        _write_new(temp, payload, 0o600, self.uid)
        os.replace(temp, destination)
        _fsync_directory(self.transaction)

    def _read_snapshot(self) -> tuple[bytes, dict, dict]:
        _check_directory(self.transaction, self.uid, 0o700)
        original, _ = _read_checked(self.transaction / "original.rc.local", self.uid, 0o400)
        metadata_bytes, _ = _read_checked(self.transaction / "metadata.json", self.uid, 0o400, 4096)
        try:
            metadata = json.loads(metadata_bytes)
            state_bytes, _ = _read_checked(self.transaction / "state.json", self.uid, 0o600, 16 * 1024)
            state = json.loads(state_bytes)
        except (ValueError, UnicodeDecodeError, OSError) as error:
            raise TransactionError("startup rollback snapshot metadata is malformed") from error
        if not isinstance(metadata, dict) or not isinstance(state, dict):
            raise TransactionError("startup rollback snapshot metadata is malformed")
        if sha256_bytes(original) != metadata.get("snapshot_sha256") or metadata.get("size") != len(original):
            raise TransactionError("startup rollback snapshot digest or length does not match")
        if state.get("snapshot_sha256") != sha256_bytes(original):
            raise TransactionError("transaction state does not match the protected rollback snapshot")
        if state.get("rollback_policy") != "remove-only-new-proxy-entry":
            raise TransactionError("transaction has an unsupported rollback policy")
        return original, metadata, state

    def _create_snapshot(self, original: bytes, metadata: os.stat_result, candidate: bytes, rollback: bytes, stage_name: str) -> dict:
        try:
            self.transaction.mkdir(mode=0o700)
        except OSError as error:
            raise TransactionError("an existing or incomplete startup transaction blocks activation") from error
        tx_meta = self.transaction.lstat()
        if not stat.S_ISDIR(tx_meta.st_mode) or tx_meta.st_uid != self.uid or stat.S_IMODE(tx_meta.st_mode) != 0o700:
            raise TransactionError("startup transaction directory ownership is invalid")
        original_digest = sha256_bytes(original)
        snapshot_meta = {
            "schema_version": 1,
            "snapshot_sha256": original_digest,
            "size": len(original),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "project_entry": OLD_ENTRY.decode("ascii"),
            "complete_original_bytes": True,
        }
        _write_new(self.transaction / "original.rc.local", original, 0o400, self.uid)
        _write_new(
            self.transaction / "metadata.json",
            (json.dumps(snapshot_meta, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            0o400,
            self.uid,
        )
        for path in (self.transaction / "original.rc.local", self.transaction / "metadata.json"):
            _regular_file(path, self.uid, 0o400)
        saved, _ = _read_checked(self.transaction / "original.rc.local", self.uid, 0o400)
        if saved != original:
            raise TransactionError("startup rollback snapshot failed exact-byte verification")
        state = {
            "schema_version": 1,
            "phase": "pending",
            "original_sha256": original_digest,
            "candidate_sha256": sha256_bytes(candidate),
            "rollback_sha256": sha256_bytes(rollback),
            "snapshot_sha256": original_digest,
            "stage_name": stage_name,
            "candidate_device": None,
            "candidate_inode": None,
            "rollback_stage_name": None,
            "rollback_device": None,
            "rollback_inode": None,
            "rollback_policy": "remove-only-new-proxy-entry",
        }
        self._write_state(state)
        _fsync_directory(self.staging)
        return state

    def _stage_name(self) -> str:
        return ".u60-rc-" + secrets.token_hex(12)

    def _replace(self, expected: bytes, replacement: bytes, state: dict, *, rollback: bool = False, original_identity: dict | None = None) -> None:
        current, current_meta = _read_checked(self.rc, self.uid, max_size=MAX_RC_BYTES)
        if current != expected or (original_identity is not None and startup_identity(current, current_meta) != original_identity):
            raise TransactionError("startup file no longer matches the transaction's expected bytes")
        name_key = "rollback_stage_name" if rollback else "stage_name"
        device_key = "rollback_device" if rollback else "candidate_device"
        inode_key = "rollback_inode" if rollback else "candidate_inode"
        stage_name = state.get(name_key)
        if stage_name is None:
            stage_name = self._stage_name()
            state[name_key] = stage_name
            if rollback:
                state["phase"] = "rollback_pending"
            self._write_state(state)
        if not isinstance(stage_name, str) or Path(stage_name).name != stage_name or not stage_name.startswith(".u60-rc-"):
            raise TransactionError("recorded startup staging path is malformed")
        stage = self.rc.parent / stage_name
        if stage.exists() or stage.is_symlink():
            checked_stage, stage_meta = _read_checked(stage, self.uid, stat.S_IMODE(current_meta.st_mode), MAX_RC_BYTES)
            if checked_stage != replacement or stage_meta.st_gid != current_meta.st_gid:
                if state.get(device_key) is not None:
                    raise TransactionError("recorded startup staging file is partial or unexpected")
                self._cleanup_one_stage(stage)
                stage_meta = _write_new(stage, replacement, stat.S_IMODE(current_meta.st_mode), self.uid, current_meta.st_gid)
        else:
            stage_meta = _write_new(stage, replacement, stat.S_IMODE(current_meta.st_mode), self.uid, current_meta.st_gid)
        if state.get(device_key) is None:
            state[device_key] = stage_meta.st_dev
            state[inode_key] = stage_meta.st_ino
            self._write_state(state)
        checked_stage, stage_meta = _read_checked(stage, self.uid, stat.S_IMODE(current_meta.st_mode), MAX_RC_BYTES)
        if checked_stage != replacement or stage_meta.st_gid != current_meta.st_gid:
            raise TransactionError("staged startup candidate failed exact-byte verification")
        if (stage_meta.st_dev, stage_meta.st_ino) != (state.get(device_key), state.get(inode_key)):
            raise TransactionError("recorded startup staging file identity changed")
        syntax = subprocess.run(["sh", "-n"], input=replacement, check=False, capture_output=True, timeout=2)
        if syntax.returncode:
            self._cleanup_one_stage(stage)
            raise TransactionError("staged startup file failed shell syntax validation")
        current_again, current_meta_again = _read_checked(self.rc, self.uid, max_size=MAX_RC_BYTES)
        if (
            current_again != expected
            or _file_signature(current_meta_again) != _file_signature(current_meta)
        ):
            self._cleanup_one_stage(stage)
            raise TransactionError("startup file changed during atomic replacement")
        try:
            os.replace(stage, self.rc)
            _fsync_directory(self.rc.parent)
        except OSError as error:
            raise TransactionError("atomic startup replacement failed") from error
        final_meta = _regular_file(self.rc, self.uid, stat.S_IMODE(stage_meta.st_mode), MAX_RC_BYTES)
        if (
            final_meta.st_nlink != 1
            or final_meta.st_gid != current_meta.st_gid
            or (final_meta.st_dev, final_meta.st_ino) != (state.get(device_key), state.get(inode_key))
        ):
            raise TransactionError("replacement startup file has unexpected links")

    def _cleanup_one_stage(self, path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        metadata = _regular_file(path, self.uid, max_size=MAX_RC_BYTES)
        if metadata.st_nlink != 1:
            raise TransactionError("recorded startup staging file has unexpected links")
        path.unlink()
        _fsync_directory(path.parent)

    def _cleanup_recorded_stage(
        self,
        state: dict,
        key: str = "stage_name",
        device_key: str = "candidate_device",
        inode_key: str = "candidate_inode",
    ) -> None:
        name = state.get(key)
        if not isinstance(name, str) or Path(name).name != name or not name.startswith(".u60-rc-"):
            raise TransactionError("recorded startup staging path is malformed")
        path = self.rc.parent / name
        if path.exists() or path.is_symlink():
            metadata = _regular_file(path, self.uid, max_size=MAX_RC_BYTES)
            expected_device, expected_inode = state.get(device_key), state.get(inode_key)
            if expected_device is not None and (metadata.st_dev, metadata.st_ino) != (expected_device, expected_inode):
                raise TransactionError("recorded startup staging identity changed; refusing cleanup")
        self._cleanup_one_stage(path)

    def _rollback(self, original: bytes, state: dict, allow_original: bool = True) -> None:
        saved_original, metadata, saved_state = self._read_snapshot()
        if saved_original != original or saved_state != state:
            raise TransactionError("startup snapshot or transaction state changed during activation")
        _, expected_rollback = transform_startup(original)
        if sha256_bytes(expected_rollback) != state["rollback_sha256"]:
            raise TransactionError("rollback candidate does not match the recorded digest")
        current, current_meta = _read_checked(self.rc, self.uid, max_size=MAX_RC_BYTES)
        current_digest = sha256_bytes(current)
        if current_digest == state["rollback_sha256"]:
            if state.get("phase") == "rollback_pending" and (current_meta.st_dev, current_meta.st_ino) != (
                state.get("rollback_device"), state.get("rollback_inode")
            ):
                raise TransactionError("rollback startup identity changed; refusing completion")
            self._cleanup_recorded_stage(state)
            state["phase"] = "rolled_back"
            self._write_state(state)
            return
        if current_digest == state["original_sha256"] and allow_original:
            if (
                current_meta.st_uid != metadata.get("uid")
                or current_meta.st_gid != metadata.get("gid")
                or stat.S_IMODE(current_meta.st_mode) != metadata.get("mode")
                or (current_meta.st_dev, current_meta.st_ino) != (metadata.get("device"), metadata.get("inode"))
            ):
                raise TransactionError("original startup identity changed; refusing recovery")
            self._cleanup_recorded_stage(state)
            state["phase"] = "rolled_back"
            self._write_state(state)
            return
        if current_digest != state["candidate_sha256"]:
            raise TransactionError("startup file is not the exact transaction candidate; refusing rollback overwrite")
        if (
            current_meta.st_uid != metadata.get("uid")
            or current_meta.st_gid != metadata.get("gid")
            or stat.S_IMODE(current_meta.st_mode) != metadata.get("mode")
            or (current_meta.st_dev, current_meta.st_ino) != (state.get("candidate_device"), state.get("candidate_inode"))
        ):
            raise TransactionError("candidate startup identity changed; refusing rollback overwrite")
        # Roll back by removing only the new proxy entry. The protected snapshot
        # retains the original file, but the obsolete Mihomo is never
        # restored into the boot path.
        self._replace(current, expected_rollback, state, rollback=True)
        self._cleanup_recorded_stage(state, "rollback_stage_name", "rollback_device", "rollback_inode")
        state["phase"] = "rolled_back"
        self._write_state(state)

    def _validated_startup(self, expected_identity: dict) -> tuple[bytes, os.stat_result, bytes, bytes]:
        original, metadata = _read_checked(self.rc, self.uid)
        observed = startup_identity(original, metadata)
        if (
            not isinstance(expected_identity, dict)
            or expected_identity.keys() != observed.keys()
            or any(type(expected_identity[key]) is not type(value) or expected_identity[key] != value
                   for key, value in observed.items())
        ):
            raise TransactionError("startup identity or complete content differs from the verified inventory")
        candidate, rollback = transform_startup(original)
        validate_startup_files(original, candidate, rollback)
        return original, metadata, candidate, rollback

    def dry_run(self, expected_identity: dict) -> None:
        self._validate_layout()
        self._validated_startup(expected_identity)

    def activate(
        self,
        launch: Callable[[], None],
        health_probe: Callable[[float], bool],
        *,
        expected_identity: dict,
        total_timeout: float = HEALTH_TIMEOUT_SECONDS,
        request_timeout: float = HEALTH_REQUEST_TIMEOUT_SECONDS,
        attempts: int = HEALTH_ATTEMPTS,
        interval: float = HEALTH_INTERVAL_SECONDS,
        failpoint: Callable[[str], None] | None = None,
    ) -> None:
        self._validate_layout()
        lock_fd = self._lock()
        try:
            original, metadata, candidate, rollback = self._validated_startup(expected_identity)
            stage_name = self._stage_name()
            state = self._create_snapshot(original, metadata, candidate, rollback, stage_name)
            try:
                if failpoint:
                    failpoint("after-snapshot")
                self._replace(original, candidate, state, original_identity=expected_identity)
                if failpoint:
                    failpoint("after-replacement")
                launch()
                healthy = wait_authenticated_health(
                    health_probe,
                    total_timeout=total_timeout,
                    request_timeout=request_timeout,
                    attempts=attempts,
                    interval=interval,
                )
                if not healthy:
                    raise ActivationFailed("authenticated proxy-only health check failed")
                state["phase"] = "activated"
                self._write_state(state)
                _fsync_directory(self.staging)
            except Exception as error:
                try:
                    # _write_state() may fail after mutating the in-memory
                    # object but before its atomic replacement is durable.
                    # Recover from the state that was actually committed.
                    _, _, persisted_state = self._read_snapshot()
                    self._rollback(original, persisted_state)
                except Exception:
                    raise TransactionError(
                        "activation failed and exact rollback did not complete; protected snapshot is retained"
                    ) from None
                if isinstance(error, ActivationFailed):
                    raise ActivationFailed(
                        "authenticated proxy-only health check failed; exact project startup entry was disabled"
                    ) from None
                raise ActivationFailed(
                    "activation failed; exact project startup entry was disabled"
                ) from None
        finally:
            os.close(lock_fd)

    def recover_pending(self) -> str:
        self._validate_transaction_paths()
        lock_fd = self._lock()
        try:
            original, _, state = self._read_snapshot()
            if state.get("phase") in {"activated", "rolled_back"}:
                return state["phase"]
            if state.get("phase") not in {"pending", "rollback_pending"}:
                raise TransactionError("startup transaction phase is unknown; refusing recovery")
            self._rollback(original, state)
            return "rolled_back"
        finally:
            os.close(lock_fd)


def wait_authenticated_health(
    probe: Callable[[float], bool],
    *,
    total_timeout: float = HEALTH_TIMEOUT_SECONDS,
    request_timeout: float = HEALTH_REQUEST_TIMEOUT_SECONDS,
    attempts: int = HEALTH_ATTEMPTS,
    interval: float = HEALTH_INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    if total_timeout <= 0 or request_timeout <= 0 or attempts < 1 or interval < 0:
        return False
    deadline = monotonic() + total_timeout
    for attempt in range(attempts):
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False
        try:
            if probe(min(deadline, monotonic() + request_timeout)) and monotonic() < deadline:
                return True
        except Exception:
            pass
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False
        if attempt + 1 < attempts:
            sleep(min(interval, remaining))
    return False


class SyntheticLocalAgentHealthProbe:
    """Synthetic authenticated probe; it cannot read a device credential."""

    def __init__(self, password_path: Path, test_root: Path, port: int = 9090):
        if port < 1 or port > 65535:
            raise ValueError("health probe port is invalid")
        root = validate_synthetic_test_root(test_root)
        expected_password_path = root / MANAGED_ROOT / "auth/password"
        try:
            resolved_password_path = password_path.resolve(strict=True)
        except OSError as error:
            raise ValueError("synthetic health probe credential is unavailable") from error
        if resolved_password_path != expected_password_path:
            raise ValueError("synthetic health probe requires the marked test-root credential path")
        self.password = read_password_file(password_path)
        self.port = port

    def _request(self, method: str, path: str, body: dict | None, token: str | None, deadline: float) -> dict:
        if (method, path) not in {
            ("GET", "/api/proxy/capabilities"),
            ("POST", "/api/auth/login"),
            ("GET", "/api/proxy/status"),
        }:
            raise ValueError("health probe route is not allowlisted")
        if token is not None and (
            not token.isascii()
            or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-" for char in token)
        ):
            raise ValueError("health token is malformed")
        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: 127.0.0.1:{self.port}",
            "Accept: application/json",
            "Connection: close",
        ]
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers.extend(("Content-Type: application/json", f"Content-Length: {len(payload)}"))
        else:
            payload = b""
        if token is not None:
            headers.append(f"Authorization: Bearer {token}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + payload

        def wait_for(connection: socket.socket, event: int) -> None:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                with selectors.DefaultSelector() as selector:
                    selector.register(connection, event)
                    if selector.select(remaining):
                        return

        def receive(connection: socket.socket, maximum: int) -> bytes:
            while True:
                wait_for(connection, selectors.EVENT_READ)
                try:
                    return connection.recv(maximum)
                except BlockingIOError:
                    continue

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.setblocking(False)
            connect_result = connection.connect_ex(("127.0.0.1", self.port))
            pending = (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR)
            if connect_result not in (0, *pending):
                raise OSError(connect_result, "loopback health connection failed")
            if connect_result != 0:
                wait_for(connection, selectors.EVENT_WRITE)
                connect_error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if connect_error:
                    raise OSError(connect_error, "loopback health connection failed")

            view = memoryview(request)
            while view:
                wait_for(connection, selectors.EVENT_WRITE)
                try:
                    sent = connection.send(view)
                except BlockingIOError:
                    continue
                if sent <= 0:
                    raise OSError("loopback health request was not sent")
                view = view[sent:]

            response = bytearray()
            header_delimiter = b"\r\n\r\n"
            while header_delimiter not in response:
                if len(response) >= 8192:
                    raise ValueError("health response headers are too large")
                block = receive(connection, min(4096, 8193 - len(response)))
                if not block:
                    raise ValueError("health response ended before headers")
                response.extend(block)
            header_end = response.index(header_delimiter)
            header_lines = bytes(response[:header_end]).split(b"\r\n")
            status_parts = header_lines[0].split(b" ", 2)
            if (
                len(status_parts) < 2
                or status_parts[0] not in (b"HTTP/1.0", b"HTTP/1.1")
                or not status_parts[1].isdigit()
                or int(status_parts[1]) != 200
            ):
                raise ValueError("health response status is invalid")
            response_headers: dict[bytes, bytes] = {}
            for line in header_lines[1:]:
                name, colon, value = line.partition(b":")
                lowered = name.lower()
                if not colon or not name or lowered in response_headers:
                    raise ValueError("health response headers are malformed")
                response_headers[lowered] = value.strip()
            if b"transfer-encoding" in response_headers:
                raise ValueError("health response must use a bounded content length")
            length_text = response_headers.get(b"content-length", b"")
            if not length_text.isdigit():
                raise ValueError("health response length is invalid")
            body_length = int(length_text)
            if body_length < 1 or body_length > 64 * 1024:
                raise ValueError("health response body size is invalid")
            body_start = header_end + len(header_delimiter)
            response_body = bytearray(response[body_start:])
            if len(response_body) > body_length:
                raise ValueError("health response exceeds its declared length")
            while len(response_body) < body_length:
                block = receive(connection, min(4096, body_length - len(response_body)))
                if not block:
                    raise ValueError("health response body is truncated")
                response_body.extend(block)
            if time.monotonic() > deadline:
                raise TimeoutError
            envelope = json.loads(response_body)
            if not isinstance(envelope, dict) or envelope.get("ok") is not True or not isinstance(envelope.get("data"), dict):
                raise ValueError("health response envelope is invalid")
            return envelope["data"]

    def __call__(self, deadline: float) -> bool:
        try:
            capabilities = self._request("GET", "/api/proxy/capabilities", None, None, deadline)
            if capabilities.get("mode") != "proxy_only" or capabilities.get("auth_required") is not True:
                return False
            login = self._request("POST", "/api/auth/login", {"password": self.password}, None, deadline)
            token = login.get("token")
            if not isinstance(token, str) or len(token) < 32 or len(token) > 256:
                return False
            status = self._request("GET", "/api/proxy/status", None, token, deadline)
            return (
                status.get("running") is True
                and status.get("enabled") is True
                and status.get("lifecycle") == "running"
                and status.get("controller_ready") is True
                and status.get("mode") == "rule"
                and status.get("preset") == "bypass_cn"
                and "profile" in status
                and status["profile"] is None
                and status.get("tun") is False
                and status.get("tun_active") is False
            )
        except Exception:
            # Do not include request bodies, credentials, tokens, or raw Agent errors.
            return False
