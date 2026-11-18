"""Strict proxy-only credential validation and secure local provisioning."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import tempfile


PASSWORD_BYTES = 32
PASSWORD_LENGTH = 43  # unpadded base64url encoding of 32 random bytes
TEST_ROOT_MARKER = ".u60-proxy-transaction-test-root"


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


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) != PASSWORD_LENGTH or not password.isascii():
        raise ValueError("proxy-only password must be a 32-byte base64url secret")
    if any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for char in password):
        raise ValueError("proxy-only password must be a 32-byte base64url secret")
    if password[-1] not in "AEIMQUYcgkosw048":
        raise ValueError("proxy-only password is not canonical base64url for 32 bytes")


def validate_synthetic_test_root(path: Path, expected_uid: int | None = None) -> Path:
    """Require the marked temporary root used by offline transaction tests."""
    owner = os.geteuid() if expected_uid is None else expected_uid
    root = path.resolve(strict=True)
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if root == temp_root or not root.is_relative_to(temp_root):
        raise ValueError("device execution is disabled; test root must be inside the temporary directory")
    root_meta = root.lstat()
    if (
        not stat.S_ISDIR(root_meta.st_mode)
        or root_meta.st_uid != owner
        or stat.S_IMODE(root_meta.st_mode) != 0o700
    ):
        raise ValueError("synthetic test root must be an owner-only directory")
    marker = root / TEST_ROOT_MARKER
    try:
        metadata = marker.lstat()
    except OSError as error:
        raise ValueError("synthetic test root marker is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("synthetic test root marker is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(marker, flags)
    try:
        opened = os.fstat(fd)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_uid != owner
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("synthetic test root marker changed while being opened")
        content = os.read(fd, 129)
    finally:
        os.close(fd)
    if content != b"synthetic-only\n":
        raise ValueError("synthetic test root marker is invalid")
    return root


def read_password_file(path: Path, expected_uid: int | None = None) -> str:
    owner = os.geteuid() if expected_uid is None else expected_uid
    try:
        before = path.lstat()
    except OSError as error:
        raise ValueError("managed proxy-only password file is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != owner
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size != PASSWORD_LENGTH + 1
    ):
        raise ValueError("managed proxy-only password file has invalid type, owner, mode, links, or size")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ValueError("managed proxy-only password file cannot be opened safely") from error
    try:
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or _file_signature(after) != _file_signature(before)
            or after.st_uid != owner
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_size != PASSWORD_LENGTH + 1
        ):
            raise ValueError("managed proxy-only password file changed while being opened")
        chunks = bytearray()
        while len(chunks) <= PASSWORD_LENGTH + 1:
            block = os.read(fd, PASSWORD_LENGTH + 2 - len(chunks))
            if not block:
                break
            chunks.extend(block)
        after_read = os.fstat(fd)
        path_after_read = path.lstat()
        if _file_signature(after) != _file_signature(after_read) or _file_signature(after) != _file_signature(path_after_read):
            raise ValueError("managed proxy-only password file changed while being read")
    finally:
        os.close(fd)

    if len(chunks) != PASSWORD_LENGTH + 1 or chunks[-1:] != b"\n" or b"\n" in chunks[:-1] or b"\r" in chunks or b"\0" in chunks:
        raise ValueError("managed proxy-only password file must contain one newline-terminated secret")
    try:
        password = chunks[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("managed proxy-only password file is malformed") from error
    validate_password(password)
    return password


def provision_password(path: Path, test_root: Path) -> None:
    """Create a random secret only in the marked synthetic tree; never print it."""
    root = validate_synthetic_test_root(test_root)
    expected_parent = root / "data/u60-pro-managed/auth"
    if path.parent.resolve(strict=True) != expected_parent:
        raise ValueError("credential output must stay inside the synthetic managed auth directory")
    for relative in (Path("data"), Path("data/u60-pro-managed"), Path("data/u60-pro-managed/auth")):
        directory = root / relative
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("synthetic managed authentication path has unsafe ownership or permissions")
    parent = path.parent
    try:
        parent_meta = parent.lstat()
    except OSError as error:
        raise ValueError("managed authentication directory is unavailable") from error
    if (
        not stat.S_ISDIR(parent_meta.st_mode)
        or parent_meta.st_uid != os.geteuid()
        or stat.S_IMODE(parent_meta.st_mode) != 0o700
    ):
        raise ValueError("managed authentication directory must be owned and mode 0700")

    secret = secrets.token_urlsafe(PASSWORD_BYTES)
    validate_password(secret)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise ValueError("managed proxy-only password already exists; refusing to replace it") from error
    except OSError as error:
        raise ValueError("cannot create managed proxy-only password file") from error

    created = None
    try:
        created = os.fstat(fd)
        payload = secret.encode("ascii") + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short credential write")
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            current = path.lstat()
            if created is not None and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino) and current.st_uid == os.geteuid() and current.st_nlink == 1:
                path.unlink()
                dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    read_password_file(path)
