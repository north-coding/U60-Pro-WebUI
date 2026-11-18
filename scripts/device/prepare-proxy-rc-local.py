#!/usr/bin/env python3
"""Dry-run by default; atomically replace one exact project-owned rc.local line."""

from __future__ import annotations

import argparse
import fcntl
import os
import stat
import subprocess
import tempfile
from pathlib import Path

OLD = b"sh /data/local/tmp/start_zte_agent.sh"
NEW = b"sh /data/u60-pro-managed/agent/start-proxy-agent.sh start"


def read_target(path: Path) -> tuple[bytes, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
            raise ValueError("startup file must be a regular, single-link file owned by the current operator")
        with os.fdopen(os.dup(fd), "rb") as stream:
            return stream.read(), metadata
    finally:
        os.close(fd)


def transformed(original: bytes) -> tuple[bytes, bool]:
    lines = original.splitlines(keepends=True)
    old_lines = [index for index, line in enumerate(lines) if line.rstrip(b"\r\n") == OLD]
    new_lines = [index for index, line in enumerate(lines) if line.rstrip(b"\r\n") == NEW]
    if len(new_lines) == 1 and not old_lines:
        return original, False
    if len(old_lines) != 1 or new_lines:
        raise ValueError("expected exactly one old Agent entry and no replacement entry; refusing an ambiguous edit")
    index = old_lines[0]
    ending = lines[index][len(OLD):]
    lines[index] = NEW + ending
    return b"".join(lines), True


def apply(path: Path, original: bytes, metadata: os.stat_result, candidate: bytes) -> None:
    parent = path.parent
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.u60-", dir=parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        os.fchown(fd, metadata.st_uid, metadata.st_gid)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        checked = subprocess.run(["sh", "-n", str(temp)], check=False, capture_output=True, text=True)
        if checked.returncode:
            raise ValueError(f"candidate rc.local failed sh -n: {checked.stderr.strip()}")

        lock_fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            current = os.fstat(lock_fd)
            with os.fdopen(os.dup(lock_fd), "rb") as stream:
                current_bytes = stream.read(max(len(original) + 1, 1))
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino) or current_bytes != original:
                raise ValueError("startup file changed during preparation; refusing replacement")
            os.replace(temp, path)
        finally:
            os.close(lock_fd)
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rc-local", required=True, type=Path, help="explicit offline or approved target file")
    parser.add_argument("--apply", action="store_true", help="atomically apply the exact one-line replacement")
    args = parser.parse_args()
    try:
        original, metadata = read_target(args.rc_local)
        candidate, changed = transformed(original)
        if not changed:
            print("startup entry is already set to the proxy-only launcher")
            return 0
        if args.apply:
            apply(args.rc_local, original, metadata, candidate)
            print("replaced the exact project-owned Agent startup line and validated sh syntax")
        else:
            print("dry run: would replace exactly one project-owned Agent startup line; no file changed")
        return 0
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
