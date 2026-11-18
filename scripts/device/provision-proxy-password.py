#!/usr/bin/env python3
"""Provision the managed proxy-only password without displaying its value."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from proxy_credentials import TEST_ROOT_MARKER, provision_password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-root", required=True, type=Path, help=f"marked disposable test root ({TEST_ROOT_MARKER})")
    args = parser.parse_args()
    path = args.test_root / "data/u60-pro-managed/auth/password"
    try:
        provision_password(path, args.test_root)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print("managed proxy-only credential created; value was not displayed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
