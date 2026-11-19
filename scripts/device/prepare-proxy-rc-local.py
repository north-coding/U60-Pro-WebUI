#!/usr/bin/env python3
"""Exercise the proxy startup transaction only against a marked synthetic tree.

This candidate intentionally cannot target /etc/rc.local or execute a device
launcher. Device execution remains disabled pending separate Owner approval.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from startup_transaction import StartupTransaction, TransactionError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-root", required=True, type=Path, help="marked disposable synthetic filesystem root")
    parser.add_argument("--inventory", type=Path, help="verified synthetic startup file identity JSON")
    parser.add_argument("--apply", action="store_true", help="apply the transaction to the synthetic tree only")
    parser.add_argument("--recover", action="store_true", help="recover an interrupted synthetic transaction")
    parser.add_argument(
        "--health-result",
        choices=("healthy", "failed", "timeout"),
        default="healthy",
        help="synthetic probe outcome; never contacts a service",
    )
    args = parser.parse_args()
    if args.apply and args.recover:
        parser.error("--apply and --recover are mutually exclusive")

    try:
        transaction = StartupTransaction(args.test_root)
        if args.recover:
            result = transaction.recover_pending()
            print(f"synthetic recovery: {result}")
            return 0
        if args.inventory is None:
            parser.error("--inventory is required for dry-run and apply")
        identity = json.loads(args.inventory.read_text(encoding="utf-8"))
        if not args.apply:
            transaction.dry_run(identity)
            print("dry run: candidate and artifacts validated; no files changed; device execution is disabled")
            return 0

        def synthetic_health(deadline: float) -> bool:
            if args.health_result == "timeout":
                time.sleep(max(0.0, min(0.25, deadline - time.monotonic())))
                return False
            return args.health_result == "healthy"

        transaction.activate(lambda: None, synthetic_health, expected_identity=identity, total_timeout=0.3, request_timeout=0.05, attempts=3, interval=0.01)
        print("synthetic activation committed; no Agent or device service was started")
        return 0
    except (OSError, ValueError, TransactionError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    sys.exit(main())
