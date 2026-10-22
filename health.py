"""Lease-aware health check for the last complete port-forwarding refresh."""

import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time


HEALTH_FILE = os.environ.get("QB_NATPMP_HEALTH_FILE", "/tmp/qb-natpmp-health.json")


def clear_health(path=HEALTH_FILE):
    """Discard a previous process's marker before attempting a new refresh."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _timestamp(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def write_health(expires_at, *, path=HEALTH_FILE):
    """Atomically publish a completed refresh with its monotonic lease expiry."""
    last_success_monotonic = time.monotonic()
    if not _timestamp(expires_at) or expires_at <= last_success_monotonic:
        raise ValueError("Cannot publish health for an expired or invalid lease")

    state = {
        "last_success": time.time(),
        "last_success_monotonic": last_success_monotonic,
        "expires_at": expires_at,
    }
    destination = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", delete=False,
        ) as temporary:
            temporary_path = temporary.name
            json.dump(state, temporary, allow_nan=False)
            temporary.write("\n")
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def check_health(path=HEALTH_FILE):
    """Return whether a complete refresh still has an unexpired lease.

    Monotonic timestamps are shared between processes on the same host. Wall
    time is recorded for operators, but clock adjustments must not extend or
    shorten the actual lease. A monotonic clock rollback invalidates the marker.
    """
    try:
        with open(path, encoding="utf-8") as source:
            state = json.load(source)
        if not isinstance(state, dict):
            return False
        last_success = state["last_success"]
        last_success_monotonic = state["last_success_monotonic"]
        expires_at = state["expires_at"]
        if not all(_timestamp(value) for value in (
            last_success, last_success_monotonic, expires_at,
        )):
            return False
        return last_success_monotonic <= time.monotonic() < expires_at
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main():
    if check_health():
        return 0
    print("No unexpired successful port-forwarding refresh", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
