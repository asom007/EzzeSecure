"""Standalone fixed-argv scheduler readiness check; exits nonzero on uncertainty."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import os
import stat


def scheduler_readiness(path: Path, max_age_seconds: int = 180) -> dict:
    try:
        if not 1 <= max_age_seconds <= 3600:
            raise ValueError("Invalid health age limit")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Not a regular health file")
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("Health file exceeds limit")
        health = json.loads(raw)
        observed = datetime.fromisoformat(health["observed_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - observed).total_seconds()
        if not 0 <= age <= max_age_seconds:
            return {"ready": False, "reason": "Scheduler health evidence is stale or future-dated"}
        if health.get("scheduler_locked") is not False or health.get("scheduler_running") is not False:
            return {"ready": False, "reason": "Scheduler locked/running flags must both explicitly be false"}
        return {"ready": True, "reason": "Fresh application probe reports scheduler idle and unlocked"}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {"ready": False, "reason": "Scheduler health evidence is missing, unreadable or invalid"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded scheduler readiness preflight")
    parser.add_argument("--health-file", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, default=180)
    args = parser.parse_args(argv)
    result = scheduler_readiness(args.health_file, args.max_age_seconds)
    print(json.dumps(result))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
