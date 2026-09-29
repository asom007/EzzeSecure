"""Opt-in current-user crontab registration with exact readback verification."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

from .executor import run_argv


class CronScheduler:
    def __init__(self, crontab: Path = Path("/usr/bin/crontab"), cwd: Path = Path("/")):
        if not crontab.is_absolute():
            raise ValueError("Absolute crontab executable required")
        self.crontab, self.cwd = crontab, cwd

    @staticmethod
    def _markers(name: str):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,60}", name):
            raise ValueError("Invalid scheduler registration name")
        return f"# HEIMDALL BEGIN {name}", f"# HEIMDALL END {name}"

    def plan(self, name: str, argv: tuple[str, ...], current: str = "") -> str:
        """Cron invokes a shell, so only a narrow literal argv alphabet is allowed.

        This deliberately excludes spaces, percent signs, redirects, quotes and
        shell substitutions. This API never accepts a raw command or schedule.
        """
        begin, end = self._markers(name)
        if not argv or not Path(argv[0]).is_absolute() or any(not re.fullmatch(r"[A-Za-z0-9_./:@=-]+", arg) for arg in argv):
            raise ValueError("Cron argv must be literal safe tokens with an absolute executable")
        lines, inside, seen = [], False, False
        for line in current.splitlines():
            if line == begin:
                if inside or seen:
                    raise ValueError("Ambiguous duplicate scheduler block")
                inside = seen = True
            elif line == end:
                if not inside:
                    raise ValueError("Unmatched scheduler block")
                inside = False
            elif not inside:
                lines.append(line)
        if inside:
            raise ValueError("Unterminated scheduler block")
        return "\n".join(lines + [begin, "* * * * * " + " ".join(argv), end, ""])

    def _read(self):
        result = run_argv((str(self.crontab), "-l"), self.cwd, 5, 131072, redact_output=False)
        if result["exit_code"] == 0 and not result["output_limited"] and not result["timed_out"]:
            return result["stdout"]
        # A missing crontab has a well-defined diagnostic; permission failures do
        # not get interpreted as an empty crontab and overwritten.
        if result["exit_code"] == 1 and "no crontab for" in result["output"].lower():
            return ""
        raise RuntimeError("Unable to safely read current user's crontab")

    def install(self, name: str, argv: tuple[str, ...]) -> dict:
        current = self._read()
        desired = self.plan(name, argv, current)
        # Recheck before writing to avoid clobbering an intervening external edit.
        if self._read() != current:
            raise RuntimeError("Crontab changed while preparing registration")
        result = subprocess.run((str(self.crontab), "-"), input=desired.encode(),
                                cwd=self.cwd, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10, shell=False)
        actual = self._read()
        verified = result.returncode == 0 and actual == desired
        return {"registered": verified, "verification": "exact_crontab_readback" if verified else "failed",
                "last_run_verified": False, "reason": "Registration does not prove cron is running; collect an application heartbeat"}

    def verify(self, name: str, argv: tuple[str, ...]) -> dict:
        actual = self._read()
        expected = self.plan(name, argv, actual)
        return {"registered": actual == expected, "verification": "exact_crontab_readback",
                "last_run_verified": False}
