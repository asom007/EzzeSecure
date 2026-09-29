"""Explicitly configured service adapters; discovery never turns into execution."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
import json
import os
import re
import stat
import sys

from .executor import RegisteredCommand, run_argv
from .security import FileIntegrity, log_tail, parse_access_log, parse_auth_log


class ServicePlugin(Protocol):
    name: str

    def collect(self) -> dict: ...

    def registered_commands(self) -> list[RegisteredCommand]: ...


class SystemdPlugin:
    """Initial coverage for nginx/apache, php-fpm, mysql/postgres, redis and workers.

    All unit names are supplied by local trusted configuration. A unit's active
    state is service evidence, not proof that its database/application is healthy.
    """
    name = "systemd"

    def __init__(self, units: list[str], systemctl: Path = Path("/usr/bin/systemctl"),
                 allow_restart: bool = False, cwd: Path = Path("/")):
        if any(not re.fullmatch(r"[A-Za-z0-9_@.:-]+\.service", unit) for unit in units):
            raise ValueError("Explicit systemd .service unit names required")
        if str(systemctl) not in {"/usr/bin/systemctl", "/bin/systemctl"}:
            raise ValueError("Community service collection requires the system systemctl executable")
        self.units, self.systemctl, self.allow_restart, self.cwd = units, systemctl, allow_restart, cwd

    def collect(self):
        rows = []
        for unit in self.units:
            result = run_argv((str(self.systemctl), "show", unit, "--property=LoadState,ActiveState,SubState", "--no-pager"),
                              self.cwd, 5, 4096)
            values = dict(line.split("=", 1) for line in result["output"].splitlines() if "=" in line)
            available = result["exit_code"] == 0 and values.get("LoadState") == "loaded"
            rows.append({"name": unit, "state": values.get("ActiveState") if available else "unknown",
                         "substate": values.get("SubState") if available else None, "available": available,
                         "reason": None if available else "Systemd unit missing, inaccessible or probe failed"})
        return {"services": rows, "source": "systemd"}

    def registered_commands(self):
        if not self.allow_restart:
            return []
        return [RegisteredCommand("service.restart", unit, (str(self.systemctl), "restart", unit), self.cwd,
                                  verification=(str(self.systemctl), "is-active", "--quiet", unit)) for unit in self.units]


class LaravelPlugin:
    """Use a configured app directory and a small exported health JSON file.

    We never read .env values or infer queue success from process names. The
    application is responsible for publishing its queue/database/worker probe.
    """
    name = "laravel"

    def __init__(self, app_root: Path, health_file: Path | None = None, php: Path = Path("/usr/bin/php"),
                 allow_actions: bool = False, integrity: FileIntegrity | None = None,
                 max_health_age_seconds: int = 180, scheduler_lock: Path | None = None):
        self.root = app_root.resolve()
        self.php = php
        if not php.is_absolute():
            raise ValueError("Absolute PHP executable required")
        self.health_file = health_file.absolute() if health_file else None
        self.allow_actions = allow_actions
        self.integrity = integrity
        self.max_health_age_seconds = max_health_age_seconds
        self.scheduler_lock = scheduler_lock.absolute() if scheduler_lock else self.root / "storage/framework/heimdall-scheduler.lock"

    def collect(self):
        application = {"framework": "laravel", "queue_backlog": None, "queue_workers": None,
                       "scheduler_last_run": None, "scheduler_locked": None, "scheduler_running": None, "database_healthy": None,
                       "failed_jobs": None, "health_available": False}
        try:
            if self.health_file is None:
                raise ValueError("No health file configured")
            descriptor = os.open(self.health_file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("Health file is not regular")
                payload = stream.read(65537)
            if len(payload) > 65536:
                raise ValueError("Health file too large")
            health = json.loads(payload)
            observed = datetime.fromisoformat(health["observed_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - observed).total_seconds()
            if not 0 <= age <= self.max_health_age_seconds:
                raise ValueError("Health file is stale or future-dated")
            for key in ("queue_backlog", "queue_workers", "failed_jobs"):
                value = health.get(key)
                if type(value) is int and value >= 0:
                    application[key] = value
            for key in ("scheduler_locked", "scheduler_running", "database_healthy"):
                if type(health.get(key)) is bool:
                    application[key] = health[key]
            if isinstance(health.get("scheduler_last_run"), str):
                application["scheduler_last_run"] = datetime.fromisoformat(health["scheduler_last_run"].replace("Z", "+00:00")).isoformat()
            application.update(health_available=True, observed_at=observed.isoformat(), source="configured_application_probe")
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            application["unavailable_reason"] = "Configured application health file missing, invalid or stale"
        result = {"application": application,
                  "configured_files": [{"path": str(self.root / name), "exists": (self.root / name).is_file()}
                                       for name in ("artisan", "composer.json", "bootstrap/app.php", "routes/console.php", "app/Console/Kernel.php")]}
        if self.integrity:
            result["file_integrity"] = self.integrity.compare()
            scan = self.integrity.scan_php_indicators()
            result["webshell_indicators"] = scan["indicators"]
            result.setdefault("evidence", {})["php_indicator_scan"] = scan["evidence"]
        return result

    def registered_commands(self):
        if not self.allow_actions:
            return []
        # queue:restart only signals workers; without a fresh app probe we do not
        # claim workers actually restarted. Likewise cache:clear only checks exit.
        preflight = (str(Path(sys.executable).resolve()), str(Path(__file__).with_name("preflight.py").resolve()),
                     "--health-file", str(self.health_file), "--max-age-seconds", str(self.max_health_age_seconds)) if self.health_file else None
        return [RegisteredCommand(action, "laravel", (str(self.php), str(self.root / "artisan"), command, "--no-interaction"),
                                  self.root, timeout_seconds=60,
                                  preflight=preflight if action == "scheduler.run" else None,
                                  shared_lock=self.scheduler_lock if action == "scheduler.run" else None)
                for action, command in (("scheduler.run", "schedule:run"), ("queue.restart", "queue:restart"),
                                        ("cache.clear", "cache:clear"))]


class LogPlugin:
    name = "logs"

    def __init__(self, access_log: Path | None = None, auth_log: Path | None = None):
        self.access_log, self.auth_log = access_log, auth_log

    def registered_commands(self):
        return []

    def collect(self):
        result = {"events": [], "evidence": {}}
        if self.access_log:
            tail = log_tail(self.access_log)
            result["evidence"]["access_log"] = {key: value for key, value in tail.items() if key != "text"}
            if tail["available"]:
                result["traffic"] = parse_access_log(tail["text"])
        if self.auth_log:
            tail = log_tail(self.auth_log)
            result["evidence"]["auth_log"] = {key: value for key, value in tail.items() if key != "text"}
            if tail["available"]:
                result["security"] = parse_auth_log(tail["text"])
                event_types = {
                    "authentication_failed": ("WARNING", "failed authentication"),
                    "authentication_succeeded": ("INFO", "successful authentication"),
                    "privileged_command": ("INFO", "privileged command"),
                    "root_login": ("WARNING", "successful root login"),
                    "user_created": ("WARNING", "user creation"),
                    "group_changed": ("WARNING", "group membership or creation"),
                    "privilege_changed": ("WARNING", "privilege membership or UID change"),
                }
                for kind, (severity, description) in event_types.items():
                    count = result["security"]["counts"].get(kind, 0)
                    if count:
                        result["events"].append({"kind": kind, "severity": severity, "count": count,
                                                 "summary": f"{count} {description} records in configured log tail",
                                                 "scope": "Log tail; no incident time-window or unauthorized activity inferred"})
        return result


class IntegrityPlugin:
    """General host-config integrity, with separate trust baselines per scope."""
    name = "integrity"

    def __init__(self, integrity: FileIntegrity, additional=()):
        self.integrity = integrity
        self.checks = (("host", integrity), *additional)

    def registered_commands(self):
        return []

    def collect(self):
        files, changes, evidence = {}, [], {}
        for name, checker in self.checks:
            comparison = checker.compare()
            files.update(comparison.get("files", {}))
            changes.extend(comparison.get("changes", []))
            evidence[name] = {"available": comparison["available"], "reason": comparison.get("reason"),
                              "configured_files": len(checker.paths)}
        available = any(item["available"] for item in evidence.values())
        result = {"available": available, "files": files, "changes": changes}
        if not available:
            result["reason"] = "No readable baseline; explicit baseline creation required"
        return {"file_integrity": result, "evidence": {"file_integrity": evidence}}
