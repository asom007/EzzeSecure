"""Project-local demonstration agent. Every mutation affects fixture state only."""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
import json
import sqlite3
import time

from .executor import ALLOWED_ACTIONS, DEFAULT_TARGETS, RequestGuard, failure


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCENARIOS = {
    "healthy": {"cpu": 24, "ram": 46, "disk": 39, "requests": 128, "baseline": 115},
    "growth": {"cpu": 68, "ram": 69, "disk": 47, "requests": 460, "baseline": 120},
    "attack": {"cpu": 91, "ram": 75, "disk": 44, "requests": 2100, "baseline": 120},
    "queue": {"cpu": 49, "ram": 58, "disk": 43, "requests": 150, "baseline": 120},
    "capacity": {"cpu": 89, "ram": 94, "disk": 91, "requests": 430, "baseline": 310},
    "database": {"cpu": 57, "ram": 78, "disk": 55, "requests": 170, "baseline": 120},
}


class DemoAgent:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.guard = RequestGuard(self.root / "execution")
        self.database = self.root / "demo.sqlite3"
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO state VALUES ('scenario', '\"healthy\"')")
        self.database.chmod(0o600)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def set_scenario(self, name: str) -> None:
        if name not in SCENARIOS:
            raise ValueError("Unknown simulation scenario")
        with self._connect() as db:
            db.execute("DELETE FROM state")
            db.execute("INSERT INTO state VALUES ('scenario', ?)", (json.dumps(name),))

    def _state(self):
        with self._connect() as db:
            return {key: json.loads(value) for key, value in db.execute("SELECT key,value FROM state")}

    def collect(self) -> dict:
        state = self._state()
        scenario = state["scenario"]
        fixture = SCENARIOS[scenario]
        queue_issue = scenario == "queue" and not state.get("queue_restarted")
        database_issue = scenario == "database"
        attack = scenario == "attack"
        events = []
        if attack:
            events.append({"kind": "security", "severity": "CRITICAL", "summary": "Simulated burst of sensitive-path probes and failed logins", "count": 180})
        if queue_issue:
            events.append({"kind": "queue", "severity": "WARNING", "summary": "Simulated worker stopped; pending jobs increasing"})
        if database_issue:
            events.append({"kind": "database", "severity": "CRITICAL", "summary": "Simulated database health probe failed"})
        scheduler_last = state.get("scheduler_last_run")
        if scheduler_last is None and not queue_issue:
            scheduler_last = utc_now()
        return {
            "demo": True, "simulated": True, "scenario": scenario, "observed_at": utc_now(),
            "metrics": {"cpu_percent": fixture["cpu"], "ram_percent": fixture["ram"],
                        "disk_percent": fixture["disk"], "load": [round(fixture["cpu"] / 25, 2), 1.3, 1.1],
                        "cpu_count": 4, "uptime_seconds": 1209600, "swap_percent": 12 if scenario == "capacity" else 0,
                        "disk_free_bytes": int(100 * 1024**3 * (1 - fixture["disk"] / 100)),
                        "memory_total_bytes": 8 * 1024**3, "disk_total_bytes": 100 * 1024**3, "source": "simulated"},
            "services": [{"name": "nginx", "state": "active", "source": "simulated"},
                         {"name": "mysql", "state": "failed" if database_issue else "active", "source": "simulated"},
                         {"name": "queue-worker", "state": "failed" if queue_issue else "active", "source": "simulated"},
                         {"name": "cron", "state": "active", "source": "simulated"}],
            "processes": [{"pid": 2101, "name": "php-fpm", "memory_bytes": 320 * 1024**2, "source": "simulated"},
                          {"pid": 810, "name": "mysqld", "memory_bytes": 1400 * 1024**2, "source": "simulated"}],
            "ports": [{"port": 443, "protocol": "tcp", "state": "listening", "source": "simulated"},
                      {"port": 22, "protocol": "tcp", "state": "listening", "source": "simulated"}],
            "sites": [{"domains": ["example.com", "shop.example.com"], "web_server": "nginx",
                       "document_root": "/srv/example/public", "configuration_complete": True,
                       "access_logs": ["/var/log/nginx/example.access.log"], "error_logs": ["/var/log/nginx/example.error.log"],
                       "status": "unknown", "status_reason": "Demo configuration; no live reachability check.",
                       "source": "simulated", "traffic": {"available": True, "request_count": 420,
                       "error_count": 12 if attack else 2, "server_error_count": 1, "source": "simulated"},
                       "resource_attribution": {"reason": "Discovery and observations only; no per-site resource enforcement."}}],
            "events": events,
            "application": {"framework": "laravel", "queue_backlog": 842 if queue_issue else 7,
                            "queue_workers": 0 if queue_issue else 4,
                            "scheduler_last_run": scheduler_last, "scheduler_locked": queue_issue and not state.get("scheduler_ran"),
                            "scheduler_running": False,
                            "scheduler_registered": True, "database_healthy": not database_issue,
                            "failed_jobs": 23 if queue_issue else 0, "source": "simulated"},
            "traffic": {"requests_per_minute": fixture["requests"], "baseline_requests_per_minute": fixture["baseline"],
                        "authenticated_ratio": .04 if attack else .82, "top_ip_ratio": .87 if attack else .07,
                        "sensitive_probes": 180 if attack else 0,
                        "http_5xx_ratio": .37 if database_issue else .12 if attack else .004,
                        "source": "simulated"},
        }

    def execute(self, action: str, parameters: dict, request_id: str) -> dict:
        if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
            return failure("Action is not registered")
        if not isinstance(parameters, dict) or set(parameters) - {"target"}:
            return failure("Only a registered target parameter is accepted")
        target = parameters.get("target", DEFAULT_TARGETS[action])
        if target != DEFAULT_TARGETS[action]:
            return failure("Target is not registered for this demo action")

        def perform():
            started = time.monotonic()
            if action == "scheduler.run" and self.collect()["application"]["scheduler_locked"]:
                result = failure("Simulated scheduler is locked; no overlapping run started", status="locked",
                                 details={"target": target, "simulated": True})
                result["simulated"] = True
                return result
            changes = {"last_action": action, "last_action_at": utc_now()}
            if action == "scheduler.run":
                changes.update(scheduler_last_run=utc_now(), scheduler_ran=True)
            elif action == "queue.restart":
                changes["queue_restarted"] = True
            elif action in {"job.run", "job.retry"}:
                changes["last_job_run"] = utc_now()
            with self._connect() as db:
                for key, value in changes.items():
                    db.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, json.dumps(value)))
            checked = self._state()
            verified = all(checked.get(key) == value for key, value in changes.items())
            return {"status": "succeeded" if verified else "failed", "simulated": True,
                    "summary": f"Simulated {action} on {target}; local fixture updated",
                    "duration_seconds": round(time.monotonic() - started, 4),
                    "verification": {"verified": verified, "status": "passed" if verified else "failed", "simulated": True,
                                     "evidence": "Read back project-local simulated state"},
                    "details": {"target": target, "simulated": True, "changed_keys": sorted(changes)}}
        return self.guard.run(action, target, request_id, perform)


class LinuxAgent:
    def __init__(self, root: Path, plugins=(), commands=(), enable_actions=False, disk_path=Path("/"), blackbox=None):
        from .collectors import LinuxCollector
        if enable_actions or commands:
            raise ValueError("The Community Linux agent is read-only; use DemoAgent for action demonstrations")
        self.collector = LinuxCollector(disk_path=disk_path)
        self.blackbox = blackbox
        self.plugins = tuple(plugins)
        if any(plugin.registered_commands() for plugin in self.plugins):
            raise ValueError("Community collectors must not register mutating actions")

    def collect(self):
        snapshot = self.collector.collect()
        for plugin in self.plugins:
            try:
                evidence = plugin.collect()
                for key, value in evidence.items():
                    if isinstance(snapshot.get(key), list) and isinstance(value, list):
                        snapshot[key].extend(value)
                    elif isinstance(snapshot.get(key), dict) and isinstance(value, dict):
                        snapshot[key].update(value)
                    else:
                        snapshot[key] = value
            except Exception:
                snapshot["evidence"][plugin.name] = {"available": False, "reason": "Configured plugin probe failed"}
        if self.blackbox:
            try:
                snapshot["forensic_events"] = self.blackbox.collect()
                snapshot["evidence"]["black_box"] = {"available": True, "scope": "Bounded sampled events; no completeness or source-host trust claim"}
            except Exception:
                snapshot["evidence"]["black_box"] = {"available": False, "reason": "Agent evidence collector interrupted"}
        else:
            snapshot["evidence"]["black_box"] = {"available": False, "reason": "Black Box collector not configured"}
        return snapshot

    def acknowledge(self, sequence):
        if self.blackbox and sequence is not None:
            self.blackbox.ack(sequence)

    def execute(self, action, parameters, request_id):
        return failure("The Community Linux agent is read-only", status="rejected")
