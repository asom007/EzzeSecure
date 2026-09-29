"""Small, explicit execution boundary; no command strings cross this API."""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from pathlib import Path
import fcntl
import hashlib
import os
import re
import selectors
import signal
import sqlite3
import stat
import subprocess
import time
from typing import Callable

ALLOWED_ACTIONS = frozenset({"scheduler.run", "queue.restart", "job.run", "job.retry",
                             "cache.clear", "service.restart", "health.check"})
DEFAULT_TARGETS = {"scheduler.run": "laravel", "queue.restart": "laravel",
                   "job.run": "demo-job", "job.retry": "demo-job", "cache.clear": "laravel",
                   "service.restart": "web", "health.check": "application"}


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in sorted((x for x in secrets if x), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r'''(?i)(["'](?:password|passwd|secret|token|api[_-]?key)["']\s*:\s*)(["'])(.*?)(\2)''',
                  r'\1\2[REDACTED]\2', text)
    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;]+",
                  r"\1[REDACTED]", text)
    return text


@dataclass(frozen=True)
class RegisteredCommand:
    action: str
    target: str
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float = 30
    max_output_bytes: int = 32768
    verification: tuple[str, ...] | None = None
    secrets: tuple[str, ...] = field(default=(), repr=False)
    preflight: tuple[str, ...] | None = None
    shared_lock: Path | None = None

    def __post_init__(self):
        if self.action not in ALLOWED_ACTIONS or not self.target or len(self.target) > 100:
            raise ValueError("Unsupported action or target")
        for argv in (self.argv, self.verification, self.preflight):
            if argv is not None and (not argv or not Path(argv[0]).is_absolute()
                                     or any(not isinstance(arg, str) or "\0" in arg for arg in argv)):
                raise ValueError("Registered argv requires an absolute executable and literal arguments")
        if not Path(self.cwd).is_absolute():
            raise ValueError("Registered working directory must be absolute")
        if self.shared_lock is not None and not Path(self.shared_lock).is_absolute():
            raise ValueError("Shared lock path must be absolute")
        if not 0 < self.timeout_seconds <= 300 or not 256 <= self.max_output_bytes <= 1048576:
            raise ValueError("Command limits out of range")


class RequestGuard:
    """Durable at-most-once reservation, and cross-process per-target advisory lock.

    A crash after reservation deliberately requires a new, reviewed request ID. We
    never replay a possibly completed side effect after losing its result.
    """
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = self.root / "executions.sqlite3"
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL)")
        self.database.chmod(0o600)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def run(self, action: str, target: str, request_id: str, callback: Callable[[], dict]) -> dict:
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 200:
            return failure("A bounded request ID is required")
        fingerprint = hashlib.sha256(f"{action}\n{target}".encode()).hexdigest()
        with self._connect() as db:
            try:
                db.execute("INSERT INTO requests VALUES (?, ?, 'reserved', ?)", (request_id, fingerprint, time.time()))
            except sqlite3.IntegrityError:
                old = db.execute("SELECT fingerprint,status FROM requests WHERE id=?", (request_id,)).fetchone()
                return failure("Request ID already used; execution was not repeated", status="duplicate",
                               details={"previous_status": old[1], "same_request": old[0] == fingerprint})
        lock_path = self.root / ("target-" + hashlib.sha256(target.encode()).hexdigest() + ".lock")
        with lock_path.open("a") as lock:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                result = failure("Target has another running action", status="locked")
            else:
                try:
                    result = callback()
                except Exception:
                    result = failure("Registered action failed internally; inspect local agent diagnostics")
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
        with self._connect() as db:
            db.execute("UPDATE requests SET status=? WHERE id=?", (result["status"], request_id))
        return result


def failure(summary: str, status: str = "failed", details: dict | None = None) -> dict:
    return {"status": status, "summary": summary, "duration_seconds": 0,
            "verification": {"verified": False, "status": "not_verified"}, "details": details or {}}


def run_argv(argv: tuple[str, ...], cwd: Path, timeout: float, limit: int, secrets=(), redact_output=True) -> dict:
    """Read both pipes incrementally; kill the entire process group on any limit."""
    started = time.monotonic()
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, start_new_session=True)
    except OSError as exc:
        return {"exit_code": None, "output": redact(str(exc), secrets), "stdout": "", "stderr": redact(str(exc), secrets), "timed_out": False,
                "output_limited": False, "duration_seconds": time.monotonic() - started}
    selector = selectors.DefaultSelector()
    for pipe in (process.stdout, process.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    output = bytearray()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    timed_out = limited = False
    try:
        while selector.get_map():
            if time.monotonic() - started >= timeout:
                timed_out = True
                break
            for key, _ in selector.select(min(.1, max(0, timeout - (time.monotonic() - started)))):
                chunk = os.read(key.fd, min(4096, limit + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                streams[key.fileobj].extend(chunk)
                if len(output) > limit:
                    limited = True
                    break
            if limited:
                break
        if timed_out or limited:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=max(.1, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    def decoded(value):
        value = value[:limit].decode("utf-8", "replace")
        return redact(value, secrets) if redact_output else value
    return {"exit_code": process.returncode, "output": decoded(output),
            "stdout": decoded(streams[process.stdout]), "stderr": decoded(streams[process.stderr]),
            "timed_out": timed_out, "output_limited": limited,
            "duration_seconds": round(time.monotonic() - started, 4)}


class RegisteredExecutor:
    def __init__(self, root: Path, commands: list[RegisteredCommand]):
        self.guard = RequestGuard(root)
        self.commands = {(c.action, c.target): c for c in commands}
        if len(self.commands) != len(commands):
            raise ValueError("Duplicate action target registration")

    def execute(self, action: str, parameters: dict, request_id: str) -> dict:
        if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
            return failure("Action is not registered")
        if not isinstance(parameters, dict) or set(parameters) - {"target"}:
            return failure("Only a registered target parameter is accepted")
        target = parameters.get("target", DEFAULT_TARGETS.get(action))
        if not isinstance(target, str) or (action, target) not in self.commands:
            return failure("Action and target are not registered")
        command = self.commands[(action, target)]

        def perform():
            preflight = None
            if command.preflight:
                preflight = run_argv(command.preflight, command.cwd, command.timeout_seconds,
                                     command.max_output_bytes, command.secrets)
                ready = preflight["exit_code"] == 0 and not preflight["timed_out"] and not preflight["output_limited"]
                if not ready:
                    result = failure("Registered readiness preflight failed; action was not started",
                                     details={"preflight": preflight, "executed": False})
                    result["duration_seconds"] = preflight["duration_seconds"]
                    return result
            details = run_argv(command.argv, command.cwd, command.timeout_seconds,
                               command.max_output_bytes, command.secrets)
            succeeded = details["exit_code"] == 0 and not details["timed_out"] and not details["output_limited"]
            verification = {"verified": False, "status": "unavailable", "reason": "No verification command registered"}
            status = "unknown" if succeeded else "failed"
            summary = "completed with exit code zero; outcome remains unverified" if succeeded else "failed"
            if succeeded and command.verification:
                check = run_argv(command.verification, command.cwd, command.timeout_seconds,
                                 command.max_output_bytes, command.secrets)
                verified = check["exit_code"] == 0 and not check["timed_out"] and not check["output_limited"]
                verification = {"verified": verified, "status": "passed" if verified else "failed", "details": check}
                status = "succeeded" if verified else "failed"
                summary = "completed and verification passed" if verified else "completed but verification failed"
            details["executed"] = True
            if preflight:
                details["preflight"] = preflight
            return {"status": status,
                    "summary": f"Registered {action} on {target} {summary}",
                    "duration_seconds": details["duration_seconds"] + verification.get("details", {}).get("duration_seconds", 0) + (preflight or {}).get("duration_seconds", 0),
                    "verification": verification, "details": details}

        def guarded_perform():
            if action == "scheduler.run" and (command.preflight is None or command.shared_lock is None):
                return failure("Scheduler readiness preflight and shared overlap lock must both be registered; action was not started",
                               details={"executed": False})
            if command.shared_lock is None:
                return perform()
            try:
                descriptor = os.open(command.shared_lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), 0o600)
                lock = os.fdopen(descriptor, "a")
            except OSError:
                return failure("Shared overlap lock is unavailable; action was not started", details={"executed": False})
            with lock:
                if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                    return failure("Shared overlap lock is not a regular file; action was not started", details={"executed": False})
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return failure("Shared scheduler/application overlap lock is held; action was not started", status="locked", details={"executed": False})
                except OSError:
                    return failure("Shared overlap lock is unavailable; action was not started", details={"executed": False})
                try:
                    return perform()
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
        return self.guard.run(action, target, request_id, guarded_perform)
