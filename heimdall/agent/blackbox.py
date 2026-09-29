"""Read-only, bounded Linux event observations with private Agent outbox.

Sampling is not complete audit coverage. The first scan establishes an
unverified local baseline; no historical activity is invented.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from .runtime import utc_now
from .security import FileIntegrity


AUTH_USER = re.compile(r"\bfor (?:invalid user )?([A-Za-z0-9_.@-]{1,64})\b")
AUTH_IP = re.compile(r"\bfrom ([0-9a-fA-F:.]+)\b")


def auth_event(line):
    lower = line.lower()
    if "sshd" in lower and ("accepted publickey" in lower or "accepted password" in lower):
        kind = "ssh_success"
    elif "sshd" in lower and ("failed password" in lower or "invalid user" in lower):
        kind = "ssh_failure"
    elif "sudo:" in lower or " su:" in lower:
        kind = "privilege_activity"
    else:
        return None
    details = {}
    user = AUTH_USER.search(line)
    if user:
        details["user"] = user.group(1)
    address = AUTH_IP.search(line)
    if address:
        try:
            details["source_address"] = str(ipaddress.ip_address(address.group(1)))
        except ValueError:
            pass
    return kind, details


def process_identity(proc, pid):
    path = proc / str(pid)
    try:
        raw = (path / "stat").read_text(errors="replace")[:16384]
        fields = raw.rsplit(")", 1)[1].split()
        start_ticks = int(fields[19])
        uid = path.stat().st_uid
        exe = os.readlink(path / "exe")[:256]
        if not exe.startswith("/"):
            return None
        name = raw.split("(", 1)[1].rsplit(")", 1)[0].replace("\n", " ").replace("\r", " ")[:80]
        info = {"pid": pid, "ppid": int(fields[1]), "uid": uid, "process": name, "executable": exe}
        try:
            with (path / "cmdline").open("rb") as stream:
                command = stream.read(4097)
            if len(command) <= 4096:
                info["argv_count"] = max(0, command.count(b"\x00") - 1)
        except OSError:
            pass
        return str(pid) + ":" + str(start_ticks), info
    except (OSError, ValueError, IndexError):
        return None


def established_connections(proc):
    """Observe IPv4 TCP endpoints; ownership is deliberately unavailable."""
    rows = {}
    try:
        for line in (proc / "net/tcp").read_text().splitlines()[1:4097]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "01":
                continue
            def endpoint(value):
                address, port = value.split(":")
                return str(ipaddress.IPv4Address(bytes.fromhex(address)[::-1])), int(port, 16)
            source, source_port = endpoint(fields[1])
            destination, destination_port = endpoint(fields[2])
            key = f"{source}:{source_port}>{destination}:{destination_port}"
            rows[key] = {"source_address": source, "source_port": source_port,
                         "destination_address": destination, "destination_port": destination_port, "protocol": "tcp"}
            if len(rows) >= 100:
                break
        return rows, True
    except (OSError, ValueError, IndexError):
        return {}, False


class BlackBoxCollector:
    def __init__(self, root: Path, *, auth_log=None, integrity_files=(), proc_root=Path("/proc"), configuration_hash=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Black Box state directory must be owner-only")
        self.path = self.root / "blackbox-outbox.json"
        self.auth_log = Path(auth_log) if auth_log else None
        self.proc = Path(proc_root)
        self.files = FileIntegrity([Path(p) for p in integrity_files], self.root / "blackbox-reference.json", max_file_bytes=1024 * 1024)
        if self.path.exists():
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError("Black Box state must be an owner-only regular file")
            self.state = json.loads(self.path.read_text())
        else:
            self.state = {"sequence": 0, "pending": [], "auth_offset": None, "files": None,
                          "processes": None, "connections": None, "collector_status": {}, "auth_identity": None}
        self.state.setdefault("collector_status", {})
        if configuration_hash:
            old_hash = self.state.get("configuration_hash")
            if old_hash and old_hash != configuration_hash:
                self._event("agent_configuration_changed", "agent", {"sha256": configuration_hash,
                            "reason": "Configured Black Box collection scope changed; operator intent is unknown"})
            self.state["configuration_hash"] = configuration_hash
        try:
            boot_id = (self.proc / "sys/kernel/random/boot_id").read_text().strip()
            if re.fullmatch(r"[0-9a-f-]{36}", boot_id):
                old_boot = self.state.get("boot_id")
                if old_boot and old_boot != boot_id:
                    self._event("agent_restarted", "agent", {"reason": "Host boot identifier changed; cause unknown"})
                self.state["boot_id"] = boot_id
        except OSError:
            pass

    def _save(self):
        descriptor, temporary = tempfile.mkstemp(prefix=".blackbox-", dir=self.root)
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(self.state, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _event(self, kind, source, details=None):
        self.state["sequence"] += 1
        now = utc_now()
        self.state["pending"].append({"sequence": self.state["sequence"], "observed_at": now,
                                      "collected_at": now, "event_type": kind, "source": source,
                                      "details": details or {}})
        # If offline long enough, old receipts are unavailable; the server
        # detects the resulting sequence gap when contact resumes.
        self.state["pending"] = self.state["pending"][-1000:]

    def _collector_failure(self, name, reason):
        if self.state["collector_status"].get(name) is not False:
            self._event("collector_interrupted", name, {"collector": name, "reason": reason})
        self.state["collector_status"][name] = False

    def _collector_ok(self, name):
        if self.state["collector_status"].get(name) is False:
            self._event("collector_resumed", name, {"collector": name})
        self.state["collector_status"][name] = True

    def _auth(self):
        if not self.auth_log:
            return
        try:
            descriptor = os.open(self.auth_log, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError()
                identity = [metadata.st_dev, metadata.st_ino]
                prior_identity = self.state.get("auth_identity")
                self.state["auth_identity"] = identity
                offset = self.state["auth_offset"]
                if offset is None:
                    self.state["auth_offset"] = metadata.st_size
                    self._collector_ok("auth_log")
                    return
                if offset > metadata.st_size or (prior_identity and prior_identity != identity):
                    self.state["auth_offset"] = metadata.st_size
                    self._collector_failure("auth_log", "Authentication log rotated or truncated; intervening events unavailable")
                    return
                stream.seek(offset)
                raw = stream.read(262145)
                self.state["auth_offset"] = stream.tell()
            if len(raw) > 262144:
                self._collector_failure("auth_log", "Log interval exceeded 256 KiB; events may be missing")
                self.state["auth_offset"] = metadata.st_size
                return
            else:
                self._collector_ok("auth_log")
            for line in raw.decode("utf-8", "replace").splitlines()[:1000]:
                parsed = auth_event(line)
                if parsed:
                    self._event(parsed[0], "auth_log", parsed[1])
        except OSError:
            self._collector_failure("auth_log", "Configured authentication log unavailable")

    def _files(self):
        if not self.files.paths:
            return
        current = self.files.snapshot()
        if any(not entry.get("available") for entry in current.values()):
            self._collector_failure("file_integrity", "One or more configured integrity files unavailable")
        else:
            self._collector_ok("file_integrity")
        previous = self.state["files"]
        if previous is not None:
            for path, entry in current.items():
                prior = previous.get(path)
                if not prior:
                    continue
                if prior.get("available") and not entry.get("available"):
                    self._event("file_deleted" if entry.get("missing") else "file_unavailable", "file_integrity",
                                {"path": path, "reason": entry.get("reason", "File unavailable")})
                    if entry.get("missing") and ("/cron" in path or "/systemd/" in path or path.endswith("/authorized_keys") or path in {"/etc/passwd", "/etc/shadow"}):
                        self._event("persistence_changed", "file_integrity", {"path": path, "change": "Configured persistence-sensitive file missing"})
                elif not prior.get("available") and entry.get("available"):
                    self._event("file_created" if prior.get("missing") else "file_available", "file_integrity",
                                {"path": path, "sha256": entry.get("sha256", "")})
                elif entry.get("available") and prior.get("available"):
                    metadata_changed = any(entry.get(k) != prior.get(k) for k in ("mode", "uid", "gid"))
                    content_changed = entry.get("sha256") != prior.get("sha256")
                    if content_changed:
                        self._event("file_modified", "file_integrity", {"path": path, "sha256": entry["sha256"]})
                    if metadata_changed:
                        self._event("file_metadata_changed", "file_integrity", {"path": path, "mode": entry.get("mode", ""), "owner": entry.get("uid", 0)})
                    if (content_changed or metadata_changed) and ("/cron" in path or "/systemd/" in path or path.endswith("/authorized_keys") or path in {"/etc/passwd", "/etc/shadow"}):
                        self._event("persistence_changed", "file_integrity", {"path": path, "change": "Configured persistence-sensitive file changed"})
        self.state["files"] = current

    def _processes(self):
        try:
            pids = sorted((int(p.name) for p in self.proc.iterdir() if p.name.isdigit()))[:256]
            current = dict(row for pid in pids if (row := process_identity(self.proc, pid)))
        except OSError:
            self._collector_failure("processes", "Process table unavailable")
            return
        if pids and not current:
            self._collector_failure("processes", "No sampled process metadata readable")
        else:
            self._collector_ok("processes")
        previous = self.state["processes"]
        if previous is not None:
            for identity, info in current.items():
                if identity not in previous:
                    self._event("process_started", "proc", info)
        self.state["processes"] = current

    def _network(self):
        current, available = established_connections(self.proc)
        if not available:
            self._collector_failure("network", "TCP connection table unavailable")
            return
        self._collector_ok("network")
        previous = self.state["connections"]
        if previous is not None:
            for identity, info in current.items():
                if identity not in previous:
                    self._event("network_connection", "proc_net", info)
        self.state["connections"] = current

    def collect(self):
        self._auth()
        self._files()
        self._processes()
        self._network()
        self._event("heartbeat", "agent")
        self._save()
        return self.state["pending"][:100]

    def ack(self, sequence):
        self.state["pending"] = [row for row in self.state["pending"] if row["sequence"] > sequence]
        self._save()
