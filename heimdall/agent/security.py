"""Bounded log summaries and explicit file-integrity baselines (no file contents)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import ipaddress
import json
import os
import re
import stat

from .runtime import utc_now


def log_tail(path: Path, max_bytes: int = 262144) -> dict:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("Log is not a regular file")
            size = metadata.st_size
            offset = max(0, size - max_bytes)
            stream.seek(offset)
            data = stream.read(max_bytes)
            if offset:
                data = data.partition(b"\n")[2]
        return {"available": True, "text": data.decode("utf-8", "replace"), "truncated": offset > 0,
                "bytes_read": len(data)}
    except OSError:
        return {"available": False, "text": "", "reason": "Configured log missing or not readable"}


def parse_auth_log(text: str) -> dict:
    counts = Counter()
    sources = Counter()
    for line in text.splitlines()[:10000]:
        lower = line.lower()
        kind = None
        if "failed password" in lower or "authentication failure" in lower or "invalid user" in lower:
            kind = "authentication_failed"
        elif "accepted password" in lower or "accepted publickey" in lower:
            kind = "authentication_succeeded"
        elif "sudo:" in lower and "command=" in lower:
            kind = "privileged_command"
        if kind:
            counts[kind] += 1
            match = re.search(r"(?:from|rhost=)\s*([0-9a-fA-F:.]+)", line)
            if match:
                try:
                    sources[str(ipaddress.ip_address(match[1]))] += 1
                except ValueError:
                    pass
        if kind == "authentication_succeeded" and re.search(r"\bfor root\b", lower):
            counts["root_login"] += 1
        if ("useradd" in lower and "new user:" in lower) or ("adduser" in lower and "adding user" in lower):
            counts["user_created"] += 1
        group_change = (("groupadd" in lower and "new group:" in lower)
                        or (any(tool in lower for tool in ("usermod", "gpasswd")) and "group" in lower
                            and any(verb in lower for verb in ("add", "remove", "delete"))))
        if group_change:
            counts["group_changed"] += 1
            if re.search(r"\b(?:sudo|wheel|admin)\b", lower):
                counts["privilege_changed"] += 1
        elif "usermod" in lower and re.search(r"\bchange user.*\buid[=: ]+0\b", lower):
            counts["privilege_changed"] += 1
    return {"available": True, "counts": dict(counts), "top_sources": sources.most_common(10),
            "scope": "Counts in supplied log tail; no time-window or full-history claim"}


ACCESS = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ ]+) [^"]+" (\d{3}) ')


def parse_access_log(text: str, now: datetime | None = None, window_seconds: int = 60) -> dict:
    if not 1 <= window_seconds <= 3600:
        raise ValueError("Log observation window must be between 1 and 3600 seconds")
    now = now or datetime.now(timezone.utc)
    ips = Counter()
    errors = probes = parsed = in_window = 0
    for line in text.splitlines()[:10000]:
        match = ACCESS.match(line)
        if not match:
            continue
        ip, stamp, method, target, status = match.groups()
        try:
            stamp = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        parsed += 1
        if not 0 <= (now - stamp).total_seconds() < window_seconds:
            continue
        in_window += 1
        ips[ip] += 1
        errors += int(int(status) >= 500)
        path = target.split("?", 1)[0].lower()
        probes += int(any(part in path for part in ("/.env", "/.git", "/wp-admin", "/wp-login", "/phpmyadmin")))
    return {"available": parsed > 0, "requests_per_minute": round(in_window * 60 / window_seconds, 2) if parsed else None,
            "http_5xx_ratio": errors / in_window if in_window else None,
            "top_ip_ratio": ips.most_common(1)[0][1] / in_window if in_window else None,
            "sensitive_probes": probes if parsed else None, "authenticated_ratio": None,
            "baseline_requests_per_minute": None, "sample_size": in_window, "parsed_lines": parsed,
            "reason": "Common/combined log tail only; completeness, identity and historical baseline unavailable"}


class FileIntegrity:
    def __init__(self, paths: list[Path], baseline_path: Path, max_file_bytes: int = 16 * 1024 * 1024):
        self.paths = [Path(p).absolute() for p in paths]
        self.baseline_path = Path(baseline_path)
        self.max_file_bytes = max_file_bytes

    def scan_php_indicators(self) -> dict:
        """Heuristic inspection of explicit PHP paths only; never return source."""
        candidates = [path for path in self.paths if path.suffix.lower() == ".php"]
        indicators, unavailable, checked = [], [], 0
        patterns = {
            "eval_base64_decode": re.compile(rb"\beval\s*\(\s*base64_decode\s*\(", re.IGNORECASE),
            "request_input_to_shell": re.compile(rb"\b(?:shell_exec|system|passthru)\s*\([^;\n]{0,512}\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", re.IGNORECASE),
        }
        for path in candidates[:100]:
            directory = None
            try:
                # Walk directories with openat + O_NOFOLLOW, so symlinked parent
                # directories are not followed either. Never traverse recursively.
                directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
                for component in path.parts[1:-1]:
                    next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = next_directory
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(descriptor, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_size > 262144:
                        raise OSError("Not regular or over scan limit")
                    data = stream.read(262145)
                    after = os.fstat(stream.fileno())
                if len(data) > 262144 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise OSError("File changed during scan")
                checked += 1
                matched = [name for name, pattern in patterns.items() if pattern.search(data)]
                if matched:
                    indicators.append({"path": str(path), "rules": matched, "heuristic": True,
                                       "assessment": "Pattern match only; not proof of a web shell or malicious intent"})
            except OSError:
                unavailable.append({"path": str(path), "reason": "Missing, inaccessible, symlinked, changing, nonregular or larger than 256 KiB"})
            finally:
                if directory is not None:
                    os.close(directory)
        return {"indicators": indicators, "evidence": {"checked_files": checked, "unavailable": unavailable,
                "truncated": len(candidates) > 100, "scope": "At most 100 explicitly configured PHP files, 256 KiB each; no recursion or symlinks",
                "limitation": "Simple source patterns may match comments/legitimate code and miss obfuscation; absence is not proof of safety"}}

    def snapshot(self) -> dict:
        result = {}
        for path in self.paths:
            entry = {"path": str(path), "available": False, "sha256": None}
            try:
                metadata = path.lstat()
                entry.update(size=metadata.st_size, mode=oct(stat.S_IMODE(metadata.st_mode)),
                             uid=metadata.st_uid, gid=metadata.st_gid, mtime_ns=metadata.st_mtime_ns,
                             device=metadata.st_dev, inode=metadata.st_ino)
                if not stat.S_ISREG(metadata.st_mode):
                    entry["reason"] = "Not a regular file; symlinks are not followed"
                elif metadata.st_size > self.max_file_bytes:
                    entry["reason"] = "File exceeds configured hash size limit"
                else:
                    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                    with os.fdopen(descriptor, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
                            raise OSError("File changed before hash")
                        digest = hashlib.sha256()
                        remaining = self.max_file_bytes + 1
                        while remaining:
                            chunk = stream.read(min(65536, remaining))
                            if not chunk:
                                break
                            remaining -= len(chunk)
                            digest.update(chunk)
                        after = os.fstat(stream.fileno())
                    current = path.lstat()
                    if remaining == 0 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
                        entry["reason"] = "File changed while hashing; retry collection"
                    else:
                        entry.update(available=True, sha256=digest.hexdigest())
            except FileNotFoundError:
                entry["reason"] = "File missing"
                entry["missing"] = True
            except OSError:
                entry["reason"] = "File missing, changed or inaccessible"
            result[str(path)] = entry
        return result

    def create_baseline(self) -> dict:
        if self.baseline_path.exists():
            raise FileExistsError("Baseline exists; explicit review and removal required to replace it")
        snapshot = {"created_at": utc_now(), "files": self.snapshot()}
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.baseline_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(snapshot, stream, indent=2)
        return snapshot

    def compare(self) -> dict:
        current = self.snapshot()
        try:
            baseline = json.loads(self.baseline_path.read_text())["files"]
        except (OSError, ValueError, KeyError):
            return {"available": False, "reason": "No readable baseline; explicit baseline creation required", "files": current}
        changes = []
        for path, entry in current.items():
            previous = baseline.get(path)
            if not entry["available"]:
                changes.append({"path": path, "kind": "unavailable", "reason": entry.get("reason")})
            elif previous is None or not previous.get("available"):
                changes.append({"path": path, "kind": "unbaselined"})
            else:
                changed = [field for field in ("sha256", "mode", "uid", "gid", "size", "mtime_ns") if entry[field] != previous.get(field)]
                if changed:
                    changes.append({"path": path, "kind": "changed", "fields": changed})
        return {"available": True, "changes": changes, "files": current, "checked_at": utc_now()}
