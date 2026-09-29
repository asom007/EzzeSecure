"""Bounded, read-only virtual-host declarations; never a live health assertion."""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from hashlib import sha256
from itertools import islice
from pathlib import Path
import os
import re
import shlex
import stat

MAX_FILES = 32
MAX_BYTES = 131072
MAX_SITES = 100
MAX_LOGS = 16
MAX_LOG_BYTES = 65536
DOMAIN = re.compile(r"(?:\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}\*?\Z")
ACCESS = re.compile(r'^\S+ \S+ \S+ \[[^\]\r\n]{1,80}\] "[^"\r\n]{1,8192}" ([1-5][0-9]{2}) (?:[0-9]+|-)(?: |$)')


@contextmanager
def _open(path: Path, directory=False):
    """Open only an explicit absolute path, refusing symlinks in every component."""
    parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    try:
        for component in path.parts[1:-1]:
            next_parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(path.name or path.anchor, flags | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        if not directory and not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("Not regular")
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _literal_path(value):
    if (isinstance(value, str) and value.startswith("/") and len(value) <= 1024
            and not any(c in value for c in "$*?{}|\n\r\x00") and all(ord(c) >= 32 for c in value)):
        return os.path.normpath(value)
    return None


def _nginx(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";{}")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    tokens = list(islice(lexer, 16385))
    if len(tokens) > 16384:
        raise ValueError("Token limit")
    root = {"name": "", "args": [], "directives": [], "children": []}
    stack, pending = [root], []
    # shlex combines adjacent punctuation; split only punctuation tokens.
    for token in (part for t in tokens for part in (list(t) if t and set(t) <= set(";{}") else [t])):
        if token == "{":
            if not pending or len(stack) >= 32:
                raise ValueError("Invalid block")
            node = {"name": pending[0], "args": pending[1:], "directives": [], "children": []}
            stack[-1]["children"].append(node)
            stack.append(node)
            pending = []
        elif token == "}":
            if pending or len(stack) == 1:
                raise ValueError("Invalid close")
            stack.pop()
        elif token == ";":
            if pending:
                stack[-1]["directives"].append(pending)
            pending = []
        else:
            pending.append(token)
    if pending or len(stack) != 1:
        raise ValueError("Incomplete config")
    found = []
    def walk(node, ancestors):
        if node["name"] == "server" and not node["args"] and all(a["name"] in ("", "http") for a in ancestors):
            inherited = any(d[0] in ("include", "root", "access_log", "error_log") for a in ancestors for d in a["directives"])
            found.append((node["directives"], bool(node["children"]) or inherited))
        for child in node["children"]:
            walk(child, ancestors + [node])
    walk(root, [])
    return found


def _apache(text):
    found, stack, current, incomplete = [], [], None, False
    unresolved_global = False
    for line in text.splitlines():
        if len(line) > 8192 or line.rstrip().endswith("\\"):
            raise ValueError("Unsupported continuation")
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("<"):
            if not line.endswith(">"):
                raise ValueError("Invalid section")
            parts = shlex.split(line[1:-1], comments=True)
            if not parts:
                raise ValueError("Empty section")
            name = parts[0].lower()
            if name.startswith("/"):
                if not stack or stack[-1] != name[1:]:
                    raise ValueError("Invalid section close")
                stack.pop()
                if name == "/virtualhost":
                    found.append((current, incomplete))
                    current = None
            else:
                if name == "virtualhost":
                    if current is not None:
                        raise ValueError("Nested vhost")
                    current, incomplete = [], bool(stack)
                elif current is not None:
                    incomplete = True
                if len(stack) >= 32:
                    raise ValueError("Section nesting limit")
                stack.append(name)
        else:
            parts = shlex.split(line, comments=True)
            if parts and current is not None and stack[-1] == "virtualhost":
                current.append([parts[0].lower(), *parts[1:]])
            elif parts and current is None and parts[0].lower() in ("include", "includeoptional", "use", "define"):
                unresolved_global = True
    if stack:
        raise ValueError("Incomplete section")
    return [(directives, partial or unresolved_global) for directives, partial in found]


class SitesPlugin:
    name = "sites"

    def __init__(self, nginx_paths=(), apache_paths=(), log_paths=()):
        self.paths = []
        for server, paths in (("nginx", nginx_paths), ("apache", apache_paths)):
            if not isinstance(paths, (list, tuple)) or len(paths) > MAX_FILES:
                raise ValueError("At most 32 explicit paths per web server")
            for path in paths:
                literal = _literal_path(str(path))
                if literal is None:
                    raise ValueError("Absolute literal site paths required")
                self.paths.append((server, Path(literal)))
        if not isinstance(log_paths, (list, tuple)) or len(log_paths) > MAX_LOGS:
            raise ValueError("At most 16 explicit log files")
        self.logs = set()
        for path in log_paths:
            literal = _literal_path(str(path))
            if literal is None:
                raise ValueError("Absolute literal log paths required")
            self.logs.add(literal)

    def registered_commands(self):
        return []

    def _row(self, server, path, index, directives, incomplete):
        names, roots, access, errors, formats = [], [], [], [], []
        limitations = []
        logging_disabled = False
        for directive in directives:
            key, args = directive[0], directive[1:]
            if key in ("server_name", "servername", "serveralias"):
                for value in args:
                    if DOMAIN.fullmatch(value):
                        names.append(value)
                    else:
                        limitations.append("Unsupported domain expression omitted")
            elif key in ("root", "documentroot", "access_log", "customlog", "transferlog", "error_log", "errorlog"):
                if key == "access_log" and args == ["off"]:
                    logging_disabled = True
                    continue
                value = _literal_path(args[0]) if args else None
                if value is None:
                    limitations.append("Nonliteral or unsupported path omitted")
                    continue
                if key in ("root", "documentroot"):
                    roots.append(value)
                elif key in ("access_log", "customlog", "transferlog"):
                    access.append(value)
                    formats.append((key == "access_log" and (len(args) == 1 or args[1] == "combined"))
                                   or (key == "customlog" and len(args) == 2 and args[1] in ("combined", "common"))
                                   or key == "transferlog")
                else:
                    errors.append(value)
            elif key in ("include", "includeoptional", "use", "define"):
                limitations.append("Includes, macros and variables are not expanded")
        if logging_disabled:
            access, formats = [], []
        if len(names) > 32 or len(set(access)) > 8 or len(set(errors)) > 8:
            limitations.append("Site metadata exceeded bounded field limits")
        if incomplete:
            limitations.append("Nested, conditional or inherited configuration is not resolved")
        if len(set(roots)) > 1:
            limitations.append("Multiple document roots are ambiguous")
        if not names:
            limitations.append("Domain names unavailable")
        if not roots:
            limitations.append("Document root unavailable; proxy or inherited roots are not inferred")
        return {"id": sha256(f"{server}:{path}:{index}".encode()).hexdigest()[:20],
                "domains": list(dict.fromkeys(names))[:32], "document_root": roots[0] if len(set(roots)) == 1 else None,
                "web_server": server, "access_logs": list(dict.fromkeys(access))[:8],
                "error_logs": list(dict.fromkeys(errors))[:8], "status": "unknown",
                "status_reason": "Configured declaration only; loaded configuration and HTTP health not probed",
                "source": "configured_vhost", "config_path": str(path),
                "configuration_complete": not limitations, "limitations": list(dict.fromkeys(limitations)),
                "resource_attribution": {"available": False, "reason": "Host metrics are not attributable to individual virtual hosts"},
                "_log_format_supported": bool(formats) and all(formats)}

    def collect(self):
        rows, files, failures, seen = [], [], [], set()
        truncated = False
        for server, path in self.paths:
            try:
                # A configured directory is scanned once, never recursively.
                with _open(path, directory=True) as descriptor:
                    with os.scandir(descriptor) as entries:
                        candidates = list(islice(entries, MAX_FILES + 1))
                    truncated |= len(candidates) > MAX_FILES
                    candidates = sorted((path / e.name for e in candidates[:MAX_FILES] if e.name.endswith(".conf")), key=str)
            except OSError:
                candidates = [path]
            for candidate in candidates:
                if (server, str(candidate)) in seen:
                    continue
                seen.add((server, str(candidate)))
                if len(seen) > MAX_FILES:
                    truncated = True
                    break
                try:
                    with _open(candidate) as descriptor:
                        data = os.read(descriptor, MAX_BYTES + 1)
                    if len(data) > MAX_BYTES:
                        truncated = True
                        raise ValueError("Config too large")
                    definitions = (_nginx if server == "nginx" else _apache)(data.decode("utf-8"))
                    files.append(str(candidate))
                    for index, (directives, incomplete) in enumerate(definitions):
                        if len(rows) >= MAX_SITES:
                            truncated = True
                            break
                        rows.append(self._row(server, candidate, index, directives, incomplete))
                except (OSError, ValueError, UnicodeError):
                    failures.append({"path": str(candidate), "reason": "Missing, denied, symlinked, nonregular, oversized or unsupported configuration"})
        usage = Counter(log for row in rows for log in row["access_logs"])
        identities = {}
        for path in self.logs:
            try:
                with _open(Path(path)) as descriptor:
                    metadata = os.fstat(descriptor)
                    identities[path] = (metadata.st_dev, metadata.st_ino)
            except OSError:
                pass
        identity_usage = Counter(identities[log] for row in rows for log in row["access_logs"] if log in identities)
        for log, identity in identities.items():
            usage[log] = max(usage[log], identity_usage[identity])
        for row in rows:
            row["traffic"] = self._traffic(row, usage, truncated or bool(failures))
            del row["_log_format_supported"]
        return {"sites": rows, "evidence": {"sites": {"available": bool(files), "files_read": len(files),
                "sites_found": len(rows), "truncated": truncated, "unavailable": failures[:MAX_FILES],
                "reason": None if files else "No readable supported virtual-host configuration",
                "scope": "Configured files only; includes not followed; declarations do not prove sites are enabled or healthy"}}}

    def _traffic(self, row, usage, discovery_partial):
        result = {"available": False, "request_count": None, "error_count": None, "server_error_count": None,
                  "recent_failures": [], "scope": "bounded_log_tail", "truncated": False,
                  "reason": "No supported, explicitly allowed access log unique among discovered hosts",
                  "attribution": "Configured log association only; undiscovered writers and hosts cannot be excluded"}
        paths = row["access_logs"]
        if discovery_partial or not row["configuration_complete"]:
            result["reason"] = "Incomplete configuration discovery; log attribution unavailable"
            return result
        if (not paths or not row["_log_format_supported"] or any(p not in self.logs or usage[p] > 1 for p in paths)):
            return result
        statuses = Counter()
        skipped = 0
        for path in paths:
            try:
                with _open(Path(path)) as descriptor:
                    size = os.fstat(descriptor).st_size
                    offset = max(0, size - MAX_LOG_BYTES)
                    os.lseek(descriptor, offset, os.SEEK_SET)
                    raw = os.read(descriptor, MAX_LOG_BYTES)
                if offset:
                    raw = raw.partition(b"\n")[2]
                    result["truncated"] = True
                # Only complete lines; no raw request, address or error text escapes.
                lines = raw.split(b"\n")[:-1]
                if len(lines) > 1000:
                    result["truncated"] = True
                for line in lines[-1000:]:
                    match = ACCESS.match(line.decode("utf-8", "replace"))
                    if match:
                        statuses[int(match[1])] += 1
                    else:
                        skipped += 1
            except OSError:
                result["reason"] = "Configured access log is missing, denied, symlinked or nonregular"
                return result
        if not statuses:
            result["reason"] = "No supported common/combined records in bounded log tail"
            return result
        result.update(available=True, request_count=sum(statuses.values()), error_count=sum(v for k, v in statuses.items() if k >= 400),
                      server_error_count=sum(v for k, v in statuses.items() if k >= 500),
                      recent_failures=[{"status": k, "count": v} for k, v in sorted(statuses.items()) if k >= 400],
                      skipped_lines=skipped,
                      reason="Matched common/combined records in configured log tail; no time window, rate or full-history claim")
        return result
