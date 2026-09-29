"""Bounded, conservative interpretation of agent observations for the console."""
from __future__ import annotations

from copy import deepcopy
import re


def _domains(row):
    names = row.get("domains") if isinstance(row.get("domains"), list) else []
    return tuple(sorted({name.strip().lower().rstrip(".") for name in names
                         if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9*_.-]{1,253}", name.strip())}))


def _site_key(row):
    # A path or collector-generated ID is evidence provenance, not vhost identity.
    # A known listener or root prevents equal hostnames on separate vhosts merging.
    return (str(row.get("web_server") or "").lower(), _domains(row),
            str(row.get("listener") or row.get("listen") or ""),
            str(row.get("document_root") or ""))


def normalize_sites(rows):
    """Collapse repeated observations without combining different listeners or roots."""
    if not isinstance(rows, list):
        return []
    groups = {}
    for row in rows[:100]:
        if not isinstance(row, dict):
            continue
        key = _site_key(row)
        # Nameless declarations require their source identity to avoid collisions.
        if not key[1]:
            key += (str(row.get("config_path") or row.get("id") or len(groups)),)
        groups.setdefault(key, []).append(row)
    result = []
    for key in sorted(groups):
        evidence = groups[key]
        # Stable winner, independent of incoming collector order.
        winner = max(evidence, key=lambda row: (bool(row.get("configuration_complete")),
                       bool(row.get("traffic", {}).get("available")) if isinstance(row.get("traffic"), dict) else False,
                       str(row.get("config_path") or ""), str(row.get("id") or "")))
        site = deepcopy(winner)
        site["domains"] = list(key[1])
        site["configuration_complete"] = all(row.get("configuration_complete") is True for row in evidence)
        site["limitations"] = sorted({str(item) for row in evidence
                                       for item in (row.get("limitations") if isinstance(row.get("limitations"), list) else [])
                                       if isinstance(item, str)})
        traffic = [row.get("traffic") for row in evidence if isinstance(row.get("traffic"), dict)
                   and row["traffic"].get("available") is True]
        counts = {tuple(value if type(value) in (int, float, str, type(None)) else None
                        for value in (item.get("request_count"), item.get("error_count"), item.get("server_error_count")))
                  for item in traffic}
        if len(counts) > 1:
            site["traffic"] = {"available": False, "reason": "Conflicting log observations; site traffic attribution is not established"}
        result.append(site)
    return result


def normalize_snapshot(snapshot):
    """Normalize both new ingestion and older stored snapshots at read time."""
    if not isinstance(snapshot, dict):
        return snapshot
    result = deepcopy(snapshot)
    result["sites"] = normalize_sites(result.get("sites"))
    app = result.get("application")
    if isinstance(app, dict):
        aliases = {"database_healthy": (("database", "sql_healthy"), ("database", "healthy")),
                   "database_latency_ms": (("database", "latency_ms"),),
                   "queue_driver": (("queue", "driver"),),
                   "queue_backlog": (("queue", "backlog"),),
                   "queue_workers": (("queue", "workers"),),
                   "scheduler_last_run": (("scheduler", "last_run"),),
                   "scheduler_interval_seconds": (("scheduler", "expected_interval_seconds"),),
                   "failed_jobs_count": (("failed_jobs", "count"), ("failed_jobs_metadata", "count")),
                   "http_status": (("http_probe", "status_code"), ("http", "status_code")),
                   "http_latency_ms": (("http_probe", "latency_ms"), ("http", "latency_ms"))}
        for target, paths in aliases.items():
            if app.get(target) is not None:
                continue
            for parent, key in paths:
                nested = app.get(parent)
                if isinstance(nested, dict) and nested.get(key) is not None:
                    app[target] = nested[key]
                    break
        if str(app.get("queue_driver") or "").lower() == "sync":
            # A reported zero is not an asynchronous backlog measurement.
            app["queue_backlog"] = None
            app["queue_workers"] = None
    traffic = result.get("traffic")
    if isinstance(traffic, dict):
        responses = traffic.get("responses")
        if isinstance(responses, dict):
            for status in ("2xx", "3xx", "4xx", "5xx"):
                if traffic.get("http_" + status) is None and type(responses.get(status)) is int and responses[status] >= 0:
                    traffic["http_" + status] = responses[status]
    return result


def supplied_baseline(snapshot, kind):
    """Use only bounded, explicit agent baseline counts when no local baseline exists."""
    if not isinstance(snapshot, dict):
        return None
    evidence = snapshot.get("evidence")
    candidates = [snapshot.get(kind[:-1] + "_baseline"),
                  snapshot.get("baselines", {}).get(kind) if isinstance(snapshot.get("baselines"), dict) else None,
                  evidence.get(kind) if isinstance(evidence, dict) else None]
    for item in candidates:
        if not isinstance(item, dict):
            continue
        expected = item.get("expected")
        if type(expected) is not int or not 0 <= expected <= 100:
            continue
        result = {"expected": expected, "source": "agent"}
        for field in ("new", "removed", "changed"):
            value = item.get(field)
            if isinstance(value, list):
                safe = []
                for entry in value[:100]:
                    if kind == "ports":
                        port = entry.get("port") if isinstance(entry, dict) else entry
                        protocol = entry.get("protocol", "tcp") if isinstance(entry, dict) else "tcp"
                        if isinstance(port, int) and 1 <= port <= 65535 and protocol in {"tcp", "udp"}:
                            safe.append((protocol, str(port)))
                    else:
                        name = entry.get("name") if isinstance(entry, dict) else entry
                        if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.@:-]{1,80}", name):
                            safe.append(name)
                result[field] = safe
            elif type(value) is int and 0 <= value <= 100:
                result[field] = value
        return result
    return None


def baseline_summary(current, expected, kind):
    """Compare observed inventory with an explicitly established baseline."""
    if not isinstance(current, list) or not isinstance(expected, list):
        return None
    def identity(row):
        if not isinstance(row, dict):
            return None
        if kind == "ports":
            port = row.get("port")
            protocol = str(row.get("protocol") or "tcp").lower()
            return (protocol, str(port)) if protocol in {"tcp", "udp"} and str(port).isdigit() and 1 <= int(port) <= 65535 else None
        name = row.get("name")
        return str(name).lower() if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.@:-]{1,80}", name) else None
    observed = {identity(row): row for row in current if identity(row) is not None}
    reference = {identity(row): row for row in expected if identity(row) is not None}
    new = sorted(observed.keys() - reference.keys())
    removed = sorted(reference.keys() - observed.keys())
    fields = ("bind_scope", "state") if kind == "ports" else ("state",)
    changed = sorted(key for key in observed.keys() & reference.keys()
                     if any(observed[key].get(field) is not None and reference[key].get(field) is not None
                            and observed[key].get(field) != reference[key].get(field) for field in fields))
    active = sum(str(row.get("state") or row.get("status") or "").lower() in
                 {"active", "running", "listening"} for row in observed.values())
    return {"expected": len(reference), "observed": len(observed), "active": active,
            "new": new, "removed": removed, "changed": changed}
