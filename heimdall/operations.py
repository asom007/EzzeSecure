"""Durable, state-based Community resource alerts and incident timelines."""
from __future__ import annotations

import json
import math
import time
import uuid
from datetime import datetime, timezone

from .security import dumps, redact


BANDS = ("WARNING", "ELEVATED", "HIGH", "CRITICAL", "SEVERE", "EMERGENCY")
DEFAULT_POLICY = {"start_threshold": 70, "escalation_step": 5,
                  "recovery_threshold": 60, "minimum_duration_seconds": 120}
RESOURCES = {"cpu": "cpu_percent", "ram": "ram_percent", "disk": "disk_percent", "load": "load"}


def stamp(at):
    return datetime.fromtimestamp(at, timezone.utc).isoformat()


def validate_policy(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT_POLICY):
        raise ValueError("Resource policy requires start, step, recovery and minimum duration")
    start, step, recovery, duration = (value[key] for key in DEFAULT_POLICY)
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (start, step, recovery, duration)):
        raise ValueError("Resource policy values must be finite numbers")
    if not (0 < recovery < start <= 100 and 0 < step <= 20 and start + step * 5 <= 100 and 0 <= duration <= 86400):
        raise ValueError("Resource policy thresholds or duration are out of range")
    return dict(value)


def band(value, policy):
    if value < policy["start_threshold"]:
        return None
    index = min(5, int((value - policy["start_threshold"]) // policy["escalation_step"]))
    return BANDS[index]


def measured_resources(metrics):
    result = {}
    for resource, key in RESOURCES.items():
        value = metrics.get(key)
        if resource == "load":
            cores = metrics.get("cpu_count")
            value = value[0] / cores * 100 if isinstance(value, list) and value and type(value[0]) in (int, float) and type(cores) is int and cores > 0 else None
        upper = 10000 if resource == "load" else 100
        if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= upper:
            result[resource] = round(value, 2)
    return result


def explanation(resource, snapshot, severity):
    """Use only measured/explicit evidence; CPU ticks are not CPU utilization."""
    facts = []
    if BANDS.index(severity) >= BANDS.index("HIGH"):
        metrics = snapshot.get("metrics", {})
        load = metrics.get("load")
        if isinstance(load, list) and load and type(load[0]) in (int, float):
            facts.append(f"One-minute load: {load[0]:.2f}.")
        processes = snapshot.get("processes")
        if resource == "ram" and isinstance(processes, list):
            measured = [p for p in processes if isinstance(p, dict) and isinstance(p.get("name"), str)
                        and type(p.get("memory_bytes")) is int]
            if measured:
                leader = max(measured, key=lambda p: p["memory_bytes"])
                facts.append(f"Largest observed process by resident memory: {leader['name'][:80]} ({leader['memory_bytes']} bytes).")
        elif resource == "cpu":
            facts.append("Per-process CPU contribution unavailable from this snapshot.")
        facts.append("Associated service/site: unavailable without reliable attribution.")
    return " ".join(facts)


class ResourceEngine:
    def __init__(self, store):
        self.store = store

    def policy(self, org, server, resource):
        row = self.store.one("SELECT data FROM resource_policies WHERE org_id=? AND server_id IN (?, '*') AND resource IN (?, '*') ORDER BY (server_id=?) DESC,(resource=?) DESC LIMIT 1",
                             (org, server, resource, server, resource))
        return json.loads(row["data"]) if row else dict(DEFAULT_POLICY)

    def configure(self, org, server, resource, value):
        if resource not in (*RESOURCES, "*") or not isinstance(server, str):
            raise ValueError("Unknown resource or server")
        value = validate_policy(value)
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO resource_policies VALUES(?,?,?,?)", (org, server, resource, dumps(value)))
        return value

    def observe(self, org, server, snapshot, *, now=None):
        now = time.time() if now is None else now
        transitions = []
        for resource, value in measured_resources(snapshot.get("metrics", {})).items():
            policy = self.policy(org, server, resource)
            current_band = band(value, policy)
            with self.store.tx() as db:
                previous = db.execute("SELECT state FROM resource_alerts WHERE org_id=? AND server_id=? AND resource=?",
                                      (org, server, resource)).fetchone()
                state = json.loads(previous["state"]) if previous else {"status": "normal"}
                old_band = state.get("band")
                if state["status"] == "normal":
                    if current_band:
                        state = {"status": "pending", "started_at": now, "peak": value, "current": value, "band": current_band}
                elif state["status"] == "pending":
                    if not current_band:
                        state = {"status": "normal"}
                    else:
                        state.update(current=value, peak=max(state["peak"], value), band=current_band)
                elif value <= policy["recovery_threshold"]:
                    transition = self._transition(db, org, server, resource, state, "RECOVERED", value, snapshot, now, policy)
                    transitions.append(transition)
                    state = {"status": "normal"}
                else:
                    state.update(current=value, peak=max(state["peak"], value))
                    # Falling within an active incident is silent. A later climb is a new escalation.
                    state["band"] = current_band
                    if current_band and (old_band is None or BANDS.index(current_band) > BANDS.index(old_band)):
                        transitions.append(self._transition(db, org, server, resource, state, current_band, value, snapshot, now, policy))
                if state["status"] == "pending" and now - state["started_at"] >= policy["minimum_duration_seconds"]:
                    state["status"] = "open"
                    transitions.append(self._transition(db, org, server, resource, state, state["band"], value, snapshot, now, policy))
                db.execute("INSERT OR REPLACE INTO resource_alerts VALUES(?,?,?,?)", (org, server, resource, dumps(state)))
        return transitions

    @staticmethod
    def _transition(db, org, server, resource, state, severity, value, snapshot, now, policy):
        incident_id = state.get("incident_id") or uuid.uuid4().hex
        state["incident_id"] = incident_id
        key = "resource:" + resource + ":" + incident_id
        started = state["started_at"]
        duration = max(0, now - started)
        threshold = (policy["recovery_threshold"] if severity == "RECOVERED" else
                     policy["start_threshold"] + policy["escalation_step"] * BANDS.index(severity))
        detail = explanation(resource, snapshot, severity) if severity in BANDS else ""
        summary = (f"{resource.upper()} recovered to {value:.1f}% (recovery threshold {threshold:.1f}%) after {duration:.0f} seconds."
                   if severity == "RECOVERED" else
                   f"{resource.upper()} {severity.lower()} at {value:.1f}%; threshold {threshold:.1f}%; peak {state['peak']:.1f}%; duration {duration:.0f} seconds. {detail}")
        data = {"category": "resource", "resource": resource, "current_value": value, "peak_value": state["peak"],
                "threshold_value": threshold,
                "duration_seconds": duration, "first_observed": stamp(started), "last_observed": stamp(now),
                "affected_resources": [resource], "probable_explanation": detail or "Cause not established from available evidence.",
                "confidence": "Low", "recommendations": ["Review measured resource history and related service health."],
                "evidence_gaps": [] if detail else ["No reliable process, service or site attribution."],
                "recovery": stamp(now) if severity == "RECOVERED" else None, "assessment": summary}
        status = "resolved" if severity == "RECOVERED" else "open"
        db.execute("INSERT INTO incidents(id,org_id,server_id,correlation_key,severity,title,status,count,first_seen,last_seen,last_notified,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,status=excluded.status,count=incidents.count+1,last_seen=excluded.last_seen,last_notified=excluded.last_notified,data=excluded.data",
                   (incident_id, org, server, key, severity, resource.upper() + " resource pressure", status,
                    1, stamp(started), stamp(now), now, dumps(data)))
        db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,NULL,?)",
                   (incident_id, org, server, stamp(now), "recovery" if severity == "RECOVERED" else "resource_escalation", summary, "High"))
        return {"incident_id": incident_id, "server_id": server, "resource": resource, "severity": severity,
                "summary": summary, "duration_seconds": duration, "current_value": value, "peak_value": state["peak"],
                "threshold_value": threshold}
