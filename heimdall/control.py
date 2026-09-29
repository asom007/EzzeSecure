"""Local control plane: authorization, evidence, incidents and approval lifecycle."""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .security import digest, dumps, password_hash, password_matches, redact, signature, utcnow
from .store import Store, decode_rows
from .policy import ACTIONS, validate_action
from .notifications import LocalNotificationChannel, alert_message
from .trust_abuse import TrustAbuse
from .reputation_scanner import ReputationScanner
from .notification_delivery import NotificationDispatcher, NotificationError
from .enrollment import EnrollmentMixin
from .intelligence.settings import AISettings
from .intelligence.providers import ProviderError
from .normalization import normalize_snapshot, baseline_summary, supplied_baseline
from .operations import ResourceEngine, RESOURCES, measured_resources
from .forensics import EvidenceLedger, validate_event
from .email_delivery import EmailDispatcher
from .ezzesend_link import EzzeSendLink


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def uid():
    return uuid.uuid4().hex


class ControlPlane(EnrollmentMixin):
    def __init__(self, root: Path, *, password: str | None = None, state_dir: Path | None = None):
        self.root = root.resolve()
        self.local = state_dir.resolve() if state_dir else self.root / ".local"
        self.local.mkdir(exist_ok=True, parents=True, mode=0o700)
        os.chmod(self.local, 0o700)
        config_path = self.local / "config.json"
        self.initial_password = None
        from .configuration import local_overrides, deployment_settings
        overrides = local_overrides(self.root)
        if config_path.exists():
            self.config = json.loads(config_path.read_text())
            # Runtime deployment settings may change; persisted identities and
            # organization settings must not be silently replaced on restart.
            self.config.update({key: overrides[key] for key in (
                "mode", "control_plane_url", "demo_enabled", "debug", "port") if key in overrides})
        else:
            example = self.root / "config/local.example.json"
            self.config = json.loads(example.read_text()) if example.exists() else {
                "organization": "Local Operations", "username": "admin", "owner_phone": "", "daily_brief_hour_utc": 6}
            self.config.update(overrides)
            deployment_settings(self.config)
            self.config["session_key"] = secrets.token_hex(32)
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as file:
                json.dump(self.config, file, indent=2)
        os.chmod(config_path, 0o600)
        self.production = deployment_settings(self.config)
        self.demo_enabled = not self.production and self.config.get("demo_enabled", True)
        self.store = Store(self.local / "heimdall.sqlite3")
        if not self.demo_enabled and self.store.one("SELECT id FROM servers WHERE environment='simulated' LIMIT 1"):
            raise ValueError("Demo-disabled mode requires separate, demo-free state")
        self.ai = AISettings(self.store, self.local)
        self.channel = LocalNotificationChannel()
        self.trust_abuse = TrustAbuse(self.store)
        self.reputation_scanner = ReputationScanner()
        self.notifications = NotificationDispatcher(self.store, self.local, control_plane_url=self.config.get("control_plane_url"))
        self.resources = ResourceEngine(self.store)
        self.ledger = EvidenceLedger(self.store)
        self.email = EmailDispatcher(self.store)
        self.ezzesend_link = EzzeSendLink(self.store, self.notifications)
        from .agent.runtime import DemoAgent
        self.agent = DemoAgent(self.local / "demo-agent") if self.demo_enabled else None
        if not self.store.one("SELECT id FROM users LIMIT 1"):
            self.initial_password = password or secrets.token_urlsafe(20)
            with self.store.tx() as db:
                db.execute("INSERT INTO organizations VALUES(?,?)", ("local", self.config["organization"]))
                db.execute("INSERT INTO users VALUES(?,?,?,?,?)", ("owner", "local", self.config["username"], password_hash(self.initial_password), "owner"))
                if self.demo_enabled:
                    db.execute("INSERT INTO identities VALUES(?,?,?,?,?,1)", ("owner-whatsapp", "owner", "local", "whatsapp", self.config["owner_phone"]))
                    db.execute("INSERT INTO servers VALUES(?,?,?,?,?,?)", ("local-demo", "local", "EzzeSecure Demo", "simulated", "online", utcnow()))
        self.login_limits = {}
        with self.store.tx() as db:
            # Only migrate the old built-in fixture name, preserving user-created names.
            db.execute("UPDATE servers SET name='EzzeSecure Demo' WHERE id='local-demo' AND name=?", ("Heimdall Demo",))
            for action in ACTIONS.values() if self.demo_enabled else ():
                db.execute("INSERT OR IGNORE INTO registrations VALUES(?,?,?)", ("local-demo", action.name, action.target))
        if self.demo_enabled and not self.snapshot("local-demo", "local"):
            self.collect()

    def login(self, username, password, remote):
        # A per-client limiter also covers nonexistent users; bounded by loopback-only service.
        now = time.time()
        with self.store.lock:
            times = [t for t in self.login_limits.get(remote, []) if t > now - 300]
            if len(times) >= 10:
                raise APIError(429, "Too many login attempts; try again in five minutes")
            times.append(now)
            self.login_limits[remote] = times
        user = self.store.one("SELECT * FROM users WHERE username=?", (username,))
        encoded = user["password_hash"] if user else password_hash("not-a-real-password")
        if not password_matches(password, encoded) or not user:
            self.store.audit(request="login", result="denied")
            raise APIError(401, "Invalid username or password")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.tx() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (now,))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (digest(token), user["id"], csrf, now + 8 * 3600))
        self.store.audit(org_id=user["org_id"], actor=user["id"], request="login", result="authenticated")
        return token, {"csrf_token": csrf, "demo_enabled": self.demo_enabled, "user": {k: user[k] for k in ("id", "username", "org_id", "role")}}

    def session(self, token):
        user = self.store.one("SELECT u.id,u.org_id,u.username,u.role,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?", (digest(token), time.time()))
        if not user:
            raise APIError(401, "Sign in to EzzeSecure")
        return user

    def server(self, server_id, org_id):
        row = self.store.one("SELECT * FROM servers WHERE id=? AND org_id=?", (server_id, org_id))
        if not row:
            raise APIError(404, "Server not found")
        return row

    def snapshot(self, server_id, org_id):
        row = self.store.one("SELECT data FROM snapshots WHERE server_id=? AND org_id=? ORDER BY id DESC LIMIT 1", (server_id, org_id))
        return normalize_snapshot(json.loads(row["data"])) if row else None

    def history(self, server_id, org_id):
        rows = self.store.rows("SELECT data FROM snapshots WHERE server_id=? AND org_id=? ORDER BY id DESC LIMIT 10000", (server_id, org_id))
        return [json.loads(r["data"]) for r in reversed(rows)]

    def collect(self):
        if not self.demo_enabled:
            raise APIError(403, "Demo collection is disabled")
        snapshot = self.agent.collect()
        return self.ingest("local-demo", "local", snapshot)

    def ingest(self, server_id, org_id, snapshot, agent_id=None):
        from .intelligence.engine import analyze
        self.server(server_id, org_id)
        self.validate_snapshot(snapshot)
        if server_id != "local-demo" and (snapshot.get("demo") or snapshot.get("simulated")):
            raise APIError(400, "Simulated telemetry belongs to the demo server, not a real monitored identity")
        forensic_batch = snapshot.get("forensic_events", [])
        if forensic_batch:
            if not agent_id or not isinstance(forensic_batch, list) or len(forensic_batch) > 100:
                raise APIError(400, "Authenticated Agent and bounded forensic batch required")
            try:
                for event in forensic_batch:
                    validate_event(event)
                gaps = self.ledger.ingest(org_id, server_id, agent_id, forensic_batch)
            except ValueError as exc:
                raise APIError(400, str(exc)) from None
            for missing_from, missing_through in gaps:
                self.evidence_gap(org_id, server_id, agent_id, missing_from, missing_through)
            self.correlate_forensic(org_id, server_id, agent_id, forensic_batch)
        snapshot = normalize_snapshot(redact({k: v for k, v in snapshot.items() if k != "forensic_events"}))
        black_box_state = snapshot.get("evidence", {}).get("black_box") if isinstance(snapshot.get("evidence"), dict) else None
        if isinstance(black_box_state, dict) and black_box_state.get("available") is False and server_id != "local-demo":
            previously_streamed = bool(agent_id and self.store.one("SELECT 1 FROM evidence_streams WHERE org_id=? AND server_id=? AND agent_id=?", (org_id, server_id, agent_id)))
            if previously_streamed or black_box_state.get("reason") != "Black Box collector not configured":
                self.collector_gap(org_id, server_id)
        elif isinstance(black_box_state, dict) and black_box_state.get("available") is True:
            self.resolve_collector_gap(org_id, server_id)
        from .observation import security_events
        baseline = self.store.one("SELECT value FROM settings WHERE key=?", ("baseline:" + server_id,))
        extra = security_events(snapshot, json.loads(baseline["value"]) if baseline else None)
        snapshot["events"] = [*snapshot.get("events", []), *extra][:100]
        # Receipt time is authoritative. Agent time remains evidence, not retention/ordering authority.
        snapshot["received_at"] = utcnow()
        snapshot.setdefault("observed_at", snapshot["received_at"])
        history = self.history(server_id, org_id)
        analysis = analyze(snapshot, history)
        with self.store.tx() as db:
            db.execute("INSERT INTO snapshots(org_id,server_id,created_at,data) VALUES(?,?,?,?)", (org_id, server_id, utcnow(), dumps(snapshot)))
            db.execute("UPDATE servers SET last_seen=?,status='online' WHERE id=? AND org_id=?", (utcnow(), server_id, org_id))
            db.execute("INSERT INTO analyses VALUES(?,?,?,?,?)", (uid(), org_id, server_id, utcnow(), dumps(analysis)))
            db.execute("INSERT INTO usage(org_id,created_at,provider,input_tokens,output_tokens,calls) VALUES(?,?,?,0,0,0)", (org_id, utcnow(), "deterministic"))
            # Bounded local storage; sufficient for 30 days at the default five-minute interval.
            db.execute("DELETE FROM snapshots WHERE server_id=? AND id NOT IN (SELECT id FROM snapshots WHERE server_id=? ORDER BY id DESC LIMIT 10000)", (server_id, server_id))
        for transition in self.resources.observe(org_id, server_id, snapshot):
            self.resource_transition(org_id, server_id, transition)
        self.correlate(server_id, org_id, snapshot, analysis)
        snapshot["forensic_accepted_through"] = forensic_batch[-1]["sequence"] if forensic_batch else None
        return snapshot

    def evidence_gap(self, org_id, server_id, agent_id, missing_from, missing_through):
        summary = f"Agent evidence sequence {missing_from}–{missing_through} was not received. Events in that interval are unavailable."
        now = utcnow()
        key = "evidence_gap:" + agent_id
        with self.store.tx() as db:
            prior = db.execute("SELECT id,count,first_seen FROM incidents WHERE org_id=? AND server_id=? AND correlation_key=?", (org_id, server_id, key)).fetchone()
            incident_id = prior["id"] if prior else uid()
            data = {"category": "security", "assessment": summary, "confidence": "High", "evidence_gaps": [summary],
                    "probable_explanation": "Cause not established.", "recommendations": ["Check Agent connectivity and local outbox."],
                    "affected_resources": ["Agent evidence stream"]}
            db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,server_id,correlation_key) DO UPDATE SET last_seen=excluded.last_seen,count=incidents.count+1,status='open',data=excluded.data",
                       (incident_id, org_id, server_id, key, "HIGH", "Evidence stream gap", "open", (prior["count"]+1 if prior else 1), prior["first_seen"] if prior else now, now, time.time(), dumps(data)))
            db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,NULL,?)",
                       (incident_id, org_id, server_id, now, "evidence_gap", summary, "High"))
        version = (self.notifications.row(org_id) or {}).get("contract_version", 1)
        self.notifications.enqueue(org_id, self.server(server_id, org_id), "evidence_gap" if version == 2 else "security_incident", "HIGH", f"{agent_id}:{missing_from}:{missing_through}", correlation=key)
        self.email.enqueue(org_id, server_id, "security", "HIGH", f"{agent_id}:{missing_from}:{missing_through}",
                           "Agent evidence sequence gap detected. Missing events are unavailable; cause unknown.")

    def collector_gap(self, org_id, server_id):
        key = "blackbox_collector"
        stamp = utcnow()
        summary = "Agent reported Black Box collector interruption. Security evidence for this interval is unavailable."
        with self.store.tx() as db:
            prior = db.execute("SELECT * FROM incidents WHERE org_id=? AND server_id=? AND correlation_key=?", (org_id, server_id, key)).fetchone()
            if prior and prior["status"] == "open":
                return
            incident_id = prior["id"] if prior else uid()
            data = {"category": "security", "assessment": summary, "confidence": "High for interruption; unknown cause",
                    "evidence_gaps": ["Black Box collector did not supply events."],
                    "probable_explanation": "Cause not established.", "recommendations": ["Inspect private Agent diagnostics and configured read permissions."],
                    "affected_resources": ["Agent evidence stream"]}
            db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,server_id,correlation_key) DO UPDATE SET status='open',last_seen=excluded.last_seen,count=incidents.count+1,data=excluded.data",
                       (incident_id, org_id, server_id, key, "HIGH", "Black Box collector interrupted", "open", 1,
                        prior["first_seen"] if prior else stamp, stamp, time.time(), dumps(data)))
            db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,NULL,?)",
                       (incident_id, org_id, server_id, stamp, "collector_interrupted", summary, "High for interruption"))
        self.notifications.enqueue(org_id, self.server(server_id, org_id), "integrity_finding", "HIGH", incident_id + ":interrupted")
        self.email.enqueue(org_id, server_id, "security", "HIGH", incident_id + ":interrupted", summary)

    def resolve_collector_gap(self, org_id, server_id):
        with self.store.tx() as db:
            prior = db.execute("SELECT id FROM incidents WHERE org_id=? AND server_id=? AND correlation_key='blackbox_collector' AND status='open'", (org_id, server_id)).fetchone()
            if prior:
                stamp = utcnow()
                db.execute("UPDATE incidents SET status='resolved',last_seen=? WHERE id=?", (stamp, prior["id"]))
                db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,NULL,?)",
                           (prior["id"], org_id, server_id, stamp, "collector_resumed", "Agent reports Black Box collection resumed. The earlier gap remains unavailable.", "High for reported resumption"))

    def correlate_forensic(self, org_id, server_id, agent_id, batch):
        important = {"ssh_failure", "privilege_activity", "file_created", "file_available", "file_modified", "file_deleted", "file_unavailable",
                     "file_metadata_changed", "persistence_changed", "agent_interrupted", "agent_configuration_changed", "collector_interrupted"}
        follow_up = {"ssh_success", "process_started", "network_connection"}
        for event in batch:
            kind = event["event_type"]
            if kind not in important | follow_up:
                continue
            receipt = self.store.one("SELECT id,received_at FROM forensic_events WHERE org_id=? AND server_id=? AND agent_id=? AND sequence=?",
                                     (org_id, server_id, agent_id, event["sequence"]))
            if not receipt:
                continue
            summary = kind.replace("_", " ").capitalize() + " observed. Cause and relationship to other events are not established."
            with self.store.tx() as db:
                if db.execute("SELECT id FROM incident_timeline WHERE evidence_id=?", (receipt["id"],)).fetchone():
                    continue
                key = "forensic:investigation"
                prior = db.execute("SELECT * FROM incidents WHERE org_id=? AND server_id=? AND correlation_key=?", (org_id, server_id, key)).fetchone()
                if kind in follow_up:
                    if not prior or prior["status"] != "open":
                        continue
                    try:
                        if (datetime.fromisoformat(receipt["received_at"]) - datetime.fromisoformat(prior["last_seen"])).total_seconds() > 900:
                            continue
                    except ValueError:
                        continue
                incident_id = prior["id"] if prior else uid()
                severity = "HIGH" if kind in {"file_modified", "file_deleted", "persistence_changed", "agent_interrupted"} else "WARNING"
                if prior and prior["severity"] == "HIGH":
                    severity = "HIGH"
                data = {"category": "security", "assessment": summary, "confidence": "Low",
                        "probable_explanation": "Not established from isolated evidence.",
                        "recommendations": ["Review the ordered evidence and verify on the monitored host."],
                        "evidence_gaps": ["Sampled collectors are not a complete host audit trail."],
                        "affected_resources": ["Authentication, process or integrity evidence"]}
                db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,server_id,correlation_key) DO UPDATE SET severity=excluded.severity,status='open',last_seen=excluded.last_seen,count=incidents.count+1,data=excluded.data",
                           (incident_id, org_id, server_id, key, severity, "Security investigation", "open",
                            1, receipt["received_at"], receipt["received_at"], time.time(), dumps(data)))
                db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,?,?)",
                           (incident_id, org_id, server_id, receipt["received_at"], kind, summary, receipt["id"], "Low"))
            if kind in important:
                self.notifications.enqueue(org_id, self.server(server_id, org_id), "security_incident", "HIGH", f"{agent_id}:{event['sequence']}", correlation=kind)
                self.email.enqueue(org_id, server_id, "security", severity, f"{agent_id}:{event['sequence']}",
                                   kind.replace("_", " ").capitalize() + " observed. Review the forensic timeline; cause unknown.")

    def resource_transition(self, org_id, server_id, transition):
        severity = transition["severity"]
        level = "INFO" if severity == "RECOVERED" else "MEDIUM" if severity in {"WARNING", "ELEVATED"} else "HIGH" if severity == "HIGH" else "CRITICAL"
        stamp = utcnow()
        with self.store.tx() as db:
            db.execute("INSERT INTO notifications VALUES(?,?,?,?,?,?,?,?,?)", (uid(), org_id, server_id, stamp, severity,
                       "local", "recorded", transition["summary"], transition["incident_id"]))
        if server_id != "local-demo":
            summary = (f"{transition['resource'].upper()} recovered to {transition['current_value']:.1f}% (recovery threshold {transition['threshold_value']:.1f}%) after {transition['duration_seconds']:.0f} seconds."
                       if severity == "RECOVERED" else
                       f"{transition['resource'].upper()} reached {transition['current_value']:.1f}% ({severity}); threshold {transition['threshold_value']:.1f}%, peak {transition['peak_value']:.1f}%, duration {transition['duration_seconds']:.0f} seconds.")
            self.email.enqueue(org_id, server_id, "recovery" if severity == "RECOVERED" else "resource", severity if severity != "RECOVERED" else "INFO",
                               transition["incident_id"] + ":" + severity + ":" + stamp, summary)
            version = (self.notifications.row(org_id) or {}).get("contract_version", 1)
            if severity != "RECOVERED" or version == 2:
                kind = "resource_recovery" if severity == "RECOVERED" else "resource_escalation" if version == 2 else "resource_pressure"
                self.notifications.enqueue(org_id, self.server(server_id, org_id), kind,
                                           level, transition["incident_id"] + ":" + severity + ":" + stamp,
                                           correlation=transition["resource"], detail=summary, transition=True)

    def resource_policies(self, org_id, server_id):
        self.server(server_id, org_id)
        return {resource: self.resources.policy(org_id, server_id, resource) for resource in RESOURCES}

    def save_resource_policy(self, user, server_id, resource, value):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        self.server(server_id, user["org_id"])
        try:
            saved = self.resources.configure(user["org_id"], server_id, resource, value)
        except ValueError as exc:
            raise APIError(400, str(exc)) from None
        self.store.audit(org_id=user["org_id"], server_id=server_id, actor=user["id"], request="resource_policy", result="saved")
        return {"resource": resource, "policy": saved}

    @staticmethod
    def validate_snapshot(snapshot):
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("metrics"), dict):
            raise APIError(400, "Telemetry requires structured metrics")
        for field in ("events", "services", "processes", "ports", "sites"):
            if field in snapshot and (not isinstance(snapshot[field], list) or len(snapshot[field]) > 100):
                raise APIError(400, "Invalid telemetry collection")
            if field in ("events", "services", "processes", "sites") and any(not isinstance(x, dict) for x in snapshot.get(field, [])):
                raise APIError(400, "Invalid telemetry record")
        if "forensic_events" in snapshot and (not isinstance(snapshot["forensic_events"], list) or len(snapshot["forensic_events"]) > 100):
            raise APIError(400, "Invalid forensic event batch")
        for field in ("application", "traffic"):
            if field in snapshot and not isinstance(snapshot[field], dict):
                raise APIError(400, "Invalid telemetry context")
        for key in ("cpu_percent", "ram_percent", "disk_percent", "swap_percent"):
            value = snapshot["metrics"].get(key)
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100):
                raise APIError(400, "Invalid percentage metric")
        if "observed_at" in snapshot:
            try:
                stamp = datetime.fromisoformat(snapshot["observed_at"].replace("Z", "+00:00")).timestamp()
                if abs(time.time() - stamp) > 3600:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise APIError(400, "Telemetry timestamp outside accepted window")

    def correlate(self, server_id, org_id, snapshot, analysis):
        findings = []
        measured = measured_resources(snapshot.get("metrics", {}))
        state_engine_owns_capacity = server_id != "local-demo" and any(
            value >= self.resources.policy(org_id, server_id, resource)["start_threshold"]
            for resource, value in measured.items())
        if analysis.get("severity") in ("WARNING", "CRITICAL") and not (analysis.get("category") in {"capacity", "resource_pressure"} and state_engine_owns_capacity):
            key = "security" if analysis["classification"] == "SUSPICIOUS_ACTIVITY" else analysis.get("category", analysis["classification"])
            findings.append((key, analysis["severity"], analysis["interpretation"]))
        for event in snapshot.get("events", []):
            if event.get("severity") in ("WARNING", "CRITICAL"):
                findings.append((str(event.get("kind", "security"))[:100], event["severity"], str(event.get("summary", "Security event"))))
        # One incident per kind/server; thousands of equivalent events remain one notification.
        unique = {}
        for kind, severity, summary in findings:
            prior = unique.get(kind)
            if not prior or severity == "CRITICAL":
                unique[kind] = (severity, summary)
        for key, (severity, summary) in unique.items():
            now, stamp = time.time(), utcnow()
            with self.store.tx() as db:
                previous = db.execute("SELECT * FROM incidents WHERE org_id=? AND server_id=? AND correlation_key=?", (org_id, server_id, key)).fetchone()
                incident_id = previous["id"] if previous else uid()
                notify = not previous or (severity == "CRITICAL" and previous["severity"] != "CRITICAL")
                notified_at = now if notify else previous["last_notified"]
                first_seen = previous["first_seen"] if previous else stamp
                try:
                    duration = max(0, now - datetime.fromisoformat(first_seen).timestamp())
                except ValueError:
                    duration = 0
                incident_data = {"category": "security" if key in {"security", "server_offline"} else "health",
                                 "assessment": summary, "confidence": "Low", "first_observed": first_seen,
                                 "last_observed": stamp, "duration_seconds": duration,
                                 "probable_explanation": "Cause not established from this observation.",
                                 "recommendations": ["Review related evidence before taking action."],
                                 "affected_resources": [key.replace("_", " ")],
                                 "evidence_gaps": ["Collector coverage may be incomplete."]}
                if previous:
                    db.execute("UPDATE incidents SET last_seen=?,count=count+1,severity=?,data=?,last_notified=?,status='open' WHERE id=?", (stamp, severity, dumps(incident_data), notified_at, incident_id))
                else:
                    db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,1,?,?,?,?)", (incident_id, org_id, server_id, key, severity, key.replace("_", " ").title(), "open", stamp, stamp, notified_at, dumps(incident_data)))
                if notify:
                    name = db.execute("SELECT name FROM servers WHERE id=?", (server_id,)).fetchone()[0]
                    message = alert_message(name, severity, key, summary)
                    result = self.channel.send(message, severity=severity, recipient_id="owner")
                    db.execute("INSERT INTO notifications VALUES(?,?,?,?,?,?,?,?,?)", (uid(), org_id, server_id, stamp, severity, "local", result["status"], message, incident_id))
                    db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,NULL,?)",
                               (incident_id, org_id, server_id, stamp, "observation", summary[:400], "Low"))
            if notify and server_id != "local-demo":
                category = "agent_lost" if key == "server_offline" else "security" if key == "security" else None
                if category:
                    safe_summary = "Agent reporting stopped; evidence is unavailable after the last receipt." if category == "agent_lost" else "Security observations require review."
                    self.email.enqueue(org_id, server_id, category, "CRITICAL" if severity == "CRITICAL" else "WARNING", incident_id + ":" + stamp, safe_summary)
            self.store.audit(org_id=org_id, server_id=server_id, actor="system", channel="collector", intent="anomaly", assessment=summary, result="correlated", incident_id=incident_id)

        self.notifications.observe(self.server(server_id, org_id), snapshot, analysis, include_resources=False)

    def form_shield_credentials(self, user):
        return {
            "items": self.trust_abuse.credentials(user["org_id"])
        }

    def form_shield_credential_request(self, user, action, data):
        try:
            if action == "create":
                created = self.trust_abuse.create_credential(
                    user["org_id"],
                    data.get("label"),
                )
                result = {
                    "status": "created",
                    "credential": created,
                    "items": self.trust_abuse.credentials(user["org_id"]),
                }

            elif action == "revoke":
                self.trust_abuse.revoke_credential(
                    user["org_id"],
                    data.get("id"),
                )
                result = {
                    "status": "revoked",
                    "items": self.trust_abuse.credentials(user["org_id"]),
                }

            else:
                raise APIError(404, "Unknown Form Shield credential operation")

        except ValueError as exc:
            raise APIError(400, str(exc)) from None

        self.store.audit(
            org_id=user["org_id"],
            actor=user["id"],
            request="form_shield_credential_" + action,
            result="processed",
        )

        return result

    def trust_rules(self, user):
        return {"items": self.trust_abuse.rules(user["org_id"])}

    def trust_rule_request(self, user, action, data):
        try:
            if action == "add":
                rule_id = self.trust_abuse.add_rule(
                    user["org_id"],
                    data.get("list_type"),
                    data.get("kind"),
                    data.get("value"),
                    data.get("reason", ""),
                    data.get("expires_at"),
                )
                result = {
                    "status": "saved",
                    "id": rule_id,
                    "items": self.trust_abuse.rules(user["org_id"]),
                }
            elif action == "remove":
                self.trust_abuse.remove_rule(
                    user["org_id"],
                    data.get("id"),
                )
                result = {
                    "status": "removed",
                    "items": self.trust_abuse.rules(user["org_id"]),
                }
            else:
                raise APIError(404, "Unknown trust rule operation")
        except ValueError as exc:
            raise APIError(400, str(exc)) from None

        self.store.audit(
            org_id=user["org_id"],
            actor=user["id"],
            request="trust_rule_" + action,
            result="processed",
        )
        return result

    def abuse_evaluate(self, user, data):
        try:
            result = self.trust_abuse.evaluate(user["org_id"], data)
        except ValueError as exc:
            raise APIError(400, str(exc)) from None

        self.store.audit(
            org_id=user["org_id"],
            actor=user["id"],
            request="abuse_evaluate",
            result=result["decision"],
            assessment={
                "risk_score": result["risk_score"],
                "intent": result["intent"],
            },
        )
        return result

    def abuse_events(self, user):
        return {"items": self.trust_abuse.events(user["org_id"])}

    def abuse_event_request(self, user, action, data):
        try:
            self.trust_abuse.quarantine_action(
                user["org_id"],
                data.get("id"),
                action,
            )
        except ValueError as exc:
            raise APIError(400, str(exc)) from None

        self.store.audit(
            org_id=user["org_id"],
            actor=user["id"],
            request="abuse_event_" + action,
            result="processed",
        )
        return {
            "status": "updated",
            "items": self.trust_abuse.events(user["org_id"]),
        }

    def reputation_findings(self, user):
        return {"items": self.trust_abuse.reputation(user["org_id"])}

    def reputation_scan(self, user, domain):
        try:
            result = self.reputation_scanner.scan(domain)

            for finding in result["findings"]:
                self.trust_abuse.record_reputation(
                    user["org_id"],
                    result["domain"],
                    finding["kind"],
                    finding["status"],
                    finding["summary"],
                    finding.get("evidence", {}),
                )

        except ValueError as exc:
            raise APIError(400, str(exc)) from None

        self.store.audit(
            org_id=user["org_id"],
            actor=user["id"],
            request="reputation_scan",
            result="completed",
            assessment={
                "domain": result["domain"],
                "mail_service_detected": result["mail_service_detected"],
            },
        )

        return result

    def reputation_record(self, user, data):
        try:
            finding_id = self.trust_abuse.record_reputation(
                user["org_id"],
                data.get("domain"),
                data.get("kind"),
                data.get("status"),
                data.get("summary", ""),
                data.get("evidence"),
            )
        except ValueError as exc:
            raise APIError(400, str(exc)) from None

        self.store.audit(
            org_id=user["org_id"],
            actor=user["id"],
            request="reputation_record",
            result="recorded",
        )
        return {"status": "recorded", "id": finding_id}

    def notification_request(self, user, action, data):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        org = user["org_id"]
        try:
            if action == "save":
                result = {"settings": self.notifications.configure(org, data), "message": "Settings saved. No connection test or message sent by saving."}
            elif action == "disable":
                result = {"settings": self.notifications.disable(org), "message": "Notifications disabled; token forgotten and queued attempts cancelled."}
            elif action == "test-connection":
                result = self.notifications.test_connection(org)
            elif action == "test-notification":
                result = {"status": self.notifications.test_notification(org)}
            else:
                raise APIError(404, "Unknown notification operation")
        except NotificationError as exc:
            raise APIError(400, str(exc)) from None
        self.store.audit(org_id=org, actor=user["id"], request="notification_" + action, result="processed")
        return result

    def email_request(self, user, action, data):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        org = user["org_id"]
        try:
            if action == "save":
                result = {"settings": self.email.configure(org, user["id"], data)}
            elif action == "test":
                result = {"queued": self.email.test(org, user["id"])}
            elif action == "route":
                server_id = data.get("server_id")
                if server_id != "*":
                    self.server(server_id, org)
                self.email.route(org, user["id"], server_id, data.get("channel"), data.get("event_class"), data.get("min_severity"), data.get("enabled"))
                result = {"routes": self.email.routes(org, user["id"])}
            else:
                raise APIError(404, "Unknown email operation")
        except ValueError as exc:
            raise APIError(400, str(exc)) from None
        self.store.audit(org_id=org, actor=user["id"], request="email_" + action, result="processed")
        return result

    def ezzesend_link_request(self, user, action, data):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        try:
            if action == "start":
                result = self.ezzesend_link.start(user, data.get("phone"))
            elif action == "complete":
                result = self.ezzesend_link.complete(user, data.get("challenge_id"), data.get("state"), data.get("grant_code"))
            else:
                raise APIError(404, "Unknown linking operation")
        except NotificationError as exc:
            raise APIError(400, str(exc)) from None
        self.store.audit(org_id=user["org_id"], actor=user["id"], request="ezzesend_link_" + action, result="processed")
        return result

    def create_canary(self, user, server_id, label):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        server = self.server(server_id, user["org_id"])
        if server["environment"] == "simulated":
            raise APIError(400, "Create canaries only for operator-controlled infrastructure")
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 80 or any(ord(c) < 32 for c in label):
            raise APIError(400, "Use a short canary label")
        token = secrets.token_urlsafe(32)
        canary_id = uid()
        with self.store.tx() as db:
            db.execute("INSERT INTO canaries(id,org_id,server_id,label,token_hash,enabled,created_at,last_trigger) VALUES(?,?,?,?,?,1,?,0)",
                       (canary_id, user["org_id"], server_id, label.strip(), digest(token), utcnow()))
        self.store.audit(org_id=user["org_id"], server_id=server_id, actor=user["id"], request="canary_create", result="created")
        return {"id": canary_id, "path": "/canary/" + token, "message": "Copy this URL now; the token is never shown again. Place it only in infrastructure you control."}

    def list_canaries(self, user):
        return self.store.rows("SELECT id,server_id,label,enabled,created_at FROM canaries WHERE org_id=? ORDER BY created_at DESC LIMIT 100", (user["org_id"],))

    def disable_canary(self, user, canary_id):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        with self.store.tx() as db:
            changed = db.execute("UPDATE canaries SET enabled=0 WHERE id=? AND org_id=?", (canary_id, user["org_id"])).rowcount
        if not changed:
            raise APIError(404, "Canary not found")
        return {"status": "disabled"}

    def trigger_canary(self, token, peer):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", token):
            return
        now = time.time()
        with self.store.tx() as db:
            row = db.execute("SELECT * FROM canaries WHERE token_hash=? AND enabled=1", (digest(token),)).fetchone()
            if not row or row["last_trigger"] > now - 60:
                return
            db.execute("UPDATE canaries SET last_trigger=? WHERE id=?", (now, row["id"]))
            canary = dict(row)
        with self.store.lock:
            stream = self.store.one("SELECT last_sequence FROM evidence_streams WHERE org_id=? AND server_id=? AND agent_id='control-plane'", (canary["org_id"], canary["server_id"]))
            sequence = stream["last_sequence"] + 1 if stream else 1
            stamp = utcnow()
            details = {"reason": "Connection peer accessed an operator-created canary URL"}
            try:
                details["source_address"] = str(ipaddress.ip_address(peer))
            except ValueError:
                details["reason"] = "Canary URL accessed; connection peer unavailable"
            evidence = {"sequence": sequence, "observed_at": stamp, "collected_at": stamp, "event_type": "canary_triggered",
                        "source": "control_plane", "details": details}
            self.ledger.ingest(canary["org_id"], canary["server_id"], "control-plane", [evidence])
        receipt = self.store.one("SELECT id FROM forensic_events WHERE org_id=? AND server_id=? AND agent_id='control-plane' AND sequence=?",
                                 (canary["org_id"], canary["server_id"], sequence))
        summary = "An operator-controlled canary URL was accessed. The observed address is the connection peer, not a verified visitor identity."
        key = "canary:" + canary["id"]
        with self.store.tx() as db:
            prior = db.execute("SELECT * FROM incidents WHERE org_id=? AND server_id=? AND correlation_key=?", (canary["org_id"], canary["server_id"], key)).fetchone()
            incident_id = prior["id"] if prior else uid()
            data = {"category": "security", "assessment": summary, "confidence": "High for URL access; unknown for identity",
                    "probable_explanation": "The canary URL was requested; intent is not established.",
                    "recommendations": ["Review the canary placement and request context."],
                    "evidence_gaps": ["Proxy headers and connection peer do not establish physical location or identity."],
                    "affected_resources": ["Operator-created canary"]}
            db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,server_id,correlation_key) DO UPDATE SET count=incidents.count+1,last_seen=excluded.last_seen,status='open',data=excluded.data",
                       (incident_id, canary["org_id"], canary["server_id"], key, "HIGH", "Canary accessed", "open", 1,
                        prior["first_seen"] if prior else stamp, stamp, now, dumps(data)))
            db.execute("INSERT INTO incident_timeline(incident_id,org_id,server_id,observed_at,kind,summary,evidence_id,confidence) VALUES(?,?,?,?,?,?,?,?)",
                       (incident_id, canary["org_id"], canary["server_id"], stamp, "canary_triggered", summary, receipt["id"], "High for URL access"))
        version = (self.notifications.row(canary["org_id"]) or {}).get("contract_version", 1)
        self.notifications.enqueue(canary["org_id"], self.server(canary["server_id"], canary["org_id"]),
                                   "canary_triggered" if version == 2 else "security_incident", "HIGH", f"{canary['id']}:{sequence}",
                                   detail="Operator-controlled canary URL accessed; visitor identity unknown.")
        self.email.enqueue(canary["org_id"], canary["server_id"], "canary", "HIGH", f"{canary['id']}:{sequence}",
                           "An operator-controlled canary URL was accessed. Review the incident; visitor identity is unknown.")

    def notification_tick(self):
        # Independent of Agent requests and the daily-brief hour. Revoked and
        # never-seen agents do not produce outage claims.
        for org in self.store.rows("SELECT id FROM organizations"):
            for server in self.safe_servers(org["id"]):
                if server["environment"] != "simulated" and server["status"] == "offline" and server["last_seen"]:
                    try:
                        if time.time() - datetime.fromisoformat(server["last_seen"]).timestamp() <= 90:
                            continue
                    except (ValueError, TypeError):
                        continue
                    stream = self.store.one("SELECT last_seen FROM evidence_streams WHERE org_id=? AND server_id=? ORDER BY last_seen DESC LIMIT 1", (org["id"], server["id"]))
                    last_verified = stream["last_seen"] if stream else "unavailable"
                    self.correlate(server["id"], org["id"],
                                   {"observed_at": server["last_seen"], "events": [{"kind": "server_offline", "severity": "CRITICAL", "summary": "Agent reporting stopped for more than 90 seconds; cause unknown. Last verified chain receipt: " + last_verified + ". Evidence after this point is unavailable."}]},
                                   {"severity": "INFO", "classification": "UNKNOWN"})
        self.notifications.dispatch()
        self.email.dispatch()

    def listing(self, table, org_id):
        if table not in {"incidents", "approvals", "audit", "analyses", "notifications", "jobs"}:
            raise APIError(404, "Not found")
        if table == "approvals":
            with self.store.tx() as db:
                db.execute("UPDATE approvals SET state='expired' WHERE state='pending' AND expires<?", (time.time(),))
        order = "id" if table == "audit" else "last_seen" if table == "incidents" else "created_at"
        rows = decode_rows(self.store.rows(f"SELECT * FROM {table} WHERE org_id=? ORDER BY {order} DESC LIMIT 200", (org_id,)))
        for row in rows:
            row.pop("code_hash", None)
            if "expires" in row:
                row["expires_at"] = datetime.fromtimestamp(row["expires"], timezone.utc).isoformat()
        return rows

    def detail(self, server_id, org_id):
        from .intelligence.engine import analyze, capacity_advice
        server = self.safe_server(server_id, org_id)
        snapshot, history = self.snapshot(server_id, org_id), self.history(server_id, org_id)
        baseline_row = self.store.one("SELECT value FROM settings WHERE key=?", ("baseline:" + server_id,))
        baseline = json.loads(baseline_row["value"]) if baseline_row else {}
        comparisons = {kind: baseline_summary(snapshot.get(kind), baseline.get(kind), kind)
                       or supplied_baseline(snapshot, kind)
                       for kind in ("ports", "services")} if snapshot else {}
        return {"server": server, "snapshot": snapshot, "history": history[-288:],
                "baseline": comparisons,
                "resource_policies": self.resource_policies(org_id, server_id),
                "resource_alerts": [dict(resource=row["resource"], **json.loads(row["state"])) for row in self.store.rows("SELECT resource,state FROM resource_alerts WHERE org_id=? AND server_id=?", (org_id,server_id))],
                "incident_timeline": self.store.rows("SELECT incident_id,observed_at,kind,summary,confidence,evidence_id FROM incident_timeline WHERE org_id=? AND server_id=? ORDER BY id DESC LIMIT 100", (org_id,server_id)),
                "black_box": self.black_box_detail(org_id, server_id),
                "analysis": analyze(snapshot, history) if snapshot else None,
                "capacity": capacity_advice(history),
                "jobs": [r for r in self.listing("jobs", org_id) if r["server_id"] == server_id]}

    def black_box_detail(self, org_id, server_id):
        agent = self.store.one("SELECT id FROM agents WHERE org_id=? AND server_id=? AND enabled=1 ORDER BY created_at DESC LIMIT 1", (org_id, server_id))
        stream_ids = {row["agent_id"] for row in self.store.rows("SELECT agent_id FROM evidence_streams WHERE org_id=? AND server_id=?", (org_id, server_id))}
        if agent:
            stream_ids.add(agent["id"])
        checks = {identity: self.ledger.verify(org_id, server_id, identity) for identity in stream_ids}
        agent_integrity = checks.get(agent["id"], {"status": "UNAVAILABLE", "count": 0, "last_verified_at": None}) if agent else {"status": "UNAVAILABLE", "count": 0, "last_verified_at": None}
        events = self.ledger.recent(org_id, server_id)
        for event in events:
            event["integrity"] = checks.get(event["agent_id"], {"status": "UNAVAILABLE"})["status"]
        return {"integrity": agent_integrity, "stream_integrity": [{"source": "Control Plane canaries" if identity == "control-plane" else "Agent",
                      **result} for identity, result in checks.items()],
                "events": events,
                "limitation": "Chain verification checks preservation after receipt. It does not establish that the source host reported truthful events."}

    def overview(self, org_id):
        if not self.demo_enabled:
            return {"demo": False, "targets": self.safe_servers(org_id)}
        result = self.detail("local-demo", org_id)
        for table in ("incidents", "approvals", "notifications"):
            result[table] = self.listing(table, org_id)
        result["stats"] = {"servers": len(self.store.rows("SELECT id FROM servers WHERE org_id=?", (org_id,))), "open_incidents": sum(i["status"] == "open" for i in result["incidents"]), "pending_approvals": sum(a["state"] == "pending" for a in result["approvals"]), "ai_calls": self.store.one("SELECT COALESCE(SUM(calls),0) AS calls FROM usage WHERE org_id=?", (org_id,))["calls"], "ai_cost": None}
        result["demo"] = True
        result["targets"] = self.safe_servers(org_id)
        return result

    def identity(self, user, channel, sender=None):
        if channel == "console":
            return user["id"]
        if channel != "whatsapp-mock":
            raise APIError(400, "Unsupported channel")
        identity = self.store.one("SELECT * FROM identities WHERE user_id=? AND org_id=? AND channel='whatsapp' AND address=? AND enabled=1", (user["id"], user["org_id"], sender))
        if not identity:
            # No user-supplied text or phone number enters the audit on denial.
            self.store.audit(org_id=user["org_id"], actor="unauthorized", channel=channel, request="operational_request", result="denied")
            raise APIError(403, "Unauthorized sender")
        return identity["id"]

    def command(self, user, text, server_id, channel="console", sender=None):
        identity = self.identity(user, channel, sender)
        self.server(server_id, user["org_id"])
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        if not isinstance(text, str) or not text.strip() or len(text) > 2000:
            raise APIError(400, "Command must contain 1–2000 characters")
        confirmation = re.fullmatch(r"\s*CONFIRM\s+(\d{6})\s*", text, re.I)
        if confirmation:
            row = self.store.one("SELECT id FROM approvals WHERE actor=? AND server_id=? AND channel=? AND identity_id=? AND state='pending' AND org_id=? ORDER BY created_at DESC LIMIT 1", (user["id"], server_id, channel, identity, user["org_id"]))
            if not row:
                raise APIError(400, "No pending approval for this identity and server")
            return self.confirm(user, row["id"], confirmation[1], channel, identity)
        from .intelligence.engine import interpret, analyze
        context_row = self.store.one("SELECT data FROM contexts WHERE actor=? AND server_id=? AND channel=? AND identity_id=? AND expires>?", (user["id"], server_id, channel, identity, time.time()))
        context = json.loads(context_row["data"]) if context_row else None
        intent = interpret(text, context)
        command_class, action = intent.get("command_class", "C"), intent.get("action")
        audit = dict(org_id=user["org_id"], server_id=server_id, actor=user["id"], channel=channel, identity_id=identity, request="natural_language_request", intent=intent.get("intent"), command_class=command_class, action=action)
        if command_class == "C":
            self.store.audit(**audit, result="protected_denied", approval_state="not_permitted")
            return {**intent, "message": "This is a protected action. EzzeSecure Community cannot execute arbitrary or destructive commands. Review it in your authenticated terminal workflow."}
        if command_class == "A":
            snapshot = self.collect() if server_id == "local-demo" else self.snapshot(server_id, user["org_id"])
            analysis = analyze(snapshot, self.history(server_id, user["org_id"])) if snapshot else None
            message = self.diagnostic_message(intent, snapshot, analysis)
            topic = intent.get("topic")
            if intent.get("intent") == "clarify":
                message = intent.get("reason", "Please specify the diagnostic or registered action you want.")
            elif topic in {"history", "daily_brief"}:
                from .intelligence.engine import daily_brief
                seconds = 3600 if any(term in text.lower() for term in ("last hour", "آخر ساعة", "اخر ساعة")) else 86400
                samples = [s for s in self.history(server_id, user["org_id"]) if datetime.fromisoformat(s.get("received_at", s["observed_at"])).timestamp() >= time.time() - seconds]
                events = list({dumps(e): e for s in samples for e in s.get("events", [])}.values())
                message = daily_brief(samples, events)["summary"]
            elif topic == "capacity":
                from .intelligence.engine import capacity_advice
                message = capacity_advice(self.history(server_id, user["org_id"]))["recommendation"]
            if re.search(r"[\u0600-\u06ff]", text):
                message = self.arabic_diagnostic(intent, snapshot, analysis, message)
            app = (snapshot or {}).get("application", {})
            context_action = "queue.restart" if intent.get("topic") == "queue" else "scheduler.run" if intent.get("topic") in {"scheduler", "cron", "cron_delay"} else None
            if context_action:
                try:
                    context_parameters = self.allowed_action(server_id, context_action, {})
                except ValueError:
                    context_parameters = None
                if context_parameters:
                    self.save_context(user, server_id, channel, identity, context_action, context_parameters)
            else:
                with self.store.tx() as db:
                    db.execute("DELETE FROM contexts WHERE actor=? AND server_id=? AND channel=? AND identity_id=?", (user["id"], server_id, channel, identity))
            self.store.audit(**audit, tools=["metrics", "services", "application", "security_events"], result="diagnostics_reported", assessment=(analysis or {}).get("interpretation"))
            return {**intent, "message": message, "analysis": analysis}
        try:
            parameters = self.allowed_action(server_id, action, intent.get("parameters", {}))
        except ValueError as error:
            self.store.audit(**audit, result="policy_denied")
            raise APIError(403, str(error))
        self.save_context(user, server_id, channel, identity, action, parameters)
        if ACTIONS[action].confirmation:
            approval_id, code, expires = uid(), f"{secrets.randbelow(1000000):06d}", time.time() + 120
            with self.store.tx() as db:
                db.execute("UPDATE approvals SET state='superseded' WHERE actor=? AND server_id=? AND channel=? AND identity_id=? AND state='pending'", (user["id"], server_id, channel, identity))
                db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?)", (approval_id, user["org_id"], server_id, user["id"], channel, identity, action, dumps(parameters), self.code_hash(code), expires, "pending", utcnow()))
            self.store.audit(**audit, result="approval_required", approval_state="pending")
            suffix = " Demo actions are simulated." if server_id == "local-demo" else " The enrolled agent must also permit this exact action."
            return {**intent, "message": f"Approve {action} on {server_id}, target {parameters['target']}? Reply CONFIRM {code} within 2 minutes." + suffix, "approval": {"id": approval_id, "code": code, "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(), "action": action, "parameters": parameters, "server_id": server_id}}
        result = self.execute(user, server_id, action, parameters, uid(), channel)
        return {**intent, "message": result["summary"], "result": result}

    def save_context(self, user, server_id, channel, identity, action, parameters):
        context = {"action": action, "parameters": parameters, "established_at": utcnow()}
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO contexts VALUES(?,?,?,?,?,?)", (user["id"], server_id, channel, identity, time.time() + 600, dumps(context)))

    @staticmethod
    def diagnostic_message(intent, snapshot, analysis):
        if not snapshot:
            return "No telemetry is available yet. No operational conclusions can be drawn."
        topic = intent.get("topic", "overview")
        app, metrics = snapshot.get("application", {}), snapshot.get("metrics", {})
        prefix = "[Simulated demo] " if snapshot.get("simulated") or snapshot.get("demo") else ""
        if topic in {"scheduler", "cron", "cron_delay"}:
            return prefix + f"Scheduler last run: {app.get('scheduler_last_run', 'unknown')}. Lock: {app.get('scheduler_locked', 'unknown')}. Queue backlog: {app.get('queue_backlog', 'unknown')}. Database healthy: {app.get('database_healthy', 'unknown')}. CPU: {metrics.get('cpu_percent', 'unknown')}%. No job was started. " + (analysis or {}).get("interpretation", "")
        if topic == "queue":
            return prefix + f"Queue backlog: {app.get('queue_backlog', 'unknown')}; active workers: {app.get('queue_workers', 'unknown')}; database healthy: {app.get('database_healthy', 'unknown')}. " + (analysis or {}).get("interpretation", "")
        if topic == "security":
            events = snapshot.get("events", [])
            return prefix + ("; ".join(str(e.get("summary", e.get("kind", "event"))) for e in events[:5]) or "No security events were observed in the available sample; this is not proof of absence.")
        if topic == "database":
            return prefix + f"Database health probe: {app.get('database_healthy', 'unknown')}. Service state alone cannot establish database health. " + (analysis or {}).get("interpretation", "")
        if topic == "logs":
            return prefix + "Raw logs are not retained. Recent structured events: " + ("; ".join(str(e.get("summary", "")) for e in snapshot.get("events", [])[:5]) or "none observed in this sample. Configure a bounded log collector for further evidence.")
        if topic == "services":
            return prefix + ("; ".join(f"{s.get('name')}: {s.get('state', 'unknown')}" for s in snapshot.get("services", [])) or "No service probes configured.")
        if topic in {"cpu", "memory", "disk"}:
            key = {"cpu": "cpu_percent", "memory": "ram_percent", "disk": "disk_percent"}[topic]
            return prefix + f"{topic.title()}: {metrics.get(key, 'unknown')}%. " + (analysis or {}).get("interpretation", "") + " " + " ".join((analysis or {}).get("recommendations", [])[:2])
        return prefix + (analysis or {}).get("interpretation", "Evidence is incomplete.") + " " + " ".join((analysis or {}).get("recommendations", [])[:2])

    @staticmethod
    def arabic_diagnostic(intent, snapshot, analysis, fallback):
        if not snapshot:
            return "لا توجد قياسات متاحة بعد؛ لا يمكن تأكيد حالة السيرفر."
        app, metrics = snapshot.get("application", {}), snapshot.get("metrics", {})
        prefix = "[محاكاة محلية] " if snapshot.get("simulated") else ""
        topic = intent.get("topic")
        if intent.get("intent") == "clarify":
            return "حدد الفحص أو الإجراء المسجل المطلوب. لم يتم تنفيذ أي إجراء."
        if topic == "queue":
            return prefix + f"الرسائل المنتظرة: {app.get('queue_backlog', 'غير معروف')}، عدد العمال: {app.get('queue_workers', 'غير معروف')}. " + ("توقف العمال قد يفسر التأخير. يمكن طلب إعادة تشغيلهم مع تأكيد جديد." if app.get("queue_workers") == 0 else "العمال موجودون؛ نحتاج مقارنة معدل الإدخال والمعالجة لتأكيد السبب.")
        if topic == "scheduler":
            return prefix + f"آخر تشغيل للمجدول: {app.get('scheduler_last_run', 'غير معروف')}؛ القفل: {app.get('scheduler_locked', 'غير معروف')}؛ CPU: {metrics.get('cpu_percent', 'غير معروف')}%. لم يتم تشغيله. يجب فحص القفل والعملية والأخطاء قبل إعادة المحاولة."
        if topic in {"overview", "operations", "cpu", "memory", "disk", "database", "security"}:
            finding = {"NORMAL_GROWTH": "القياسات تتوافق مع زيادة استخدام مشروعة؛ راقب الاستمرار قبل زيادة السعة.", "APPLICATION_BOTTLENECK": "هناك مؤشر على اختناق بالتطبيق أو أحد اعتماداته؛ يلزم فحص السبب.", "SUSPICIOUS_ACTIVITY": "هناك مؤشرات نشاط مشبوه؛ لم يتم حظر أي مصدر تلقائياً.", "CAPACITY_PRESSURE": "هناك ضغط موارد؛ لا ننصح بترقية اعتماداً على قفزة واحدة.", "BACKGROUND_WORKLOAD": "المعطيات تشير إلى حمل من مهام خلفية.", "UNKNOWN": "الاستنتاج محدود بالأدلة المتاحة؛ لا نفترض وجود عطل أو غيابه."}.get((analysis or {}).get("classification"), "الأدلة غير كافية.")
            return prefix + f"CPU: {metrics.get('cpu_percent', 'غير معروف')}%، RAM: {metrics.get('ram_percent', 'غير معروف')}%، القرص: {metrics.get('disk_percent', 'غير معروف')}%. " + finding
        return prefix + "الملخص من القياسات المسجلة فقط: " + fallback

    def code_hash(self, code):
        return hmac.new(self.config["session_key"].encode(), str(code).encode(), hashlib.sha256).hexdigest()

    def confirm(self, user, approval_id, code, channel="console", identity=None):
        identity = identity or user["id"]
        error, row = None, None
        with self.store.tx() as db:
            item = db.execute("SELECT * FROM approvals WHERE id=? AND org_id=? AND actor=? AND channel=? AND identity_id=?", (approval_id, user["org_id"], user["id"], channel, identity)).fetchone()
            if not item or user["role"] != "owner":
                raise APIError(404, "Approval not found for this identity")
            row = dict(item)
            if row["state"] != "pending":
                error = "Approval was already used or is no longer valid"
            elif row["expires"] < time.time():
                db.execute("UPDATE approvals SET state='expired' WHERE id=?", (approval_id,))
                error = "Approval expired"
            elif not hmac.compare_digest(self.code_hash(code), row["code_hash"]):
                attempts = row["attempts"] + 1
                db.execute("UPDATE approvals SET attempts=?,state=? WHERE id=?", (attempts, "locked" if attempts >= 5 else "pending", approval_id))
                error = "Invalid approval code"
            else:
                # Atomic consume BEFORE any execution; crash means explicit manual investigation, never replay.
                db.execute("UPDATE approvals SET state='consumed' WHERE id=?", (approval_id,))
        self.store.audit(org_id=user["org_id"], server_id=row["server_id"], actor=user["id"], channel=channel, identity_id=identity, request="approval_confirmation", command_class="B", action=row["action"], approval_state="rejected" if error else "consumed", result="denied" if error else "approved")
        if error:
            raise APIError(409, error)
        # Re-check both policy and registered server at execution time.
        self.server(row["server_id"], user["org_id"])
        parameters = self.allowed_action(row["server_id"], row["action"], json.loads(row["parameters"]))
        result = self.execute(user, row["server_id"], row["action"], parameters, approval_id, channel)
        return {"message": result["summary"], "result": result, "command_class": "B", "intent": row["action"]}

    def execute(self, user, server_id, action, parameters, request_id, channel):
        parameters = self.allowed_action(server_id, action, parameters)
        with self.store.tx() as db:
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", (request_id, user["org_id"], server_id, user["id"], action, dumps(parameters), "running", utcnow(), None))
        try:
            result = self.agent.execute(action, parameters, request_id)
        except Exception:
            result = {"status": "failed", "summary": "Agent execution failed; inspect local diagnostics. No automatic retry.", "verification": "unknown"}
        result = redact(result)
        with self.store.tx() as db:
            db.execute("UPDATE jobs SET status=?,result=? WHERE id=?", (result["status"], dumps(result), request_id))
        self.collect()
        self.store.audit(org_id=user["org_id"], server_id=server_id, actor=user["id"], channel=channel, command_class="B", action=action, tools=[action], result=result)
        return result

    def brief(self, org_id, server_id="local-demo"):
        from .intelligence.engine import daily_brief
        server = self.server(server_id, org_id)
        samples = self.history(server_id, org_id)
        cutoff = time.time() - 86400
        samples = [s for s in samples if datetime.fromisoformat(s.get("received_at", s["observed_at"])).timestamp() >= cutoff]
        # Events in fixture snapshots recur; de-duplicate identical observations across polling.
        events = list({dumps(e): e for s in samples for e in s.get("events", [])}.values())
        brief = daily_brief(samples, events)
        message = brief.get("message") or brief.get("summary") or dumps(brief)
        with self.store.tx() as db:
            db.execute("INSERT INTO notifications VALUES(?,?,?,?,?,?,?,?,NULL)", (uid(), org_id, server_id, utcnow(), "INFO", "local", "recorded_locally", "EzzeSecure Daily Brief — " + server["name"] + "\n" + str(message)))
        self.store.audit(org_id=org_id, server_id=server_id, actor="system", request="daily_brief", result="recorded_locally")
        return {"message": message, "brief": brief}

    def scheduled_tick(self):
        now = datetime.now(timezone.utc)
        day = now.date().isoformat()
        if now.hour < int(self.config.get("daily_brief_hour_utc", 6)):
            return
        row = self.store.one("SELECT value FROM settings WHERE key='last_daily_brief'")
        if row and row["value"] == day:
            return
        for server in self.safe_servers("local"):
            if server["id"] == "local-demo" or server["status"] in {"online", "offline"}:
                self.brief("local", server["id"])
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES('last_daily_brief',?)", (day,))

    def safe_settings(self, user):
        phone = self.config.get("owner_phone", "")
        return {"organization": self.config["organization"], "username": user["username"], "owner_phone_masked": "••••" + phone[-4:], "mode": "Production read-only monitoring" if self.production else "Community read-only monitoring with a separate simulated demo", "provider": "Deterministic by default; optional BYOK reviews", "edition": "EzzeSecure Community", "version": "0.1.0 Community Preview", "mfa": "Not enabled" if self.production else "Not enabled; protect access with the documented SSH tunnel", "registered_actions": [{"action": a.name, "target": a.target, "description": a.description, "requires_confirmation": a.confirmation} for a in (ACTIONS.values() if self.demo_enabled else ())], "notifications": "Local records plus optional WhatsApp via EzzeSend", "ai_provider": self.ai.public(user["org_id"])}

    def ai_settings(self, user):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        return self.ai.public(user["org_id"])

    def ai_request(self, user, action, data):
        if user["role"] != "owner":
            raise APIError(403, "Owner role required")
        server_id = None
        try:
            if action == "analyze":
                server_id = data.get("server_id")
                self.server(server_id, user["org_id"])
                snapshot = self.snapshot(server_id, user["org_id"])
                if not snapshot:
                    raise APIError(409, "Collect observations before requesting an AI review")
                result = self.ai.analyze(user["org_id"], snapshot, self.history(server_id, user["org_id"]))
                with self.store.tx() as db:
                    db.execute("INSERT INTO analyses VALUES(?,?,?,?,?)", (uid(), user["org_id"], server_id, utcnow(), dumps(result)))
                response = {"analysis": result, "message": "Optional AI evidence review complete. No action was executed."}
            else:
                response = self.ai.configure(action, data, user["org_id"])
        except ProviderError as error:
            self.store.audit(org_id=user["org_id"], server_id=server_id, actor=user["id"], request="ai_" + action, result="failed; no provider response retained")
            raise APIError(400, str(error)) from None
        self.store.audit(org_id=user["org_id"], server_id=server_id, actor=user["id"], request="ai_" + action, result="completed")
        return response

    def enrollment_token(self, name="Local Linux Agent"):
        return self.create_enrollment({"id": "local-admin", "org_id": "local", "role": "owner"}, name)

    def enroll(self, data):
        with self.store.tx() as db:
            token = db.execute("SELECT * FROM enrollment_tokens WHERE token_hash=? AND used=0 AND expires>?", (digest(str(data.get("token", ""))), time.time())).fetchone()
            if not token:
                raise APIError(401, "Invalid enrollment credential")
            if db.execute("SELECT 1 FROM agents WHERE enabled=1 LIMIT 1").fetchone():
                raise APIError(409, "Community supports one active monitored agent; revoke the existing identity before replacement")
            if not db.execute("SELECT 1 FROM servers WHERE id=? AND org_id=?", (token["server_id"], token["org_id"])).fetchone():
                raise APIError(401, "Invalid enrollment credential")
            agent_id, secret = uid(), secrets.token_hex(32)
            db.execute("UPDATE enrollment_tokens SET used=1 WHERE server_id=? AND org_id=?", (token["server_id"], token["org_id"]))
            db.execute("UPDATE servers SET status='enrolled',last_seen=NULL WHERE id=? AND org_id=?", (token["server_id"], token["org_id"]))
            db.execute("INSERT INTO agents VALUES(?,?,?,?,1,?)", (agent_id, token["org_id"], token["server_id"], secret, utcnow()))
        self.store.audit(org_id=token["org_id"], server_id=token["server_id"], actor=agent_id, channel="agent", request="enroll", result="enrolled")
        return {"agent_id": agent_id, "secret": secret, "server_id": token["server_id"]}

    def authenticate_agent(self, method, path, headers, body):
        agent_id, stamp, nonce, supplied = (headers.get(k, "") for k in ("X-Agent-ID", "X-Agent-Timestamp", "X-Agent-Nonce", "X-Agent-Signature"))
        try:
            valid_time = abs(time.time() - int(stamp)) <= 300
        except (ValueError, TypeError):
            valid_time = False
        if not valid_time or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
            raise APIError(401, "Agent authentication failed")
        with self.store.tx() as db:
            agent = db.execute("SELECT * FROM agents WHERE id=? AND enabled=1", (agent_id,)).fetchone()
            if not agent or not hmac.compare_digest(signature(agent["secret"], method, path, stamp, nonce, body), supplied):
                raise APIError(401, "Agent authentication failed")
            db.execute("DELETE FROM nonces WHERE expires<?", (time.time(),))
            try:
                db.execute("INSERT INTO nonces VALUES(?,?,?)", (agent_id, nonce, time.time() + 610))
            except Exception:
                raise APIError(409, "Agent request replay rejected")
            return dict(agent)

    def agent_actions(self, agent):
        # A monitored Community agent has no action delivery capability.
        return {"items": []}

    def agent_result(self, agent, data):
        raise APIError(403, "Community agents report telemetry only; simulated results stay local")

    def revoke_agent(self, agent_id):
        agent = self.store.one("SELECT server_id,org_id FROM agents WHERE id=?", (agent_id,))
        if not agent:
            return False
        self.manage_server({"id": "local-admin", "org_id": agent["org_id"], "role": "owner"}, agent["server_id"], "revoke")
        return True

    def rotate_agent(self, agent_id):
        secret = secrets.token_hex(32)
        with self.store.tx() as db:
            changed = db.execute("UPDATE agents SET secret=? WHERE id=? AND enabled=1", (secret, agent_id)).rowcount
        if not changed:
            raise APIError(404, "Active agent not found")
        self.store.audit(actor="local-admin", channel="local-cli", request="rotate_agent", result="rotated")
        return {"agent_id": agent_id, "secret": secret}

    def allowed_action(self, server_id, action, parameters):
        if server_id != "local-demo":
            raise ValueError("Monitored Community agents are read-only. Action demonstrations use the simulated server only.")
        if action not in ACTIONS or not isinstance(parameters, dict) or set(parameters) - {"target"}:
            raise ValueError("Action is not registered by policy")
        rows = self.store.rows("SELECT target FROM registrations WHERE server_id=? AND action=?", (server_id, action))
        targets = [r["target"] for r in rows]
        target = parameters.get("target")
        if target is None and len(targets) == 1:
            target = targets[0]
        if target not in targets:
            raise ValueError("Target is not registered for this server")
        return {"target": target}

    def register_action(self, server_id, action, target):
        self.server(server_id, "local")
        if server_id != "local-demo":
            raise APIError(403, "Community registers simulated actions only; monitored agents are read-only")
        if action not in ACTIONS or not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_@.:-]{1,100}", target):
            raise APIError(400, "Supply an allowlisted action and literal target identifier")
        with self.store.tx() as db:
            db.execute("INSERT OR IGNORE INTO registrations VALUES(?,?,?)", (server_id, action, target))
        self.store.audit(server_id=server_id, actor="local-admin", channel="local-cli", request="register_action", action=action, result={"registered_target": target})
        return {"server_id": server_id, "action": action, "target": target}

    def baseline(self, server_id):
        self.server(server_id, "local")
        snapshot = self.snapshot(server_id, "local")
        if not snapshot:
            raise APIError(400, "Collect evidence before creating an observation baseline")
        key = "baseline:" + server_id
        if self.store.one("SELECT value FROM settings WHERE key=?", (key,)):
            raise APIError(409, "Baseline exists; review changes before replacing it")
        value = {k: snapshot.get(k) for k in ("ports", "services", "users", "firewall", "processes")}
        with self.store.tx() as db:
            db.execute("INSERT INTO settings VALUES(?,?)", (key, dumps(value)))
        self.store.audit(server_id=server_id, actor="local-admin", channel="local-cli", request="create_observation_baseline", result="created")
        return {"server_id": server_id, "status": "baseline_created"}
