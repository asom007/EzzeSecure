"""Optional EzzeSend contract v1, encrypted settings and durable bounded delivery.

No raw observations, logs, provider responses or credentials enter delivery records.
Network I/O happens only in dispatch/test_connection, never in telemetry ingestion.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from datetime import datetime, timezone
from urllib import error, parse, request

from .intelligence.settings import AISettings
from .intelligence.providers import _NoRedirects
from .security import redact

V1_EVENTS = {
    "security_incident": "Security observations require review",
    "server_offline": "Agent heartbeat expired",
    "service_failure": "A monitored service reports an unavailable state",
    "disk_critical": "Critical disk usage measured",
    "resource_pressure": "Sustained resource pressure observed",
    "integrity_finding": "Integrity observations require review",
}
V2_EVENTS = {
    **V1_EVENTS,
    "resource_escalation": "Resource severity increased",
    "resource_recovery": "Resource usage recovered",
    "canary_triggered": "Operator-controlled canary was accessed",
    "evidence_gap": "Agent evidence stream has a gap",
}
EVENTS = V2_EVENTS
LEVELS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class NotificationError(ValueError):
    """Only fixed, credential-free messages may cross the API boundary."""


def endpoint(value):
    try:
        url = parse.urlsplit(value)
        valid = (isinstance(value, str) and len(value) <= 500 and url.scheme == "https"
                 and url.hostname and not (url.username or url.password or url.query or url.fragment)
                 and url.path.rstrip("/").endswith("/api/integrations/ezzesecure")
                 and not any(ord(c) < 33 or ord(c) > 126 for c in value) and "\\" not in value)
        url.port
        if valid:
            return value.rstrip("/")
    except (ValueError, TypeError, AttributeError):
        pass
    raise NotificationError("Use an HTTPS EzzeSend integration URL ending in /api/integrations/ezzesecure.")


def idempotency_key(org, event_id):
    return hashlib.sha256(("ezzesecure:v1:" + org + ":" + event_id).encode()).hexdigest()


def http_transport(method, url, headers, payload):
    """Verified TLS, no redirects/proxy inheritance; bounded response/time."""
    req = request.Request(url, data=json.dumps(payload).encode() if payload is not None else None,
                          headers=headers, method=method)
    opener = request.build_opener(request.ProxyHandler({}), _NoRedirects)
    try:
        with opener.open(req, timeout=8) as response:
            return response.status, response.read(8193), response.headers
    except error.HTTPError as exc:
        # Never read or propagate provider error bodies (which may echo secrets).
        code, headers = exc.code, exc.headers
        exc.close()
        return code, b"", headers


class EzzeSendProvider:
    def __init__(self, transport=None):
        self.transport = transport or http_transport

    def call(self, config, token, payload=None):
        auth_header = "Bearer " + token
        headers = {"Accept": "application/json"}
        headers["Authorization"] = auth_header
        if payload is not None:
            headers.update({"Content-Type": "application/json", "Idempotency-Key": payload["idempotency_key"]})
        try:
            code, raw, response_headers = self.transport(
                "GET" if payload is None else "POST",
                config["api_url"] + ("/connection" if payload is None else "/notifications"), headers, payload)
            if code in (401, 403):
                return {"status": "failed", "reason": "authentication_rejected"}
            if code == 429 or 500 <= code <= 599:
                delay = response_headers.get("Retry-After", "30")
                delay = min(3600, max(30, int(delay))) if str(delay).isdigit() and len(str(delay)) < 8 else 30
                return {"status": "retry", "reason": "rate_limited" if code == 429 else "provider_unavailable", "delay": delay}
            if code not in (200, 202):
                return {"status": "failed", "reason": "request_rejected"}
            if len(raw) > 8192:
                raise ValueError()
            result = json.loads(raw)
            if payload is None:
                valid = code == 200 and result.get("status") == "ready" and result.get("contract_version") == config.get("contract_version", 1)
            else:
                valid = result.get("status") == "accepted" and result.get("idempotency_key") == payload["idempotency_key"]
            if not valid:
                raise ValueError()
            return {"status": "verified" if payload is None else "accepted", "reason": ""}
        except (TimeoutError, OSError):
            return {"status": "retry", "reason": "network_error", "delay": 30}
        except Exception:
            # Even a provider/transport exception containing the token is discarded.
            return {"status": "retry", "reason": "invalid_response", "delay": 30}


class NotificationDispatcher:
    def __init__(self, store, local, transport=None, control_plane_url=None):
        self.store, self.local = store, local
        self.vault = AISettings(store, local)
        self.provider = EzzeSendProvider(transport)
        self.incident_url = None
        if control_plane_url:
            from .agent.connection import validate_origin
            try:
                origin = validate_origin(control_plane_url)
                if origin.startswith("https://"):
                    self.incident_url = origin + "/#incidents"
            except ValueError:
                pass

    def row(self, org):
        row = self.store.one("SELECT value FROM settings WHERE key=?", ("notifications:" + org,))
        return json.loads(row["value"]) if row else None

    @staticmethod
    def supported_events(version):
        return V2_EVENTS if version == 2 else V1_EVENTS

    def public(self, org):
        row = self.row(org) or {}
        return {"available": self.vault.available(), "configured": bool(row), "enabled": row.get("enabled", False),
                "api_url": row.get("api_url", ""), "token_mask": "••••••••" if row else "Not configured",
                "minimum_severity": row.get("minimum_severity", "HIGH"),
                "event_types": row.get("event_types", list(V1_EVENTS)), "cooldown": row.get("cooldown", 1800),
                "contract_version": row.get("contract_version", 1)}

    def token(self, row, org):
        try:
            data = json.loads(self.vault.cipher(key_name="notification-vault.key").decrypt(row["encrypted_token"].encode()))
            if data["organization"] != org or data["purpose"] != "ezzesend-notifications":
                raise ValueError()
            return data["credential"]
        except Exception:
            raise NotificationError("Notification credential unavailable; restore the protected key or reconfigure.") from None

    def configure(self, org, data):
        if not isinstance(data, dict) or not self.vault.available():
            raise NotificationError("Install the optional encryption dependency before saving notifications.")
        base = endpoint(data.get("api_url"))
        version = data.get("contract_version", (self.row(org) or {}).get("contract_version", 1))
        if type(version) is not int or version not in (1, 2):
            raise NotificationError("Unsupported EzzeSend contract version")
        allowed_events = self.supported_events(version)
        minimum, events, cooldown = data.get("minimum_severity", "HIGH"), data.get("event_types", list(allowed_events)), data.get("cooldown", 1800)
        enabled = data.get("enabled", False)
        if (type(enabled) is not bool or minimum not in ("MEDIUM", "HIGH", "CRITICAL") or not isinstance(events, list)
                or not all(isinstance(e, str) and e in allowed_events for e in events) or len(events) > len(allowed_events)
                or type(cooldown) is not int or not 300 <= cooldown <= 86400):
            raise NotificationError("Choose supported events, severity and a cooldown of 300–86400 seconds.")
        prior = self.row(org)
        token = data.get("token", "")
        if token == "" and prior:
            if prior["api_url"] != base:
                raise NotificationError("Supply a new token when changing the integration URL.")
            token = self.token(prior, org)
        if not isinstance(token, str) or not 16 <= len(token) <= 4096 or not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token):
            raise NotificationError("Enter a valid integration token; saved tokens are never returned.")
        try:
            # Reuse the existing encryption helper with an independent notification key.
            # Never replace a lost key while encrypted notification settings exist.
            encrypted_exists = self.store.one("SELECT key FROM settings WHERE key LIKE 'notifications:%' LIMIT 1")
            encrypted = self.vault.cipher(create=not bool(encrypted_exists), key_name="notification-vault.key").encrypt(json.dumps({
                "purpose": "ezzesend-notifications", "organization": org, "credential": token}).encode()).decode()
        except Exception:
            raise NotificationError("Notification encryption unavailable; no settings were saved.") from None
        row = {"api_url": base, "enabled": enabled, "minimum_severity": minimum, "event_types": sorted(set(events)),
               "contract_version": version,
               "cooldown": cooldown, "encrypted_token": encrypted, "revision": uuid.uuid4().hex}
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("notifications:" + org, json.dumps(row)))
            self._cancel(db, org)
        return self.public(org)

    @staticmethod
    def _cancel(db, org):
        # Already-in-flight requests cannot be unsent; revision guards prevent future attempts.
        db.execute("UPDATE notification_deliveries SET status='cancelled',reason='configuration_changed' WHERE org_id=? AND status IN ('pending','retry')", (org,))

    def disable(self, org):
        with self.store.tx() as db:
            db.execute("DELETE FROM settings WHERE key=?", ("notifications:" + org,))
            self._cancel(db, org)
        return self.public(org)

    def test_connection(self, org):
        row = self.row(org)
        if not row:
            raise NotificationError("Save integration settings first.")
        # Durable, cross-worker click throttling; no messages sent by this endpoint.
        with self.store.tx() as db:
            key, now = "notification-test:" + org, time.time()
            previous = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            if previous and now - float(previous["value"]) < 30:
                raise NotificationError("Wait 30 seconds before testing the connection again.")
            db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, str(now)))
        return self.provider.call(row, self.token(row, org))

    def enqueue(self, org, server, event_type, severity, source_id, *, correlation=None, detail="", now=None, transition=False):
        now = time.time() if now is None else now
        with self.store.tx() as db:
            saved = db.execute("SELECT value FROM settings WHERE key=?", ("notifications:" + org,)).fetchone()
            row = json.loads(saved["value"]) if saved else None
            if not row or not row["enabled"]:
                return "disabled"
            if severity not in LEVELS or (event_type != "test" and (event_type not in row["event_types"] or (event_type != "resource_recovery" and LEVELS[severity] < LEVELS[row["minimum_severity"]]))):
                return "filtered"
            if event_type not in self.supported_events(row.get("contract_version", 1)) and event_type != "test":
                return "filtered"
            # A source event identifies one logical notification; retries never create another.
            source = json.dumps([server["id"], event_type, correlation, source_id, severity], separators=(",", ":"))
            event_id = hashlib.sha256(source.encode()).hexdigest()
            key = idempotency_key(org, event_id)
            if db.execute("SELECT id FROM notification_deliveries WHERE id=?", (key,)).fetchone():
                return "duplicate"
            scope = json.dumps([server["id"], correlation or event_type])
            previous = db.execute("SELECT * FROM notification_cooldowns WHERE org_id=? AND scope=?", (org, scope)).fetchone()
            cooldown = 60 if event_type == "test" else row["cooldown"]
            if previous and now - previous["last_queued"] < cooldown and not transition and not (severity == "CRITICAL" and previous["severity"] != "CRITICAL"):
                return "cooldown"
            # Hard local safety cap independent of user-selected cooldown (includes tests).
            if db.execute("SELECT COUNT(*) FROM notification_deliveries WHERE org_id=? AND created_at>?", (org, now - 3600)).fetchone()[0] >= 30:
                return "rate_limited"
            title = EVENTS.get(event_type, "Test notification — no incident")
            message = ("MEASURED FACT: " + detail + "\n" if detail else "") + "ASSESSMENT: " + title + ".\nRECOMMENDATION: Review dashboard evidence.\nAction taken: None."
            payload = {"event_id": event_id, "idempotency_key": key, "severity": severity, "event_type": event_type,
                       "server_name": str(redact(server["name"]))[:100], "title": title, "message": message,
                       "occurred_at": datetime.fromtimestamp(now, timezone.utc).isoformat()}
            if self.incident_url:
                payload["incident_url"] = self.incident_url
            db.execute("INSERT INTO notification_deliveries(id,org_id,server_id,created_at,revision,payload,status,attempts,next_attempt,lease_until,reason) VALUES(?,?,?,?,?,?,'pending',0,?,0,'')",
                       (key, org, server["id"], now, row["revision"], json.dumps(payload), now))
            db.execute("INSERT OR REPLACE INTO notification_cooldowns VALUES(?,?,?,?)", (org, scope, now, severity))
        return "pending"

    def test_notification(self, org):
        row = self.row(org)
        if not row or not row["enabled"]:
            raise NotificationError("Save and enable the provider before explicitly sending a test.")
        return self.enqueue(org, {"id": "notification-test", "name": "Control Plane test"}, "test", "HIGH", uuid.uuid4().hex)

    def observe(self, server, snapshot, analysis, *, include_resources=True):
        if server["environment"] == "simulated":
            return
        org = server["org_id"]
        configured = self.row(org)
        if not configured or not configured["enabled"]:
            return
        source = str(snapshot.get("observed_at", ""))
        for finding in analysis.get("findings", [analysis]):
            event_type = {"attack": "security_incident", "service": "service_failure", "capacity": "resource_pressure" if include_resources else None}.get(finding.get("category"))
            if event_type:
                self.enqueue(org, server, event_type, finding.get("notification_severity", "MEDIUM"), source)
        disk = snapshot.get("metrics", {}).get("disk_percent")
        if include_resources and type(disk) in (int, float) and math.isfinite(disk) and 95 <= disk <= 100:
            self.enqueue(org, server, "disk_critical", "CRITICAL", source, detail=f"Disk usage measured at {disk:.1f}%.")
        for event in snapshot.get("events", []):
            kind = event.get("kind", "")
            if not isinstance(kind, str) or not isinstance(event.get("severity", "MEDIUM"), str):
                continue
            if kind == "server_offline":
                event_type = "server_offline"
            elif kind in {"file_integrity_changed", "environment_changed", "cron_changed", "systemd_changed", "firewall_changed", "privilege_changed", "webshell_indicator"}:
                event_type = "integrity_finding"
            elif kind in {"authentication_failed", "root_login", "unexpected_ports", "unexpected_services", "unexpected_users", "suspicious_process"}:
                event_type = "security_incident"
            else:
                continue
            severity = {"WARNING": "MEDIUM"}.get(event.get("severity"), event.get("severity", "MEDIUM"))
            # No raw agent event summaries, paths, URLs, command arguments or message contents.
            detail = "No Agent telemetry received for more than 90 seconds." if kind == "server_offline" else ""
            self.enqueue(org, server, event_type, severity, source, correlation=kind, detail=detail)

    def dispatch(self, now=None, limit=4):
        now = time.time() if now is None else now
        for _ in range(limit):
            with self.store.tx() as db:
                item = db.execute("SELECT * FROM notification_deliveries WHERE (status IN ('pending','retry') AND next_attempt<=?) OR (status='sending' AND lease_until<=?) ORDER BY CASE json_extract(payload,'$.severity') WHEN 'CRITICAL' THEN 0 ELSE 1 END, created_at LIMIT 1", (now, now)).fetchone()
                if not item:
                    return
                item = dict(item)
                saved = db.execute("SELECT value FROM settings WHERE key=?", ("notifications:" + item["org_id"],)).fetchone()
                config = json.loads(saved["value"]) if saved else None
                server = db.execute("SELECT status FROM servers WHERE id=? AND org_id=?", (item["server_id"], item["org_id"])).fetchone()
                valid_server = item["server_id"] == "notification-test" or server and server["status"] != "revoked"
                if not config or not config["enabled"] or config["revision"] != item["revision"] or not valid_server:
                    db.execute("UPDATE notification_deliveries SET status='cancelled',reason='configuration_changed' WHERE id=?", (item["id"],))
                    continue
                if item["attempts"] >= 5:
                    db.execute("UPDATE notification_deliveries SET status='failed',reason='retry_exhausted' WHERE id=?", (item["id"],))
                    continue
                attempt = item["attempts"] + 1
                db.execute("UPDATE notification_deliveries SET status='sending',attempts=?,lease_until=? WHERE id=?", (attempt, now + 60, item["id"]))
            try:
                result = self.provider.call(config, self.token(config, item["org_id"]), json.loads(item["payload"]))
            except NotificationError:
                result = {"status": "failed", "reason": "credential_unavailable"}
            status = result["status"]
            if status == "retry" and attempt >= 5:
                status = "failed"
            with self.store.tx() as db:
                db.execute("UPDATE notification_deliveries SET status=?,reason=?,next_attempt=?,lease_until=0 WHERE id=? AND status='sending' AND attempts=?",
                           (status, result["reason"], now + max(result.get("delay", 30), min(1800, 30 * 2 ** (attempt - 1))), item["id"], attempt))

    def deliveries(self, org):
        return self.store.rows("SELECT id,server_id,created_at,status,attempts,reason FROM notification_deliveries WHERE org_id=? ORDER BY created_at DESC LIMIT 50", (org,))
