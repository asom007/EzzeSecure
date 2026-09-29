"""Independent Community SMTP delivery with durable, scoped routing.

SMTP credentials are read only from the Control Plane process environment;
they never enter SQLite, responses, frontend state or the outbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import smtplib
import ssl
import time
from email.message import EmailMessage

from .security import dumps, redact, utcnow


SEVERITY = {"INFO": 0, "WARNING": 1, "ELEVATED": 2, "HIGH": 3,
            "CRITICAL": 4, "SEVERE": 5, "EMERGENCY": 6}
CLASSES = {"resource", "security", "recovery", "agent_lost", "canary", "test"}
EMAIL = re.compile(r"[A-Za-z0-9_.+%-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\Z")
HOST = re.compile(r"[A-Za-z0-9.-]{1,253}\Z")


def smtp_send(config, recipient, subject, body):
    message = EmailMessage()
    message["From"] = config["sender"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    if config["tls_mode"] == "ssl":
        transport = smtplib.SMTP_SSL(config["host"], config["port"], timeout=8, context=ssl.create_default_context())
    else:
        transport = smtplib.SMTP(config["host"], config["port"], timeout=8)
    with transport as connection:
        if config["tls_mode"] == "starttls":
            connection.starttls(context=ssl.create_default_context())
        username = os.environ.get("EZZESECURE_SMTP_USERNAME", "")
        password = os.environ.get("EZZESECURE_SMTP_PASSWORD", "")
        if username:
            if not password or config["tls_mode"] == "local":
                raise ValueError("SMTP credential unavailable")
            connection.login(username, password)
        connection.send_message(message)


class EmailDispatcher:
    def __init__(self, store, sender=None):
        self.store = store
        self.sender = sender or smtp_send

    def row(self, org):
        item = self.store.one("SELECT value FROM settings WHERE key=?", ("email:" + org,))
        return json.loads(item["value"]) if item else None

    def public(self, org, user_id):
        config = self.row(org) or {}
        identity = self.store.one("SELECT address FROM identities WHERE org_id=? AND user_id=? AND channel='email'", (org, user_id))
        return {"enabled": config.get("enabled", False), "host": config.get("host", ""),
                "port": config.get("port", 587), "tls_mode": config.get("tls_mode", "starttls"),
                "sender": config.get("sender", ""), "recipient": identity["address"] if identity else "",
                "credential_present": bool(os.environ.get("EZZESECURE_SMTP_USERNAME") and os.environ.get("EZZESECURE_SMTP_PASSWORD"))}

    def configure(self, org, user_id, data):
        if not isinstance(data, dict):
            raise ValueError("Invalid email settings")
        host, port, mode = data.get("host"), data.get("port"), data.get("tls_mode")
        sender, recipient, enabled = data.get("sender"), data.get("recipient"), data.get("enabled")
        if (not isinstance(host, str) or not HOST.fullmatch(host) or type(port) is not int or not 1 <= port <= 65535
                or mode not in {"ssl", "starttls", "local"} or type(enabled) is not bool
                or not isinstance(sender, str) or not EMAIL.fullmatch(sender)
                or not isinstance(recipient, str) or not EMAIL.fullmatch(recipient)):
            raise ValueError("Choose a valid SMTP host, port, TLS mode and email addresses")
        if mode == "local" and host not in {"localhost", "127.0.0.1"}:
            raise ValueError("Unencrypted SMTP is allowed only for loopback delivery")
        config = {"enabled": enabled, "host": host, "port": port, "tls_mode": mode, "sender": sender}
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("email:" + org, dumps(config)))
            db.execute("DELETE FROM identities WHERE org_id=? AND user_id=? AND channel='email'", (org, user_id))
            db.execute("INSERT INTO identities VALUES(?,?,?,?,?,1)", ("email:" + user_id, user_id, org, "email", recipient))
            # Explicit defaults are scoped to this user; routes remain editable.
            for event_class, level in (("resource", "WARNING"), ("security", "WARNING"), ("recovery", "INFO"),
                                       ("agent_lost", "HIGH"), ("canary", "HIGH")):
                db.execute("INSERT OR IGNORE INTO notification_routes VALUES(?,?,?,?,?,?,1)", (org, user_id, "*", "email", event_class, level))
        return self.public(org, user_id)

    def route(self, org, user_id, server_id, channel, event_class, minimum, enabled):
        if (channel != "email" or event_class not in CLASSES - {"test"}
                or minimum not in SEVERITY or type(enabled) is not bool):
            raise ValueError("Invalid notification route")
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO notification_routes VALUES(?,?,?,?,?,?,?)",
                       (org, user_id, server_id, channel, event_class, minimum, int(enabled)))

    def routes(self, org, user_id):
        return self.store.rows("SELECT server_id,channel,event_class,min_severity,enabled FROM notification_routes WHERE org_id=? AND user_id=? ORDER BY server_id,channel,event_class", (org, user_id))

    def enqueue(self, org, server_id, event_class, severity, source_id, summary, *, test_user=None):
        if event_class not in CLASSES or severity not in SEVERITY:
            raise ValueError("Invalid notification classification")
        config = self.row(org)
        if not config or not config["enabled"]:
            return 0
        users = self.store.rows("SELECT user_id,address FROM identities WHERE org_id=? AND channel='email' AND enabled=1", (org,))
        queued = 0
        with self.store.tx() as db:
            for user in users:
                if test_user and user["user_id"] != test_user:
                    continue
                if event_class != "test":
                    route = db.execute("SELECT * FROM notification_routes WHERE org_id=? AND user_id=? AND server_id IN (?, '*') AND channel='email' AND event_class=? ORDER BY (server_id=?) DESC LIMIT 1",
                                       (org, user["user_id"], server_id, event_class, server_id)).fetchone()
                    if not route or not route["enabled"] or SEVERITY[severity] < SEVERITY[route["min_severity"]]:
                        continue
                identifier = hashlib.sha256(dumps([org, user["user_id"], server_id, event_class, severity, source_id]).encode()).hexdigest()
                safe_summary = redact(summary)[:300]
                if db.execute("SELECT COUNT(*) FROM email_outbox WHERE org_id=? AND created_at>?", (org, time.time() - 3600)).fetchone()[0] >= 60:
                    break
                cursor = db.execute("INSERT OR IGNORE INTO email_outbox VALUES(?,?,?,?,?,?,?,?, 'pending',0,?)",
                                    (identifier, org, user["user_id"], server_id, event_class, severity, safe_summary, time.time(), time.time()))
                queued += cursor.rowcount
        return queued

    def test(self, org, user_id):
        return self.enqueue(org, "control-plane", "test", "INFO", str(time.time()),
                            "EzzeSecure Community SMTP test. No incident was generated.", test_user=user_id)

    def dispatch(self, now=None, limit=4):
        now = time.time() if now is None else now
        due = self.store.rows("SELECT * FROM email_outbox WHERE status IN ('pending','retry','sending') AND next_attempt<=? ORDER BY created_at LIMIT ?", (now, limit))
        for item in due:
            with self.store.tx() as db:
                claimed = db.execute("UPDATE email_outbox SET status='sending',next_attempt=? WHERE id=? AND status=? AND next_attempt<=?",
                                     (now + 60, item["id"], item["status"], now)).rowcount
            if not claimed:
                continue
            config = self.row(item["org_id"])
            recipient = self.store.one("SELECT address FROM identities WHERE org_id=? AND user_id=? AND channel='email' AND enabled=1",
                                       (item["org_id"], item["user_id"]))
            if not config or not config["enabled"] or not recipient:
                status, reason = "cancelled", "configuration_disabled"
            else:
                try:
                    name = self.store.one("SELECT name FROM servers WHERE id=? AND org_id=?", (item["server_id"], item["org_id"]))
                    server_name = name["name"] if name else "Control Plane"
                    subject = f"EzzeSecure {item['severity']} {item['event_class'].replace('_', ' ')}"
                    body = (f"Server: {server_name}\nObserved: {item['summary']}\n"
                            "Review EzzeSecure for evidence and recommendations.\nAction taken on monitored host: none.\n")
                    self.sender(config, recipient["address"], subject, body)
                    status, reason = "sent", "accepted_by_smtp"
                except Exception:
                    status, reason = ("failed", "delivery_failed") if item["attempts"] >= 4 else ("retry", "delivery_unavailable")
            with self.store.tx() as db:
                db.execute("UPDATE email_outbox SET status=?,attempts=attempts+1,next_attempt=? WHERE id=?",
                           (status, now + min(1800, 30 * 2 ** item["attempts"]), item["id"]))
                db.execute("INSERT OR REPLACE INTO email_deliveries VALUES(?,?,?,?,?,?,?,?)",
                           (item["id"], item["org_id"], item["user_id"], item["server_id"], utcnow(), item["event_class"], status, reason))

    def deliveries(self, org, user_id):
        return self.store.rows("SELECT server_id,created_at,event_class,status,reason FROM email_deliveries WHERE org_id=? AND user_id=? ORDER BY created_at DESC LIMIT 30", (org, user_id))
