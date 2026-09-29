"""Small SQLite persistence layer; transactions serialize security state transitions."""
from __future__ import annotations
import contextlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from .security import dumps, redact, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS organizations(id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, org_id TEXT NOT NULL, channel TEXT NOT NULL, address TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, UNIQUE(channel,address));
CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL, environment TEXT NOT NULL, status TEXT NOT NULL, last_seen TEXT);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, secret TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment_tokens(token_hash TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS nonces(agent_id TEXT NOT NULL, nonce TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(agent_id,nonce));
CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, correlation_key TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, count INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_notified REAL NOT NULL, data TEXT NOT NULL, UNIQUE(org_id,server_id,correlation_key));
CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, created_at TEXT NOT NULL, severity TEXT NOT NULL, channel TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL, incident_id TEXT);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, actor TEXT NOT NULL, channel TEXT NOT NULL, identity_id TEXT NOT NULL, action TEXT NOT NULL, parameters TEXT NOT NULL, code_hash TEXT NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, org_id TEXT NOT NULL, server_id TEXT, actor TEXT NOT NULL, channel TEXT NOT NULL, identity_id TEXT, request TEXT, intent TEXT, tools TEXT, command_class TEXT, approval_state TEXT, action TEXT, result TEXT, assessment TEXT, incident_id TEXT);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, parameters TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, result TEXT);
CREATE TABLE IF NOT EXISTS action_queue(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, agent_id TEXT NOT NULL, action TEXT NOT NULL, parameters TEXT NOT NULL, state TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS contexts(actor TEXT NOT NULL, server_id TEXT NOT NULL, channel TEXT NOT NULL, identity_id TEXT NOT NULL, expires REAL NOT NULL, data TEXT NOT NULL, PRIMARY KEY(actor,server_id,channel,identity_id));
CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, created_at TEXT NOT NULL, provider TEXT NOT NULL, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL, calls INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS registrations(server_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, PRIMARY KEY(server_id,action,target));
CREATE TABLE IF NOT EXISTS notification_deliveries(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, created_at REAL NOT NULL, revision TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, next_attempt REAL NOT NULL, lease_until REAL NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notification_cooldowns(org_id TEXT NOT NULL, scope TEXT NOT NULL, last_queued REAL NOT NULL, severity TEXT NOT NULL, PRIMARY KEY(org_id,scope));
CREATE TABLE IF NOT EXISTS resource_policies(org_id TEXT NOT NULL, server_id TEXT NOT NULL, resource TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(org_id,server_id,resource));
CREATE TABLE IF NOT EXISTS resource_alerts(org_id TEXT NOT NULL, server_id TEXT NOT NULL, resource TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(org_id,server_id,resource));
CREATE TABLE IF NOT EXISTS incident_timeline(id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL, org_id TEXT NOT NULL, server_id TEXT NOT NULL, observed_at TEXT NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL, evidence_id INTEGER, confidence TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS incident_timeline_recent ON incident_timeline(org_id,server_id,id DESC);
CREATE TABLE IF NOT EXISTS forensic_events(id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, agent_id TEXT NOT NULL, sequence INTEGER NOT NULL, observed_at TEXT NOT NULL, collected_at TEXT NOT NULL, received_at TEXT NOT NULL, event_type TEXT NOT NULL, source TEXT NOT NULL, body TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, integrity TEXT NOT NULL, UNIQUE(org_id,server_id,agent_id,sequence));
CREATE INDEX IF NOT EXISTS forensic_recent ON forensic_events(org_id,server_id,id DESC);
CREATE TABLE IF NOT EXISTS evidence_streams(org_id TEXT NOT NULL, server_id TEXT NOT NULL, agent_id TEXT NOT NULL, last_sequence INTEGER NOT NULL, last_hash TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(org_id,server_id,agent_id));
CREATE TABLE IF NOT EXISTS canaries(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_id TEXT NOT NULL, label TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, last_trigger REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS notification_routes(org_id TEXT NOT NULL, user_id TEXT NOT NULL, server_id TEXT NOT NULL, channel TEXT NOT NULL, event_class TEXT NOT NULL, min_severity TEXT NOT NULL, enabled INTEGER NOT NULL, PRIMARY KEY(org_id,user_id,server_id,channel,event_class));
CREATE TABLE IF NOT EXISTS email_deliveries(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, server_id TEXT NOT NULL, created_at TEXT NOT NULL, event_class TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS email_outbox(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, server_id TEXT NOT NULL, event_class TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL, created_at REAL NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, next_attempt REAL NOT NULL);
CREATE INDEX IF NOT EXISTS email_due ON email_outbox(status,next_attempt);
CREATE TABLE IF NOT EXISTS trust_rules(
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    list_type TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    reason TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at REAL,
    UNIQUE(org_id,list_type,kind,value)
);
CREATE INDEX IF NOT EXISTS trust_rules_org ON trust_rules(org_id,list_type,kind);

CREATE TABLE IF NOT EXISTS abuse_events(
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_epoch REAL NOT NULL,
    source TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    intent TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS abuse_events_recent ON abuse_events(org_id,created_epoch DESC);
CREATE INDEX IF NOT EXISTS abuse_events_fingerprint ON abuse_events(org_id,fingerprint,created_epoch);

CREATE TABLE IF NOT EXISTS form_shield_credentials(
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS form_shield_credentials_org
ON form_shield_credentials(org_id,enabled);

CREATE TABLE IF NOT EXISTS reputation_findings(
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    observed_epoch REAL NOT NULL,
    evidence TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reputation_recent ON reputation_findings(org_id,domain,observed_epoch DESC);
CREATE TABLE IF NOT EXISTS ezzesend_link_challenges(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, provider_id TEXT NOT NULL, state_hash TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS notification_due ON notification_deliveries(status,next_attempt);
CREATE INDEX IF NOT EXISTS snapshots_server ON snapshots(org_id,server_id,id DESC);
CREATE INDEX IF NOT EXISTS audit_org ON audit(org_id,id DESC);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path, self.lock = path, threading.RLock()
        with self.tx() as db:
            db.executescript(SCHEMA)
        os.chmod(path, 0o600)

    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def rows(self, sql, values=()):
        with self.tx() as db:
            return [dict(row) for row in db.execute(sql, values)]

    def one(self, sql, values=()):
        rows = self.rows(sql, values)
        return rows[0] if rows else None

    def audit(self, org_id="local", server_id=None, actor="anonymous", channel="console", **fields):
        allowed = ["identity_id", "request", "intent", "tools", "command_class", "approval_state", "action", "result", "assessment", "incident_id"]
        values = [utcnow(), org_id, server_id, actor, channel]
        for key in allowed:
            value = redact(fields.get(key))
            values.append(dumps(value) if isinstance(value, (dict, list)) else value)
        with self.tx() as db:
            db.execute("INSERT INTO audit(timestamp,org_id,server_id,actor,channel," + ",".join(allowed) + ") VALUES(" + ",".join("?" for _ in values) + ")", values)


def decode_rows(rows):
    for row in rows:
        for key in ("data", "parameters", "result", "tools"):
            if row.get(key):
                try:
                    value = json.loads(row[key])
                    if key == "data" and isinstance(value, dict):
                        row.update(value)
                        del row[key]
                    else:
                        row[key] = value
                except (ValueError, TypeError):
                    pass
    return rows
