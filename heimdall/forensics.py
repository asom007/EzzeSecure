"""Bounded forensic receipts and local append-oriented integrity verification.

The chain detects local mutation and sequence gaps. It cannot attest that a
compromised source host told the truth, or survive an administrator rewriting
both the database and all stored hashes.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import uuid
from datetime import datetime, timezone

from .security import dumps, redact, utcnow


ZERO_HASH = "0" * 64
EVENT_TYPES = {"heartbeat", "ssh_success", "ssh_failure", "privilege_activity", "process_started",
               "network_connection", "file_created", "file_available", "file_modified", "file_deleted", "file_unavailable", "file_metadata_changed",
               "persistence_changed", "agent_interrupted", "agent_configuration_changed", "agent_restarted",
               "collector_interrupted", "collector_resumed", "canary_triggered"}
DETAIL_KEYS = {"user", "uid", "pid", "ppid", "process", "executable", "source_address", "destination_address",
               "source_port", "destination_port", "protocol", "session", "path", "change", "sha256", "mode", "owner",
               "request_method", "request_path", "request_host", "user_agent_class", "reason", "collector", "argv_count"}


def validate_event(event):
    if not isinstance(event, dict) or set(event) != {"sequence", "observed_at", "collected_at", "event_type", "source", "details"}:
        raise ValueError("Invalid forensic event schema")
    if type(event["sequence"]) is not int or event["sequence"] < 1 or event["sequence"] > 2**63 - 1:
        raise ValueError("Invalid forensic sequence")
    for key in ("observed_at", "collected_at"):
        try:
            when = datetime.fromisoformat(event[key].replace("Z", "+00:00"))
            if when.tzinfo is None or abs(time.time() - when.timestamp()) > 3600:
                raise ValueError()
        except (AttributeError, TypeError, ValueError):
            raise ValueError("Invalid forensic UTC timestamp") from None
    if not isinstance(event["event_type"], str) or event["event_type"] not in EVENT_TYPES or not isinstance(event["source"], str) or not re.fullmatch(r"[a-z0-9_.:-]{1,64}", event["source"]):
        raise ValueError("Invalid forensic source or type")
    details = event["details"]
    if not isinstance(details, dict) or len(details) > 24 or set(details) - DETAIL_KEYS:
        raise ValueError("Invalid forensic detail fields")
    cleaned = {}
    for key, value in details.items():
        if type(value) in (int, bool) and (type(value) is bool or 0 <= value <= 2**63-1):
            cleaned[key] = value
        elif isinstance(value, str) and len(value) <= 256 and "\n" not in value and "\r" not in value:
            cleaned[key] = redact(value)
        else:
            raise ValueError("Invalid forensic detail value")
    for key in ("source_address", "destination_address"):
        if key in cleaned:
            try:
                cleaned[key] = str(ipaddress.ip_address(cleaned[key]))
            except ValueError:
                raise ValueError("Invalid forensic address") from None
    return {**event, "details": cleaned}


def event_hash(agent_id, event, previous):
    body = {"agent_id": agent_id, "event": event, "previous_hash": previous}
    return hashlib.sha256(dumps(body).encode()).hexdigest()


class EvidenceLedger:
    def __init__(self, store):
        self.store = store

    def ingest(self, org, server, agent_id, batch):
        if not isinstance(batch, list) or len(batch) > 100:
            raise ValueError("Forensic batch must contain at most 100 events")
        events = [validate_event(event) for event in batch]
        if any(b["sequence"] <= a["sequence"] for a, b in zip(events, events[1:])):
            raise ValueError("Forensic sequences must increase within a batch")
        gaps = []
        with self.store.tx() as db:
            state = db.execute("SELECT * FROM evidence_streams WHERE org_id=? AND server_id=? AND agent_id=?", (org, server, agent_id)).fetchone()
            last = state["last_sequence"] if state else 0
            previous = state["last_hash"] if state else ZERO_HASH
            for event in events:
                sequence = event["sequence"]
                if sequence <= last:
                    saved = db.execute("SELECT body FROM forensic_events WHERE org_id=? AND server_id=? AND agent_id=? AND sequence=?", (org, server, agent_id, sequence)).fetchone()
                    if not saved or json.loads(saved["body"]) != event:
                        raise ValueError("Forensic sequence replay differs from stored evidence")
                    continue
                integrity = "VERIFIED"
                if sequence != last + 1:
                    gaps.append((last + 1, sequence - 1))
                    integrity = "EVIDENCE GAP"
                digest = event_hash(agent_id, event, previous)
                db.execute("INSERT INTO forensic_events(org_id,server_id,agent_id,sequence,observed_at,collected_at,received_at,event_type,source,body,previous_hash,event_hash,integrity) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (org, server, agent_id, sequence, event["observed_at"], event["collected_at"], utcnow(), event["event_type"], event["source"], dumps(event), previous, digest, integrity))
                last, previous = sequence, digest
            if events and last > (state["last_sequence"] if state else 0):
                db.execute("INSERT OR REPLACE INTO evidence_streams VALUES(?,?,?,?,?,?,?)", (org, server, agent_id, last, previous, utcnow(), "EVIDENCE GAP" if gaps else "VERIFIED"))
        return gaps

    def verify(self, org, server, agent_id):
        rows = self.store.rows("SELECT * FROM forensic_events WHERE org_id=? AND server_id=? AND agent_id=? ORDER BY sequence", (org, server, agent_id))
        if not rows:
            return {"status": "UNAVAILABLE", "count": 0, "last_verified_at": None}
        previous, sequence, gap = ZERO_HASH, 0, False
        for row in rows:
            try:
                valid = row["previous_hash"] == previous and row["event_hash"] == event_hash(agent_id, json.loads(row["body"]), previous)
            except (ValueError, TypeError, KeyError):
                valid = False
            if not valid:
                return {"status": "UNVERIFIED", "count": len(rows), "last_verified_at": None}
            if row["sequence"] != sequence + 1:
                gap = True
            sequence, previous = row["sequence"], row["event_hash"]
        state = self.store.one("SELECT * FROM evidence_streams WHERE org_id=? AND server_id=? AND agent_id=?", (org, server, agent_id))
        if not state or state["last_sequence"] != sequence or state["last_hash"] != previous:
            return {"status": "UNVERIFIED", "count": len(rows), "last_verified_at": None}
        return {"status": "EVIDENCE GAP" if gap else "VERIFIED", "count": len(rows), "last_verified_at": rows[-1]["received_at"]}

    def recent(self, org, server, limit=100):
        rows = self.store.rows("SELECT id,agent_id,sequence,observed_at,collected_at,received_at,event_type,source,body,integrity FROM forensic_events WHERE org_id=? AND server_id=? ORDER BY id DESC LIMIT ?", (org, server, min(limit, 100)))
        for row in rows:
            try:
                row["details"] = json.loads(row.pop("body"))["details"]
            except (ValueError, TypeError, KeyError):
                row["details"] = {}
                row["integrity"] = "UNVERIFIED"
        return rows
