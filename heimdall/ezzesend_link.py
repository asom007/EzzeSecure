"""Opt-in client for a future EzzeSend-owned verified phone linking contract.

No phone number proves ownership. The provider must authenticate/verify the
existing EzzeSend account and return a one-use scoped grant before linking.
The flow is unavailable until an operator configures a reviewed provider API.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time

from .notification_delivery import endpoint, http_transport, NotificationError


PHONE = re.compile(r"\+[1-9][0-9]{7,14}\Z")
OPAQUE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")


class EzzeSendLink:
    def __init__(self, store, notifications, transport=None, api_url=None):
        self.store, self.notifications = store, notifications
        self.transport = transport or http_transport
        candidate = api_url if api_url is not None else os.environ.get("EZZESECURE_EZZESEND_LINK_API_URL", "")
        self.api_url = endpoint(candidate) if candidate else None

    def public(self):
        return {"available": bool(self.api_url), "status": "Provider linking API required" if not self.api_url else "Ready for verified account linking"}

    def _call(self, path, payload):
        try:
            code, raw, _ = self.transport("POST", self.api_url + path,
                                          {"Accept": "application/json", "Content-Type": "application/json"}, payload)
            if code not in (200, 202) or len(raw) > 8192:
                raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except Exception:
            # Provider bodies/exceptions could contain personal data or tokens.
            raise NotificationError("EzzeSend verified linking is unavailable; retry or check provider support.") from None

    def start(self, user, phone):
        if not self.api_url:
            raise NotificationError("EzzeSend has not provided the verified linking API contract.")
        if user["role"] != "owner" or not isinstance(phone, str) or not PHONE.fullmatch(phone):
            raise NotificationError("Owner sign-in and a valid registered phone number are required.")
        if self.store.one("SELECT 1 FROM ezzesend_link_challenges WHERE org_id=? AND user_id=? AND used=0 AND expires>? LIMIT 1",
                          (user["org_id"], user["id"], time.time())):
            raise NotificationError("A linking challenge is already active; finish it or wait for expiry.")
        state = secrets.token_urlsafe(32)
        result = self._call("/link/challenges", {"phone": phone, "state_hash": hashlib.sha256(state.encode()).hexdigest(),
                                                 "scope": "ezzesecure.notifications:create"})
        challenge = result.get("challenge_id")
        expires = result.get("expires_in")
        if result.get("status") != "challenge_pending" or not isinstance(challenge, str) or not OPAQUE.fullmatch(challenge) or type(expires) is not int or not 1 <= expires <= 300:
            raise NotificationError("EzzeSend returned an invalid linking challenge.")
        local_id = secrets.token_urlsafe(24)
        with self.store.tx() as db:
            db.execute("INSERT INTO ezzesend_link_challenges VALUES(?,?,?,?,?,?,0)",
                       (local_id, user["org_id"], user["id"], challenge, hashlib.sha256(state.encode()).hexdigest(),
                        time.time() + expires))
        return {"challenge_id": local_id, "state": state, "expires_in": expires,
                "message": "Verify the account in EzzeSend, then enter its one-time authorization code here."}

    def complete(self, user, challenge_id, state, grant_code):
        if not self.api_url:
            raise NotificationError("EzzeSend verified linking is unavailable.")
        if user["role"] != "owner" or any(not isinstance(v, str) or not OPAQUE.fullmatch(v) for v in (challenge_id, state, grant_code)):
            raise NotificationError("Invalid linking response")
        with self.store.tx() as db:
            row = db.execute("SELECT * FROM ezzesend_link_challenges WHERE id=? AND org_id=? AND user_id=? AND used=0 AND expires>?",
                             (challenge_id, user["org_id"], user["id"], time.time())).fetchone()
            if not row or not secrets.compare_digest(row["state_hash"], hashlib.sha256(state.encode()).hexdigest()):
                raise NotificationError("Linking challenge expired or already used")
            db.execute("UPDATE ezzesend_link_challenges SET used=1 WHERE id=?", (challenge_id,))
        result = self._call("/link/exchange", {"challenge_id": row["provider_id"], "state": state,
                                               "grant_code": grant_code, "scope": "ezzesecure.notifications:create"})
        credential = result.get("integration_credential")
        if (result.get("status") != "authorized" or result.get("scope") != "ezzesecure.notifications:create"
                or result.get("contract_version") != 2 or not isinstance(credential, str)
                or not 16 <= len(credential) <= 4096 or not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", credential)):
            raise NotificationError("EzzeSend did not return a valid scoped integration credential.")
        settings = self.notifications.configure(user["org_id"], {"api_url": self.api_url, "enabled": True,
            "token": credential, "minimum_severity": "MEDIUM", "event_types": list(self.notifications.supported_events(2)),
            "cooldown": 300, "contract_version": 2})
        return {"status": "linked", "settings": settings}
