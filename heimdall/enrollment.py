"""Authenticated, organization-scoped Community agent identity lifecycle."""
from datetime import datetime, timezone
import secrets
import shlex
import time
import uuid

from .security import digest
from .agent.connection import validate_origin


class EnrollmentMixin:
    def _enrollment_owner(self, user):
        from .control import APIError
        if user.get("role") != "owner":
            raise APIError(403, "Owner role required")

    def create_enrollment(self, user, name=None, server_id=None):
        from .control import APIError
        self._enrollment_owner(user)
        try:
            origin = validate_origin(self.config.get("control_plane_url") or f"http://127.0.0.1:{getattr(self, 'listen_port', 8787)}")
        except ValueError:
            raise APIError(400, "Configure a valid HTTPS or loopback Control Plane origin") from None
        if server_id:
            server = self.server(server_id, user["org_id"])
            if server["environment"] == "simulated":
                raise APIError(400, "The simulated server cannot enroll")
            name = server["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 100 or any(ord(c) < 32 for c in name):
            raise APIError(400, "Use a server name between 1 and 100 characters")
        token, expires = secrets.token_urlsafe(32), time.time() + 600
        replacement = server_id is not None
        server_id = server_id or "srv-" + uuid.uuid4().hex[:12]
        with self.store.tx() as db:
            if replacement:
                self._disable_server_identity(db, server_id, user["org_id"])
                db.execute("UPDATE servers SET status='awaiting_enrollment',last_seen=NULL WHERE id=? AND org_id=?", (server_id, user["org_id"]))
            else:
                db.execute("INSERT INTO servers VALUES(?,?,?,?,?,NULL)", (server_id, user["org_id"], name.strip(), "linux", "awaiting_enrollment"))
            db.execute("INSERT INTO enrollment_tokens VALUES(?,?,?,?,0)", (digest(token), user["org_id"], server_id, expires))
        self.store.audit(org_id=user["org_id"], actor=user["id"], server_id=server_id,
                         request="reenroll_server" if replacement else "create_enrollment", result="created")
        return {"server_id": server_id, "token": token, "expires_in": 600,
                "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
                "control_plane_url": origin,
                "configure_command": f"sudo -u ezzesecure-agent /usr/bin/python3 /opt/ezzesecure-agent/agent.pyz configure --url {shlex.quote(origin)} --connection /var/lib/ezzesecure-agent/connection.json",
                "command": f"sudo -u ezzesecure-agent /usr/bin/python3 /opt/ezzesecure-agent/agent.pyz enroll --url {shlex.quote(origin)} --connection /var/lib/ezzesecure-agent/connection.json --credentials /var/lib/ezzesecure-agent/credentials.json"}

    def _disable_server_identity(self, db, server_id, org_id):
        db.execute("UPDATE agents SET enabled=0,secret='' WHERE server_id=? AND org_id=?", (server_id, org_id))
        db.execute("UPDATE enrollment_tokens SET used=1 WHERE server_id=? AND org_id=?", (server_id, org_id))
        db.execute("UPDATE action_queue SET state='revoked' WHERE server_id=? AND org_id=? AND state='pending'", (server_id, org_id))

    def manage_server(self, user, server_id, operation):
        from .control import APIError
        self._enrollment_owner(user)
        server = self.server(server_id, user["org_id"])
        if server["environment"] == "simulated":
            raise APIError(400, "The simulated server cannot be revoked or removed")
        if operation == "reenroll":
            return self.create_enrollment(user, server_id=server_id)
        if operation not in {"revoke", "remove"}:
            raise APIError(404, "Unknown server operation")
        with self.store.tx() as db:
            self._disable_server_identity(db, server_id, user["org_id"])
            if operation == "remove":
                # Preserve audit events; remove observations and pending local work.
                for table in ("snapshots", "analyses", "incidents", "notifications", "approvals", "jobs", "action_queue"):
                    db.execute(f"DELETE FROM {table} WHERE server_id=? AND org_id=?", (server_id, user["org_id"]))
                db.execute("DELETE FROM contexts WHERE server_id=?", (server_id,))
                db.execute("DELETE FROM registrations WHERE server_id=?", (server_id,))
                db.execute("DELETE FROM settings WHERE key=?", ("baseline:" + server_id,))
                db.execute("DELETE FROM servers WHERE id=? AND org_id=?", (server_id, user["org_id"]))
            else:
                db.execute("UPDATE servers SET status='revoked' WHERE id=? AND org_id=?", (server_id, user["org_id"]))
        status = "removed" if operation == "remove" else "revoked"
        self.store.audit(org_id=user["org_id"], actor=user["id"], server_id=server_id, request=operation + "_server", result=status)
        return {"server_id": server_id, "status": status}

    def safe_server(self, server_id, org_id):
        result = self.server(server_id, org_id)
        result["agent_id"] = None
        result["read_only"] = result["environment"] != "simulated"
        if not result["read_only"]:
            return result
        active = self.store.one("SELECT id,created_at FROM agents WHERE server_id=? AND org_id=? AND enabled=1", (server_id, org_id))
        if active:
            result["agent_id"] = active["id"]
            result["status"] = "enrolled"
            if result["last_seen"]:
                try:
                    age = time.time() - datetime.fromisoformat(result["last_seen"]).timestamp()
                    result["status"] = "online" if 0 <= age <= 90 else "offline"
                except (TypeError, ValueError):
                    result["status"] = "offline"
        elif result["status"] != "revoked":
            token = self.store.one("SELECT expires FROM enrollment_tokens WHERE server_id=? AND org_id=? AND used=0 ORDER BY expires DESC LIMIT 1", (server_id, org_id))
            result["status"] = ("awaiting_enrollment" if token["expires"] > time.time() else "enrollment_expired") if token else "revoked"
        return result

    def safe_servers(self, org_id):
        return [self.safe_server(row["id"], org_id) for row in self.store.rows("SELECT id FROM servers WHERE org_id=? ORDER BY name", (org_id,))]
