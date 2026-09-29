"""Outbound-only signed HTTPS/loopback transport; optional Cloudflare Access."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit
import hashlib
import hmac
import http.client
import json
import os
import ssl
import time
import uuid

from .connection import access_headers, read_private_json, validate_origin


def signature(secret: str, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    canonical = "\n".join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest()))
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


class LocalAgentClient:
    def __init__(self, base_url: str, agent_id: str | None = None, secret: str | None = None, *, cloudflare_access=None):
        origin = validate_origin(base_url)
        url = urlsplit(origin)
        self.scheme = url.scheme
        self.host, self.port = url.hostname, url.port or (443 if self.scheme == "https" else 80)
        self._access_headers = access_headers(origin, cloudflare_access)
        self.agent_id, self.secret = agent_id, secret

    def _request(self, method: str, path: str, payload: dict | None = None, signed=True) -> dict:
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode() if payload is not None else b""
        if len(body) > 262144:
            raise ValueError("Agent payload exceeds 256 KiB")
        headers = {"Content-Type": "application/json", **self._access_headers}
        if signed:
            if not self.agent_id or not self.secret:
                raise ValueError("Agent credentials required")
            timestamp, nonce = str(int(time.time())), uuid.uuid4().hex
            headers.update({"X-Agent-ID": self.agent_id, "X-Agent-Timestamp": timestamp,
                            "X-Agent-Nonce": nonce,
                            "X-Agent-Signature": signature(self.secret, method, path, timestamp, nonce, body)})
        connection = (http.client.HTTPSConnection(self.host, self.port, timeout=10, context=ssl.create_default_context())
                      if self.scheme == "https" else http.client.HTTPConnection(self.host, self.port, timeout=10))
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(262145)
            if len(raw) > 262144:
                raise RuntimeError("Control-plane response exceeded size limit")
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Control plane returned HTTP {response.status}")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise RuntimeError("Control plane returned an invalid object")
            return result
        finally:
            connection.close()

    def enroll(self, token: str, name: str, credentials_path: Path) -> dict:
        credentials_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Reserve before consuming a one-use token; never overwrite an identity.
        descriptor = os.open(credentials_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            result = self._request("POST", "/api/agent/enroll", {"token": token, "name": name}, signed=False)
            for key in ("agent_id", "secret", "server_id"):
                if not isinstance(result.get(key), str) or not result[key]:
                    raise RuntimeError("Invalid enrollment response")
            with os.fdopen(descriptor, "w") as stream:
                descriptor = None
                json.dump(result, stream)
                stream.flush()
                os.fsync(stream.fileno())
            self.agent_id, self.secret = result["agent_id"], result["secret"]
            return {"agent_id": result["agent_id"], "server_id": result["server_id"]}
        finally:
            if descriptor is not None:
                os.close(descriptor)
                credentials_path.unlink(missing_ok=True)

    @classmethod
    def from_credentials(cls, base_url: str, credentials_path: Path, *, cloudflare_access=None):
        credentials = read_private_json(credentials_path)
        return cls(base_url, credentials["agent_id"], credentials["secret"], cloudflare_access=cloudflare_access)

    def poll_once(self, agent) -> dict:
        snapshot = agent.collect()
        accepted = self._request("POST", "/api/agent/telemetry", snapshot)
        if hasattr(agent, "acknowledge"):
            agent.acknowledge(accepted.get("forensic_accepted_through"))
        # Real Linux agents never fetch or execute actions, even from a compromised control plane.
        from .runtime import DemoAgent
        if not isinstance(agent, DemoAgent):
            return {"telemetry_sent": True, "results": []}
        actions = self._request("GET", "/api/agent/actions").get("items", [])
        if not isinstance(actions, list) or len(actions) > 100:
            raise RuntimeError("Invalid or excessive pending action batch")
        results = []
        for action in actions:
            if not isinstance(action, dict) or not isinstance(action.get("id"), str):
                raise RuntimeError("Malformed queued action")
            result = agent.execute(action.get("action"), action.get("parameters", {}), action["id"])
            self._request("POST", "/api/agent/results", {"id": action["id"], "result": result})
            results.append({"id": action["id"], "status": result["status"]})
        return {"telemetry_sent": True, "results": results}
