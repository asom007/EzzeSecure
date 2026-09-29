"""Optional Community BYOK: authenticated encryption, explicit I/O, bounded usage."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .providers import AnthropicProvider, OpenAICompatibleProvider, ProviderError, _NoRedirects

DEFAULT_URLS = {"openai": "https://api.openai.com/v1", "anthropic": "https://api.anthropic.com/v1"}


class AISettings:
    def __init__(self, store, local):
        self.store, self.local = store, local
        self.lock = threading.RLock()
        self.last_test = {}

    @staticmethod
    def available():
        return importlib.util.find_spec("cryptography") is not None

    def row(self, org):
        row = self.store.one("SELECT value FROM settings WHERE key=?", ("byok:" + org,))
        return json.loads(row["value"]) if row else None

    def public(self, org):
        row = self.row(org) or {}
        return {"available": self.available(), "configured": bool(row),
                "provider": row.get("provider", "openai"), "model": row.get("model", ""),
                "base_url": row.get("base_url", DEFAULT_URLS["openai"]),
                "enabled": row.get("enabled", False), "key_mask": row.get("key_mask", "Not configured"),
                "mode": "BYOK only", "daily_limit": 20}

    def cipher(self, *, create=False, key_name="ai-vault.key"):
        if not self.available():
            raise ProviderError("Optional AI encryption is not installed. Follow docs/AI_BYOK.md; monitoring remains available.")
        from cryptography.fernet import Fernet
        path = self.local / key_name
        if create and not path.exists():
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(Fernet.generate_key())
            except FileExistsError:
                pass
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 100:
                    raise ValueError()
                return Fernet(stream.read())
        except (OSError, ValueError):
            raise ProviderError("AI encryption key is unavailable or has unsafe permissions. Restore the protected key or remove and reconfigure AI.") from None

    def decrypt(self, row, org):
        from cryptography.fernet import InvalidToken
        try:
            value = json.loads(self.cipher().decrypt(row["encrypted_key"].encode()))
            if value["organization"] != org:
                raise ValueError()
            return value["credential"]
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise ProviderError("Stored AI credentials could not be unlocked. Restore the protected key or reconfigure AI.") from None

    def candidate(self, data, org):
        if not isinstance(data, dict) or not self.available():
            raise ProviderError("Install the optional AI encryption dependency before configuring BYOK.")
        provider, model = data.get("provider"), data.get("model", "")
        if provider not in {"openai", "anthropic", "openai-compatible"}:
            raise ProviderError("Choose a supported provider.")
        if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}", model):
            raise ProviderError("Enter a valid model identifier from your provider.")
        base = data.get("base_url") or DEFAULT_URLS.get(provider, "")
        if not isinstance(base, str) or len(base) > 500:
            raise ProviderError("Enter a valid provider base URL.")
        base = base.rstrip("/")
        try:
            url = urllib.parse.urlsplit(base)
            valid = url.hostname and not (url.username or url.password or url.query or url.fragment)
            valid = valid and (url.scheme == "https" or url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"})
            valid = valid and not any(c.isspace() or ord(c) < 32 for c in base)
            url.port
        except ValueError:
            valid = False
        if not valid or provider in DEFAULT_URLS and base != DEFAULT_URLS[provider]:
            raise ProviderError("Use the official provider URL, or choose OpenAI-compatible for a custom HTTPS or loopback URL.")
        key = data.get("api_key", "")
        if not isinstance(key, str):
            raise ProviderError("Enter a valid provider key.")
        prior = self.row(org)
        if not key and prior:
            if prior["provider"] != provider or prior["base_url"] != base:
                raise ProviderError("Enter a new key when changing the provider or endpoint.")
            key = self.decrypt(prior, org)
        if not 8 <= len(key) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ProviderError("Enter a valid provider key; it will never be returned after saving.")
        enabled = data.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ProviderError("Enabled must be a boolean setting.")
        return {"provider": provider, "model": model, "base_url": base, "enabled": enabled}, key

    def test_connection(self, config, key):
        headers = {"Accept": "application/json"}
        if config["provider"] == "anthropic":
            headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
        else:
            headers["Authorization"] = "Bearer " + key
        endpoint = config["base_url"] + "/models/" + urllib.parse.quote(config["model"], safe="")
        request = urllib.request.Request(endpoint, headers=headers, method="GET")
        try:
            # Do not inherit a workstation proxy or follow redirects carrying credentials.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects)
            with opener.open(request, timeout=8) as response:
                raw = response.read(32769)
            if len(raw) > 32768 or json.loads(raw).get("id") != config["model"]:
                raise ValueError()
        except (OSError, ValueError, AttributeError, TypeError):
            raise ProviderError("Connection test failed. Check the key, model, endpoint and network. The provider must support model retrieval; no changes were saved.") from None
        return "Connection verified for this model. No inference request was made; structured review compatibility is checked when you request a review."

    def configure(self, action, data, org):
        with self.lock:
            if action == "disable":
                row = self.row(org)
                with self.store.tx() as db:
                    if data.get("remove") is True:
                        db.execute("DELETE FROM settings WHERE key=?", ("byok:" + org,))
                    elif row:
                        row["enabled"] = False
                        db.execute("UPDATE settings SET value=? WHERE key=?", (json.dumps(row), "byok:" + org))
                return {"message": "AI disabled. Monitoring remains active.", "settings": self.public(org)}
            if action not in {"test", "save"}:
                raise ProviderError("Unsupported AI settings operation.")
            config, key = self.candidate(data, org)
            # Avoid accidental click bursts without spending inference tokens.
            if time.monotonic() - self.last_test.get(org, -100) < 2:
                raise ProviderError("Wait two seconds before testing again.")
            self.last_test[org] = time.monotonic()
            message = self.test_connection(config, key)
            if action == "save":
                encrypted = self.cipher(create=not bool(self.row(org))).encrypt(json.dumps({"organization": org, "credential": key}).encode()).decode()
                row = {**config, "key_mask": "••••••••" + key[-4:], "encrypted_key": encrypted}
                with self.store.tx() as db:
                    db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("byok:" + org, json.dumps(row)))
                message = "Provider verified and saved. AI reviews run only when requested."
            return {"message": message, "settings": self.public(org)}

    def analyze(self, org, evidence, history):
        with self.lock:
            row = self.row(org)
            if not row or not row["enabled"]:
                raise ProviderError("Optional AI is disabled. Configure BYOK in Settings; deterministic analysis is already available.")
            if not self.available():
                raise ProviderError("Optional AI encryption dependency is unavailable.")
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            with self.store.tx() as db:
                count = db.execute("SELECT COALESCE(SUM(calls),0) FROM usage WHERE org_id=? AND created_at>=?", (org, day)).fetchone()[0]
                if count >= 20:
                    raise ProviderError("Daily AI review limit reached (20 attempts). Monitoring remains available.")
                # Count failed attempts too, before network I/O. This budget survives restarts.
                db.execute("INSERT INTO usage(org_id,created_at,provider,input_tokens,output_tokens,calls) VALUES(?,?,?,?,?,1)",
                           (org, datetime.now(timezone.utc).isoformat(), row["provider"], 0, 0))
            key = self.decrypt(row, org)
            cls = AnthropicProvider if row["provider"] == "anthropic" else OpenAICompatibleProvider
            endpoint = row["base_url"] + ("/messages" if row["provider"] == "anthropic" else "/chat/completions")
            provider = cls(endpoint=endpoint, model=row["model"], api_key=key, max_calls=1, timeout_seconds=10)
            provider._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects)
            return provider.analyze(evidence, history)
