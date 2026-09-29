"""Loopback-only HTTP transport with same-origin sessions and bounded JSON bodies."""
from __future__ import annotations
import hmac
import json
import mimetypes
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .control import APIError, ControlPlane
from .security import digest, dumps

MAX_BODY = 256 * 1024


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app):
        if address[0] != "127.0.0.1":
            raise ValueError("Local V1 only binds to 127.0.0.1")
        self.app = app
        super().__init__(address, Handler)
        self.app.listen_port = self.server_port


class Handler(BaseHTTPRequestHandler):
    server_version = "EzzeSecure/0.1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Requests can contain secrets; the structured audit is the application log.
        pass

    @property
    def app(self):
        return self.server.app

    def respond(self, status, data, *, cookie=None, content_type="application/json; charset=utf-8"):
        body = data if isinstance(data, bytes) else dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["heimdall_session"].value if "heimdall_session" in cookie else ""
        except Exception:
            return ""

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        try:
            self.dispatch()
        except APIError as error:
            if error.status in (401, 403, 409) and self.path.startswith("/api/agent/"):
                self.app.store.audit(actor="unverified-agent", channel="agent", request="agent_request", result="denied")
            self.respond(error.status, {"error": error.message})
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            self.respond(400, {"error": "Invalid request"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.app.store.audit(actor="system", request="http_request", result="internal_error")
            self.respond(500, {"error": "An internal error occurred. Review the local audit history."})

    def dispatch(self):
        port = self.server.server_port
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        allowed_origins = {"http://" + host for host in allowed_hosts}
        if self.app.production:
            public_url = self.app.config["control_plane_url"]
            # Loopback Host remains available for tunneled agent requests.
            allowed_hosts.add(urlsplit(public_url).netloc)
            allowed_origins = {public_url}
        if self.headers.get("Host") not in allowed_hosts:
            raise APIError(403, "Untrusted Host header")
        origin = self.headers.get("Origin")
        if origin and origin not in allowed_origins:
            raise APIError(403, "Cross-origin request denied")
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            raise APIError(400, "Query parameters are not supported")
        path, method = parsed.path, self.command
        if self.headers.get("Transfer-Encoding"):
            raise APIError(400, "Transfer encoding not supported")
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY:
            raise APIError(413, "Request body too large")
        body = self.rfile.read(length) if length else b""
        if method == "GET" and body:
            raise APIError(400, "GET body not allowed")
        if method == "POST" and not self.headers.get("Content-Type", "").startswith("application/json"):
            raise APIError(415, "Use application/json")
        data = json.loads(body, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())) if body else {}
        if not isinstance(data, dict):
            raise APIError(400, "JSON object required")
        if method == "GET" and path == "/api/health":
            return self.respond(200, {"status": "ok"})
        if method == "GET" and path.startswith("/canary/"):
            try:
                self.app.trigger_canary(path.removeprefix("/canary/"), self.client_address[0])
            except Exception:
                self.app.store.audit(actor="system", request="canary_receipt", result="unavailable")
            return self.respond(404, {"error": "Not found"})
        if method == "POST" and path == "/api/login":
            username, password = data.get("username", ""), data.get("password", "")
            if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
                raise APIError(400, "Invalid login")
            token, result = self.app.login(username, password, self.client_address[0])
            secure = "; Secure" if self.app.production else ""
            return self.respond(200, result, cookie=f"heimdall_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{secure}")
        if path == "/api/integrations/form-shield/evaluate":
            if method != "POST":
                raise APIError(405, "Method not allowed")

            authorization = self.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                raise APIError(401, "Integration credential required")

            credential = self.app.trust_abuse.authenticate_credential(
                authorization[7:].strip()
            )
            if not credential:
                raise APIError(401, "Invalid integration credential")

            # The integration identity controls organization scope.
            # Client-supplied organization identifiers are ignored.
            payload = dict(data)
            payload.pop("org_id", None)
            payload["source"] = credential["label"]

            try:
                result = self.app.trust_abuse.evaluate(
                    credential["org_id"],
                    payload,
                )
            except ValueError as exc:
                raise APIError(400, str(exc)) from None

            self.app.store.audit(
                org_id=credential["org_id"],
                actor="form-shield:" + credential["id"],
                channel="integration",
                request="form_shield_evaluate",
                result=result["decision"],
                assessment={
                    "risk_score": result["risk_score"],
                    "intent": result["intent"],
                },
            )

            return self.respond(200, result)

        if path.startswith("/api/agent/"):
            if method == "POST" and path == "/api/agent/enroll":
                return self.respond(200, self.app.enroll(data))
            # Serialize identity validation and ingestion with revocation/removal.
            with self.app.store.lock:
                agent = self.app.authenticate_agent(method, self.path, self.headers, body)
                if path == "/api/agent/telemetry" and method == "POST":
                    result = self.app.ingest(agent["server_id"], agent["org_id"], data, agent_id=agent["id"])
                    return self.respond(200, {"status": "accepted", "forensic_accepted_through": result.get("forensic_accepted_through")})
                if path == "/api/agent/actions" and method == "GET":
                    return self.respond(200, self.app.agent_actions(agent))
                if path == "/api/agent/results" and method == "POST":
                    return self.respond(200, self.app.agent_result(agent, data))
                raise APIError(404, "Agent endpoint not found")
        if not path.startswith("/api/"):
            assets = {"/favicon.ico": "favicon.svg", "/favicon.svg": "favicon.svg", "/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/style.css": "style.css", "/ai-settings.js": "ai-settings.js", "/notification-settings.js": "notification-settings.js", "/operations-ui.js": "operations-ui.js", "/trust-reputation.js": "trust-reputation.js"}
            if method != "GET" or path not in assets:
                raise APIError(404, "Not found")
            asset = self.app.root / "heimdall/static" / assets[path]
            return self.respond(200, asset.read_bytes(), content_type=mimetypes.guess_type(str(asset))[0] + "; charset=utf-8")
        user = self.app.session(self.session_token())
        if method == "POST" and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), user["csrf"]):
            raise APIError(403, "CSRF validation failed")
        if path == "/api/session" and method == "GET":
            return self.respond(200, {"csrf_token": user["csrf"], "demo_enabled": self.app.demo_enabled, "user": {k: user[k] for k in ("id", "username", "org_id", "role")}})
        if path == "/api/logout" and method == "POST":
            with self.app.store.tx() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(self.session_token()),))
            return self.respond(200, {"status": "signed_out"}, cookie="heimdall_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if self.app.production else ""))
        if method == "GET":
            if path == "/api/overview":
                return self.respond(200, self.app.overview(user["org_id"]))
            if path == "/api/servers":
                return self.respond(200, {"items": self.app.safe_servers(user["org_id"])})
            if path.startswith("/api/servers/"):
                return self.respond(200, self.app.detail(path.rsplit("/", 1)[1], user["org_id"]))
            if path == "/api/notifications/settings":
                if user["role"] != "owner":
                    raise APIError(403, "Owner role required")
                return self.respond(200, {"settings": self.app.notifications.public(user["org_id"]), "deliveries": self.app.notifications.deliveries(user["org_id"])})
            if path == "/api/email/settings":
                if user["role"] != "owner":
                    raise APIError(403, "Owner role required")
                return self.respond(200, {"settings": self.app.email.public(user["org_id"], user["id"]),
                                          "routes": self.app.email.routes(user["org_id"], user["id"]),
                                          "deliveries": self.app.email.deliveries(user["org_id"], user["id"])})
            if path == "/api/canaries":
                return self.respond(200, {"items": self.app.list_canaries(user)})
            if path == "/api/ezzesend/link/status":
                if user["role"] != "owner":
                    raise APIError(403, "Owner role required")
                return self.respond(200, self.app.ezzesend_link.public())
            if path.startswith("/api/resource-policies/"):
                return self.respond(200, {"items": self.app.resource_policies(user["org_id"], path.rsplit("/", 1)[1])})
            if path == "/api/ai/settings":
                return self.respond(200, self.app.ai_settings(user))
            if path == "/api/settings":
                return self.respond(200, self.app.safe_settings(user))
            if path == "/api/trust/rules":
                return self.respond(200, self.app.trust_rules(user))
            if path == "/api/form-shield/credentials":
                if user["role"] != "owner":
                    raise APIError(403, "Owner role required")
                return self.respond(200, self.app.form_shield_credentials(user))
            if path == "/api/abuse/events":
                return self.respond(200, self.app.abuse_events(user))
            if path == "/api/reputation/findings":
                return self.respond(200, self.app.reputation_findings(user))
            if path.split("/")[-1] in {"incidents", "approvals", "audit", "analyses", "notifications", "jobs"}:
                return self.respond(200, {"items": self.app.listing(path.split("/")[-1], user["org_id"])})
        if method == "POST":
            if not self.app.demo_enabled and (path in {"/api/demo/scenario", "/api/collect", "/api/commands"} or path.startswith("/api/approvals/")):
                raise APIError(403, "Demo operations are disabled")
            if user["role"] != "owner":
                raise APIError(403, "Owner role required")
            if path in {"/api/notifications/save", "/api/notifications/disable", "/api/notifications/test-connection", "/api/notifications/test-notification"}:
                return self.respond(200, self.app.notification_request(user, path.rsplit("/", 1)[1], data))
            if path in {"/api/trust/rules/add", "/api/trust/rules/remove"}:
                return self.respond(200, self.app.trust_rule_request(user, path.rsplit("/", 1)[1], data))
            if path in {"/api/form-shield/credentials/create", "/api/form-shield/credentials/revoke"}:
                return self.respond(
                    200,
                    self.app.form_shield_credential_request(
                        user,
                        path.rsplit("/", 1)[1],
                        data,
                    ),
                )
            if path == "/api/abuse/evaluate":
                return self.respond(200, self.app.abuse_evaluate(user, data))
            if path in {"/api/abuse/events/release", "/api/abuse/events/block"}:
                return self.respond(200, self.app.abuse_event_request(user, path.rsplit("/", 1)[1], data))
            if path == "/api/reputation/findings/record":
                return self.respond(200, self.app.reputation_record(user, data))
            if path == "/api/reputation/scan":
                return self.respond(200, self.app.reputation_scan(user, data.get("domain")))
            if path in {"/api/email/save", "/api/email/test", "/api/email/route"}:
                return self.respond(200, self.app.email_request(user, path.rsplit("/", 1)[1], data))
            if path == "/api/canaries/create":
                return self.respond(200, self.app.create_canary(user, data.get("server_id"), data.get("label")))
            if path == "/api/canaries/disable":
                return self.respond(200, self.app.disable_canary(user, data.get("id")))
            if path in {"/api/ezzesend/link/start", "/api/ezzesend/link/complete"}:
                return self.respond(200, self.app.ezzesend_link_request(user, path.rsplit("/", 1)[1], data))
            if path.startswith("/api/resource-policies/"):
                return self.respond(200, self.app.save_resource_policy(user, path.rsplit("/", 1)[1], data.get("resource"), data.get("policy")))
            if path == "/api/enrollment":
                return self.respond(200, self.app.create_enrollment(user, data.get("name")))
            parts = path.split("/")
            if len(parts) == 5 and parts[1:3] == ["api", "servers"] and parts[4] in {"revoke", "remove", "reenroll"}:
                return self.respond(200, self.app.manage_server(user, parts[3], parts[4]))
            if path in {"/api/ai/test", "/api/ai/save", "/api/ai/disable", "/api/ai/analyze"}:
                return self.respond(200, self.app.ai_request(user, path.rsplit("/", 1)[1], data))
            if path == "/api/commands":
                return self.respond(200, self.app.command(user, data.get("text"), data.get("server_id", "local-demo"), data.get("channel", "console"), data.get("sender")))
            if path.startswith("/api/approvals/") and path.endswith("/confirm"):
                return self.respond(200, self.app.confirm(user, path.split("/")[3], data.get("code", "")))
            if path == "/api/collect":
                self.app.collect()
                return self.respond(200, self.app.overview(user["org_id"]))
            if path == "/api/demo/scenario":
                scenario = data.get("scenario")
                if scenario not in {"healthy", "growth", "attack", "queue", "capacity", "database"}:
                    raise APIError(400, "Unknown demo scenario")
                self.app.agent.set_scenario(scenario)
                self.app.collect()
                self.app.store.audit(org_id=user["org_id"], actor=user["id"], request="demo_scenario", result=scenario)
                return self.respond(200, self.app.overview(user["org_id"]))
            if path == "/api/brief":
                return self.respond(200, self.app.brief(user["org_id"], data.get("server_id", "local-demo")))
        raise APIError(404, "Endpoint not found")


def run(app, port=8787):
    server = Server(("127.0.0.1", port), app)
    stop = threading.Event()

    def background():
        ticks = 0
        while not stop.wait(30):
            try:
                app.notification_tick()
                app.scheduled_tick()
                ticks += 1
                if app.demo_enabled and ticks % 10 == 0:
                    app.collect()
            except Exception:
                app.store.audit(actor="system", request="scheduled_tick", result="failed")

    thread = threading.Thread(target=background, daemon=True)
    thread.start()
    print(f"EzzeSecure Community: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
