"""Production WSGI bridge to the existing HTTP handler; never opens a socket."""
from contextlib import contextmanager
from email.message import Message
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
import fcntl
import os
import sqlite3
import stat
import threading
import time

from .control import ControlPlane
from .server import Handler


class WSGIHandler(Handler):
    def __init__(self, app, environ):
        # Bypass BaseHTTPRequestHandler's socket-oriented constructor completely.
        self.server = SimpleNamespace(app=app, server_port=0)
        self.command = environ.get("REQUEST_METHOD", "GET")
        self.path = environ.get("PATH_INFO", "/") or "/"
        if environ.get("QUERY_STRING"):
            self.path += "?" + environ["QUERY_STRING"]
        self.headers = Message()
        for key, value in environ.items():
            if key.startswith("HTTP_") and key not in {"HTTP_CONTENT_LENGTH", "HTTP_CONTENT_TYPE"}:
                self.headers[key[5:].replace("_", "-")] = value
        for key, name in (("CONTENT_TYPE", "Content-Type"), ("CONTENT_LENGTH", "Content-Length")):
            if environ.get(key):
                self.headers[name] = environ[key]
        self.client_address = (environ.get("REMOTE_ADDR", "unknown"), 0)
        self.rfile = environ["wsgi.input"]
        self.wfile = BytesIO()
        self.status = 500
        self.response_headers = []

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, keyword, value):
        self.response_headers.append((keyword, value))

    def end_headers(self):
        pass


class Application:
    def __init__(self, root):
        for name, expected in (("EZZESECURE_MODE", "production"),
                               ("EZZESECURE_DEMO_ENABLED", "false"), ("EZZESECURE_DEBUG", "false")):
            value = os.environ.setdefault(name, expected)
            if value != expected:
                raise ValueError("WSGI requires production with demo/debug disabled")
        state = os.environ.get("EZZESECURE_STATE_DIR", "")
        if not state or not Path(state).is_absolute():
            raise ValueError("WSGI requires an absolute EZZESECURE_STATE_DIR")
        self.root, self.state = Path(root).resolve(), Path(state)
        self.app = None
        self.lock = threading.Lock()
        self.last_tick = 0

    @contextmanager
    def serialized(self):
        # Serialize identity validation + ingestion across Passenger processes as
        # well as threads; the existing store RLock alone is process-local.
        with self.lock:
            info = self.state.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or any(p.is_symlink() for p in self.state.parents)):
                raise ValueError("State must be private, owned and not symlinked")
            descriptor = os.open(self.state / "wsgi.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError("Invalid private request lock")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                os.close(descriptor)

    def __call__(self, environ, start_response):
        try:
            with self.serialized():
                if self.app is None:
                    # Never generate an inaccessible initial password in a web
                    # worker. The installer/CLI initializes credentials privately.
                    database = self.state / "heimdall.sqlite3"
                    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
                        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                            raise ValueError("Explicit initialization required")
                    self.app = ControlPlane(self.root, state_dir=self.state)
                    if not self.app.production or self.app.demo_enabled or self.app.initial_password:
                        raise ValueError("Invalid production initialization")
                handler = WSGIHandler(self.app, environ)
                path = environ.get("PATH_INFO", "/") or "/"
                # WSGI paths are decoded by the host. Existing API routes are
                # ASCII: reject ambiguous/raw encoded routes before HMAC dispatch.
                raw = environ.get("RAW_URI", environ.get("REQUEST_URI", path))
                if (environ.get("SCRIPT_NAME", "") not in {"", "/"} or not path.startswith("/") or path.startswith("//")
                        or any(ord(c) < 32 or ord(c) > 126 for c in path)
                        or any(c in path for c in "%?#") or "%" in raw.split("?", 1)[0]):
                    handler.respond(400, {"error": "Unsupported request path"})
                elif handler.command not in {"GET", "POST"}:
                    handler.respond(405, {"error": "Method not allowed"})
                else:
                    handler.handle_request()
                # Passenger may stop idle workers. Do not rely on background
                # threads: daily briefs catch up on the next request, at most once
                # per 30 seconds per worker, with the shared lock above.
                if time.monotonic() - self.last_tick >= 30:
                    self.last_tick = time.monotonic()
                    try:
                        self.app.scheduled_tick()
                    except Exception:
                        self.app.store.audit(actor="system", request="scheduled_tick", result="failed")
                body = handler.wfile.getvalue()
                status = f"{handler.status} {HTTPStatus(handler.status).phrase}"
                headers = handler.response_headers
        except Exception:
            # No configuration, paths, credentials or exception details in HTTP.
            body = b'{"error":"Control Plane unavailable; initialize or review private runtime configuration"}'
            status = "503 Service Unavailable"
            headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("Cache-Control", "no-store")]
        start_response(status, headers)
        return [body]
