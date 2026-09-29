from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
from .control import ControlPlane
from .security import password_hash
from .configuration import local_overrides


def main():
    os.umask(0o077)
    root = Path(__file__).resolve().parent.parent
    overrides = local_overrides(root)
    parser = argparse.ArgumentParser(description="EzzeSecure Community — AI Operations & Security Assistant by EzzeMedia")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve", "init", "reset-password", "enrollment-token", "revoke-agent", "rotate-agent", "register-action", "baseline", "notification-tick"])
    parser.add_argument("--port", type=int, default=overrides.get("port", 8787))
    parser.add_argument("--state-dir", type=Path, help="Separate local state directory; defaults to .local")
    parser.add_argument("--bootstrap-file", type=Path, help="Exclusive private output for production initialization credentials")
    parser.add_argument("--agent-id")
    parser.add_argument("--server-id")
    parser.add_argument("--action")
    parser.add_argument("--target")
    parser.add_argument("--name", default="Local Linux Agent")
    args = parser.parse_args()
    if overrides.get("mode") == "production" and args.command == "init" and not args.bootstrap_file:
        parser.error("Production initialization requires --bootstrap-file")
    app = ControlPlane(root, state_dir=args.state_dir)
    app.listen_port = args.port
    if app.initial_password:
        if app.production:
            if not args.bootstrap_file:
                raise SystemExit("Production credentials are not logged; initialize explicitly with --bootstrap-file or reset-password")
            fd = os.open(args.bootstrap_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump({"username": app.config["username"], "password": app.initial_password}, stream)
        else:
            print(f"Initial local username: {app.config['username']}\nInitial local password: {app.initial_password}\nStore this password safely; it will not be shown again.", flush=True)
    if args.command == "serve":
        from .server import run
        run(app, args.port)
    elif args.command == "reset-password":
        password = getpass.getpass("New local password (at least 12 characters): ")
        if len(password) < 12:
            raise SystemExit("Password must contain at least 12 characters")
        with app.store.tx() as db:
            db.execute("UPDATE users SET password_hash=? WHERE id='owner'", (password_hash(password),))
            db.execute("DELETE FROM sessions")
        app.store.audit(actor="local-admin", channel="local-cli", request="reset_password", result="updated; sessions invalidated")
        print("Local password updated. All sessions invalidated.")
    elif args.command == "enrollment-token":
        print(json.dumps(app.enrollment_token(args.name)))
    elif args.command == "revoke-agent":
        print("Revoked" if app.revoke_agent(args.agent_id) else "Agent not found")
    elif args.command == "rotate-agent":
        print(json.dumps(app.rotate_agent(args.agent_id)))
    elif args.command == "register-action":
        print(json.dumps(app.register_action(args.server_id, args.action, args.target)))
    elif args.command == "notification-tick":
        app.notification_tick()
        print("Notification tick completed.")
    elif args.command == "baseline":
        print(json.dumps(app.baseline(args.server_id)))
    else:
        print("Local EzzeSecure Community initialized.")


if __name__ == "__main__":
    main()
