"""Local HTTP boundary; optional ASGI wrapper is provided for container labs."""

import json
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .auth import authenticate
from .app import scope
from .ml import train, promote, predict, drift
from .synthetic import ml_dataset

STATIC = Path(__file__).with_name("static")
MAX = 2 * 1024 * 1024


def route(app, actor, method, path, data=None):
    data = data or {}
    if "tenant_id" in data or "tenant" in data:
        raise PermissionError("Tenant is derived from the authenticated token")
    tenant = actor["tenant"]
    if method == "POST" and path == "/api/events/detail":
        scope(actor, {"analyst", "cloud", "compliance", "approver"})
        item = app.store.get(tenant, "event", data.get("id"))
        if actor["role"] == "cloud" and item["source"] not in ("cloud", "kubernetes"):
            raise PermissionError("Event outside role scope")
        return item
    if method == "POST" and path == "/api/alerts/triage":
        return app.triage(actor, data)
    if method == "POST" and path == "/api/assets":
        return app.save_asset(actor, data)
    if method == "POST" and path == "/api/cases/update":
        return app.update_case(actor, data)
    if method == "GET" and path == "/api/activity":
        return app.activity(actor)
    if method == "POST" and path == "/api/sample-data":
        scope(actor, {"analyst"})
        from .synthetic import scenarios

        return app.ingest(actor, scenarios())
    if method == "POST" and path == "/api/assistant/generate":
        from .assistant import generate

        return generate(app, actor, data.get("case_id"))
    if method == "POST" and path == "/api/assistant/review":
        from .assistant import review

        return review(app, actor, data)
    if method == "POST" and path == "/api/ledger/deploy":
        from .evidence_ledger import deploy

        return deploy(app, actor)
    if method == "POST" and path == "/api/ledger/anchor":
        from .evidence_ledger import anchor

        return anchor(app, actor, data.get("id"))
    if method == "POST" and path == "/api/ledger/verify":
        from .evidence_ledger import verify

        return verify(app, actor, data.get("id"), data.get("document"))
    if method == "GET" and path == "/api/state":
        return app.state(actor)
    if method == "GET" and path == "/api/audit":
        scope(actor, {"compliance", "analyst"})
        return app.store.verify_audit(tenant)
    if method == "POST" and path == "/api/events":
        return app.ingest(actor, data.get("events"), bool(data.get("queued", False)))
    if method == "POST" and path == "/api/worker":
        return app.work(actor)
    if method == "POST" and path == "/api/cases":
        return app.case(actor, data.get("alert_id"), data.get("note"))
    if method == "POST" and path == "/api/cases/review":
        return app.review_case(
            actor,
            data.get("id"),
            data.get("status"),
            data.get("note"),
            data.get("verification", ""),
        )
    if method == "POST" and path == "/api/runs":
        return app.request_run(actor, data.get("case_id"), data.get("playbook"))
    if method == "POST" and path == "/api/runs/approve":
        return app.approve(
            actor, data.get("id"), data.get("decision"), data.get("note")
        )
    if method == "POST" and path == "/api/runs/execute":
        return app.execute(actor, data.get("id"), bool(data.get("rollback", False)))
    if method == "POST" and path == "/api/evidence":
        return app.report(actor)
    if method == "POST" and path == "/api/models/train":
        return train(app, actor, ml_dataset())
    if method == "POST" and path == "/api/models/promote":
        return promote(app, actor, data.get("id"))
    if method == "POST" and path == "/api/models/score":
        scope(actor, {"analyst"})
        model = app.store.get(tenant, "model", data.get("model_id"))
        from .normalise import normalise

        event = normalise(data.get("event"), tenant, app.key)
        import hashlib
        from .store import canonical

        if (
            hashlib.sha256(canonical(model["model"]).encode()).hexdigest()
            != model["model_sha256"]
        ):
            raise ValueError("Model digest mismatch")
        return predict(model["model"], event)
    raise ValueError("Unknown API route")


def make_server(app, config, port=8765):
    hits = defaultdict(deque)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def reply(self, status, value, mime="application/json"):
            body = (
                json.dumps(value, allow_nan=False).encode()
                if mime == "application/json"
                else value
            )
            self.send_response(status)
            for k, v in {
                "Content-Type": mime,
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def dispatch(self):
            allowed = {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
            if self.headers.get("Host") not in allowed:
                return self.reply(403, {"error": "Invalid Host"})
            if self.headers.get("Origin") and self.headers["Origin"] not in {
                "http://" + h for h in allowed
            }:
                return self.reply(403, {"error": "Origin rejected"})
            path = self.path.split("?", 1)[0]
            files = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript"),
                "/style.css": ("style.css", "text/css"),
            }
            if self.command == "GET" and path in files:
                name, mime = files[path]
                return self.reply(200, (STATIC / name).read_bytes(), mime)
            if path == "/healthz":
                return self.reply(
                    200, {"status": "ok", "application": "SecureFI", "version": "2.1.0"}
                )
            try:
                actor = authenticate(config, self.headers.get("Authorization"))
                queue = hits[actor["id"]]
                now = time.monotonic()
                while queue and now - queue[0] > 60:
                    queue.popleft()
                if len(queue) >= 180:
                    return self.reply(429, {"error": "Rate limit exceeded"})
                queue.append(now)
                data = {}
                if self.command == "POST":
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX:
                        return self.reply(
                            413, {"error": "Body must be 1 byte to 2 MiB"}
                        )
                    if (
                        self.headers.get("Transfer-Encoding")
                        or self.headers.get_content_type() != "application/json"
                    ):
                        raise ValueError(
                            "application/json with Content-Length required"
                        )
                    data = json.loads(
                        self.rfile.read(length),
                        parse_constant=lambda _: (_ for _ in ()).throw(
                            ValueError("Invalid JSON number")
                        ),
                    )
                    if not isinstance(data, dict):
                        raise ValueError("JSON object required")
                result = route(app, actor, self.command, path, data)
                self.reply(200, result)
            except PermissionError as error:
                self.reply(403, {"error": str(error)})
            except (ValueError, KeyError, TypeError, RecursionError) as error:
                self.reply(400, {"error": str(error)})
            except Exception:
                self.reply(
                    503,
                    {
                        "error": "Operation failed; inspect local service and database health"
                    },
                )

        def do_GET(self):
            self.dispatch()

        def do_POST(self):
            self.dispatch()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server
