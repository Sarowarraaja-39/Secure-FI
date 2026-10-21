"""Loopback-only single-user HTTP adapter. Not a production web server."""

import hmac
import json
import logging
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .integrations import Integrations

STATIC = Path(__file__).parent / "static"
MAX_BODY = 2 * 1024 * 1024
LOG = logging.getLogger("securefi")


def make_server(service, port=8765, token=None):
    integrations = Integrations(service)
    token = token or secrets.token_urlsafe(32)
    if len(token) < 24:
        raise ValueError("API token must have at least 24 characters")

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureFI"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, fmt, *args):
            # Do not log tokens, URL parameters, report content or reviewer notes.
            LOG.debug("HTTP request completed")

        def reply(self, status, payload, content_type="application/json"):
            raw = (
                json.dumps(payload, allow_nan=False).encode()
                if content_type == "application/json"
                else payload
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(raw)

        def allowed(self):
            allowed_hosts = {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
            if self.headers.get("Host") not in allowed_hosts:
                self.reply(403, {"error": "Invalid Host header"})
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{h}" for h in allowed_hosts}:
                self.reply(403, {"error": "Cross-origin requests are not allowed"})
                return False
            return True

        def authorized(self):
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
                self.reply(
                    401, {"error": "Enter the access token printed in your terminal"}
                )
                return False
            return True

        def do_GET(self):
            if not self.allowed():
                return
            path = urlsplit(self.path).path
            static = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
            }
            if path in static:
                filename, mime = static[path]
                self.reply(200, (STATIC / filename).read_bytes(), mime)
                return
            if not self.authorized():
                return
            try:
                if path == "/api/state":
                    self.reply(200, service.snapshot())
                elif path == "/api/integrations":
                    self.reply(200, integrations.state())
                elif path.startswith("/api/ledger/snapshot/"):
                    row = integrations.get_snapshot(int(path.rsplit("/", 1)[1]))
                    self.reply(200, json.loads(row["content"]))
                elif path == "/api/health":
                    self.reply(200, {"status": "ok", "mode": "local-single-user"})
                elif path == "/api/export":
                    self.reply(200, service.snapshot())
                else:
                    self.reply(404, {"error": "Not found"})
            except ValueError as exc:
                self.reply(400, {"error": str(exc)})
            except sqlite3.Error:
                LOG.exception("Database read failed")
                self.reply(
                    503, {"error": "Database unavailable; inspect the local server log"}
                )

        def do_POST(self):
            if not self.allowed() or not self.authorized():
                return
            if self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                self.reply(400, {"error": "Transfer-Encoding is not supported"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    self.close_connection = True
                    self.reply(
                        413, {"error": "JSON body must be between 1 byte and 2 MiB"}
                    )
                    return
                if self.headers.get_content_type() != "application/json":
                    self.close_connection = True
                    self.reply(415, {"error": "Content-Type must be application/json"})
                    return
                raw = self.rfile.read(length)
                data = json.loads(
                    raw,
                    parse_constant=lambda _: (_ for _ in ()).throw(
                        ValueError("Non-finite JSON number")
                    ),
                )
                if not isinstance(data, dict):
                    raise ValueError("Request must be an object")
                path = urlsplit(self.path).path
                if path == "/api/ai/draft":
                    result = integrations.generate(data.get("finding_id"))
                elif path == "/api/ai/review":
                    result = integrations.review_draft(data)
                elif path == "/api/ledger/snapshot":
                    result = integrations.freeze()
                elif path == "/api/ledger/deploy":
                    result = integrations.deploy()
                elif path == "/api/ledger/anchor":
                    result = integrations.anchor(data.get("id"))
                elif path == "/api/ledger/verify":
                    result = integrations.verify(data.get("id"), data.get("document"))
                elif path == "/api/assets":
                    result = service.create_asset(data)
                elif path == "/api/import":
                    result = service.ingest(
                        data.get("asset_id"), data.get("format"), data.get("report")
                    )
                elif path == "/api/findings/review":
                    result = service.update_finding(data.get("id"), data)
                elif path == "/api/evidence":
                    result = service.add_evidence(data)
                elif path == "/api/controls/review":
                    result = service.review_control(data.get("control_id"), data)
                else:
                    self.reply(404, {"error": "Not found"})
                    return
                self.reply(200, result)
            except (
                ValueError,
                TypeError,
                KeyError,
                UnicodeDecodeError,
                RecursionError,
            ) as exc:
                self.reply(400, {"error": str(exc) or "Malformed request"})
            except sqlite3.Error:
                LOG.exception("Database write failed")
                self.reply(
                    503, {"error": "Database unavailable; inspect the local server log"}
                )

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server, token
