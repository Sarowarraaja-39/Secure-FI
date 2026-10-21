import http.client
import json
import os
from unittest.mock import patch
import tempfile
import threading
import unittest
from pathlib import Path
from securefi.db import Database
from securefi.service import Service
from securefi.server import make_server

TOKEN = "test-token-with-at-least-24-characters"


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = patch.dict(
            os.environ,
            {
                "SECUREFI_AI_PROVIDER": "rules",
                "SECUREFI_CHAIN_ENABLED": "0",
                "SECUREFI_OLLAMA_URL": "http://127.0.0.1:11434",
            },
        )
        cls.env.start()
        cls.temp = tempfile.TemporaryDirectory()
        cls.service = Service(Database(Path(cls.temp.name) / "http.db"))
        cls.server, _ = make_server(cls.service, 0, TOKEN)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()
        cls.env.stop()

    def request(self, path="/api/state", method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdr = {"Authorization": "Bearer " + TOKEN}
        hdr.update(headers or {})
        if isinstance(body, dict):
            body = json.dumps(body)
            hdr["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body, headers=hdr)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_token_required(self):
        self.assertEqual(self.request(headers={"Authorization": ""})[0], 401)

    def test_bad_token(self):
        self.assertEqual(
            self.request(headers={"Authorization": "Bearer wrong"})[0], 401
        )

    def test_health(self):
        status, _, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_cross_origin_rejected(self):
        self.assertEqual(
            self.request(headers={"Origin": "https://example.com"})[0], 403
        )

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.request(headers={"Host": "attacker.example"})[0], 403)

    def test_security_headers(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn(TOKEN.encode(), body)

    def test_static_files(self):
        for path in ("/app.js", "/style.css"):
            self.assertEqual(self.request(path)[0], 200)

    def test_static_traversal_rejected(self):
        self.assertEqual(self.request("/../db.py")[0], 404)

    def test_invalid_json(self):
        self.assertEqual(
            self.request(
                "/api/assets", "POST", "{bad", {"Content-Type": "application/json"}
            )[0],
            400,
        )

    def test_body_limit(self):
        self.assertEqual(
            self.request("/api/import", "POST", "x", {"Content-Length": "3000000"})[0],
            413,
        )

    def test_wrong_content_type(self):
        self.assertEqual(
            self.request("/api/assets", "POST", "{}", {"Content-Type": "text/plain"})[
                0
            ],
            415,
        )

    def test_nonfinite_json(self):
        self.assertEqual(
            self.request(
                "/api/assets",
                "POST",
                '{"criticality": NaN}',
                {"Content-Type": "application/json"},
            )[0],
            400,
        )

    def test_api_end_to_end(self):
        status, _, raw = self.request(
            "/api/assets",
            "POST",
            dict(
                name="HTTP asset", owner="Team", criticality=3, internet_exposed=False
            ),
        )
        self.assertEqual(status, 200)
        asset = json.loads(raw)["id"]
        report = {
            "findings": [
                dict(
                    external_id="test",
                    title="Test issue",
                    source="test",
                    location="resource",
                    severity="high",
                    category="manual",
                    recommendation="Retest",
                )
            ]
        }
        self.assertEqual(
            self.request(
                "/api/import",
                "POST",
                {"asset_id": asset, "format": "normalized", "report": report},
            )[0],
            200,
        )
        snapshot = json.loads(self.request("/api/state")[2])
        finding = next(f for f in snapshot["findings"] if f["asset_id"] == asset)
        for stage in ("triaged", "in_progress", "resolved"):
            self.assertEqual(
                self.request(
                    "/api/findings/review",
                    "POST",
                    {
                        "id": finding["id"],
                        "status": stage,
                        "note": "Reviewed",
                        "assignee": "Team",
                        "verification": "Retest passed",
                    },
                )[0],
                200,
            )
        self.assertEqual(
            self.request(
                "/api/evidence",
                "POST",
                {
                    "control_id": "vulnerability",
                    "finding_id": finding["id"],
                    "note": "Retest evidence",
                },
            )[0],
            200,
        )
        self.assertEqual(
            self.request(
                "/api/controls/review",
                "POST",
                {
                    "control_id": "vulnerability",
                    "review_status": "reviewed",
                    "owner": "Team",
                    "note": "Reviewed evidence",
                },
            )[0],
            200,
        )
        export = json.loads(self.request("/api/export")[2])
        self.assertTrue(any(e["note"] == "Retest evidence" for e in export["evidence"]))

    def test_invalid_payload_shape(self):
        self.assertEqual(
            self.request(
                "/api/assets", "POST", "[]", {"Content-Type": "application/json"}
            )[0],
            400,
        )

    def test_unknown_route(self):
        self.assertEqual(self.request("/api/missing")[0], 404)

    def test_extension_api_workflow(self):
        status, _, raw = self.request(
            "/api/assets",
            "POST",
            dict(
                name="Extension API asset",
                owner="Team",
                criticality=2,
                internet_exposed=False,
            ),
        )
        self.assertEqual(status, 200)
        asset = json.loads(raw)["id"]
        report = {
            "findings": [
                dict(
                    external_id="extension",
                    title="Example observation",
                    source="test",
                    location="resource",
                    severity="medium",
                    category="manual",
                    recommendation="Retest",
                )
            ]
        }
        self.request(
            "/api/import",
            "POST",
            {"asset_id": asset, "format": "normalized", "report": report},
        )
        state = json.loads(self.request("/api/state")[2])
        finding = next(f for f in state["findings"] if f["asset_id"] == asset)
        status, _, raw = self.request(
            "/api/ai/draft", "POST", {"finding_id": finding["id"]}
        )
        self.assertEqual(status, 200)
        draft = json.loads(raw)
        self.assertEqual(
            self.request(
                "/api/ai/review",
                "POST",
                {"id": draft["id"], "decision": "approved", "note": "Reviewed draft"},
            )[0],
            200,
        )
        status, _, raw = self.request("/api/ledger/snapshot", "POST", {})
        self.assertEqual(status, 200)
        id_ = json.loads(raw)["id"]
        exported = json.loads(self.request("/api/ledger/snapshot/" + str(id_))[2])
        status, _, raw = self.request(
            "/api/ledger/verify", "POST", {"id": id_, "document": exported}
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw)["matches_snapshot"])
        self.assertFalse(json.loads(raw)["verified"])
        self.assertEqual(self.request("/api/integrations")[0], 200)
        self.assertEqual(self.request("/api/ledger/snapshot/not-an-id")[0], 400)
