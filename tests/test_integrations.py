import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from securefi.db import Database
from securefi.service import Service
from securefi.demo import seed
from securefi.integrations import Integrations
from securefi.ai import draft, context, validate_draft, settings
from securefi.local_http import local_url
from securefi.blockchain import canonical, LedgerClient


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.service = Service(Database(Path(self.temp.name) / "app.db"))
        seed(self.service)
        self.app = Integrations(self.service)
        self.env = patch.dict(
            os.environ,
            {
                "SECUREFI_AI_PROVIDER": "rules",
                "SECUREFI_CHAIN_ENABLED": "0",
                "SECUREFI_OLLAMA_URL": "http://127.0.0.1:11434",
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_rules_provider_is_labelled(self):
        result = self.app.generate(1)
        self.assertEqual(result["provider"], "rules")
        self.assertIn("not enabled", result["fallback_reason"])
        self.assertEqual(self.app.state()["drafts"][0]["status"], "pending")

    def test_approval_does_not_change_finding(self):
        before = self.service.snapshot()["findings"]
        result = self.app.generate(1)
        self.app.review_draft(
            {
                "id": result["id"],
                "decision": "approved",
                "note": "Validated suggestions",
            }
        )
        self.assertEqual(self.service.snapshot()["findings"], before)
        with self.assertRaises(ValueError):
            self.app.review_draft(
                {"id": result["id"], "decision": "rejected", "note": "Second review"}
            )

    def test_review_requires_note(self):
        result = self.app.generate(1)
        with self.assertRaises(ValueError):
            self.app.review_draft(
                {"id": result["id"], "decision": "approved", "note": ""}
            )

    def test_unknown_finding(self):
        with self.assertRaises(ValueError):
            self.app.generate(999)

    def test_context_minimises_and_redacts(self):
        finding = self.service.snapshot()["findings"][0]
        finding["title"] = "Email user@example.com at 192.0.2.1 token=abc123"
        inputs = context(finding)
        text = json.dumps(inputs)
        self.assertNotIn("user@example.com", text)
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn("abc123", text)
        for key in ("asset_name", "assignee", "location", "evidence"):
            self.assertNotIn(key, inputs)

    def test_ai_response_validation(self):
        valid = {
            "finding_id": 1,
            "summary": "Draft",
            "investigation_steps": ["Check scope"],
        }
        self.assertEqual(validate_draft(valid, 1), valid)
        for bad in (
            {**valid, "finding_id": 2},
            {**valid, "extra": "fabricated"},
            {**valid, "investigation_steps": []},
            {**valid, "summary": "x" * 3001},
        ):
            with self.subTest(bad=str(bad)[:100]), self.assertRaises(ValueError):
                validate_draft(bad, 1)

    def test_model_unavailable_falls_back(self):
        finding = self.service.snapshot()["findings"][0]
        with patch("securefi.ai.post_json", side_effect=ValueError("offline")):
            result = draft(
                finding,
                {
                    "provider": "ollama",
                    "model": "test-local",
                    "url": "http://127.0.0.1:11434",
                },
            )
        self.assertEqual(result["provider"], "rules")
        self.assertIn("fallback", result["fallback_reason"])

    def test_wrong_model_reference_falls_back(self):
        finding = self.service.snapshot()["findings"][0]
        with patch(
            "securefi.ai.post_json",
            return_value={
                "response": json.dumps(
                    {"finding_id": 999, "summary": "bad", "investigation_steps": ["x"]}
                )
            },
        ):
            result = draft(
                finding,
                {
                    "provider": "ollama",
                    "model": "test-local",
                    "url": "http://127.0.0.1:11434",
                },
            )
        self.assertEqual(result["provider"], "rules")

    def test_only_literal_loopback_is_allowed(self):
        self.assertEqual(local_url("http://127.0.0.1:8545/"), "http://127.0.0.1:8545")
        for url in (
            "https://example.com",
            "http://localhost:8545",
            "http://127.0.0.1:8545@evil.com",
            "http://127.0.0.1:8545/path",
            "http://127.0.0.1:8545?x=1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                local_url(url)

    def test_chain_disabled_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "disabled"):
            self.app.deploy()

    def test_snapshot_frozen_after_live_changes(self):
        item = self.app.freeze()
        row = self.app.get_snapshot(item["id"])
        self.service.add_evidence({"control_id": "access", "note": "New evidence"})
        self.assertEqual(self.app.get_snapshot(item["id"])["content"], row["content"])
        self.assertEqual(
            hashlib.sha256(row["content"].encode()).hexdigest(), item["digest"]
        )

    def test_hash_ignores_json_whitespace_and_key_order(self):
        self.assertEqual(canonical({"b": 2, "a": 1}), canonical({"a": 1, "b": 2}))
        item = self.app.freeze()
        document = json.loads(self.app.get_snapshot(item["id"])["content"])
        result = self.app.verify(item["id"], document)
        self.assertTrue(result["matches_snapshot"])
        self.assertFalse(result["verified"])
        self.assertIn("not been anchored", result["reason"])

    def test_modified_evidence_fails_without_chain_call(self):
        item = self.app.freeze()
        document = json.loads(self.app.get_snapshot(item["id"])["content"])
        document["snapshot"]["findings"][0]["title"] = "changed"
        result = self.app.verify(item["id"], document)
        self.assertFalse(result["matches_snapshot"])
        self.assertFalse(result["verified"])

    def test_tampered_stored_snapshot_is_not_anchored(self):
        item = self.app.freeze()
        with self.service.db.connect() as conn:
            conn.execute(
                "UPDATE ledger_snapshots SET content='{}' WHERE id=?", (item["id"],)
            )
        with self.assertRaisesRegex(ValueError, "changed"):
            self.app.anchor(item["id"])

    def test_snapshot_includes_draft_provenance(self):
        self.app.generate(1)
        item = self.app.freeze()
        document = json.loads(self.app.get_snapshot(item["id"])["content"])
        self.assertEqual(document["ai_drafts"][0]["provider"], "rules")
        self.assertNotIn("ledger_snapshots", document)

    def test_registry_reset_requires_explicit_confirmation(self):
        with self.assertRaises(ValueError):
            self.app.reset_registry("yes")

    def test_additive_migration_preserves_version_one_rows(self):
        with self.service.db.connect() as conn:
            conn.execute("DROP TABLE ai_drafts")
            conn.execute("DROP TABLE ledger_snapshots")
            conn.execute("DROP TABLE settings")
            conn.execute("PRAGMA user_version=1")
        migrated = Service(Database(self.service.db.path))
        self.assertEqual(len(migrated.snapshot()["findings"]), 8)
        self.assertEqual(Integrations(migrated).state()["drafts"], [])
        with migrated.db.connect() as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_future_database_is_rejected(self):
        with self.service.db.connect() as conn:
            conn.execute("PRAGMA user_version=99")
        with self.assertRaises(ValueError):
            Database(self.service.db.path)

    def test_ollama_http_contract(self):
        captured = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                captured.append(body)
                inputs = json.loads(body["prompt"].split("\n", 1)[1])
                output = {
                    "finding_id": inputs["finding_id"],
                    "summary": "Review the supplied observation.",
                    "investigation_steps": ["Validate the scope with the owner."],
                }
                raw = json.dumps({"response": json.dumps(output)}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with patch.dict(
                os.environ,
                {
                    "SECUREFI_AI_PROVIDER": "ollama",
                    "SECUREFI_AI_MODEL": "fixture-model",
                    "SECUREFI_OLLAMA_URL": f"http://127.0.0.1:{server.server_port}",
                },
            ):
                result = self.app.generate(1)
            self.assertEqual(result["provider"], "ollama")
            self.assertEqual(result["model"], "fixture-model")
            self.assertFalse(captured[0]["stream"])
            self.assertEqual(captured[0]["format"]["type"], "object")
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
