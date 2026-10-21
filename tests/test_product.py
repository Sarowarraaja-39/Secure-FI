"""Regression checks for the user-facing security operations application."""

import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch
from securefi.platform.product import Product
from securefi.platform.store import Store, canonical
from securefi.platform import assistant, evidence_ledger
from securefi.platform.server import route
from securefi.platform.synthetic import scenarios

KEY = "synthetic-product-test-key-32characters"


def actor(role="analyst", tenant="a"):
    return {"id": "person-" + role, "role": role, "tenant": tenant}


def event(id_="one", **data):
    return {
        "event_id": id_,
        "synthetic": True,
        "source": "cloud",
        "time": "2026-10-21T10:00:00Z",
        "data": {
            "operation": "storage_update",
            "public": True,
            "encrypted": True,
            "asset": "payments-store",
            **data,
        },
    }


class ProductTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.app = Product(Store(Path(temp.name) / "app.db"), KEY)
        self.app.ingest(actor(), [event()])
        self.alert = self.app.store.list("a", "alert")[0]

    def triage(self, **values):
        return self.app.triage(
            actor(),
            {
                "id": self.alert["id"],
                "status": "triaged",
                "note": "Checked source observation",
                **values,
            },
        )

    def asset(self, **values):
        return self.app.save_asset(
            actor(),
            {
                "name": "payments-store",
                "owner": "Payments",
                "criticality": 5,
                "internet_exposed": True,
                "environment": "test",
                "note": "Registered authoritative asset context",
                **values,
            },
        )

    def case(self):
        return self.app.case(
            actor(), self.alert["id"], "Investigate synthetic exposure"
        )

    def test_triage_requires_rationale(self):
        with self.assertRaises(ValueError):
            self.triage(note=" ")
        self.assertEqual(
            self.app.store.get("a", "alert", self.alert["id"])["status"], "new"
        )

    def test_triage_owner_and_resolution_verification(self):
        with self.assertRaises(ValueError):
            self.triage(status="in_progress")
        with self.assertRaises(ValueError):
            self.triage(status="resolved")
        result = self.triage(
            status="resolved", verification="Retest denied anonymous read"
        )
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(self.app.state(actor())["metrics"]["active_alerts"], 0)

    def test_risk_acceptance_requires_expiry_and_counts_active_correctly(self):
        with self.assertRaises(ValueError):
            self.triage(
                status="risk_accepted", assignee="Payments", accepted_until="2020-01-01"
            )
        self.triage(
            status="risk_accepted",
            assignee="Payments",
            accepted_until=(date.today() + timedelta(days=2)).isoformat(),
        )
        self.assertEqual(
            self.app.state(actor("executive"))["metrics"]["active_alerts"], 0
        )
        with self.app.store.connection("a") as conn:
            alert = self.app.store.get("a", "alert", self.alert["id"], conn)
            alert["accepted_until"] = "2020-01-01"
            self.app.store.put(conn, "a", "alert", alert)
        self.assertTrue(self.app.state(actor())["alerts"][0]["acceptance_expired"])
        self.assertEqual(
            self.app.state(actor("executive"))["metrics"]["active_alerts"], 1
        )

    def test_repeat_event_preserves_triage_fields(self):
        self.triage(status="in_progress", assignee="On-call")
        self.app.ingest(actor(), [event("two")])
        alert = self.app.store.get("a", "alert", self.alert["id"])
        self.assertEqual(alert["status"], "in_progress")
        self.assertEqual(alert["assignee"], "On-call")
        self.assertEqual(alert["occurrences"], 2)

    def test_new_observation_reopens_resolved_alert_but_duplicate_does_not(self):
        self.triage(status="resolved", verification="Retest passed")
        self.app.ingest(actor(), [event()])
        self.assertEqual(
            self.app.store.get("a", "alert", self.alert["id"])["status"], "resolved"
        )
        self.app.ingest(actor(), [event("two")])
        self.assertEqual(
            self.app.store.get("a", "alert", self.alert["id"])["status"], "new"
        )
        self.assertTrue(
            any(a["action"] == "alert.reopened" for a in self.app.activity(actor()))
        )

    def test_asset_context_reprioritises_without_rewriting_observation(self):
        original = self.app.store.get("a", "event", "one")
        before = self.alert["risk"]["score"]
        self.asset()
        self.assertGreater(
            self.app.store.get("a", "alert", self.alert["id"])["risk"]["score"], before
        )
        self.assertEqual(original, self.app.store.get("a", "event", "one"))
        self.assertEqual(self.app.ingest(actor(), [event()])["duplicates"], 1)
        with self.assertRaises(ValueError):
            self.app.ingest(actor(), [event(public=False)])

    def test_future_and_queued_events_use_current_asset_context(self):
        self.app.ingest(actor(), [event("queued")], queued=True)
        self.asset()
        self.app.work(actor("ingestor"))
        self.assertEqual(
            self.app.store.get("a", "alert", self.alert["id"])["risk"]["factors"][
                "exposure"
            ],
            10,
        )
        self.app.ingest(actor(), [event("new")])
        self.assertEqual(
            self.app.store.get("a", "event", "new")["data"]["criticality"], 5
        )
        self.asset(criticality=2, internet_exposed=False)
        self.assertEqual(self.app.ingest(actor(), [event("new")])["duplicates"], 1)

    def test_asset_validation_and_permissions(self):
        for field, value in [
            ("criticality", True),
            ("internet_exposed", "yes"),
            ("owner", ""),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.asset(**{field: value})
        with self.assertRaises(PermissionError):
            self.app.save_asset(actor("compliance"), {})

    def test_case_deduplicated_and_status_updates_alert(self):
        case = self.case()
        self.assertEqual(self.case()["id"], case["id"])
        with self.assertRaises(ValueError):
            self.app.update_case(
                actor(), {"id": case["id"], "status": "resolved", "note": "Done"}
            )
        result = self.app.update_case(
            actor(),
            {
                "id": case["id"],
                "status": "resolved",
                "note": "Remediation verified",
                "verification": "Anonymous read denied",
            },
        )
        self.assertEqual(len(result["activity"]), 2)
        self.assertEqual(
            self.app.store.get("a", "alert", self.alert["id"])["status"], "resolved"
        )
        self.assertNotEqual(self.case()["id"], case["id"])

    def test_compatibility_case_review_uses_same_workflow(self):
        case = self.case()
        self.app.review_case(actor(), case["id"], "resolved", "Reviewed", "Retested")
        self.assertEqual(
            self.app.store.get("a", "alert", self.alert["id"])["status"], "resolved"
        )

    def test_case_cannot_skip_lifecycle(self):
        case = self.case()
        with self.assertRaises(ValueError):
            self.app.update_case(
                actor(),
                {
                    "id": case["id"],
                    "status": "closed",
                    "note": "Done",
                    "verification": "Retested",
                },
            )

    def test_cloud_permissions_apply_to_ingest_triage_events_and_assistant(self):
        identities = [e for e in scenarios() if e["source"] == "identity"]
        self.app.ingest(actor(), identities)
        target = next(
            a for a in self.app.store.list("a", "alert") if a["source"] == "identity"
        )
        case = self.app.case(actor(), target["id"], "Investigate identity")
        for operation in (
            lambda: self.app.ingest(actor("cloud"), identities),
            lambda: self.app.triage(
                actor("cloud"),
                {"id": target["id"], "status": "triaged", "note": "Checked"},
            ),
            lambda: route(
                self.app,
                actor("cloud"),
                "POST",
                "/api/events/detail",
                {"id": identities[0]["event_id"]},
            ),
            lambda: assistant.generate(self.app, actor("cloud"), case["id"]),
        ):
            with self.assertRaises(PermissionError):
                operation()

    def test_advisory_draft_review_cannot_execute_actions_or_change_case(self):
        case = self.case()
        with patch.dict(os.environ, {"SECUREFI_AI_PROVIDER": "rules"}):
            draft = assistant.generate(self.app, actor(), case["id"])
        self.assertEqual(draft["provider"], "rules")
        assistant.review(
            self.app,
            actor(),
            {
                "id": draft["id"],
                "decision": "approved",
                "note": "Compared against evidence",
            },
        )
        self.assertEqual(self.app.store.get("a", "case", case["id"]), case)
        self.assertEqual(self.app.store.list("a", "run"), [])
        with self.assertRaises(ValueError):
            assistant.review(
                self.app,
                actor(),
                {"id": draft["id"], "decision": "rejected", "note": "Second review"},
            )

    def test_local_ai_contract_and_minimised_context(self):
        case = self.case()
        response = {
            "response": json.dumps(
                {
                    "case_id": case["id"],
                    "summary": "Check permissions",
                    "investigation_steps": ["Read source configuration"],
                }
            )
        }
        env = {
            "SECUREFI_AI_PROVIDER": "ollama",
            "SECUREFI_AI_MODEL": "test-model",
            "SECUREFI_OLLAMA_URL": "http://127.0.0.1:11434",
        }
        with (
            patch.dict(os.environ, env),
            patch(
                "securefi.platform.assistant.post_json", return_value=response
            ) as mocked,
        ):
            draft = assistant.generate(self.app, actor(), case["id"])
        self.assertEqual(draft["provider"], "ollama")
        request = str(mocked.call_args)
        self.assertNotIn("payments-store", request)
        self.assertNotIn("Investigate synthetic exposure", request)
        self.assertNotIn("principal", request)

    def test_bad_model_case_reference_falls_back_explicitly(self):
        case = self.case()
        bad = {
            "response": json.dumps(
                {"case_id": "wrong", "summary": "Bad", "investigation_steps": ["Check"]}
            )
        }
        with (
            patch.dict(
                os.environ,
                {"SECUREFI_AI_PROVIDER": "ollama", "SECUREFI_AI_MODEL": "test-model"},
            ),
            patch("securefi.platform.assistant.post_json", return_value=bad),
        ):
            draft = assistant.generate(self.app, actor(), case["id"])
        self.assertEqual(draft["provider"], "rules")
        self.assertIn("fallback", draft["fallback_reason"])
        self.assertEqual(draft["draft"]["case_id"], case["id"])

    def test_report_is_frozen_includes_work_and_verifies_hash_before_chain(self):
        self.asset()
        self.case()
        report = self.app.report(actor("compliance"))
        self.assertEqual(
            report["digest"],
            hashlib.sha256(canonical(report["document"]).encode()).hexdigest(),
        )
        self.assertEqual(report["document"]["response_mode"], "simulation")
        self.assertEqual(len(report["document"]["assets"]), 1)
        self.triage(status="false_positive")
        self.assertEqual(report, self.app.store.get("a", "evidence", report["id"]))
        self.assertFalse(
            evidence_ledger.verify(self.app, actor(), report["id"])["verified"]
        )
        altered = copy.deepcopy(report["document"])
        altered["scope"] = "Tampered"
        with patch("securefi.platform.evidence_ledger.LedgerClient") as client:
            result = evidence_ledger.verify(self.app, actor(), report["id"], altered)
        self.assertFalse(result["matches_document"])
        client.assert_not_called()

    def test_cross_tenant_and_role_boundaries_for_new_routes(self):
        case = self.case()
        for operation in (
            lambda: assistant.generate(self.app, actor(tenant="b"), case["id"]),
            lambda: self.app.update_case(
                actor(tenant="b"), {"id": case["id"], "note": "Attempt"}
            ),
        ):
            with self.assertRaises(ValueError):
                operation()
        with self.assertRaises(PermissionError):
            self.app.activity(actor("executive"))
        self.assertEqual(self.app.activity(actor(tenant="b")), [])
        with self.assertRaises(PermissionError):
            evidence_ledger.deploy(self.app, actor())

    def test_activity_and_evidence_do_not_break_audit_integrity(self):
        self.triage()
        self.asset()
        self.case()
        self.app.report(actor("compliance"))
        self.assertTrue(self.app.store.verify_audit("a")["valid"])
        self.assertEqual(self.app.activity(actor())[0]["action"], "evidence.generated")
