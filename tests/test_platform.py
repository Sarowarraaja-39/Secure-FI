import hashlib
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from securefi.db import Database
from securefi.service import Service
from securefi.risk import score, priority
from securefi.adapters import parse_report
from securefi.demo import seed

ROOT = Path(__file__).resolve().parents[1]


def example(name):
    return json.loads((ROOT / "examples" / name).read_text())


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.service = Service(Database(Path(self.temp.name) / "test.db"))
        self.asset = self.service.create_asset(
            dict(
                name="Payments",
                owner="Platform",
                criticality=5,
                internet_exposed=True,
                environment="test",
            )
        )["id"]

    def ingest(self):
        return self.service.ingest(self.asset, "normalized", example("findings.json"))

    def advance(self):
        self.ingest()
        self.service.update_finding(
            1, {"status": "triaged", "note": "Reproduced", "assignee": "Platform"}
        )
        self.service.update_finding(
            1, {"status": "in_progress", "note": "Patch prepared"}
        )

    def test_risk_factors_and_cap(self):
        result = score("high", 5, True, True)
        self.assertEqual(result["score"], 97)
        self.assertEqual(score("critical", 5, True, True)["score"], 100)
        self.assertEqual(
            [priority(n) for n in (34, 35, 59, 60, 79, 80)],
            ["P4", "P3", "P3", "P2", "P2", "P1"],
        )

    def test_empty_database(self):
        state = self.service.snapshot()
        self.assertEqual(state["metrics"]["active_findings"], 0)
        self.assertEqual(len(state["controls"]), 6)
        self.assertTrue(self.service.gate()["passed"])

    def test_duplicate_import_updates_observation(self):
        self.assertEqual(self.ingest()["created"], 2)
        self.assertEqual(self.ingest()["updated"], 2)
        state = self.service.snapshot()
        self.assertEqual(len(state["findings"]), 2)
        self.assertTrue(all(f["occurrences"] == 2 for f in state["findings"]))

    def test_batch_deduplication(self):
        report = example("findings.json")
        report["findings"].append(report["findings"][0])
        self.assertEqual(
            self.service.ingest(self.asset, "normalized", report)["created"], 2
        )

    def test_invalid_batch_is_atomic(self):
        report = example("findings.json")
        report["findings"][1]["severity"] = "urgent"
        with self.assertRaises(ValueError):
            self.service.ingest(self.asset, "normalized", report)
        self.assertEqual(len(self.service.snapshot()["findings"]), 0)

    def test_missing_asset_rejected(self):
        with self.assertRaises(ValueError):
            self.service.ingest(999, "normalized", example("findings.json"))

    def test_wrong_types_rejected(self):
        for value in (True, 0, "1", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.service.ingest(value, "normalized", example("findings.json"))

    def test_duplicate_asset_rejected(self):
        with self.assertRaises(ValueError):
            self.service.create_asset(
                dict(
                    name="Payments",
                    owner="Other",
                    criticality=1,
                    internet_exposed=False,
                )
            )

    def test_invalid_asset_values_rejected(self):
        base = dict(name="Other", owner="Team", criticality=1, internet_exposed=False)
        for key, value in [
            ("criticality", 6),
            ("criticality", True),
            ("internet_exposed", "false"),
            ("owner", ""),
            ("environment", "invalid"),
        ]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.service.create_asset({**base, key: value})

    def test_cannot_skip_triage(self):
        self.ingest()
        with self.assertRaises(ValueError):
            self.service.update_finding(
                1,
                {
                    "status": "resolved",
                    "note": "Done",
                    "verification": "Retest",
                    "assignee": "A",
                },
            )

    def test_owner_required_for_progress(self):
        self.ingest()
        self.service.update_finding(1, {"status": "triaged", "note": "Checked"})
        with self.assertRaises(ValueError):
            self.service.update_finding(1, {"status": "in_progress", "note": "Fixing"})

    def test_resolution_requires_verification(self):
        self.advance()
        with self.assertRaises(ValueError):
            self.service.update_finding(1, {"status": "resolved", "note": "Done"})
        self.service.update_finding(
            1,
            {
                "status": "resolved",
                "note": "Done",
                "verification": "Anonymous access denied in retest",
            },
        )
        first = next(f for f in self.service.snapshot()["findings"] if f["id"] == 1)
        self.assertFalse(first["active"])
        self.assertEqual(first["status"], "resolved")

    def test_observed_again_reopens_resolved(self):
        self.advance()
        self.service.update_finding(
            1, {"status": "resolved", "note": "Done", "verification": "Retested"}
        )
        self.ingest()
        state = self.service.snapshot()
        self.assertEqual(
            next(f for f in state["findings"] if f["id"] == 1)["status"], "open"
        )
        self.assertTrue(any(e["action"] == "finding.reopened" for e in state["events"]))

    def test_acceptance_requires_future_expiry(self):
        self.advance()
        for until in ("", "2020-01-01", "not-a-date"):
            with self.subTest(until=until), self.assertRaises(ValueError):
                self.service.update_finding(
                    1,
                    {"status": "accepted", "note": "Approved", "accepted_until": until},
                )

    def test_expired_acceptance_blocks_gate(self):
        self.advance()
        self.service.update_finding(
            1,
            {
                "status": "accepted",
                "note": "Approved temporarily",
                "accepted_until": (date.today() + timedelta(days=1)).isoformat(),
            },
        )
        self.assertTrue(self.service.gate()["passed"])
        with self.service.db.connect() as conn:
            conn.execute("UPDATE findings SET accepted_until='2020-01-01' WHERE id=1")
        self.assertFalse(self.service.gate()["passed"])
        self.assertTrue(
            next(f for f in self.service.snapshot()["findings"] if f["id"] == 1)[
                "acceptance_expired"
            ]
        )

    def test_overdue_only_active(self):
        self.advance()
        self.service.update_finding(
            1, {"note": "Deadline missed", "due_date": "2020-01-01"}
        )
        self.assertEqual(self.service.snapshot()["metrics"]["overdue"], 1)
        self.service.update_finding(
            1, {"status": "resolved", "note": "Done", "verification": "Retested"}
        )
        self.assertEqual(self.service.snapshot()["metrics"]["overdue"], 0)

    def test_evidence_hash_and_review(self):
        note = "Reviewed the test record."
        evidence = self.service.add_evidence({"control_id": "access", "note": note})
        self.assertEqual(evidence["sha256"], hashlib.sha256(note.encode()).hexdigest())
        self.service.review_control(
            "access",
            {
                "review_status": "reviewed",
                "owner": "Security",
                "note": "Evidence checked",
            },
        )
        self.assertEqual(self.service.snapshot()["metrics"]["reviewed_controls"], 1)
        self.service.add_evidence(
            {"control_id": "access", "note": "Updated test record"}
        )
        self.assertEqual(self.service.snapshot()["metrics"]["reviewed_controls"], 0)

    def test_evidence_reference_validation(self):
        for data in (
            {"control_id": "unknown", "note": "x"},
            {"control_id": "access", "finding_id": 999, "note": "x"},
        ):
            with self.assertRaises(ValueError):
                self.service.add_evidence(data)
        self.assertEqual(self.service.snapshot()["evidence"], [])

    def test_control_cannot_be_reviewed_without_evidence(self):
        with self.assertRaises(ValueError):
            self.service.review_control(
                "access",
                {"review_status": "reviewed", "owner": "Security", "note": "Approved"},
            )

    def test_sarif_import(self):
        result = self.service.ingest(self.asset, "sarif", example("sast.sarif"))
        self.assertEqual(result["created"], 1)
        f = self.service.snapshot()["findings"][0]
        self.assertEqual(f["location"], "payments/refunds.py:42")
        self.assertEqual(f["severity"], "high")

    def test_sbom_upsert_and_vulnerability(self):
        report = example("sbom.json")
        self.service.ingest(self.asset, "cyclonedx", report)
        self.service.ingest(self.asset, "cyclonedx", report)
        state = self.service.snapshot()
        self.assertEqual(len(state["components"]), 1)
        self.assertEqual(len(state["findings"]), 1)
        self.assertEqual(state["findings"][0]["category"], "SCA")

    def test_inventory_alone_does_not_create_vulnerability(self):
        report = example("sbom.json")
        report.pop("vulnerabilities")
        self.service.ingest(self.asset, "cyclonedx", report)
        self.assertEqual(self.service.snapshot()["findings"], [])

    def test_adapter_rejects_bad_structure(self):
        cases = [
            ("sarif", {"version": "2.1.0", "runs": [None]}),
            (
                "cyclonedx",
                {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [None]},
            ),
            ("normalized", {"findings": {}}),
            ("unknown", {}),
        ]
        for kind, report in cases:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                parse_report(kind, report)

    def test_cloud_checks(self):
        self.assertEqual(
            self.service.ingest(self.asset, "cloud", example("cloud.json"))["created"],
            2,
        )
        report = example("cloud.json")
        del report["resources"][0]["encrypted"]
        with self.assertRaises(ValueError):
            self.service.ingest(self.asset, "cloud", report)

    def test_event_correlation(self):
        report = example("events.json")
        self.assertEqual(
            self.service.ingest(self.asset, "events", report)["created"], 1
        )
        self.assertEqual(
            self.service.ingest(self.asset, "events", report)["updated"], 1
        )
        self.assertEqual(
            parse_report("events", {"events": report["events"][:4]})[0], []
        )

    def test_duplicate_events_do_not_trigger(self):
        event = example("events.json")["events"][0]
        self.assertEqual(parse_report("events", {"events": [event] * 10})[0], [])

    def test_distinct_event_buckets(self):
        report = example("events.json")
        report["events"][-1]["at"] = "2026-10-12T10:05:00Z"
        self.assertEqual(parse_report("events", report)[0], [])

    def test_event_timestamp_requires_timezone(self):
        report = example("events.json")
        report["events"][0]["at"] = "2026-10-12T10:00:00"
        with self.assertRaises(ValueError):
            parse_report("events", report)

    def test_sql_text_is_not_executed(self):
        self.service.create_asset(
            dict(
                name="test'); DROP TABLE assets;--",
                owner="Team",
                criticality=1,
                internet_exposed=False,
            )
        )
        self.assertEqual(len(self.service.snapshot()["assets"]), 2)

    def test_restart_preserves_state(self):
        self.ingest()
        other = Service(Database(self.service.db.path))
        self.assertEqual(len(other.snapshot()["findings"]), 2)

    def test_demo_refuses_nonempty_database(self):
        with self.assertRaises(ValueError):
            seed(self.service)

    def test_demo_empty_database(self):
        demo = Service(Database(Path(self.temp.name) / "demo.db"))
        self.assertEqual(seed(demo)["findings"], 8)
        self.assertEqual(demo.snapshot()["metrics"]["assets"], 4)
        self.assertEqual(len(demo.snapshot()["findings"]), 8)

    def test_malformed_enum_values_are_validation_errors(self):
        for field in ("severity", "category"):
            report = example("findings.json")
            report["findings"][0][field] = []
            with self.assertRaises(ValueError):
                parse_report("normalized", report)
        with self.assertRaises(ValueError):
            parse_report([], {})
