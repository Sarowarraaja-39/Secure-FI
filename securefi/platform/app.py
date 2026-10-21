"""Transactional security operations with tenant and approval boundaries."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from .store import canonical, utcnow
from .normalise import normalise
from .detection import catalogue, detect

ROLES = {"admin", "analyst", "approver", "ingestor", "cloud", "compliance", "executive"}


def scope(actor, roles):
    if not isinstance(actor, dict) or actor.get("role") not in set(roles) | {"admin"}:
        raise PermissionError("Role does not permit this action")
    if not actor.get("tenant") or not actor.get("id"):
        raise PermissionError("Missing authenticated identity")
    return actor["tenant"]


class Platform:
    def __init__(self, store, key):
        if len(key) < 24:
            raise ValueError("Pseudonymisation key must have at least 24 characters")
        self.store = store
        self.key = key
        self.rules = catalogue()
        self.playbooks = json.loads(
            Path(__file__).with_name("playbooks.json").read_text()
        )
        self.controls = json.loads(
            Path(__file__).with_name("controls.json").read_text()
        )

    def _process(self, conn, tenant, event):
        history = self.store.list(tenant, "event", conn)
        hits = detect(event, history, self.rules)
        for model in self.store.list(tenant, "model", conn):
            if (
                model["status"] != "active"
                or event["source"] != "application"
                or event["data"]["operation"] != "api_request"
            ):
                continue
            if (
                hashlib.sha256(canonical(model["model"]).encode()).hexdigest()
                != model["model_sha256"]
            ):
                raise ValueError("Active model failed integrity verification")
            from .ml import predict

            prediction = predict(model["model"], event)
            if prediction["hybrid_flag"]:
                from .detection import risk

                hits.append(
                    {
                        "rule_id": "ML-001",
                        "name": "Approved hybrid behavioural anomaly",
                        "severity": "high",
                        "risk": risk("high", event["data"], 0.6),
                        "attack": {
                            "technique": None,
                            "tactic": None,
                            "relationship": "anomaly_not_attack_coverage",
                        },
                        "controls": ["LOG", "MODEL"],
                        "evidence_ids": [event["id"]],
                        "recommended_action": "Validate the anomalous feature contributions before responding.",
                        "playbook": "ai_investigate",
                        "model_id": model["id"],
                        "explanation": prediction,
                    }
                )
        alerts = []
        for hit in hits:
            # One alert per rule/principal/asset/fixed five-minute window.
            bucket = int(datetime.fromisoformat(event["time"]).timestamp()) // 300
            identity = [
                hit["rule_id"],
                event["data"].get("principal", ""),
                event["data"].get("asset", ""),
                bucket,
            ]
            id_ = hashlib.sha256(canonical(identity).encode()).hexdigest()[:32]
            try:
                existing = self.store.get(tenant, "alert", id_, conn)
            except ValueError:
                existing = None
            evidence = sorted(
                set(hit["evidence_ids"])
                | set(existing["evidence_ids"] if existing else [])
            )
            value = {
                **hit,
                "evidence_ids": evidence,
                "asset": event["data"].get("asset", "unknown"),
                "source": event["source"],
                "status": existing["status"] if existing else "new",
                "first_seen": existing["first_seen"] if existing else event["time"],
                "detected_at": utcnow(),
                "last_seen": event["time"],
                "occurrences": (existing["occurrences"] + 1) if existing else 1,
            }
            alerts.append(self.store.put(conn, tenant, "alert", value, id_))
        self.store.put(conn, tenant, "event", event, event["id"])
        return alerts

    def ingest(self, actor, raw_events, queued=False):
        tenant = scope(actor, {"ingestor", "analyst", "cloud"})
        if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= 500:
            raise ValueError("Submit between 1 and 500 synthetic events")
        events = [normalise(e, tenant, self.key) for e in raw_events]
        events.sort(key=lambda e: (e["time"], e["id"]))
        accepted = duplicates = 0
        alerts = []
        with self.store.connection(tenant) as conn:
            for event in events:
                try:
                    existing = self.store.get(tenant, "event", event["id"], conn)
                except ValueError:
                    existing = None
                if existing:
                    compare = lambda e: {
                        k: v for k, v in e.items() if k not in ("ingested_at",)
                    }
                    if compare(existing) != compare(event):
                        raise ValueError("Event ID collision with different content")
                    duplicates += 1
                    continue
                if queued:
                    self.store.put(conn, tenant, "event", event, event["id"])
                    self.store.enqueue(conn, tenant, {"event_id": event["id"]})
                else:
                    alerts.extend(self._process(conn, tenant, event))
                accepted += 1
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "events.ingested",
                {"accepted": accepted, "duplicates": duplicates, "queued": queued},
            )
        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "alerts": len(alerts),
            "queued": queued,
        }

    def work(self, actor, limit=100):
        tenant = scope(actor, {"ingestor"})
        done = failed = 0
        for _ in range(min(500, limit)):
            with self.store.connection(tenant) as conn:
                row = conn.execute(
                    "SELECT id,payload,attempts FROM jobs WHERE tenant=? AND state='pending' ORDER BY id LIMIT 1",
                    (tenant,),
                ).fetchone()
                if not row:
                    break
                try:
                    event = self.store.get(
                        tenant, "event", json.loads(row[1])["event_id"], conn
                    )
                    # A queued event may already be in history; detect excludes its ID.
                    self._process(conn, tenant, event)
                    conn.execute(
                        "UPDATE jobs SET state='done',attempts=attempts+1 WHERE tenant=? AND id=?",
                        (tenant, row[0]),
                    )
                    done += 1
                except (ValueError, KeyError) as error:
                    state = "dead" if row[2] >= 2 else "pending"
                    conn.execute(
                        "UPDATE jobs SET state=?,attempts=attempts+1,error=? WHERE tenant=? AND id=?",
                        (state, str(error)[:300], tenant, row[0]),
                    )
                    failed += 1
        return {"processed": done, "failed_attempts": failed}

    def case(self, actor, alert_id, note):
        tenant = scope(actor, {"analyst", "cloud"})
        if not isinstance(note, str) or not note.strip() or len(note) > 4000:
            raise ValueError("Investigation note required")
        with self.store.connection(tenant) as conn:
            alert = self.store.get(tenant, "alert", alert_id, conn)
            if actor["role"] == "cloud" and alert["source"] not in (
                "cloud",
                "kubernetes",
            ):
                raise PermissionError("Cloud role is limited to cloud/Kubernetes cases")
            case = self.store.put(
                conn,
                tenant,
                "case",
                {
                    "alert_id": alert_id,
                    "title": alert["name"],
                    "status": "investigating",
                    "owner": actor["id"],
                    "created_at": utcnow(),
                    "notes": [note],
                    "asset": alert["asset"],
                    "resolved_at": None,
                },
            )
            self.store.put(
                conn, tenant, "alert", {**alert, "status": "investigating"}, alert_id
            )
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "case.opened",
                {"case_id": case["id"], "alert_id": alert_id},
            )
        return case

    def review_case(self, actor, id_, status, note, verification=""):
        tenant = scope(actor, {"analyst"})
        transitions = {
            "investigating": {"contained", "resolved"},
            "contained": {"investigating", "resolved"},
            "resolved": {"closed", "investigating"},
            "closed": {"investigating"},
        }
        if not note or len(note) > 4000:
            raise ValueError("Review note required")
        with self.store.connection(tenant) as conn:
            case = self.store.get(tenant, "case", id_, conn)
            if status not in transitions[case["status"]]:
                raise ValueError("Invalid incident lifecycle transition")
            if status in ("resolved", "closed") and not verification:
                raise ValueError("Resolution requires verification evidence")
            case.update(
                status=status,
                notes=case["notes"] + [note],
                verification=verification,
                resolved_at=utcnow() if status in ("resolved", "closed") else None,
            )
            self.store.put(conn, tenant, "case", case, id_)
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "case.reviewed",
                {"case_id": id_, "status": status, "note": note},
            )
        return case

    def request_run(self, actor, case_id, playbook):
        tenant = scope(actor, {"analyst", "cloud"})
        definition = next((p for p in self.playbooks if p["id"] == playbook), None)
        if not definition:
            raise ValueError("Unknown playbook")
        with self.store.connection(tenant) as conn:
            case = self.store.get(tenant, "case", case_id, conn)
            alert = self.store.get(tenant, "alert", case["alert_id"], conn)
            if actor["role"] == "cloud" and alert["source"] not in (
                "cloud",
                "kubernetes",
            ):
                raise PermissionError("Cloud role is limited to cloud/Kubernetes cases")
            run = self.store.put(
                conn,
                tenant,
                "run",
                {
                    "case_id": case_id,
                    "playbook": playbook,
                    "requested_by": actor["id"],
                    "status": "pending_approval",
                    "created_at": utcnow(),
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(hours=1)
                    ).isoformat(),
                    "asset": case["asset"],
                    "steps": [],
                    "mode": "lab_simulation",
                },
            )
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "playbook.requested",
                {"run_id": run["id"], "playbook": playbook},
            )
        return run

    def approve(self, actor, id_, decision, note):
        tenant = scope(actor, {"approver"})
        if decision not in ("approve", "reject") or not note or len(note) > 4000:
            raise ValueError("Decision and review note required")
        with self.store.connection(tenant) as conn:
            run = self.store.get(tenant, "run", id_, conn)
            if run["requested_by"] == actor["id"]:
                raise PermissionError("Requester cannot approve their own response")
            if run["status"] != "pending_approval":
                raise ValueError("Run already reviewed")
            if datetime.fromisoformat(run["expires_at"]) < datetime.now(timezone.utc):
                raise ValueError("Approval request expired")
            run.update(
                status="approved" if decision == "approve" else "rejected",
                approved_by=actor["id"],
                approval_note=note,
            )
            self.store.put(conn, tenant, "run", run, id_)
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "playbook.reviewed",
                {"run_id": id_, "decision": decision},
            )
        return run

    def execute(self, actor, id_, rollback=False):
        tenant = scope(actor, {"analyst", "cloud", "approver"})
        with self.store.connection(tenant) as conn:
            run = self.store.get(tenant, "run", id_, conn)
            if not rollback and run["status"] == "completed":
                return {**run, "idempotent_replay": True}
            if rollback:
                if run["status"] != "completed":
                    raise ValueError("Only completed runs may be rolled back")
            elif run["status"] != "approved":
                raise ValueError("Explicit approval required")
            if not rollback and datetime.fromisoformat(
                run["expires_at"]
            ) < datetime.now(timezone.utc):
                raise ValueError("Approval expired before execution")
            if actor["role"] == "cloud":
                case = self.store.get(tenant, "case", run["case_id"], conn)
                alert = self.store.get(tenant, "alert", case["alert_id"], conn)
                if alert["source"] not in ("cloud", "kubernetes"):
                    raise PermissionError("Cloud role scope exceeded")
            definition = next(p for p in self.playbooks if p["id"] == run["playbook"])
            # The only response adapter mutates a reversible synthetic resource record.
            resource_id = hashlib.sha256(run["asset"].encode()).hexdigest()[:24]
            try:
                resource = self.store.get(tenant, "resource", resource_id, conn)
            except ValueError:
                resource = {"asset": run["asset"], "state": "normal"}
            if rollback:
                resource = run["before"]
                run["status"] = "rolled_back"
            else:
                run["before"] = resource.copy()
                resource = {
                    **resource,
                    "state": definition["lab_action"],
                    "run_id": id_,
                }
                run.update(
                    status="completed",
                    completed_at=utcnow(),
                    steps=[
                        {"step": s, "result": "simulated_success"}
                        for s in definition["steps"]
                    ],
                )
            self.store.put(conn, tenant, "resource", resource, resource_id)
            self.store.put(conn, tenant, "run", run, id_)
            self.store.put(
                conn,
                tenant,
                "notification",
                {
                    "type": "in_app",
                    "run_id": id_,
                    "message": "Lab response " + run["status"],
                    "at": utcnow(),
                },
            )
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "playbook." + run["status"],
                {"run_id": id_, "mode": "lab_simulation"},
            )
        return run

    def report(self, actor):
        tenant = scope(actor, {"compliance", "analyst"})
        with self.store.connection(tenant) as conn:
            alerts = self.store.list(tenant, "alert", conn)
            audit = self.store.verify_audit(tenant)
            document = {
                "schema": "securefi-compliance/v2",
                "tenant_id": tenant,
                "generated_at": utcnow(),
                "scope": "Synthetic lab; candidate control relationships, no certification",
                "alerts": alerts,
                "cases": self.store.list(tenant, "case", conn),
                "playbooks": self.store.list(tenant, "run", conn),
                "control_register": self.controls,
                "audit_checkpoint": audit,
                "data_minimisation": "Raw principal, IP, prompt and output text not retained",
            }
            digest = hashlib.sha256(canonical(document).encode()).hexdigest()
            result = self.store.put(
                conn,
                tenant,
                "evidence",
                {"digest": digest, "document": document, "created_at": utcnow()},
            )
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "evidence.generated",
                {"id": result["id"], "sha256": digest},
            )
        return result

    def state(self, actor):
        tenant = scope(actor, ROLES)
        with self.store.connection() as conn:
            alerts = self.store.list(tenant, "alert", conn)
            events = self.store.list(tenant, "event", conn)
            cases = self.store.list(tenant, "case", conn)
            runs = self.store.list(tenant, "run", conn)
            jobs = conn.execute(
                "SELECT state,COUNT(*) FROM jobs WHERE tenant=? GROUP BY state",
                (tenant,),
            ).fetchall()
        delays = [
            max(
                0,
                (
                    datetime.fromisoformat(a["detected_at"])
                    - datetime.fromisoformat(a["first_seen"])
                ).total_seconds(),
            )
            for a in alerts
        ]
        completed = [c for c in cases if c.get("resolved_at")]
        metrics = {
            "events": len(events),
            "alerts": len(alerts),
            "open_cases": sum(c["status"] not in ("resolved", "closed") for c in cases),
            "high_risk": sum(a["risk"]["score"] >= 80 for a in alerts),
            "mean_detection_seconds": sum(delays) / max(1, len(delays)),
            "mean_resolution_seconds": sum(
                (
                    datetime.fromisoformat(c["resolved_at"])
                    - datetime.fromisoformat(c["created_at"])
                ).total_seconds()
                for c in completed
            )
            / max(1, len(completed)),
            "completed_runs": sum(r["status"] == "completed" for r in runs),
            "jobs": dict(jobs),
        }
        result = {
            "metrics": metrics,
            "role": actor["role"],
            "tenant": tenant,
            "rules": self.rules,
            "controls": self.controls,
            "playbooks": self.playbooks,
        }
        if actor["role"] in ("executive", "ingestor"):
            return result
        if actor["role"] == "cloud":
            alerts = [a for a in alerts if a["source"] in ("cloud", "kubernetes")]
            events = [e for e in events if e["source"] in ("cloud", "kubernetes")]
            allowed = {a["id"] for a in alerts}
            cases = [c for c in cases if c["alert_id"] in allowed]
            allowed_cases = {c["id"] for c in cases}
            runs = [r for r in runs if r["case_id"] in allowed_cases]
        notifications = self.store.list(tenant, "notification")
        models = self.store.list(tenant, "model")
        evidence = self.store.list(tenant, "evidence")
        if actor["role"] == "cloud":
            notifications = [
                n for n in notifications if n.get("run_id") in {r["id"] for r in runs}
            ]
            models = []
            evidence = []
        result.update(
            events=events[-500:],
            alerts=sorted(alerts, key=lambda a: -a["risk"]["score"]),
            cases=cases,
            runs=runs,
            notifications=notifications,
            models=models,
            evidence=evidence,
        )
        return result

    def retention(self, actor, days=30):
        tenant = scope(actor, {"compliance"})
        if not isinstance(days, int) or not 1 <= days <= 365:
            raise ValueError("Retention must be 1–365 days")
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self.store.connection(tenant) as conn:
            references = {
                id_
                for a in self.store.list(tenant, "alert", conn)
                for id_ in a["evidence_ids"]
            }
            removed = 0
            for event in self.store.list(tenant, "event", conn):
                if (
                    event["id"] not in references
                    and datetime.fromisoformat(event["time"]) < cutoff
                ):
                    conn.execute(
                        "DELETE FROM records WHERE tenant=? AND kind=? AND id=?",
                        (tenant, "event", event["id"]),
                    )
                    removed += 1
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "retention.executed",
                {"days": days, "unreferenced_events_removed": removed},
            )
        return {"removed": removed, "protected_by_evidence_reference": len(references)}
