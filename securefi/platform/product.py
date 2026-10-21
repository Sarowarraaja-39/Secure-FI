"""Application workflows for alert triage, assets and case collaboration."""

import hashlib
from datetime import date, datetime, timezone
from .app import Platform, scope
from .store import utcnow


def text(value, name, limit=4000, optional=False):
    if (
        not isinstance(value, str)
        or len(value) > limit
        or (not optional and not value.strip())
    ):
        raise ValueError(
            f"{name} must be a valid text value (maximum {limit} characters)"
        )
    return value.strip()


class Product(Platform):
    def _process(self, conn, tenant, event):
        previous = {a["id"]: a for a in self.store.list(tenant, "alert", conn)}
        assets = {a["name"]: a for a in self.store.list(tenant, "asset", conn)}
        alerts = super()._process(conn, tenant, event)
        review_fields = (
            "assignee",
            "triage_note",
            "accepted_until",
            "verification",
            "reviewed_at",
            "reviewed_by",
        )
        for alert in alerts:
            before = previous.get(alert["id"], {})
            for field in review_fields:
                if field in before:
                    alert[field] = before[field]
            asset = assets.get(alert["asset"])
            if asset:
                factors = {
                    **alert["risk"]["factors"],
                    "asset": (asset["criticality"] - 1) * 3,
                    "exposure": 10 if asset["internet_exposed"] else 0,
                }
                alert["risk"] = {
                    **alert["risk"],
                    "factors": factors,
                    "score": min(100, sum(factors.values())),
                }
            if alert["status"] == "resolved" and alert["occurrences"] > 1:
                alert["status"] = "new"
                self.store.audit(
                    conn,
                    tenant,
                    "detector",
                    "alert.reopened",
                    {"alert_id": alert["id"], "reason": "New supporting event"},
                )
            self.store.put(conn, tenant, "alert", alert, alert["id"])
        return alerts

    def _alert(self, conn, actor, id_):
        alert = self.store.get(actor["tenant"], "alert", id_, conn)
        if actor["role"] == "cloud" and alert["source"] not in ("cloud", "kubernetes"):
            raise PermissionError(
                "Cloud role is limited to cloud and Kubernetes alerts"
            )
        return alert

    def ingest(self, actor, raw_events, queued=False):
        tenant = scope(actor, {"ingestor", "analyst", "cloud"})
        if not isinstance(raw_events, list):
            raise ValueError("Events must be an array")
        assets = {a["name"]: a for a in self.store.list(tenant, "asset")}
        prepared = []
        for event in raw_events:
            if not isinstance(event, dict):
                raise ValueError("Each event must be an object")
            if actor["role"] == "cloud" and event.get("source") not in (
                "cloud",
                "kubernetes",
            ):
                raise PermissionError(
                    "Cloud role cannot import other telemetry sources"
                )
            data = event.get("data")
            if isinstance(data, dict) and data.get("asset") in assets:
                asset = assets[data["asset"]]
                original = event
                event = {
                    **event,
                    "data": {
                        **data,
                        "criticality": asset["criticality"],
                        "internet_exposed": asset["internet_exposed"],
                    },
                }
                try:
                    existing = self.store.get(tenant, "event", original.get("event_id"))
                except ValueError:
                    existing = None
                if existing:
                    from .normalise import normalise

                    incoming = normalise(original, tenant, self.key)

                    def identity(record):
                        result = {k: v for k, v in record.items() if k != "ingested_at"}
                        result["data"] = {
                            k: v
                            for k, v in result["data"].items()
                            if k not in ("criticality", "internet_exposed")
                        }
                        return result

                    if identity(incoming) == identity(existing):
                        # Preserve the recorded observation while current asset context
                        # is applied separately to the alert priority.
                        for field in ("criticality", "internet_exposed"):
                            if field in existing["data"]:
                                event["data"][field] = existing["data"][field]
                            else:
                                event["data"].pop(field, None)
            prepared.append(event)
        return super().ingest(actor, prepared, queued)

    def save_asset(self, actor, values):
        tenant = scope(actor, {"analyst"})
        name = text(values.get("name"), "Asset name", 120)
        owner = text(values.get("owner"), "Owner", 120)
        criticality = values.get("criticality")
        if type(criticality) is not int or not 1 <= criticality <= 5:
            raise ValueError("Criticality must be an integer from 1 to 5")
        if type(values.get("internet_exposed")) is not bool:
            raise ValueError("Exposure must be boolean")
        environment = values.get("environment", "test")
        if environment not in ("production", "staging", "test"):
            raise ValueError("Environment must be production, staging or test")
        note = text(values.get("note"), "Change note")
        id_ = hashlib.sha256(name.encode()).hexdigest()[:24]
        with self.store.connection(tenant) as conn:
            result = self.store.put(
                conn,
                tenant,
                "asset",
                {
                    "name": name,
                    "owner": owner,
                    "criticality": criticality,
                    "internet_exposed": values["internet_exposed"],
                    "environment": environment,
                    "updated_at": utcnow(),
                    "updated_by": actor["id"],
                },
                id_,
            )
            for alert in self.store.list(tenant, "alert", conn):
                if alert["asset"] != name:
                    continue
                factors = {
                    **alert["risk"]["factors"],
                    "asset": (criticality - 1) * 3,
                    "exposure": 10 if values["internet_exposed"] else 0,
                }
                alert["risk"] = {
                    **alert["risk"],
                    "factors": factors,
                    "score": min(100, sum(factors.values())),
                }
                self.store.put(conn, tenant, "alert", alert, alert["id"])
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "asset.updated",
                {"asset_id": id_, "note": note},
            )
        return result

    def triage(self, actor, values):
        tenant = scope(actor, {"analyst", "cloud"})
        status = values.get("status")
        if status not in (
            "new",
            "triaged",
            "in_progress",
            "false_positive",
            "risk_accepted",
            "resolved",
        ):
            raise ValueError("Unknown alert status")
        note = text(values.get("note"), "Triage note")
        assignee = text(values.get("assignee", ""), "Assignee", 120, optional=True)
        expiry = values.get("accepted_until", "")
        if status in ("in_progress", "risk_accepted") and not assignee:
            raise ValueError(
                "Assign an owner before progressing or accepting this alert"
            )
        if status == "risk_accepted":
            try:
                parsed = date.fromisoformat(expiry)
                if (
                    parsed.isoformat() != expiry
                    or parsed < datetime.now(timezone.utc).date()
                ):
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError(
                    "Risk acceptance requires an unexpired YYYY-MM-DD date"
                ) from None
        verification = text(
            values.get("verification", ""),
            "Verification",
            optional=status != "resolved",
        )
        with self.store.connection(tenant) as conn:
            alert = self._alert(conn, actor, values.get("id"))
            before = alert["status"]
            alert.update(
                status=status,
                assignee=assignee,
                triage_note=note,
                accepted_until=expiry if status == "risk_accepted" else "",
                verification=verification,
                reviewed_at=utcnow(),
                reviewed_by=actor["id"],
            )
            result = self.store.put(conn, tenant, "alert", alert, alert["id"])
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "alert.triaged",
                {"alert_id": alert["id"], "from": before, "to": status, "note": note},
            )
        return result

    def case(self, actor, alert_id, note):
        tenant = scope(actor, {"analyst", "cloud"})
        note = text(note, "Investigation note")
        with self.store.connection(tenant) as conn:
            alert = self._alert(conn, actor, alert_id)
            cases = self.store.list(tenant, "case", conn)
            existing = next(
                (
                    c
                    for c in cases
                    if c["alert_id"] == alert_id
                    and c["status"] not in ("resolved", "closed")
                ),
                None,
            )
            if existing:
                return {**existing, "already_exists": True}
            case = self.store.put(
                conn,
                tenant,
                "case",
                {
                    "reference": f"INC-{len(cases) + 1:04d}",
                    "alert_id": alert_id,
                    "title": alert["name"],
                    "status": "investigating",
                    "owner": actor["id"],
                    "created_at": utcnow(),
                    "notes": [note],
                    "activity": [
                        {
                            "at": utcnow(),
                            "actor": actor["id"],
                            "note": note,
                            "action": "opened",
                        }
                    ],
                    "asset": alert["asset"],
                    "resolved_at": None,
                },
            )
            self.store.put(
                conn, tenant, "alert", {**alert, "status": "in_progress"}, alert_id
            )
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "case.opened",
                {"case_id": case["id"], "alert_id": alert_id},
            )
        return case

    def update_case(self, actor, values):
        tenant = scope(actor, {"analyst", "cloud"})
        note = text(values.get("note"), "Case note")
        with self.store.connection(tenant) as conn:
            case = self.store.get(tenant, "case", values.get("id"), conn)
            alert = self._alert(conn, actor, case["alert_id"])
            status = values.get("status", case["status"])
            allowed = {
                "investigating": {"contained", "resolved"},
                "contained": {"investigating", "resolved"},
                "resolved": {"closed", "investigating"},
                "closed": {"investigating"},
            }
            if status != case["status"] and status not in allowed[case["status"]]:
                raise ValueError("Invalid case transition")
            verification = text(
                values.get("verification", case.get("verification", "")),
                "Verification",
                optional=status not in ("resolved", "closed"),
            )
            owner = text(values.get("owner", case["owner"]), "Owner", 120)
            activity = case.get("activity", []) + [
                {"at": utcnow(), "actor": actor["id"], "note": note, "action": status}
            ]
            case.update(
                status=status,
                owner=owner,
                notes=case["notes"] + [note],
                activity=activity,
                verification=verification,
                updated_at=utcnow(),
                resolved_at=utcnow() if status in ("resolved", "closed") else None,
            )
            self.store.put(conn, tenant, "case", case, case["id"])
            alert["status"] = (
                "resolved" if status in ("resolved", "closed") else "in_progress"
            )
            self.store.put(conn, tenant, "alert", alert, alert["id"])
            self.store.audit(
                conn,
                tenant,
                actor["id"],
                "case.updated",
                {"case_id": case["id"], "status": status, "note": note},
            )
        return case

    def review_case(self, actor, id_, status, note, verification=""):
        return self.update_case(
            actor,
            {"id": id_, "status": status, "note": note, "verification": verification},
        )

    def activity(self, actor):
        tenant = scope(actor, {"analyst", "compliance", "approver"})
        with self.store.connection() as conn:
            rows = conn.execute(
                "SELECT payload,digest FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 150",
                (tenant,),
            ).fetchall()
        import json

        return [{**json.loads(payload), "digest": digest} for payload, digest in rows]

    def report(self, actor):
        from .store import canonical

        tenant = scope(actor, {"compliance", "analyst"})
        with self.store.connection(tenant) as conn:
            document = {
                "schema": "securefi-evidence/v3",
                "tenant_id": tenant,
                "generated_at": utcnow(),
                "scope": "Controlled workspace; candidate control relationships require human review",
                "data_mode": "synthetic_telemetry",
                "response_mode": "simulation",
                "alerts": self.store.list(tenant, "alert", conn),
                "cases": self.store.list(tenant, "case", conn),
                "assets": self.store.list(tenant, "asset", conn),
                "playbooks": self.store.list(tenant, "run", conn),
                "assistant_drafts": self.store.list(tenant, "draft", conn),
                "control_register": self.controls,
                "audit_checkpoint": self.store.verify_audit(tenant),
                "data_minimisation": "Raw principal, IP, prompt and output text excluded from normalised telemetry",
            }
            digest = hashlib.sha256(canonical(document).encode()).hexdigest()
            report = self.store.put(
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
                {"id": report["id"], "sha256": digest},
            )
        return report

    def state(self, actor):
        state = super().state(actor)
        if actor["role"] in ("executive", "ingestor"):
            all_alerts = self.store.list(actor["tenant"], "alert")
            today = datetime.now(timezone.utc).date().isoformat()
            active = [
                a
                for a in all_alerts
                if a["status"] not in ("false_positive", "resolved", "risk_accepted")
                or (
                    a["status"] == "risk_accepted"
                    and a.get("accepted_until", "") < today
                )
            ]
            state["source_counts"] = {
                source: sum(a["source"] == source for a in active)
                for source in {a["source"] for a in active}
            }
            state["metrics"]["active_alerts"] = len(active)
            state["metrics"]["high_risk"] = sum(
                a["risk"]["score"] >= 80 for a in active
            )
            return state
        assets = {
            a["name"]: {**a, "registered": True}
            for a in self.store.list(actor["tenant"], "asset")
        }
        for event in state["events"]:
            name = event["data"].get("asset", "unknown")
            assets.setdefault(
                name,
                {
                    "id": hashlib.sha256(name.encode()).hexdigest()[:24],
                    "name": name,
                    "owner": "Unassigned",
                    "criticality": event["data"].get("criticality", 3),
                    "internet_exposed": event["data"].get("internet_exposed", False),
                    "registered": False,
                },
            )
        if actor["role"] == "cloud":
            names = {e["data"].get("asset", "unknown") for e in state["events"]}
            assets = {name: value for name, value in assets.items() if name in names}
        today = datetime.now(timezone.utc).date().isoformat()
        for alert in state["alerts"]:
            alert["acceptance_expired"] = (
                alert["status"] == "risk_accepted"
                and alert.get("accepted_until", "") < today
            )
            alert["active"] = (
                alert["status"] not in ("false_positive", "resolved", "risk_accepted")
                or alert["acceptance_expired"]
            )
        state["assets"] = sorted(assets.values(), key=lambda a: a["name"])
        state["metrics"]["active_alerts"] = sum(a["active"] for a in state["alerts"])
        state["metrics"]["high_risk"] = sum(
            a["active"] and a["risk"]["score"] >= 80 for a in state["alerts"]
        )
        drafts = self.store.list(actor["tenant"], "draft")
        if actor["role"] == "cloud":
            allowed_cases = {c["id"] for c in state["cases"]}
            drafts = [d for d in drafts if d["case_id"] in allowed_cases]
        state["assistant_drafts"] = drafts
        state["response_mode"] = "Simulation adapter"
        import os

        state["integrations"] = {
            "ai_provider": os.environ.get("SECUREFI_AI_PROVIDER", "rules"),
            "blockchain_enabled": os.environ.get("SECUREFI_CHAIN_ENABLED") == "1",
        }
        return state
