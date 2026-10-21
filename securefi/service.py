"""Application rules shared by HTTP and CLI entry points."""

import hashlib
import json
from datetime import datetime, timezone, date
from .adapters import parse_report, fingerprint, string, obj
from .controls import CONTROLS
from .risk import score, priority, summarise

TRANSITIONS = {
    "open": {"triaged"},
    "triaged": {"in_progress", "accepted"},
    "in_progress": {"resolved", "accepted"},
    "resolved": {"open"},
    "accepted": {"open"},
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def log(conn, actor, action, target, details):
    conn.execute(
        "INSERT INTO events(at,actor,action,target,details) VALUES(?,?,?,?,?)",
        (now(), actor, action, str(target), json.dumps(details, sort_keys=True)),
    )


def integer(value, label, low=1, high=2147483647):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer between {low} and {high}")
    return value


def iso_date(value, label, required=False):
    if not isinstance(value, str) or (required and not value):
        raise ValueError(f"{label} must be YYYY-MM-DD")
    if value:
        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            raise ValueError(f"{label} must be YYYY-MM-DD") from None
        if parsed.isoformat() != value:
            raise ValueError(f"{label} must be YYYY-MM-DD")
    return value


class Service:
    def __init__(self, db):
        self.db = db
        with db.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO controls(id,title,frameworks) VALUES(?,?,?)",
                [
                    (i, title, json.dumps(frameworks))
                    for i, title, frameworks in CONTROLS
                ],
            )

    def create_asset(self, data, actor="local analyst"):
        obj(data)
        name = string(data.get("name"), "name", 120)
        owner = string(data.get("owner"), "owner", 120)
        criticality = integer(data.get("criticality"), "criticality", 1, 5)
        exposed = data.get("internet_exposed")
        if type(exposed) is not bool:
            raise ValueError("internet_exposed must be boolean")
        environment = data.get("environment", "test")
        if environment not in ("production", "staging", "test"):
            raise ValueError("environment must be production, staging or test")
        with self.db.connect() as conn:
            if conn.execute("SELECT id FROM assets WHERE name=?", (name,)).fetchone():
                raise ValueError("An asset with this name already exists")
            id_ = conn.execute(
                "INSERT INTO assets(name,owner,criticality,internet_exposed,environment,created_at) VALUES(?,?,?,?,?,?)",
                (name, owner, criticality, exposed, environment, now()),
            ).lastrowid
            log(conn, actor, "asset.created", id_, {"name": name})
        return {"id": id_}

    def ingest(self, asset_id, kind, payload, actor="local analyst"):
        integer(asset_id, "asset_id")
        findings, components = parse_report(kind, payload)
        created = updated = 0
        stamp = now()
        with self.db.connect() as conn:
            if not conn.execute(
                "SELECT id FROM assets WHERE id=?", (asset_id,)
            ).fetchone():
                raise ValueError("Unknown asset")
            # Reject duplicate identities in one batch; repeated imports update observations.
            seen = set()
            for item in findings:
                fp = fingerprint(asset_id, item)
                if fp in seen:
                    continue
                seen.add(fp)
                previous = conn.execute(
                    "SELECT * FROM findings WHERE fingerprint=?", (fp,)
                ).fetchone()
                if previous:
                    status = (
                        "open"
                        if previous["status"] == "resolved"
                        else previous["status"]
                    )
                    conn.execute(
                        "UPDATE findings SET title=?,severity=?,category=?,recommendation=?,known_exploited=?,last_seen=?,occurrences=occurrences+1,status=? WHERE id=?",
                        (
                            item["title"],
                            item["severity"],
                            item["category"],
                            item["recommendation"],
                            item["known_exploited"],
                            stamp,
                            status,
                            previous["id"],
                        ),
                    )
                    if status != previous["status"]:
                        log(
                            conn,
                            actor,
                            "finding.reopened",
                            previous["id"],
                            {"reason": "Observed again in imported report"},
                        )
                    updated += 1
                else:
                    conn.execute(
                        "INSERT INTO findings(fingerprint,asset_id,source,external_id,location,title,severity,category,recommendation,known_exploited,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            fp,
                            asset_id,
                            item["source"],
                            item["external_id"],
                            item["location"],
                            item["title"],
                            item["severity"],
                            item["category"],
                            item["recommendation"],
                            item["known_exploited"],
                            stamp,
                            stamp,
                        ),
                    )
                    created += 1
            for item in components:
                conn.execute(
                    "INSERT INTO components(asset_id,ref,name,version,purl) VALUES(?,?,?,?,?) ON CONFLICT(asset_id,ref) DO UPDATE SET name=excluded.name,version=excluded.version,purl=excluded.purl",
                    (
                        asset_id,
                        item["ref"],
                        item["name"],
                        item["version"],
                        item["purl"],
                    ),
                )
            result = {
                "created": created,
                "updated": updated,
                "components": len(components),
            }
            log(conn, actor, "report.imported", asset_id, {"format": kind, **result})
        return result

    def update_finding(self, id_, data, actor="local analyst"):
        integer(id_, "finding id")
        obj(data)
        note = string(data.get("note"), "review note", 4000)
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (id_,)).fetchone()
            if not row:
                raise ValueError("Unknown finding")
            status = data.get("status", row["status"])
            if status != row["status"] and status not in TRANSITIONS[row["status"]]:
                raise ValueError(
                    f"Cannot move {row['status']} to {status}; follow the review workflow"
                )
            assignee = string(
                data.get("assignee", row["assignee"]), "assignee", 120, empty=True
            )
            due = iso_date(data.get("due_date", row["due_date"]), "due_date")
            until = iso_date(
                data.get("accepted_until", row["accepted_until"]), "accepted_until"
            )
            if status in ("in_progress", "accepted", "resolved") and not assignee:
                raise ValueError("Assign an owner before progressing this finding")
            if status == "accepted" and (not until or until < date.today().isoformat()):
                raise ValueError(
                    "Risk acceptance requires an unexpired accepted_until date"
                )
            if status == "resolved":
                evidence = string(
                    data.get("verification"), "verification evidence", 4000
                )
            else:
                evidence = ""
            conn.execute(
                "UPDATE findings SET status=?,assignee=?,due_date=?,accepted_until=? WHERE id=?",
                (status, assignee, due, until if status == "accepted" else "", id_),
            )
            log(
                conn,
                actor,
                "finding.reviewed",
                id_,
                {
                    "from": row["status"],
                    "to": status,
                    "note": note,
                    "verification": evidence,
                    "assignee": assignee,
                    "due_date": due,
                    "accepted_until": until if status == "accepted" else "",
                },
            )
        return {"id": id_, "status": status}

    def add_evidence(self, data, actor="local analyst"):
        obj(data)
        control = string(data.get("control_id"), "control_id", 100)
        note = string(data.get("note"), "evidence note", 12000)
        finding = data.get("finding_id")
        if finding is not None:
            integer(finding, "finding_id")
        digest = hashlib.sha256(note.encode()).hexdigest()
        with self.db.connect() as conn:
            if not conn.execute(
                "SELECT id FROM controls WHERE id=?", (control,)
            ).fetchone():
                raise ValueError("Unknown control")
            if (
                finding
                and not conn.execute(
                    "SELECT id FROM findings WHERE id=?", (finding,)
                ).fetchone()
            ):
                raise ValueError("Unknown finding")
            id_ = conn.execute(
                "INSERT INTO evidence(control_id,finding_id,note,sha256,author,created_at) VALUES(?,?,?,?,?,?)",
                (control, finding, note, digest, actor, now()),
            ).lastrowid
            conn.execute(
                "UPDATE controls SET review_status='needs_review' WHERE id=?",
                (control,),
            )
            log(
                conn,
                actor,
                "evidence.added",
                id_,
                {"control": control, "sha256": digest},
            )
        return {"id": id_, "sha256": digest}

    def review_control(self, control_id, data, actor="local analyst"):
        obj(data)
        status = data.get("review_status")
        if status not in ("needs_review", "reviewed", "gap"):
            raise ValueError("review_status must be needs_review, reviewed or gap")
        owner = string(data.get("owner"), "owner", 120)
        note = string(data.get("note"), "review note", 4000)
        with self.db.connect() as conn:
            if not conn.execute(
                "SELECT id FROM controls WHERE id=?", (control_id,)
            ).fetchone():
                raise ValueError("Unknown control")
            if (
                status == "reviewed"
                and not conn.execute(
                    "SELECT id FROM evidence WHERE control_id=?", (control_id,)
                ).fetchone()
            ):
                raise ValueError("Add evidence before marking a control reviewed")
            conn.execute(
                "UPDATE controls SET review_status=?,owner=? WHERE id=?",
                (status, owner, control_id),
            )
            log(
                conn,
                actor,
                "control.reviewed",
                control_id,
                {"status": status, "note": note, "owner": owner},
            )
        return {"id": control_id, "review_status": status}

    def snapshot(self):
        with self.db.connect() as conn:
            assets = [
                dict(r) for r in conn.execute("SELECT * FROM assets ORDER BY name")
            ]
            findings = [
                dict(r)
                for r in conn.execute(
                    "SELECT f.*,a.name AS asset_name,a.criticality,a.internet_exposed FROM findings f JOIN assets a ON a.id=f.asset_id"
                )
            ]
            controls = [
                dict(r) for r in conn.execute("SELECT * FROM controls ORDER BY id")
            ]
            evidence = [
                dict(r) for r in conn.execute("SELECT * FROM evidence ORDER BY id DESC")
            ]
            components = [
                dict(r) for r in conn.execute("SELECT * FROM components ORDER BY name")
            ]
            events = [
                dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id DESC")
            ]
        today = date.today().isoformat()
        for f in findings:
            f["risk"] = score(
                f["severity"],
                f["criticality"],
                f["internet_exposed"],
                f["known_exploited"],
            )
            f["priority"] = priority(f["risk"]["score"])
            f["acceptance_expired"] = (
                f["status"] == "accepted" and f["accepted_until"] < today
            )
            f["active"] = (
                f["status"] not in ("resolved", "accepted") or f["acceptance_expired"]
            )
            f["overdue"] = bool(f["active"] and f["due_date"] and f["due_date"] < today)
            f["summary"] = summarise(f)
        findings.sort(key=lambda f: (-f["risk"]["score"], f["id"]))
        for c in controls:
            c["frameworks"] = json.loads(c["frameworks"])
            c["evidence_count"] = sum(e["control_id"] == c["id"] for e in evidence)
        for e in events:
            e["details"] = json.loads(e["details"])
        active = [f for f in findings if f["active"]]
        return {
            "generated_at": now(),
            "assets": assets,
            "findings": findings,
            "controls": controls,
            "evidence": evidence,
            "components": components,
            "events": events,
            "metrics": {
                "assets": len(assets),
                "active_findings": len(active),
                "p1": sum(f["priority"] == "P1" for f in active),
                "overdue": sum(f["overdue"] for f in active),
                "reviewed_controls": sum(
                    c["review_status"] == "reviewed" for c in controls
                ),
            },
        }

    def gate(self, threshold=80):
        integer(threshold, "threshold", 1, 100)
        blocked = [
            f["id"]
            for f in self.snapshot()["findings"]
            if f["active"] and f["risk"]["score"] >= threshold
        ]
        return {
            "passed": not blocked,
            "threshold": threshold,
            "blocking_findings": blocked,
        }
