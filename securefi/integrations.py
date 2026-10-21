"""AI drafts and frozen evidence snapshots. No autonomous finding mutations."""

import hashlib
import json
import os
import threading
from . import ai
from .adapters import obj, string
from .blockchain import LedgerClient, canonical
from .service import now, log, integer


class Integrations:
    def __init__(self, service):
        self.service = service
        self.db = service.db
        self.lock = threading.Lock()

    def state(self):
        with self.db.connect() as conn:
            drafts = [
                dict(r)
                for r in conn.execute("SELECT * FROM ai_drafts ORDER BY id DESC")
            ]
            snapshots = [
                dict(r)
                for r in conn.execute(
                    "SELECT id,digest,created_at,chain_id,contract_address,tx_hash,block_number FROM ledger_snapshots ORDER BY id DESC"
                )
            ]
            stored = conn.execute(
                "SELECT value FROM settings WHERE key='registry'"
            ).fetchone()
        for item in drafts:
            item["draft"] = json.loads(item.pop("draft_json"))
            item["input"] = json.loads(item.pop("input_json"))
        try:
            config = ai.settings()
            ai_config = {
                "provider": config["provider"],
                "model": config["model"],
                "error": "",
            }
        except ValueError as error:
            ai_config = {"provider": "invalid", "model": "", "error": str(error)}
        return {
            "ai": ai_config,
            "drafts": drafts,
            "snapshots": snapshots,
            "chain_enabled": os.environ.get("SECUREFI_CHAIN_ENABLED") == "1",
            "registry": json.loads(stored["value"]) if stored else None,
        }

    def generate(self, finding_id):
        integer(finding_id, "finding_id")
        finding = next(
            (f for f in self.service.snapshot()["findings"] if f["id"] == finding_id),
            None,
        )
        if not finding:
            raise ValueError("Unknown finding")
        result = ai.draft(finding)
        with self.db.connect() as conn:
            id_ = conn.execute(
                "INSERT INTO ai_drafts(finding_id,provider,model,fallback_reason,input_sha256,input_json,draft_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    finding_id,
                    result["provider"],
                    result["model"],
                    result["fallback_reason"],
                    result["input_sha256"],
                    json.dumps(result["input"]),
                    json.dumps(result["draft"]),
                    now(),
                ),
            ).lastrowid
            log(
                conn,
                "local analyst",
                "ai.draft_created",
                id_,
                {"provider": result["provider"], "finding_id": finding_id},
            )
        return {"id": id_, **result}

    def review_draft(self, data):
        obj(data)
        id_ = integer(data.get("id"), "draft id")
        decision = data.get("decision")
        if decision not in ("approved", "rejected"):
            raise ValueError("decision must be approved or rejected")
        note = string(data.get("note"), "review note", 4000)
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM ai_drafts WHERE id=?", (id_,)).fetchone()
            if not row:
                raise ValueError("Unknown draft")
            if row["status"] != "pending":
                raise ValueError(
                    "Draft already reviewed; generate a new draft for another review"
                )
            conn.execute(
                "UPDATE ai_drafts SET status=?,reviewer_note=? WHERE id=?",
                (decision, note, id_),
            )
            log(
                conn,
                "local analyst",
                "ai.draft_reviewed",
                id_,
                {"decision": decision, "note": note},
            )
        return {"id": id_, "status": decision}

    def freeze(self):
        # Exclude ledger history to prevent recursive snapshots of prior snapshots.
        document = {
            "schema": "securefi-evidence/v1",
            "snapshot": self.service.snapshot(),
            "ai_drafts": self.state()["drafts"],
        }
        raw = canonical(document)
        if len(raw) > 1500000:
            raise ValueError("Snapshot exceeds the 1.5 MB portfolio limit")
        digest = hashlib.sha256(raw).hexdigest()
        with self.db.connect() as conn:
            id_ = conn.execute(
                "INSERT INTO ledger_snapshots(digest,content,created_at) VALUES(?,?,?)",
                (digest, raw.decode(), now()),
            ).lastrowid
            log(
                conn,
                "local analyst",
                "ledger.snapshot_created",
                id_,
                {"digest": digest},
            )
        return {"id": id_, "digest": digest}

    def get_snapshot(self, id_):
        integer(id_, "snapshot id")
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ledger_snapshots WHERE id=?", (id_,)
            ).fetchone()
        if not row:
            raise ValueError("Unknown snapshot")
        return dict(row)

    def deploy(self):
        with self.lock:
            client = LedgerClient()
            current = self.state()["registry"]
            if current:
                client.check_contract(current["contract_address"])
                return {**current, "reused": True}
            result = client.deploy()
            with self.db.connect() as conn:
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('registry',?)",
                    (json.dumps(result),),
                )
                log(
                    conn,
                    "local analyst",
                    "ledger.registry_deployed",
                    result["contract_address"],
                    result,
                )
            return result

    def reset_registry(self, confirm):
        if confirm != "LOCAL CHAIN RESET":
            raise ValueError("Confirmation must be LOCAL CHAIN RESET")
        with self.lock, self.db.connect() as conn:
            conn.execute("DELETE FROM settings WHERE key='registry'")
            log(
                conn,
                "local analyst",
                "ledger.registry_forgotten",
                "registry",
                {"reason": "Local chain reset; historical records retained"},
            )
        return {
            "status": "registry configuration removed; historical snapshots retained"
        }

    def anchor(self, id_):
        with self.lock:
            row = self.get_snapshot(id_)
            actual = hashlib.sha256(canonical(json.loads(row["content"]))).hexdigest()
            if actual != row["digest"]:
                raise ValueError("Stored snapshot has changed; refusing to anchor")
            registry = self.state()["registry"]
            if not registry:
                raise ValueError("Deploy the local registry first")
            if (
                row["contract_address"]
                and row["contract_address"] != registry["contract_address"]
            ):
                raise ValueError(
                    "Snapshot belongs to another registry; create a new snapshot"
                )
            result = LedgerClient().anchor(registry["contract_address"], row["digest"])
            tx_hash = result["tx_hash"] or row["tx_hash"]
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE ledger_snapshots SET chain_id=?,contract_address=?,tx_hash=?,block_number=? WHERE id=?",
                    (
                        31337,
                        registry["contract_address"],
                        tx_hash,
                        result["block_number"],
                        id_,
                    ),
                )
                log(
                    conn,
                    "local analyst",
                    "ledger.snapshot_anchored",
                    id_,
                    {
                        "digest": row["digest"],
                        "tx_hash": tx_hash,
                        "contract_address": registry["contract_address"],
                        "already_recorded": result["already_recorded"],
                    },
                )
            return {"id": id_, **result, "tx_hash": tx_hash}

    def verify(self, id_, document=None):
        row = self.get_snapshot(id_)
        actual = hashlib.sha256(
            canonical(json.loads(row["content"]) if document is None else document)
        ).hexdigest()
        matches = actual == row["digest"]
        result = {
            "id": id_,
            "expected_digest": row["digest"],
            "actual_digest": actual,
            "matches_snapshot": matches,
            "recorded_on_chain": False,
            "verified": False,
        }
        if not matches:
            return {
                **result,
                "reason": "The document does not match the frozen snapshot",
            }
        if not row["contract_address"]:
            return {**result, "reason": "Snapshot has not been anchored"}
        record = LedgerClient().lookup(row["contract_address"], actual)
        result.update(
            recorded_on_chain=record["recorded"],
            verified=record["recorded"],
            record=record,
        )
        return result
