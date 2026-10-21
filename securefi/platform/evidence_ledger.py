"""Development-chain attestation of product evidence reports."""

import hashlib
import json
from .app import scope
from .store import canonical, utcnow
from ..blockchain import LedgerClient

REGISTRY_ID = "evidence-registry"


def deploy(app, actor):
    tenant = scope(actor, {"approver"})
    client = LedgerClient()
    # One tenant transaction serialises this deployment with other mutations.
    with app.store.connection(tenant) as conn:
        try:
            existing = app.store.get(tenant, "registry", REGISTRY_ID, conn)
        except ValueError:
            existing = None
        if existing:
            client.check_contract(existing["contract_address"])
            return {**existing, "reused": True}
        result = client.deploy()
        result = app.store.put(conn, tenant, "registry", result, REGISTRY_ID)
        app.store.audit(conn, tenant, actor["id"], "registry.deployed", result)
    return result


def anchor(app, actor, id_):
    tenant = scope(actor, {"compliance", "analyst"})
    client = LedgerClient()
    with app.store.connection(tenant) as conn:
        report = app.store.get(tenant, "evidence", id_, conn)
        actual = hashlib.sha256(canonical(report["document"]).encode()).hexdigest()
        if actual != report["digest"]:
            raise ValueError("Evidence document changed; refusing to record its hash")
        registry = app.store.get(tenant, "registry", REGISTRY_ID, conn)
        result = client.anchor(registry["contract_address"], actual)
        report["attestation"] = {
            "contract_address": registry["contract_address"],
            "chain_id": 31337,
            "tx_hash": result["tx_hash"]
            or report.get("attestation", {}).get("tx_hash"),
            "block_number": result["block_number"],
            "recorded_at": utcnow(),
        }
        app.store.put(conn, tenant, "evidence", report, id_)
        app.store.audit(
            conn,
            tenant,
            actor["id"],
            "evidence.anchored",
            {"id": id_, "digest": actual, **report["attestation"]},
        )
    return report["attestation"]


def verify(app, actor, id_, document=None):
    tenant = scope(actor, {"compliance", "analyst"})
    report = app.store.get(tenant, "evidence", id_)
    actual = hashlib.sha256(
        canonical(document if document is not None else report["document"]).encode()
    ).hexdigest()
    result = {
        "matches_document": actual == report["digest"],
        "recorded_on_chain": False,
        "verified": False,
        "expected_digest": report["digest"],
        "actual_digest": actual,
    }
    if not result["matches_document"]:
        return {**result, "reason": "Document hash mismatch"}
    if not report.get("attestation"):
        return {**result, "reason": "Evidence has not been recorded on the blockchain"}
    record = LedgerClient().lookup(report["attestation"]["contract_address"], actual)
    result.update(
        recorded_on_chain=record["recorded"], verified=record["recorded"], record=record
    )
    return result
