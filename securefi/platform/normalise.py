"""OCSF-inspired internal envelope, explicitly not full OCSF conformance."""

import hashlib
import hmac
import ipaddress
import json
import math
import os
from datetime import datetime, timezone

SOURCES = {
    "cloud",
    "identity",
    "network",
    "endpoint",
    "application",
    "kubernetes",
    "web3",
    "ai",
}
FIELDS = {
    "operation",
    "result",
    "principal",
    "asset",
    "src_ip",
    "country",
    "lat",
    "lon",
    "bytes_out",
    "duration_ms",
    "request_count",
    "failed_count",
    "distinct_targets",
    "criticality",
    "internet_exposed",
    "known_exploited",
    "mfa",
    "privileged",
    "public",
    "encrypted",
    "logging",
    "approved",
    "permission",
    "resource",
    "port",
    "command",
    "domain",
    "image",
    "trusted_image",
    "mount",
    "namespace",
    "anonymous",
    "prompt",
    "output",
    "tool",
    "allowed_tool",
    "model_id",
    "model_hash",
    "expected_hash",
    "drift",
    "training_error",
    "new_principal",
    "new_region",
    "spender",
    "allowance",
    "amount",
    "balance_before",
    "destination",
    "known_bad",
    "contract",
    "event_name",
    "expected_contract",
    "chain_id",
    "feature_shift",
    "token_count",
    "approved_model",
    "signed",
    "reason",
}
CLASS = {
    "identity": 3002,
    "network": 4001,
    "endpoint": 1007,
    "application": 6003,
    "cloud": 6003,
    "kubernetes": 6003,
    "ai": 0,
    "web3": 0,
}


def normalise(raw, tenant, key=None):
    if not isinstance(raw, dict) or raw.get("source") not in SOURCES:
        raise ValueError("Event needs a supported source")
    if raw.get("synthetic") is not True:
        raise ValueError("Only explicitly synthetic/lab events are accepted")
    id_ = raw.get("event_id")
    if not isinstance(id_, str) or not 1 <= len(id_) <= 120:
        raise ValueError("event_id must be a string of 1–120 characters")
    try:
        stamp = datetime.fromisoformat(raw["time"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError()
        stamp = stamp.astimezone(timezone.utc)
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError("time requires an ISO-8601 timestamp with timezone") from None
    data = raw.get("data")
    if not isinstance(data, dict) or set(data) - FIELDS:
        raise ValueError("data must use the documented allowlisted fields")
    clean = {}
    for field, value in data.items():
        if not isinstance(value, (str, int, float, bool)) or (
            isinstance(value, float) and not math.isfinite(value)
        ):
            raise ValueError("Event data values must be finite scalars")
        if isinstance(value, str) and len(value) > 4000:
            raise ValueError("Event text field exceeds 4000 characters")
        clean[field] = value
    if not isinstance(clean.get("operation"), str):
        raise ValueError("data.operation is required")
    booleans = {
        "internet_exposed",
        "known_exploited",
        "mfa",
        "privileged",
        "public",
        "encrypted",
        "logging",
        "approved",
        "anonymous",
        "trusted_image",
        "allowed_tool",
        "new_principal",
        "new_region",
        "known_bad",
        "approved_model",
        "signed",
    }
    for field in booleans & clean.keys():
        if type(clean[field]) is not bool:
            raise ValueError(f"{field} must be boolean")
    if "criticality" in clean and (
        type(clean["criticality"]) is not int or not 1 <= clean["criticality"] <= 5
    ):
        raise ValueError("criticality must be integer 1–5")
    for field in (
        "lat",
        "lon",
        "bytes_out",
        "duration_ms",
        "request_count",
        "failed_count",
        "distinct_targets",
        "port",
        "drift",
        "feature_shift",
        "allowance",
        "amount",
        "balance_before",
        "token_count",
        "training_error",
    ):
        if field in clean and (
            type(clean[field]) not in (int, float)
            or (field not in ("lat", "lon") and clean[field] < 0)
        ):
            raise ValueError(f"{field} requires a valid numeric value")
    if abs(clean.get("lat", 0)) > 90 or abs(clean.get("lon", 0)) > 180:
        raise ValueError("Invalid coordinates")
    if "src_ip" in clean:
        try:
            ipaddress.ip_address(clean["src_ip"])
        except ValueError:
            raise ValueError("Invalid synthetic IP address") from None
    secret = key or os.environ.get("SECUREFI_PSEUDONYM_KEY")
    if not secret or len(secret) < 24:
        raise ValueError("Set SECUREFI_PSEUDONYM_KEY to at least 24 characters")
    for field in ("principal", "src_ip"):
        if field in clean:
            clean[field] = hmac.new(
                secret.encode(),
                (tenant + ":" + str(clean[field])).encode(),
                hashlib.sha256,
            ).hexdigest()[:24]
    # Do not retain arbitrary prompts or model outputs in the event store.
    for field in ("prompt", "output"):
        if field in clean:
            import re

            text = clean[field]
            clean[field + "_sha256"] = hashlib.sha256(text.encode()).hexdigest()
            clean[field + "_signals"] = ",".join(
                name
                for name, pattern in {
                    "override": r"ignore (?:all |previous )?instructions|system prompt|developer mode",
                    "jailbreak": r"DAN mode|no safety|bypass safeguards",
                    "secret": r"(?:token|secret|password|api_key)\s*[:=]|BEGIN PRIVATE KEY",  # pragma: allowlist secret; detection pattern only
                    "exfil": r"https?://[^\s]+|send .* to|upload .* to",
                }.items()
                if re.search(pattern, text, re.I)
            )
            del clean[field]
    if raw["source"] == "web3" and clean.get("chain_id", 31337) != 31337:
        raise ValueError("Web3 telemetry must target development chain 31337")
    class_uid = CLASS[raw["source"]]
    activity_id = 99 if class_uid else 0
    return {
        "id": id_,
        "event_id": id_,
        "tenant_id": tenant,
        "time": stamp.isoformat(),
        "source": raw["source"],
        "class_uid": class_uid,
        "category_uid": class_uid // 1000,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": 1,
        "metadata": {
            "product": {"name": "SecureFI", "version": "2.1.0"},
            "normalisation": "ocsf-inspired/v1",
            "synthetic": True,
        },
        "data": clean,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
