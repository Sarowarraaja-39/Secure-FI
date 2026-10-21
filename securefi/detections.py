"""Offline policy checks and deterministic correlation of exported telemetry."""

from collections import defaultdict
from datetime import datetime, timezone
from .adapters import obj, array, string


def cloud_findings(document):
    """Evaluate a small, provider-neutral snapshot. Missing flags fail validation."""
    findings = []
    checks = [
        (
            "public_access",
            True,
            "PUBLIC",
            "high",
            "Public access enabled",
            "Remove unintended public access and verify permitted consumers.",
        ),
        (
            "encrypted",
            False,
            "ENCRYPTION",
            "high",
            "Encryption flag disabled",
            "Enable the approved encryption configuration and verify key ownership.",
        ),
        (
            "logging_enabled",
            False,
            "LOGGING",
            "medium",
            "Access logging disabled",
            "Enable access logging and document retention and review responsibilities.",
        ),
    ]
    for resource in array(document.get("resources"), "resources"):
        obj(resource, "resource")
        name = string(resource.get("id"), "resource id", 400)
        for field, bad, rule, title_severity, title, recommendation in checks:
            value = resource.get(field)
            if type(value) is not bool:
                raise ValueError(f"{field} must be a boolean for every resource")
            if value == bad:
                findings.append(
                    dict(
                        external_id=rule,
                        title=f"{title}: {name}"[:500],
                        source="SecureFI snapshot policy",
                        location=name,
                        severity=title_severity,
                        category="cloud",
                        recommendation=recommendation,
                    )
                )
    return findings


def correlate_events(document):
    """Five failures per principal in a fixed UTC five-minute bucket creates an alert."""
    buckets = defaultdict(set)
    for event in array(document.get("events"), "events"):
        obj(event, "event")
        id_ = string(event.get("id"), "event id", 120)
        principal = string(event.get("principal"), "principal", 120)
        at = string(event.get("at"), "at", 50)
        try:
            stamp = datetime.fromisoformat(at.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError()
            epoch = int(stamp.timestamp())
        except (ValueError, OverflowError):
            raise ValueError(
                "Event at must be an ISO-8601 timestamp with a timezone"
            ) from None
        event_type = string(event.get("type"), "event type", 100)
        if event_type == "login_failed":
            buckets[(principal, epoch // 300)].add(id_)
    findings = []
    for (principal, bucket), ids in sorted(buckets.items()):
        if len(ids) < 5:
            continue
        start = datetime.fromtimestamp(bucket * 300, timezone.utc).isoformat()
        findings.append(
            dict(
                external_id="AUTH-BURST-001",
                title=f"{len(ids)} failed sign-ins for {principal} in a five-minute window",
                source="SecureFI event correlation",
                location=f"{principal}@{start}",
                severity="high",
                category="SIEM",
                recommendation="Review identity and gateway logs, verify activity with the account owner, and obtain approval before any containment action.",
            )
        )
    return findings
