"""Synthetic examples; no customer, payment or personal records."""

from datetime import date, timedelta


def seed(service):
    if service.snapshot()["assets"]:
        raise ValueError("Demo requires an empty database. Choose a new --db path.")
    definitions = [
        ("Payments API", "Payments engineering", 5, True, "production"),
        ("Settlement worker", "Core banking", 5, False, "production"),
        ("Customer portal", "Digital channels", 4, True, "production"),
        ("Analytics storage", "Data platform", 3, False, "staging"),
    ]
    ids = []
    for name, owner, criticality, exposed, environment in definitions:
        ids.append(
            service.create_asset(
                dict(
                    name=name,
                    owner=owner,
                    criticality=criticality,
                    internet_exposed=exposed,
                    environment=environment,
                ),
                "demo setup",
            )["id"]
        )
    examples = [
        (
            0,
            "DEMO-001",
            "Privileged API route missing role check",
            "high",
            "SAST",
            "/admin/refunds",
            "Add server-side role checks and a negative authorisation test.",
        ),
        (
            0,
            "DEMO-002",
            "Public service accepts legacy TLS policy",
            "medium",
            "cloud",
            "api-edge",
            "Apply the approved TLS policy and verify clients can still connect.",
        ),
        (
            1,
            "DEMO-003",
            "Outdated settlement parser dependency",
            "critical",
            "SCA",
            "pkg:pypi/demo-parser@0.1",
            "Upgrade the parser in staging and rerun reconciliation tests.",
        ),
        (
            2,
            "DEMO-004",
            "Session cookie lacks a security attribute",
            "medium",
            "DAST",
            "/login",
            "Set the appropriate cookie attributes and retest login and logout.",
        ),
        (
            3,
            "DEMO-005",
            "Storage access logging disabled",
            "low",
            "cloud",
            "analytics-bucket",
            "Enable access logging with a documented retention policy.",
        ),
        (
            0,
            "DEMO-006",
            "Repeated failed privileged sign-ins",
            "high",
            "SIEM",
            "admin-auth",
            "Correlate identity and gateway records; verify whether the attempts are expected.",
        ),
        (
            1,
            "DEMO-007",
            "Service account review overdue",
            "medium",
            "manual",
            "settlement-service",
            "Review entitlements with the service owner and record the decision.",
        ),
        (
            2,
            "DEMO-008",
            "Verbose error response",
            "low",
            "DAST",
            "/checkout",
            "Return generic client errors and retain detailed server-side diagnostics.",
        ),
    ]
    for asset, id_, title, severity, category, location, recommendation in examples:
        service.ingest(
            ids[asset],
            "normalized",
            {
                "findings": [
                    dict(
                        external_id=id_,
                        title=title,
                        severity=severity,
                        category=category,
                        location=location,
                        recommendation=recommendation,
                        source="Synthetic demo",
                        known_exploited=False,
                    )
                ]
            },
            "demo setup",
        )
    due = (date.today() + timedelta(days=7)).isoformat()
    service.update_finding(
        1,
        dict(
            status="triaged",
            note="Reproduced using a synthetic test identity.",
            assignee="Payments engineering",
            due_date=due,
        ),
        "demo analyst",
    )
    service.update_finding(
        1,
        dict(status="in_progress", note="Fix assigned to the next patch release."),
        "demo analyst",
    )
    service.add_evidence(
        dict(
            control_id="vulnerability",
            finding_id=1,
            note="Synthetic evidence: triage completed, owner assigned, patch verification still pending.",
        ),
        "demo analyst",
    )
    service.ingest(
        ids[1],
        "cyclonedx",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "bom-ref": "demo-parser",
                    "name": "demo-parser",
                    "version": "0.1",
                    "purl": "pkg:pypi/demo-parser@0.1",
                }
            ],
        },
        "demo setup",
    )
    return {"assets": 4, "findings": 8, "message": "Synthetic demo loaded"}
