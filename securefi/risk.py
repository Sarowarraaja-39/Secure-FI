"""Transparent prioritisation, deliberately separate from scanner severity."""

SEVERITIES = {"info": 0, "low": 15, "medium": 35, "high": 60, "critical": 80}


def score(severity, criticality, internet_exposed, known_exploited=False):
    parts = {
        "severity": SEVERITIES[severity],
        "business_criticality": (criticality - 1) * 3,
        "internet_exposure": 10 if internet_exposed else 0,
        "known_exploitation": 15 if known_exploited else 0,
    }
    return {"score": min(100, sum(parts.values())), "factors": parts}


def priority(value):
    return (
        "P1" if value >= 80 else "P2" if value >= 60 else "P3" if value >= 35 else "P4"
    )


def summarise(finding):
    """No LLM or outbound disclosure; every sentence derives from stored fields."""
    risk = finding["risk"]
    factors = ", ".join(
        f"{k.replace('_', ' ')} +{v}" for k, v in risk["factors"].items() if v
    )
    return (
        f"{finding['title']} affects {finding['asset_name']}. "
        f"Priority {finding['priority']}, score {risk['score']}/100 ({factors or 'no modifiers'}). "
        f"Current status: {finding['status']}. "
        f"Suggested next step: {finding['recommendation']} "
        "Analyst validation is required before accepting or closing this finding."
    )
