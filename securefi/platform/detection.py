"""Declarative, bounded detection DSL and event-time correlations."""

import hashlib
import json
import math
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def catalogue():
    return json.loads((ROOT / "catalogue.json").read_text())


def field(event, path):
    value = event
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def match(event, condition):
    value = field(event, condition["field"])
    op = condition["op"]
    expected = condition.get("value")
    if op == "eq":
        return type(value) is type(expected) and value == expected
    if op == "neq":
        return value is not None and value != expected
    if op == "gte":
        return type(value) in (int, float) and value >= expected
    if op == "contains":
        return isinstance(value, str) and str(expected).lower() in value.lower()
    if op == "in":
        return value in expected
    if op == "fraction_gte":
        base = field(event, expected["field"])
        return (
            type(value) in (int, float)
            and type(base) in (int, float)
            and base > 0
            and value / base >= expected["ratio"]
        )
    if op == "diff":
        return (
            value is not None
            and field(event, expected) is not None
            and value != field(event, expected)
        )
    raise ValueError("Unsupported detection operator")


def risk(severity, data, confidence=0.8):
    contributions = {
        "severity": {"low": 15, "medium": 35, "high": 60, "critical": 80}[severity],
        "asset": (data.get("criticality", 3) - 1) * 3,
        "exposure": 10 if data.get("internet_exposed") else 0,
        "exploitation": 15 if data.get("known_exploited") else 0,
    }
    return {
        "score": min(100, sum(contributions.values())),
        "factors": contributions,
        "confidence": confidence,
        "meaning": "Priority heuristic, not probability of compromise",
    }


def distance(a, b):
    lat1, lat2 = math.radians(a["lat"]), math.radians(b["lat"])
    dlat = lat2 - lat1
    dlon = math.radians(b["lon"] - a["lon"])
    h = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 6371 * 2 * math.asin(min(1, math.sqrt(h)))


def detect(event, history, rules=None):
    hits = []
    for rule in rules or catalogue():
        if event["source"] != rule["source"] or not all(
            match(event, c) for c in rule.get("conditions", [])
        ):
            continue
        evidence = [event["id"]]
        correlation = rule.get("correlation")
        if correlation:
            current = datetime.fromisoformat(event["time"])
            candidates = [
                e
                for e in history
                if e["source"] == event["source"]
                and e["data"].get(correlation["group"])
                == event["data"].get(correlation["group"])
                and 0
                <= (current - datetime.fromisoformat(e["time"])).total_seconds()
                <= correlation["seconds"]
                and (
                    e["data"].get("operation") == correlation.get("previous_operation")
                    if correlation["kind"] == "sequence"
                    else all(match(e, c) for c in rule.get("conditions", []))
                )
                and e["id"] != event["id"]
            ]
            if correlation["kind"] == "count":
                evidence = sorted({e["id"] for e in candidates} | {event["id"]})
                if len(evidence) < correlation["threshold"]:
                    continue
            elif correlation["kind"] == "sequence":
                if not candidates:
                    continue
                evidence = [max(candidates, key=lambda e: e["time"])["id"], event["id"]]
            elif correlation["kind"] == "travel":
                valid = [
                    e
                    for e in candidates
                    if all(
                        k in e["data"] and k in event["data"] for k in ("lat", "lon")
                    )
                ]
                if not valid:
                    continue
                previous = max(valid, key=lambda e: e["time"])
                hours = (
                    current - datetime.fromisoformat(previous["time"])
                ).total_seconds() / 3600
                if (
                    hours <= 0
                    or distance(previous["data"], event["data"]) / hours
                    < correlation["threshold"]
                ):
                    continue
                evidence = [previous["id"], event["id"]]
        hits.append(
            {
                "rule_id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "risk": risk(rule["severity"], event["data"], rule["confidence"]),
                "attack": rule["attack"],
                "controls": rule["controls"],
                "evidence_ids": evidence,
                "recommended_action": rule["response"],
                "playbook": rule["playbook"],
            }
        )
    return hits
