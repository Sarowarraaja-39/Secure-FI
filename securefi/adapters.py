"""Small, documented format subsets; malformed imports fail atomically."""

import hashlib
import json
from .risk import SEVERITIES

CATEGORIES = {"SAST", "DAST", "SCA", "cloud", "SIEM", "manual"}


def obj(value, label="document"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def array(value, label):
    if not isinstance(value, list) or len(value) > 5000:
        raise ValueError(f"{label} must be an array with at most 5000 entries")
    return value


def string(value, label, maximum=4000, empty=False):
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or (not empty and not value.strip())
    ):
        raise ValueError(
            f"{label} must be {'a non-empty' if not empty else 'a'} string, maximum {maximum} characters"
        )
    return value.strip()


def normalise(item):
    obj(item, "finding")
    result = {
        key: string(item.get(key), key, 4000 if key == "recommendation" else 500)
        for key in ("external_id", "title", "source", "location", "recommendation")
    }
    result["severity"] = string(item.get("severity"), "severity", 20)
    result["category"] = string(item.get("category"), "category", 20)
    if result["severity"] not in SEVERITIES:
        raise ValueError("severity must be info, low, medium, high or critical")
    if result["category"] not in CATEGORIES:
        raise ValueError("unsupported category")
    if type(item.get("known_exploited", False)) is not bool:
        raise ValueError("known_exploited must be a boolean")
    result["known_exploited"] = item.get("known_exploited", False)
    return result


def parse_report(kind, data):
    obj(data)
    if not isinstance(kind, str):
        raise ValueError("format must be a string")
    findings, components = [], []
    if kind == "normalized":
        findings = array(data.get("findings"), "findings")
    elif kind in ("cloud", "events"):
        from .detections import cloud_findings, correlate_events

        findings = cloud_findings(data) if kind == "cloud" else correlate_events(data)
    elif kind == "sarif":
        if data.get("version") != "2.1.0":
            raise ValueError("Only SARIF 2.1.0 is supported")
        for run in array(data.get("runs"), "runs"):
            obj(run, "run")
            driver = obj(obj(run.get("tool"), "tool").get("driver"), "driver")
            source = string(driver.get("name"), "tool name", 500)
            for result in array(run.get("results", []), "results"):
                obj(result, "result")
                locations = array(result.get("locations", []), "locations")
                location = "unspecified"
                if locations:
                    physical = obj(obj(locations[0]).get("physicalLocation", {}))
                    uri = obj(physical.get("artifactLocation", {})).get(
                        "uri", "unspecified"
                    )
                    line = obj(physical.get("region", {})).get("startLine", 0)
                    location = f"{uri}:{line}"
                level = string(result.get("level", "warning"), "SARIF level", 20)
                if level not in ("error", "warning", "note", "none"):
                    raise ValueError("unsupported SARIF level")
                findings.append(
                    dict(
                        external_id=result.get("ruleId", "unspecified"),
                        title=obj(result.get("message")).get("text"),
                        source=source,
                        location=location,
                        severity={
                            "error": "high",
                            "warning": "medium",
                            "note": "low",
                            "none": "info",
                        }[level],
                        category="SAST",
                        recommendation="Review the scanner result and validate a code fix.",
                    )
                )
    elif kind == "cyclonedx":
        if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") not in (
            "1.4",
            "1.5",
            "1.6",
        ):
            raise ValueError("Supported CycloneDX versions: 1.4, 1.5, 1.6")
        for raw in array(data.get("components", []), "components"):
            obj(raw, "component")
            name = string(raw.get("name"), "component name", 500)
            version = string(raw.get("version", ""), "version", 500, empty=True)
            ref = string(
                raw.get("bom-ref") or raw.get("purl") or f"{name}@{version}", "ref", 500
            )
            components.append(
                dict(
                    ref=ref,
                    name=name,
                    version=version,
                    purl=string(raw.get("purl", ""), "purl", 1000, empty=True),
                )
            )
        for vuln in array(data.get("vulnerabilities", []), "vulnerabilities"):
            obj(vuln, "vulnerability")
            ratings = array(vuln.get("ratings", []), "ratings")
            severities = [
                string(obj(r).get("severity", "info"), "rating severity", 20)
                for r in ratings
            ]
            if any(s not in SEVERITIES for s in severities):
                raise ValueError(
                    "CycloneDX rating severity must be info/low/medium/high/critical"
                )
            severity = (
                max(severities, key=lambda s: SEVERITIES[s]) if severities else "info"
            )
            for affect in array(vuln.get("affects", []), "affects"):
                findings.append(
                    dict(
                        external_id=vuln.get("id"),
                        title=vuln.get("description") or vuln.get("id"),
                        source="CycloneDX",
                        location=obj(affect).get("ref"),
                        severity=severity,
                        category="SCA",
                        recommendation=vuln.get("recommendation")
                        or "Validate applicability and upgrade the affected component.",
                    )
                )
    else:
        raise ValueError("format must be normalized, sarif, cyclonedx, cloud or events")
    if len(findings) > 5000:
        raise ValueError("At most 5000 findings per import")
    return [normalise(f) for f in findings], components


def fingerprint(asset_id, finding):
    identity = [
        asset_id,
        finding["source"],
        finding["external_id"],
        finding["location"],
    ]
    return hashlib.sha256(
        json.dumps(identity, separators=(",", ":")).encode()
    ).hexdigest()
