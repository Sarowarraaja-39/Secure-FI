"""Reproducible supervised/unsupervised baselines with JSON-only model artifacts."""

import hashlib
import json
import math
import random
import statistics
from datetime import datetime
from .store import canonical, utcnow
from .app import scope

FEATURES = [
    "log_bytes_out",
    "log_request_count",
    "distinct_targets",
    "log_duration_ms",
    "log_token_count",
    "privileged",
]


def features(event):
    d = event["data"]
    return [
        math.log1p(d.get("bytes_out", 0)),
        math.log1p(d.get("request_count", 0)),
        float(d.get("distinct_targets", 0)),
        math.log1p(d.get("duration_ms", 0)),
        math.log1p(d.get("token_count", 0)),
        float(bool(d.get("privileged", False))),
    ]


def sigmoid(x):
    return 1 / (1 + math.exp(-max(-40, min(40, x))))


def measure(labels, scores, threshold):
    predictions = [s >= threshold for s in scores]
    tp = sum(y == 1 and p for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p for y, p in zip(labels, predictions))
    fn = sum(y == 1 and not p for y, p in zip(labels, predictions))
    tn = len(labels) - tp - fp - fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(1e-9, precision + recall),
        "false_positive_rate": fp / max(1, fp + tn),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def predict(model, event):
    x = features(event)
    z = [(v - m) / s for v, m, s in zip(x, model["means"], model["scales"])]
    contributions = [w * v for w, v in zip(model["weights"], z)]
    supervised = sigmoid(model["bias"] + sum(contributions))
    anomaly = math.sqrt(sum(v * v for v in z) / len(z))
    return {
        "probability_like_score": supervised,
        "anomaly_score": anomaly,
        "hybrid_flag": supervised >= model["threshold"]
        and anomaly >= model["anomaly_threshold"],
        "contributions": dict(zip(FEATURES, contributions)),
        "explanation": "Exact logistic log-odds contributions, not SHAP and not calibrated real-world breach probability.",
    }


def train(app, actor, rows, seed=73):
    tenant = scope(actor, {"analyst"})
    if len(rows) < 100 or len(rows) > 20000:
        raise ValueError("Training requires 100–20000 synthetic examples")
    for r in rows:
        if r["event"].get("synthetic") is not True or r["label"] not in (0, 1):
            raise ValueError("Invalid synthetic training record")
    parts = {
        split: [r for r in rows if r["split"] == split]
        for split in ("train", "validation", "test")
    }
    if any(not p for p in parts.values()):
        raise ValueError("Chronological train/validation/test splits required")
    if not max(r["event"]["time"] for r in parts["train"]) < min(
        r["event"]["time"] for r in parts["validation"]
    ) or not max(r["event"]["time"] for r in parts["validation"]) < min(
        r["event"]["time"] for r in parts["test"]
    ):
        raise ValueError("Temporal split leakage detected")
    normal = [features(r["event"]) for r in parts["train"] if r["label"] == 0]
    means = [statistics.mean(c) for c in zip(*normal)]
    scales = [max(0.001, statistics.pstdev(c)) for c in zip(*normal)]
    model = {
        "means": means,
        "scales": scales,
        "weights": [0.0] * len(FEATURES),
        "bias": 0.0,
        "threshold": 0.5,
        "anomaly_threshold": 2,
        "features": FEATURES,
    }
    rng = random.Random(seed)
    training = [
        (
            [(v - m) / s for v, m, s in zip(features(r["event"]), means, scales)],
            r["label"],
        )
        for r in parts["train"]
    ]
    for epoch in range(65):
        rng.shuffle(training)
        for x, label in training:
            error = (
                sigmoid(model["bias"] + sum(w * v for w, v in zip(model["weights"], x)))
                - label
            )
            model["weights"] = [
                w - 0.008 * (error * v + 0.002 * w) for w, v in zip(model["weights"], x)
            ]
            model["bias"] -= 0.008 * error
    validation = [predict(model, r["event"]) for r in parts["validation"]]
    y = [r["label"] for r in parts["validation"]]
    model["threshold"] = max(
        [i / 100 for i in range(10, 91, 5)],
        key=lambda t: measure(y, [v["probability_like_score"] for v in validation], t)[
            "f1"
        ],
    )
    distances = sorted(
        v["anomaly_score"]
        for v, r in zip(validation, parts["validation"])
        if r["label"] == 0
    )
    model["anomaly_threshold"] = distances[
        min(len(distances) - 1, int(len(distances) * 0.95))
    ]
    test = [predict(model, r["event"]) for r in parts["test"]]
    labels = [r["label"] for r in parts["test"]]
    evaluation = {
        "supervised_logistic": measure(
            labels, [p["probability_like_score"] for p in test], model["threshold"]
        ),
        "unsupervised_distance": measure(
            labels, [p["anomaly_score"] for p in test], model["anomaly_threshold"]
        ),
        "hybrid_and": measure(labels, [int(p["hybrid_flag"]) for p in test], 0.5),
    }
    artifact_hash = hashlib.sha256(canonical(model).encode()).hexdigest()
    manifest = {
        "schema": "securefi-model/v1",
        "seed": seed,
        "training_rows": len(parts["train"]),
        "validation_rows": len(parts["validation"]),
        "test_rows": len(parts["test"]),
        "dataset_sha256": hashlib.sha256(canonical(rows).encode()).hexdigest(),
        "model_sha256": artifact_hash,
        "model": model,
        "evaluation": evaluation,
        "status": "candidate",
        "trained_by": actor["id"],
        "created_at": utcnow(),
        "limitations": [
            "Synthetic only",
            "No live deployment accuracy claim",
            "No automatic model promotion",
            "Plain JSON, never pickle",
        ],
    }
    with app.store.connection(tenant) as conn:
        result = app.store.put(conn, tenant, "model", manifest)
        app.store.audit(
            conn,
            tenant,
            actor["id"],
            "model.trained",
            {"model_id": result["id"], "hash": artifact_hash},
        )
    return result


def promote(app, actor, id_):
    tenant = scope(actor, {"approver"})
    with app.store.connection(tenant) as conn:
        model = app.store.get(tenant, "model", id_, conn)
        if model["trained_by"] == actor["id"]:
            raise PermissionError("Trainer cannot approve their own model")
        if (
            hashlib.sha256(canonical(model["model"]).encode()).hexdigest()
            != model["model_sha256"]
        ):
            raise ValueError("Model artifact integrity check failed")
        for old in app.store.list(tenant, "model", conn):
            if old["status"] == "active":
                app.store.put(
                    conn, tenant, "model", {**old, "status": "retired"}, old["id"]
                )
        result = app.store.put(
            conn,
            tenant,
            "model",
            {
                **model,
                "status": "active",
                "approved_by": actor["id"],
                "approved_at": utcnow(),
            },
            id_,
        )
        app.store.audit(conn, tenant, actor["id"], "model.promoted", {"id": id_})
    return result


def drift(reference, current, bins=8):
    if len(reference) < 20 or len(current) < 20:
        raise ValueError("At least 20 observations per drift sample")
    ordered = sorted(reference)
    edges = [
        ordered[min(len(ordered) - 1, int(i * len(ordered) / bins))]
        for i in range(1, bins)
    ]

    def distribution(values):
        counts = [0.5] * bins
        for v in values:
            counts[sum(v > e for e in edges)] += 1
        return [c / sum(counts) for c in counts]

    a, b = distribution(reference), distribution(current)
    psi = sum((p - q) * math.log(p / q) for p, q in zip(a, b))
    return {
        "psi": psi,
        "review_required": psi > 0.25,
        "threshold": 0.25,
        "interpretation": "Distribution shift, not proof of model attack",
    }
