"""Rule fixture coverage, explicitly separate from real-world accuracy claims."""

import tempfile
from pathlib import Path
from .store import Store
from .app import Platform
from .synthetic import scenarios


def evaluate():
    with tempfile.TemporaryDirectory() as temp:
        app = Platform(
            Store(Path(temp) / "evaluation.db"),
            "evaluation-pseudonym-key-32-characters",
        )
        actor = {"id": "evaluation", "role": "admin", "tenant": "evaluation"}
        result = app.ingest(actor, scenarios())
        state = app.state(actor)
        covered = {a["rule_id"] for a in state["alerts"]}
        result.update(
            rules=len(app.rules),
            covered_rules=len(covered),
            missing_rules=sorted({r["id"] for r in app.rules} - covered),
            meaning="Catalogue-driven positive smoke coverage, not an unbiased accuracy benchmark",
            audit=app.store.verify_audit("evaluation"),
        )
        return result
