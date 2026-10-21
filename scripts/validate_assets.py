"""Static asset validation. This does not replace Terraform/Helm/cluster validation."""

import json, sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
import yaml, jsonschema, hcl2

for path in root.rglob("*.json"):
    if any(p in path.parts for p in ("node_modules", "data", "artifacts")):
        continue
    json.loads(path.read_text())
for path in [
    *root.glob("deploy/kubernetes/*.yaml"),
    root / "deploy/compose/compose.yaml",
    *root.glob(".github/workflows/*.yml"),
]:
    list(yaml.safe_load_all(path.read_text()))
for path in root.glob("infra/terraform/**/*.tf"):
    with path.open() as f:
        hcl2.load(f)
schema = json.loads((root / "schemas/event.schema.json").read_text())
for event in json.loads((root / "datasets/sample-normalised.json").read_text()):
    jsonschema.validate(event, schema)
print(
    "PASS: JSON, normalised-event schema, raw YAML and HCL syntax parsing. External deployment tools not invoked."
)
