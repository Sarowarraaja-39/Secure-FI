from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from securefi.platform.synthetic import scenarios, ml_dataset
from securefi.platform.normalise import normalise

root = Path(__file__).resolve().parents[1]
(root / "datasets/sample-events.json").write_text(json.dumps(scenarios(), indent=2))
(root / "datasets/ml-synthetic.jsonl").write_text(
    "\n".join(json.dumps(row) for row in ml_dataset()) + "\n"
)
seen = {}
for e in scenarios():
    seen.setdefault(
        e["source"], normalise(e, "sample-tenant", "documentation-only-pseudonym-key")
    )
(root / "datasets/sample-normalised.json").write_text(
    json.dumps(list(seen.values()), indent=2)
)
print("Generated synthetic fixtures for", len(seen), "telemetry sources")
