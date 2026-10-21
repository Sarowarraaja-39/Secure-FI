from pathlib import Path
import json, sys, tempfile, time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from securefi.platform.store import Store
from securefi.platform.product import Product as Platform
from securefi.platform.synthetic import ml_dataset, scenarios
from securefi.platform.ml import train
from securefi.platform.evaluate import evaluate

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    app = Platform(Store(Path(temp) / "eval.db"), "evaluation-pseudonymisation-key-32")
    actor = {"role": "admin", "id": "eval", "tenant": "eval"}
    start = time.perf_counter()
    app.ingest(actor, scenarios())
    elapsed = time.perf_counter() - start
    model = train(app, actor, ml_dataset())
    result = {
        "rule_coverage": evaluate(),
        "ml": model["evaluation"],
        "dataset_hash": model["dataset_sha256"],
        "benchmark": {
            "events": len(scenarios()),
            "elapsed_seconds": elapsed,
            "events_per_second": len(scenarios()) / elapsed,
            "meaning": "Single-process local microbenchmark, not sustained throughput",
        },
        "environment": {"python": sys.version, "external_services": "none"},
    }
(root / "artifacts").mkdir(exist_ok=True)
(root / "artifacts/evaluation.json").write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
