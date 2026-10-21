# Validation

## Release check results

Run date: **21 October 2026**. Environment: Linux, Python 3.12.14, Node 24.19.0; actual Chromium 153 for the browser check. Results apply to this source release and the supplied synthetic scenarios.

| Check | Result | Practical meaning |
| --- | --- | --- |
| Python unit/boundary suite | 124 passed | Domain rules, imports, HTTP/auth boundaries, persistence, approval, integrity and product regressions |
| Real Chromium workflow | Passed | Ten views, search/triage, source drill-down, assets, cases, draft review, independent approval, simulated execution/restore, JSONL import, report download, audit, executive privacy and mobile overflow |
| FastAPI/ASGI integration | Passed | Synthetic ingestion, 49 rule hits, role/tenant/origin boundaries and scoped state |
| Local EVM integration | Passed | Actual deployment, current application evidence recording/verification, duplicate handling, tamper rejection, owner/zero-hash restrictions and chain-reset failure |
| Catalogue fixture evaluation | 49 of 49 rules exercised by 55 synthetic events | Positive fixture coverage; not measured attack-detection accuracy |
| Structured asset validation | Passed | JSON, event schema, deployment YAML and Terraform HCL syntax parsing |
| Bandit SAST | No medium/high findings at `-ll -ii` | Three low-severity findings remain; no claim of a complete audit |
| Dependency scan | No known vulnerabilities reported by pip-audit | Point-in-time advisory check for `requirements-platform.txt` |
| Secret scan | No unsuppressed findings | Bounded fixtures/generated paths excluded; specific resource-name/detector literals annotated |

A model-service contract test uses controlled model responses. No real LLM weights were downloaded or executed. The default deterministic assistant and invalid-output fallback were tested. Docker image builds/scans, Terraform provider validation/apply, Helm rendering, OPA execution, Kubernetes deployment and PostgreSQL/RabbitMQ/OpenSearch end-to-end runtime were **not executed** in this environment. Their CI jobs and deployment assets are supplied for further validation.

## Core tests

No third-party packages are needed:

```bash
python -m unittest discover -s tests -v
python -m compileall -q securefi services scripts start.py
python scripts/evaluate.py
```

`tests/test_product.py` covers triage rationale/ownership, acceptance expiry, repeated-event metadata, resolved-alert reopening, registered context and queued scoring, case lifecycle/deduplication, cloud scopes, advisory-only drafts, model-output reference checking, tenant separation and frozen evidence integrity. Earlier suites cover the shared import adapters and existing security boundaries.

Tests create temporary data directories. They do not require production credentials, real funds or a live cloud account.

## Browser check

Requires supported Node, npm and a Playwright Chromium installation:

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

On Linux CI, use `npx playwright install --with-deps chromium` to install operating-system dependencies. The test launches a temporary local server and private database, uses a real browser, and removes its workspace afterward. No browser service is required for normal application use.

For an already installed browser, set `SECUREFI_BROWSER_PATH` to its executable. `SECUREFI_BROWSER_ARGS` optionally accepts a JSON array for a constrained test environment. Default tests do not disable browser security flags. They do not generate or commit screenshots.

## Optional ASGI and syntax checks

```bash
python -m pip install -r requirements-platform.txt httpx
python scripts/test_asgi.py
python scripts/validate_assets.py
```

The pinned Starlette release emits an `httpx` compatibility deprecation warning in its test client. It does not affect the default application; the ASGI check passes. This does not exercise a real reverse proxy, database service or container deployment.

## Actual local-chain test

```bash
npm ci --prefix blockchain
npm run compile --prefix blockchain
python tests/evm_smoke.py
```

The test starts and stops its own loopback development chain on an available port. It deploys the compiled Solidity contract, sends actual development-chain transactions, verifies storage, attempts prohibited writes and resets chain state to test failure handling. It also exercises the current Product evidence workflow. All accounts and transactions are disposable development data.

## Security checks

```bash
python -m pip install bandit pip-audit detect-secrets
bandit -r securefi services -ll -ii
pip-audit -r requirements-platform.txt
```

The exact secret-scan command and justified path exclusions live in `.github/workflows/security.yml`. It rejects unsuppressed detections; it does not silently approve new findings. Newly disclosed dependencies may fail future CI runs; update and re-test the affected component.

## Synthetic model evaluation

Default generator seed 73 produces 1,800 rows split chronologically into 60% training, 20% validation and 20% held-out testing. Validation selects thresholds. Re-run `python scripts/evaluate.py` to create `artifacts/evaluation.json` with confusion counts, the dataset hash and a labelled local microbenchmark.

| Baseline | Precision | Recall | F1 | False-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Logistic | 0.8302 | 0.6875 | 0.7521 | 0.0304 |
| Normal-only distance | 0.8485 | 0.4375 | 0.5773 | 0.0169 |
| Hybrid AND | 0.8621 | 0.3906 | 0.5376 | 0.0135 |

The hybrid trades recall for fewer false positives in this generated dataset. It is not automatically a better model. Feature contributions explain the linear score, not a causal explanation of an incident. Use independently constructed data and a stated acceptance criterion before operational adaptation. A 55-event timing sample is not a sustained throughput benchmark.
