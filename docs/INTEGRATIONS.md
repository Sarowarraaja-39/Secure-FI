# Optional integrations

The main application runs without any integration below. Enable each deliberately and verify the resulting provider/status in the UI. Configuration is read from process environment variables; SecureFI does not automatically load `.env` files.

## Local investigation model

Install Ollama using its [official instructions](https://docs.ollama.com/quickstart), then install a local model that fits your hardware. Set these variables in the same terminal before starting SecureFI:

```bash
export SECUREFI_AI_PROVIDER=ollama
export SECUREFI_AI_MODEL='your-installed-local-model-tag'
export SECUREFI_OLLAMA_URL=http://127.0.0.1:11434
python start.py --demo
```

The model tag above is a placeholder: replace it with an actual installed local tag. Cloud-backed tags are rejected. The endpoint must use HTTP on a literal loopback address; redirects and proxy inheritance are disabled. Do not configure a model requiring remote inference for this project.

Open a case and choose **Generate investigation draft**. Only case ID, rule name/ID, severity, risk score and recommended checks are sent. Strict output validation checks the case reference, exact fields, length and number of steps. If the local model is unavailable or its output is invalid, the saved result explicitly says deterministic fallback. Invalid integration configuration is reported as an error.

The model has no execution tools and cannot approve responses, set risk scores, close a case or decide compliance. Review the generated text against evidence. Test results in `TESTING.md` cover the adapter contract with controlled responses; a downloaded LLM was not executed in this release environment.

## Evidence registry on a development chain

Requires Node 24 and npm for the pinned development tools. No wallet extension is needed.

```bash
npm ci --prefix blockchain
npm run compile --prefix blockchain
npm run chain --prefix blockchain
```

Keep that development chain running on loopback. In another terminal:

```bash
export SECUREFI_CHAIN_ENABLED=1
export SECUREFI_CHAIN_RPC=http://127.0.0.1:8545
python start.py --demo
```

Sign in as approver/admin and open **Controls & evidence** to deploy or check the registry. Sign in as analyst/compliance, create a report, record its hash and verify it. An exported report contains the frozen document, digest and subsequent attestation metadata.

The adapter allows only local chain **31337**, verifies the compiled contract runtime and uses a disposable unlocked local account. The Solidity registry restricts new hash records to its owner, rejects zero/duplicate hashes and exposes a lookup. No real funds, production chain or production wallet key belongs in this workflow.

Restarting or resetting the chain can invalidate the stored registry address. Verification must then fail. To initialise a clean chain experiment, use a fresh private application data directory through the CLI's `--db` and `--auth` arguments. Do not delete existing investigation data merely to silence a verification failure.

The registry proves that the currently queried development chain holds a matching digest. It does not independently certify the evidence, guarantee long-term availability or make a database immutable.

## Optional platform services

`requirements-platform.txt` pins the FastAPI, PostgreSQL, AMQP and schema-validation dependencies used for the optional profile. See [Operations](OPERATIONS.md) for startup and deployment prerequisites.

- PostgreSQL: `SECUREFI_DATABASE_URL` selects the operational store; all domain transactions retain tenant keys and tenant write locks.
- RabbitMQ: `services.queue_bridge` watches pending SQL jobs and publishes durable wake-up messages with confirms. The SQL ledger prevents completed job replay.
- OpenSearch: `services.search_projection` projects tenant events over verified TLS to a tenant-derived index. It is a one-shot projection helper, not an automatically connected UI search service. Set URL, user, password and optional CA in environment variables. Create the mapping from `schemas/opensearch-events.json` first and apply tenant-scoped credentials.

The Compose file supplies PostgreSQL and RabbitMQ, but not OpenSearch, Ollama or an EVM. Literal-loopback restrictions mean host integrations are supported by the local application; container loopback is a different network namespace. A containerised remote-model or remote-chain integration requires a separately reviewed adapter change.
