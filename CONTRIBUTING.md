# Contributing

Keep changes focused on a concrete analyst or operator problem. Include the expected behaviour, a reproducible synthetic input, the change and the relevant validation in your pull request.

Run the core suite and evaluation before submitting:

```bash
python -m unittest discover -s tests -v
python scripts/evaluate.py
```

Use the browser check for interface/workflow changes and the EVM test for contract or chain-adapter changes; see `TESTING.md`. Add a regression test when a bug affects data integrity, tenant/role boundaries, lifecycle transitions or evidence. Do not add tests that merely repeat implementation details.

Python source is formatted with Ruff; frontend files use ordinary JavaScript and CSS without a bundler. Preserve explicit validation, transaction boundaries and HTML escaping. Keep executable models out of stored artifacts: use bounded JSON, not pickle.

For a detection change, update its individual JSON definition, bundled runtime catalogue, synthetic positive/negative scenarios and control/ATT&CK rationale as appropriate. Distinguish behavioural evidence from posture gaps and analogies. For a playbook, preserve independent approval and exact before-state recovery; any real action connector needs its own scope, idempotency and failure design.

Use only synthetic or lab-generated observations. Do not submit credentials, customer data, real financial transactions, production chain data or real private keys. Describe scan/deployment status accurately. Do not manufacture green CI badges, test results or project history.
