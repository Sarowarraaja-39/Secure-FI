# User guide

## Workspace access

Run `python start.py --demo` from the repository root and open the printed loopback URL. The first run prints one token per role. Later starts preserve the workspace and do not print those tokens again.

| Role | Intended access |
| --- | --- |
| Analyst | Event import, triage, asset context, cases, response requests, assistant drafts, evidence |
| Approver | Independent response review, simulation execution, model promotion, development registry deployment |
| Cloud | Cloud/Kubernetes observations, alerts, cases and bounded response operations |
| Compliance | Evidence reports, audit verification and evidence-hash operations |
| Executive | Aggregate metrics and reference catalogues; no event or case payloads |
| Ingestor | Event import and durable-queue processing; no investigation payloads |
| Admin | Workspace administration and all actions; requester still cannot self-approve |

Tokens select a tenant and identity at the server. A request body cannot change tenant. The default sample tenant is `fintech-lab`, which is a workspace identifier rather than a claim of deployment to financial systems.

If you lose a token, issue a new identity from your private local terminal:

```bash
python -m securefi app token --role analyst --tenant fintech-lab --identity analyst-two
```

Restart the running application after changing access configuration. To revoke a token, stop the server, remove the corresponding principal entry from your private `data/access.json`, and restart. The CLI does not currently provide managed rotation or revocation commands. Do not commit that file.

## Events and alerts

Use **Import events** to upload a JSON array, `{"events": [...]}`, or JSON Lines. `examples/sample-events.json` contains the supported raw envelope. Imports are limited to 2 MiB and 500 events, and require `synthetic: true`. Never relabel real data as synthetic.

Repeated event IDs with the same content are ignored. Reusing an ID with changed observation content rejects the transaction. Immediate processing updates detections during import. Queued mode stores durable jobs; an ingestor or admin can choose **Process queued events** on Overview, or run:

```bash
python -m securefi app worker
```

Search the inbox by rule ID, detection name, asset or owner. Filters combine severity, source and status. Open an alert to inspect evidence IDs and explicit priority factors. Detection-library details explain the rule logic, ATT&CK relationship and tuning considerations.

Triage requires a decision note. In-progress and accepted-risk decisions require an owner. Risk acceptance requires a non-expired date. Resolution requires verification. Expired acceptance becomes active exposure again. A new supporting observation reopens a resolved alert; replaying the original event does not. Recorded false-positive decisions remain in effect for their existing alert aggregation window; later windows produce fresh alerts.

## Assets and cases

The asset inventory discovers names from displayed observations. Register the exact name, owner, environment, business criticality and exposure to provide authoritative scoring context. Registered context updates existing alert scores and future processing while preserving historical source observations.

Open a case from an alert and add a clear initial hypothesis. One active case is reused for the same alert. A resolved or closed case allows a new investigation. The case timeline retains each update with its actor and timestamp.

Supported case transitions are investigating → contained or resolved; contained → investigating or resolved; resolved → closed or investigating; closed → investigating. Resolving or closing requires verification text. Updating a case also updates its linked alert's operational status.

## AI assistance and models

Generate an investigation draft inside a case. Without optional model configuration, the application explicitly uses a deterministic fallback. A draft records its provider, model, context hash and review decision. Approving a draft retains it for reference; it does not modify the case or approve a response.

The AI security page separately monitors supplied AI telemetry. Its model registry trains the included behavioural baselines on synthetic data. A second identity must approve a candidate before it becomes active. Re-promoting a previous, integrity-checked model provides version rollback. See `ml/MODEL_CARD.md` for evaluation limits.

## Response and recovery

Request a playbook from a case. A separate approver records a decision before the one-hour request expires. Approved requests can be executed by an authorised role before expiry. Execution updates a synthetic resource record and records simulated step results, with the exact before-state available for restoration. It does not revoke a real session, isolate a real host or modify a cloud account.

Notifications are stored in the workspace. This release does not send email, Slack messages or external webhooks. Use the API or evidence report to inspect full stored run details.

## Evidence and activity

Generate a report after documenting the investigation. Each report freezes its case, asset, alert, playbook and assistant state, includes control references and an audit checkpoint, and records a canonical JSON SHA-256 digest. Download the report envelope as JSON. Later workspace edits do not change the frozen document.

Without blockchain configuration, document verification reports whether the stored document matches its digest and states that it has no chain record. With the development registry enabled, record the digest and verify it against the current chain. A digest match establishes content identity; it does not prove that an observation is true.

Activity log shows the most recent 150 tenant audit entries. Audit verification checks the full retained chain. Keep independent checkpoints if you need to detect removal of the end of a chain or complete rewriting by a database administrator.
