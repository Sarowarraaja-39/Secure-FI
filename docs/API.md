# HTTP API

The browser and optional ASGI service use the same route dispatcher. Send `Authorization: Bearer <workspace-token>`. POST bodies must be JSON objects; event batches are nested under `events`. Do not put tokens in URLs. Tenant and actor are supplied by authentication, not request bodies.

The local profile returns `200` on success, `400` on validation failure, `403` for missing/invalid auth or denied scope, `413` for body limits, and `429` for its per-identity rate limit. Local transport enforces a 2 MiB body and 180 authenticated requests per minute. The ASGI profile needs edge rate limiting and request buffering limits before external exposure; its in-process body check runs after reading the body.

| Method and path | Body / result | Role scope, plus admin |
| --- | --- | --- |
| GET `/healthz` | Process liveness, public | Any |
| GET `/api/state` | Scoped catalogues, metrics and operational records | Authenticated |
| POST `/api/events` | `{events: [...], queued: false}` → accepted/duplicate/alert counts | Analyst, ingestor, cloud |
| POST `/api/events/detail` | `{id}` → tenant-scoped normalised event | Analyst, compliance, approver, cloud |
| POST `/api/worker` | `{}` → processed/failed attempts | Ingestor |
| POST `/api/sample-data` | `{}` → deterministic fixture import | Analyst |
| POST `/api/assets` | `{name, owner, criticality, internet_exposed, environment, note}` | Analyst |
| POST `/api/alerts/triage` | `{id, status, note, assignee, accepted_until, verification}` | Analyst, cloud |
| POST `/api/cases` | `{alert_id, note}` → new or existing active case | Analyst, cloud |
| POST `/api/cases/update` | `{id, status, owner, note, verification}` | Analyst, cloud |
| POST `/api/cases/review` | Compatibility form `{id,status,note,verification}`; same lifecycle rules | Analyst, cloud |
| POST `/api/runs` | `{case_id, playbook}` → pending request | Analyst, cloud |
| POST `/api/runs/approve` | `{id,decision: "approve" or "reject",note}` | Approver; independent identity |
| POST `/api/runs/execute` | `{id,rollback: false}` → run; true restores before-state | Analyst, cloud, approver |
| POST `/api/assistant/generate` | `{case_id}` → advisory draft with provenance | Analyst, cloud |
| POST `/api/assistant/review` | `{id,decision: "approved" or "rejected",note}` | Analyst, cloud |
| POST `/api/models/train` | `{}` → synthetic model candidate and evaluation | Analyst |
| POST `/api/models/promote` | `{id}` → activated version | Approver; independent trainer identity |
| POST `/api/models/score` | `{model_id,event}` → hybrid prediction and contributions | Analyst |
| POST `/api/evidence` | `{}` → frozen document/digest envelope | Analyst, compliance |
| GET `/api/audit` | Full tenant audit verification | Analyst, compliance |
| GET `/api/activity` | Latest 150 audit entries | Analyst, compliance, approver |
| POST `/api/ledger/deploy` | `{}` → verified development registry | Approver |
| POST `/api/ledger/anchor` | `{id: evidence-id}` → attestation | Analyst, compliance |
| POST `/api/ledger/verify` | `{id,document?: exported-document}` → hash/chain result | Analyst, compliance |

Cloud role operations additionally require cloud/Kubernetes sources. Executives and ingestors do not receive raw event, case or alert payloads in state. Risk scores are transparent priority factors, not calibrated incident probabilities.

## Raw event example

```json
{
  "event_id": "example-storage-001",
  "synthetic": true,
  "source": "cloud",
  "time": "2026-10-21T10:00:00Z",
  "data": {
    "operation": "storage_update",
    "asset": "payments-test-store",
    "public": true,
    "encrypted": true,
    "criticality": 4,
    "internet_exposed": true
  }
}
```

Supported sources: cloud, identity, network, endpoint, application, Kubernetes (`kubernetes`), Web3 (`web3`) and AI (`ai`). Fields are allowlisted in `normalise.py`; the envelope is OCSF-inspired, with custom AI/Web3 classes, rather than fully OCSF-conformant. A raw event ID must be 1–120 characters and a time must include its timezone. Web3 uses chain 31337 only. See `examples/sample-events.json` for all scenarios.

## Call the API

Set `SECUREFI_TOKEN` in your terminal to a freshly issued token without committing it. For example, use your shell's private environment-variable mechanism, then:

```bash
curl http://127.0.0.1:8765/api/state -H "Authorization: Bearer $SECUREFI_TOKEN"
```

To independently check an exported report, POST its inner `document` object together with the saved report ID to `/api/ledger/verify`. The endpoint first compares canonical hashes; it does not call the chain when the document differs. Verification of a matching document without an attestation explicitly reports that no chain record exists. A report from another workspace is unavailable through a foreign tenant's token.
