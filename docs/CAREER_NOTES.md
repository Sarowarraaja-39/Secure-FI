# Demonstration and engineering evidence

A useful demonstration follows one observation through the system instead of clicking every dashboard. Use the README investigation, show a rejected boundary condition, then download a report and explain how you verified it.

| Role | Evidence to show | Engineering discussion |
| --- | --- | --- |
| SOC analyst | Search, source evidence, triage notes and case timeline | Hypothesis, prioritisation, false positives, verification |
| Detection engineer | A rule, correlation window, positive/negative fixtures and ATT&CK relationship | Required telemetry, tuning and coverage limits |
| Cybersecurity engineer | Tenant/role tests, event contracts and transparent risk factors | Secure defaults and data-integrity boundaries |
| Incident responder | Request, separate approval, expiry, idempotent simulation and before-state restoration | Approval design, recovery and the missing real-action connector |
| Cloud security engineer | Imported cloud/Kubernetes findings, Terraform modules and workload security | Sensor requirements, least privilege and deployment assumptions |
| DevSecOps engineer | CI jobs, policy tests, container standards, dependency/SBOM gates | Reproducibility, scan findings and release-signing prerequisites |
| AI security engineer | Prompt/tool/model indicators, model card, independent promotion and draft validation | Data minimisation, prompt trust boundaries and synthetic evaluation limits |
| GRC engineer | Finding-to-control register, frozen report and verified audit checkpoint | Applicability, evidence quality and limits of integrity proofs |
| Web3 security engineer | Approval/transfer scenarios, Solidity registry and real-EVM negative tests | Owner restrictions, chain reset, digest semantics and excluded real funds |

Capture your own results: rule fixture coverage, confusion counts, replay/collision checks, response approval failures, report hash verification and a short timed demo. Separate simulated observations from actual adapter execution. Show test commands and explain one failure you reproduced and corrected.

For your GitHub profile, describe this as a maintained security engineering application with reproducible scenarios. For interviews, discuss why you chose a modular monolith, what would change for customer scale, how database transactions differ from external action atomicity, and why a hash does not prove evidence truth.

## Product follow-up work

These are future engineering priorities, not implemented features:

1. OIDC/MFA, managed token lifecycle and a reviewed external-service edge.
2. Cursor pagination, bounded correlation state and indexed event partitions.
3. Independent end-to-end Compose/Kubernetes validation with restore drills.
4. Sanitised collector contracts and integration-specific read-only cloud sensors.
5. Real response connectors with scoped permissions, dry-run policy and compensating recovery.
6. Operational metrics/logs, denied-request audit, durable scheduler and service readiness.
7. Independent evaluation datasets, adversarial model tests and a reviewed model update process.
8. Deployment-specific compliance applicability reviews and evidence-owner sign-off.
