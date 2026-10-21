# Threat model

Assets: tenant observations, access configuration, cases, approvals, model artifacts, evidence documents and audit checkpoints. The primary boundary is a private workstation with deliberately synthetic data. Optional ASGI/cloud profiles widen that boundary and require additional review.

| STRIDE area | Example scenario | Implemented control | Residual limitation |
| --- | --- | --- | --- |
| Spoofing | Stolen workspace token submits events | Random hashed bearer tokens; loopback default | No SSO/MFA, session revocation or managed rotation |
| Tampering | Changed source ID, model artifact or evidence document | Collision rejection, SHA-256 checks, audit links, optional registry digest | Privileged database/operator access remains trusted |
| Repudiation | Analyst denies an approval or case decision | Identity/timestamp/rationale in tenant audit | Audit needs independent checkpoints; token sharing weakens attribution |
| Information disclosure | Foreign tenant reads a case; model receives raw evidence | Tenant-derived lookups, scoped state, minimised model context | No database row-level security; free-text notes require user care |
| Denial of service | Very large imports or repeated requests | Event/body/field limits; local rate limit; request timeout | History scans and ASGI full-body reads require edge/service hardening |
| Elevation of privilege | Requester approves own response; injected prompt requests execution | Independent approval, role checks, tool-free advisory model | Admin is highly privileged; no real action connectors are installed |

## Attack paths to exercise

A foreign-token path must fail at tenant-scoped lookup before a case, event, report or approval is returned. A requester-to-response path must fail until another authorised identity supplies an unexpired approval. A prompt-to-action path ends at a pending advisory draft, with no execution API available to the model. A changed-evidence path must fail its digest comparison before any blockchain call.

A malicious operator who rewrites the complete database and all local chain state remains outside the integrity assurance of this prototype. Independent storage, signed checkpoints and separation of operational ownership would be needed for stronger evidence claims.

These checks are covered by automated boundary and regression tests. They do not replace independent penetration testing, a cloud-account review or an internet-facing service assessment.
