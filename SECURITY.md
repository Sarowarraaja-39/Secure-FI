# Security policy

SecureFI 2.1 is a private-workspace engineering application evaluated with synthetic telemetry. The default transport binds to loopback. It is not supported as an internet-facing, multi-customer security service.

The code enforces token-derived tenant scopes, role checks, independent response/model approval, explicit synthetic-event validation, bounded event fields, tenant HMAC identifiers, advisory-only model output and local development-chain restrictions. These controls are tested boundaries, not a guarantee that the software is vulnerability-free.

Keep `data/`, tokens, pseudonymisation keys, model-service configuration, database URLs and infrastructure state out of public repositories. The local chain uses publicly known disposable development accounts; never fund them or reuse their keys outside development.

To report a vulnerability in your published fork, enable GitHub private vulnerability reporting and use the repository Security tab. Until an owner has enabled that channel, contact that repository's maintainer through a verified private channel. Include the affected version, a minimal synthetic reproduction and impact. Do not post working credentials, sensitive payloads or production evidence in public issues.

Any production-oriented adaptation needs a new threat model, identity/edge hardening, operational monitoring and independent testing. Candidate compliance mappings and audit hashes must not be described as certification, unalterable storage or proof of evidence truth.
