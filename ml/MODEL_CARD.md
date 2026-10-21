# SecureFI synthetic behavioural baselines

Intended use: controlled comparison of detection approaches on generated API-like feature aggregates. Not intended for production decisions or a claim of real-world incident probability.

Dataset: 1,800 seed-73 rows with a 60/20/20 chronological partition. There are overlapping normal and attack-like distributions and benign bursts. The generator code, row labels and dataset hash are supplied. Generator assumptions are not a validated description of financial traffic.

Features: log bytes out, log request count, distinct targets, log duration, log token count and privileged flag. No rule IDs, labels, split names or known-bad labels enter inference.

Models: supervised logistic regression, normal-only standardised distance and a hybrid AND decision. Validation chooses thresholds. Held-out confusion counts and precision/recall/F1/FPR are in artifacts/evaluation.json. Re-run several seeds and an independently constructed scenario dataset before drawing operational conclusions.

Explanation: exact linear log-odds contributions and visible factor definitions. No SHAP/LIME claim. Artifact format: JSON plus SHA-256 manifest; no executable pickle. Trainer/approver separation and hash verification are enforced before promotion. Retired versions can be re-promoted by a distinct approver for rollback.

Known limitations: correlated synthetic labels, a linear decision boundary, simple scaling, no calibrated real-world probability, dataset/feature poisoning not eliminated by hashing, and limited transfer to a new source population. Drift needs investigation rather than automatic retraining.
