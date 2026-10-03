# Final Results

| Metric | Result | Evaluation Set |
|---|---:|---|
| SQLi Accuracy | 0.9924 | Held-out SQLi test set |
| SQLi Precision | 0.9967553536664504 | Held-out SQLi test set |
| SQLi Recall | 0.9869351038766331 | Held-out SQLi test set |
| SQLi F1 | 0.991820921222557 | Held-out SQLi test set |
| XSS Precision | 1.0 | Existing XSS fixture set |
| XSS Recall | 1.0 | Existing XSS fixture set |
| Hybrid Detection Rate | 0.7692307692307693 | Controlled hybrid fixture set |
| False Positive Rate | 0.0 | Normal request fixture set |
| Average WAF Latency | 0.731098 ms | 100 normal detector iterations |

## Component comparison

| Component | Detection mechanism | Coverage | Explainability | Risk / behavior |
|---|---|---|---|---|
| SQLi ML | Existing character TF-IDF and Decision Tree | SQL Injection patterns represented in held-out data | Model prediction and evidence | Deterministic HIGH risk for a single attack |
| XSS Rules | Existing normalized structural patterns | Patterns implemented by the rule detector | Matched pattern name | Deterministic HIGH risk for a single attack |
| Hybrid | Both detectors combined | SQLi, XSS, and simultaneous signals | ML, RULE, or HYBRID source | CRITICAL for multiple attack types |
| Behavioral Layer | Time-window count heuristic | Repeated blocked activity | Threshold, window, and count | Contextual CRITICAL signal; no retraining |

The values above are generated from executed evaluation outputs, not estimated values. See `docs/phase10.md` for setup, limitations, and reproducibility details.
