# Phase 8: Hybrid Detection and Explainability

The WAF now combines two existing detection mechanisms through
`backend/services/hybrid_detector.py`:

- SQL Injection uses the existing TF-IDF character n-gram pipeline and Decision Tree model.
- XSS uses the existing dedicated rule/pattern detector and normalization logic.
- A request containing both detection types is classified as `MULTIPLE_ATTACKS`.

## Risk assessment

Risk is a transparent rule-based assessment, not a calibrated probability:

- `LOW` / `0.0`: no detector matched.
- `HIGH` / `0.85`: one confirmed SQL Injection or XSS detection.
- `CRITICAL` / `1.0`: more than one attack type was detected.

When the SQL model exposes `predict_proba`, its value is reported only as an
uncalibrated model probability inside internal detection evidence. The final
risk score remains separate and deterministic.

## Explainability

Blocked responses include the attack type, detection source (`ML`, `RULE`, or
`HYBRID`), risk level, decision, explanation, and bounded evidence names.
Raw request values are excluded from responses. Existing security logging keeps
the established sensitive-parameter redaction behavior.

The existing `SECURITY_EVENTS` schema is reused. New risk scores are stored in
the existing `confidence` column, while dashboard APIs derive source and risk
labels from attack type and reason without a schema migration.

The security dashboard exposes detection summaries through
`GET /api/security/detection-summary` and displays source, risk, and explanation
for recent events.

## Limitations and future work

XSS is not ML-based; it remains dedicated rule/pattern-based detection. The
combined system is hybrid because it combines an SQL Injection ML detector with
an XSS rule detector. Risk scores are not calibrated probabilities, and no
complex behavioral model has been added. Future work could add a labeled XSS
dataset, a separately evaluated XSS classifier, calibrated probabilities, and a
small time-window behavioral signal.