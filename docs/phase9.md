# Phase 9: Behavioral Analysis and Verified Knowledge

Phase 9 adds a small, deterministic behavioral signal around the existing Phase 8 WAF. It does not replace the SQL Injection model, XSS detector, or hybrid detector.

## Behavioral detection

`backend/services/behavior_monitor.py` counts blocked requests for the same source/session identity in a rolling window:

- `BEHAVIOR_WINDOW_SECONDS = 300` (5 minutes)
- `REPEATED_ATTACK_THRESHOLD = 5`
- `RULE_SUGGESTION_THRESHOLD = 2` verified occurrences

The monitor is rule-based and does not create another ML model. When the threshold is reached, the response includes `REPEATED_ATTACKS`, a redacted behavioral alert, and `CRITICAL` risk. A single SQL Injection or XSS remains `HIGH / 0.85`; multiple detector types remain `CRITICAL / 1.0`. These scores are deterministic risk scores, not calibrated probabilities.

## Review workflow

Security events now receive additive `review_status` and `reviewed_at` fields. Existing rows are migrated idempotently and default to `UNREVIEWED`.

Authenticated endpoints:

- `PATCH /api/security/events/<event_id>/review` with `CONFIRMED_ATTACK` or `FALSE_POSITIVE`
- `GET /api/security/adaptive-rules`
- `PATCH /api/security/adaptive-rules/<rule_id>` with `APPROVED` or `REJECTED`
- `GET /api/security/behavior-alerts`

There is no role column in the existing application, so Phase 9 preserves the established authenticated-session security model.

## Attack knowledge

`ATTACK_KNOWLEDGE` stores only bounded normalized pattern summaries, attack type, detection source, verification status, timestamps, and occurrence counts. Passwords, tokens, banking data, and complete requests are not stored in this table. Confirming an event creates or updates verified knowledge. Marking an event as a false positive creates neither knowledge nor an active rule.

Repeated confirmed patterns can create an `ADAPTIVE_RULE_SUGGESTIONS` row. Suggestions contain a bounded pattern summary, a reason, count, source event, timestamps, and one of `SUGGESTED`, `APPROVED`, or `REJECTED`.

The flow is intentionally:

`Detection -> verification -> knowledge -> rule suggestion -> human approval -> optional future activation`

Approval only records the human decision. Approved suggestions are not loaded into the active WAF in Phase 9. This review step prevents an unverified false positive or a sensitive request value from becoming a blocking rule.

## Security limitations

All Phase 9 endpoints require the existing authenticated session. IDs and status values are validated, SQL is parameterized, normalized patterns are bounded, and dashboard responses omit raw request values. Source identifiers in behavioral alerts are redacted.

The system does not automatically retrain the ML model or automatically activate new WAF rules from unverified requests.

This remains a research and educational banking WAF, not production-grade banking security. Risk values are not probabilities, behavior thresholds are heuristic, and approved rule deployment remains future work.
