from datetime import datetime

from flask import Blueprint, jsonify, request, session

from backend.database import get_db
from backend.services.behavior_monitor import (
    RULE_SUGGESTION_THRESHOLD,
    analyze_behavior,
    normalize_attack_pattern,
)


security_bp = Blueprint("security", __name__)


def _require_authenticated():
    if not session.get("customer_id"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    return None


def _date_filters():
    clauses = []
    parameters = []
    exact_date = request.args.get("date")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

    if exact_date:
        clauses.append("date(timestamp) = ?")
        parameters.append(exact_date)
    else:
        if date_from:
            clauses.append("timestamp >= ?")
            parameters.append(f"{date_from} 00:00:00")
        if date_to:
            clauses.append("timestamp < date(?, '+1 day')")
            parameters.append(date_to)
    return clauses, parameters


def _positive_id(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _event_source(attack_type):
    return {
        "SQL_INJECTION": "ML",
        "SQL Injection": "ML",
        "XSS": "RULE",
        "MULTIPLE_ATTACKS": "HYBRID",
    }.get(attack_type, "UNKNOWN")


@security_bp.get("/summary")
def security_summary():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized

    row = get_db().execute(
        """
        SELECT
            COUNT(*) AS total_events,
            COALESCE(SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED') THEN 1 ELSE 0 END), 0) AS blocked_events,
            COALESCE(SUM(CASE WHEN attack_type IN ('SQL_INJECTION', 'SQL Injection') THEN 1 ELSE 0 END), 0) AS sql_injection,
            COALESCE(SUM(CASE WHEN attack_type = 'XSS' THEN 1 ELSE 0 END), 0) AS xss,
            COALESCE(SUM(CASE WHEN attack_type = 'MULTIPLE_ATTACKS' THEN 1 ELSE 0 END), 0) AS multiple_attacks
        FROM SECURITY_EVENTS
        """
    ).fetchone()
    return jsonify({"success": True, **dict(row)})


@security_bp.get("/events")
def security_events():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized

    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    except (TypeError, ValueError):
        limit = 20

    clauses, parameters = _date_filters()
    attack_type = request.args.get("attack_type")
    if attack_type:
        clauses.append("CASE WHEN attack_type = 'SQL Injection' THEN 'SQL_INJECTION' ELSE attack_type END = ?")
        parameters.append(attack_type)

    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)
    rows = get_db().execute(
        f"""
        SELECT event_id, timestamp, source_ip, endpoint, http_method,
               CASE WHEN attack_type = 'SQL Injection' THEN 'SQL_INJECTION' ELSE attack_type END AS attack_type,
               confidence, confidence AS risk_score, action, reason,
               review_status, reviewed_at,
               COALESCE((
                   SELECT notification_status.status
                   FROM SECURITY_NOTIFICATIONS AS notification_status
                   WHERE notification_status.event_id = SECURITY_EVENTS.event_id
                   ORDER BY notification_status.notification_id DESC
                   LIMIT 1
               ), 'NOT_SENT') AS notification_status,
               reason AS explanation,
               CASE
                   WHEN attack_type IN ('SQL_INJECTION', 'SQL Injection') THEN 'ML'
                   WHEN attack_type = 'XSS' THEN 'RULE'
                   WHEN attack_type = 'MULTIPLE_ATTACKS' THEN 'HYBRID'
                   ELSE 'UNKNOWN'
               END AS source,
               CASE
                   WHEN attack_type = 'MULTIPLE_ATTACKS' THEN 'CRITICAL'
                   WHEN attack_type IN ('SQL_INJECTION', 'SQL Injection', 'XSS') THEN 'HIGH'
                   ELSE 'LOW'
               END AS risk_level
        FROM SECURITY_EVENTS
        {where_clause}
        ORDER BY timestamp DESC, event_id DESC
        LIMIT ?
        """,
        parameters,
    ).fetchall()
    return jsonify({"success": True, "events": [dict(row) for row in rows]})


@security_bp.patch("/events/<event_id>/review")
def review_security_event(event_id):
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized
    event_id = _positive_id(event_id)
    status = request.get_json(silent=True)
    status = status.get("status") if isinstance(status, dict) else None
    valid_statuses = {"CONFIRMED_ATTACK", "FALSE_POSITIVE"}
    if event_id is None or status not in valid_statuses:
        return jsonify({"success": False, "message": "Invalid event ID or review status."}), 400

    db = get_db()
    event = db.execute(
        "SELECT * FROM SECURITY_EVENTS WHERE event_id = ?", (event_id,)
    ).fetchone()
    if event is None:
        return jsonify({"success": False, "message": "Security event not found."}), 404

    reviewed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE SECURITY_EVENTS SET review_status = ?, reviewed_at = ? WHERE event_id = ?",
        (status, reviewed_at, event_id),
    )
    knowledge = None
    if status == "CONFIRMED_ATTACK":
        pattern = normalize_attack_pattern(event["attack_type"], event["request_value"])
        if pattern:
            now = reviewed_at
            db.execute(
                """
                INSERT INTO ATTACK_KNOWLEDGE
                    (attack_type, normalized_pattern, detection_source, verification_status,
                     first_seen, last_seen, occurrence_count, created_at, updated_at)
                VALUES (?, ?, ?, 'CONFIRMED_ATTACK', ?, ?, 1, ?, ?)
                ON CONFLICT(attack_type, normalized_pattern) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    occurrence_count = occurrence_count + 1,
                    updated_at = excluded.updated_at,
                    verification_status = 'CONFIRMED_ATTACK'
                """,
                (event["attack_type"], pattern, _event_source(event["attack_type"]), event["timestamp"], event["timestamp"], now, now),
            )
            knowledge = db.execute(
                "SELECT * FROM ATTACK_KNOWLEDGE WHERE attack_type = ? AND normalized_pattern = ?",
                (event["attack_type"], pattern),
            ).fetchone()
            if knowledge and knowledge["occurrence_count"] >= RULE_SUGGESTION_THRESHOLD:
                db.execute(
                    """
                    INSERT INTO ADAPTIVE_RULE_SUGGESTIONS
                        (attack_type, rule_pattern, reason, occurrence_count, source_event_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(attack_type, rule_pattern) DO UPDATE SET
                        occurrence_count = excluded.occurrence_count,
                        source_event_id = excluded.source_event_id
                    """,
                    (event["attack_type"], pattern, f"Repeated verified {event['attack_type']} pattern", knowledge["occurrence_count"], event_id, now),
                )
    db.commit()
    return jsonify({"success": True, "event_id": event_id, "review_status": status})


@security_bp.get("/adaptive-rules")
def adaptive_rules():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized
    rows = get_db().execute(
        "SELECT id, attack_type, rule_pattern, reason, occurrence_count, source_event_id, status, created_at, reviewed_at "
        "FROM ADAPTIVE_RULE_SUGGESTIONS ORDER BY created_at DESC, id DESC"
    ).fetchall()
    return jsonify({"success": True, "suggestions": [dict(row) for row in rows]})


@security_bp.patch("/adaptive-rules/<rule_id>")
def review_adaptive_rule(rule_id):
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized
    rule_id = _positive_id(rule_id)
    payload = request.get_json(silent=True)
    status = payload.get("status") if isinstance(payload, dict) else None
    if rule_id is None or status not in {"APPROVED", "REJECTED"}:
        return jsonify({"success": False, "message": "Invalid rule ID or rule status."}), 400
    reviewed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = get_db().execute(
        "UPDATE ADAPTIVE_RULE_SUGGESTIONS SET status = ?, reviewed_at = ? WHERE id = ? AND status = 'SUGGESTED'",
        (status, reviewed_at, rule_id),
    )
    get_db().commit()
    if cursor.rowcount == 0:
        return jsonify({"success": False, "message": "Rule suggestion not found or already reviewed."}), 404
    return jsonify({"success": True, "rule_id": rule_id, "status": status})


@security_bp.get("/attack-distribution")
def attack_distribution():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized

    rows = get_db().execute(
        """
        SELECT
            CASE WHEN attack_type = 'SQL Injection' THEN 'SQL_INJECTION' ELSE attack_type END AS attack_type,
            COUNT(*) AS count
        FROM SECURITY_EVENTS
        GROUP BY CASE WHEN attack_type = 'SQL Injection' THEN 'SQL_INJECTION' ELSE attack_type END
        ORDER BY count DESC, attack_type ASC
        """
    ).fetchall()
    return jsonify({"success": True, "distribution": [dict(row) for row in rows]})


@security_bp.get("/behavior-alerts")
def behavior_alerts():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized
    db = get_db()
    rows = db.execute(
        """
        SELECT source_ip, customer_id, MAX(attack_type) AS attack_type, COUNT(*) AS attack_count,
               MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
        FROM SECURITY_EVENTS
        WHERE action IN ('BLOCK', 'BLOCKED')
        GROUP BY source_ip, customer_id
        """
    ).fetchall()
    alerts = []
    for row in rows:
        behavior = analyze_behavior(db, row["source_ip"], row["customer_id"], row["attack_type"])
        if behavior["behavior_detected"]:
            alerts.append({
                "behavior_type": behavior["behavior_type"],
                "risk_level": behavior["risk_level"],
                "attack_type": row["attack_type"],
                "source": "redacted",
                "attack_count": behavior["attack_count"],
                "window_seconds": behavior["window_seconds"],
                "reason": behavior["reason"],
            })
    return jsonify({"success": True, "alerts": alerts})


@security_bp.get("/detection-summary")
def detection_summary():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized

    rows = get_db().execute(
        """
        SELECT
            CASE WHEN attack_type = 'SQL Injection' THEN 'SQL_INJECTION' ELSE attack_type END AS attack_type,
            CASE
                WHEN attack_type IN ('SQL_INJECTION', 'SQL Injection') THEN 'ML'
                WHEN attack_type = 'XSS' THEN 'RULE'
                WHEN attack_type = 'MULTIPLE_ATTACKS' THEN 'HYBRID'
                ELSE 'UNKNOWN'
            END AS source,
            COUNT(*) AS count
        FROM SECURITY_EVENTS
        WHERE attack_type IN ('SQL_INJECTION', 'SQL Injection', 'XSS', 'MULTIPLE_ATTACKS')
        GROUP BY
            CASE WHEN attack_type = 'SQL Injection' THEN 'SQL_INJECTION' ELSE attack_type END,
            source
        ORDER BY count DESC, attack_type ASC
        """
    ).fetchall()
    risk_rows = get_db().execute(
        """
        SELECT
            CASE
                WHEN attack_type = 'MULTIPLE_ATTACKS' THEN 'CRITICAL'
                ELSE 'HIGH'
            END AS risk_level,
            COUNT(*) AS count
        FROM SECURITY_EVENTS
        WHERE attack_type IN ('SQL_INJECTION', 'SQL Injection', 'XSS', 'MULTIPLE_ATTACKS')
        GROUP BY risk_level
        """
    ).fetchall()

    summary = {
        row["attack_type"].lower(): {"count": row["count"], "source": row["source"]}
        for row in rows
    }
    return jsonify({
        "success": True,
        "detections": summary,
        "risk_levels": {row["risk_level"]: row["count"] for row in risk_rows},
    })


@security_bp.get("/trends")
def security_trends():
    unauthorized = _require_authenticated()
    if unauthorized:
        return unauthorized

    clauses, parameters = _date_filters()
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = get_db().execute(
        f"""
        SELECT
            date(timestamp) AS date,
            COUNT(*) AS count,
            COALESCE(SUM(CASE WHEN attack_type IN ('SQL_INJECTION', 'SQL Injection') THEN 1 ELSE 0 END), 0) AS sql_injection,
            COALESCE(SUM(CASE WHEN attack_type = 'XSS' THEN 1 ELSE 0 END), 0) AS xss,
            COALESCE(SUM(CASE WHEN attack_type = 'MULTIPLE_ATTACKS' THEN 1 ELSE 0 END), 0) AS multiple_attacks
        FROM SECURITY_EVENTS
        {where_clause}
        GROUP BY date(timestamp)
        ORDER BY date(timestamp) ASC
        """,
        parameters,
    ).fetchall()
    return jsonify({"success": True, "trends": [dict(row) for row in rows]})