from datetime import datetime, timedelta


BEHAVIOR_WINDOW_SECONDS = 300
REPEATED_ATTACK_THRESHOLD = 5
RULE_SUGGESTION_THRESHOLD = 2
MAX_PATTERN_LENGTH = 200


def analyze_behavior(db, source_ip, customer_id, attack_type, now=None):
    """Find repeated blocked attacks for one source/session in a short window."""
    now = now or datetime.now()
    window_start = (now - timedelta(seconds=BEHAVIOR_WINDOW_SECONDS)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    clauses = [
        "timestamp >= ?",
        "action IN ('BLOCK', 'BLOCKED')",
        "attack_type IS NOT NULL",
    ]
    parameters = [window_start]
    identity_clauses = []
    if source_ip:
        identity_clauses.append("source_ip = ?")
        parameters.append(source_ip)
    if customer_id is not None:
        identity_clauses.append("customer_id = ?")
        parameters.append(customer_id)
    if identity_clauses:
        clauses.append(f"({' OR '.join(identity_clauses)})")
    row = db.execute(
        f"SELECT COUNT(*) AS attack_count FROM SECURITY_EVENTS WHERE {' AND '.join(clauses)}",
        parameters,
    ).fetchone()
    attack_count = int(row["attack_count"])
    detected = attack_count >= REPEATED_ATTACK_THRESHOLD
    return {
        "behavior_detected": detected,
        "behavior_type": "REPEATED_ATTACKS" if detected else None,
        "risk_level": "CRITICAL" if detected else None,
        "attack_count": attack_count,
        "window_seconds": BEHAVIOR_WINDOW_SECONDS,
        "reason": (
            "Repeated malicious requests detected within the configured time window."
            if detected
            else None
        ),
    }


def normalize_attack_pattern(attack_type, request_value):
    """Return a bounded, non-sensitive pattern summary for verified knowledge."""
    if not request_value or request_value == "[REDACTED]":
        return None
    value = " ".join(str(request_value).split()).casefold()
    if attack_type == "XSS":
        from backend.xss_detector import detect_xss

        pattern = detect_xss(value).get("pattern")
        return f"xss:{pattern}"[:MAX_PATTERN_LENGTH] if pattern else None
    if attack_type in {"SQL_INJECTION", "SQL Injection"}:
        import re

        value = re.sub(r"(['\"]).*?\1", "?", value)
        value = re.sub(r"\b\d+(?:\.\d+)?\b", "?", value)
        return f"sqli:{value}"[:MAX_PATTERN_LENGTH]
    return f"{str(attack_type).casefold()}"[:MAX_PATTERN_LENGTH]
