import logging
import os
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

LOGGER = logging.getLogger(__name__)
COOLDOWN_SECONDS = 300


def _enabled():
    return os.environ.get("MAIL_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _mask_email(email):
    if not email or "@" not in email:
        return "[REDACTED]"
    local, domain = email.split("@", 1)
    return f"{local[:1]}***@{domain}"


def _notification_type(attack_type, behavior_detected):
    if behavior_detected:
        return "REPEATED_ATTACK"
    return {
        "SQL_INJECTION": "SQL_INJECTION",
        "SQL Injection": "SQL_INJECTION",
        "XSS": "XSS",
        "MULTIPLE_ATTACKS": "MULTIPLE_ATTACKS",
    }.get(attack_type, "SECURITY_EVENT")


def _activity_description(attack_type, behavior_detected):
    if behavior_detected:
        return "Repeated malicious requests were blocked within the configured monitoring window."
    return {
        "SQL_INJECTION": "A SQL Injection request was blocked by the WAF.",
        "SQL Injection": "A SQL Injection request was blocked by the WAF.",
        "XSS": "An XSS request was blocked by the WAF.",
        "MULTIPLE_ATTACKS": "Multiple attack indicators were blocked by the hybrid WAF.",
    }.get(attack_type, "Suspicious activity was blocked by the WAF.")


def _record(db, event_id, customer_id, notification_type, recipient, status, created_at, sent_at=None, failure_reason=None):
    try:
        db.execute(
            """
            INSERT INTO SECURITY_NOTIFICATIONS
                (event_id, customer_id, notification_type, recipient, status, created_at, sent_at, failure_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, customer_id, notification_type, recipient, status, created_at, sent_at, failure_reason),
        )
        db.commit()
    except Exception:
        db.rollback()
        LOGGER.exception("Unable to record security notification for event %s", event_id)


def notify_blocked_security_event(db, event_id, customer_id, attack_type, timestamp, risk_level, behavior_detected=False):
    """Attempt a redacted customer alert without allowing notification failures to affect the WAF."""
    if customer_id is None:
        return "NOT_SENT"

    customer = db.execute(
        "SELECT first_name, email FROM CUSTOMERS WHERE customer_id = ?",
        (customer_id,),
    ).fetchone()
    if not customer or not customer["email"]:
        return "NOT_SENT"

    notification_type = _notification_type(attack_type, behavior_detected)
    created_at = datetime.now()
    created_text = created_at.strftime("%Y-%m-%d %H:%M:%S")
    recipient = _mask_email(customer["email"])
    cutoff = (created_at - timedelta(seconds=COOLDOWN_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    recent = db.execute(
        """
        SELECT 1 FROM SECURITY_NOTIFICATIONS
        WHERE customer_id = ? AND notification_type = ? AND created_at >= ?
        ORDER BY notification_id DESC LIMIT 1
        """,
        (customer_id, notification_type, cutoff),
    ).fetchone()
    if recent:
        _record(db, event_id, customer_id, notification_type, recipient, "NOT_SENT", created_text, failure_reason="Cooldown active")
        return "NOT_SENT"

    if not _enabled():
        _record(db, event_id, customer_id, notification_type, recipient, "NOT_SENT", created_text, failure_reason="Email alerts disabled")
        return "NOT_SENT"

    try:
        host = os.environ["MAIL_HOST"]
        port = int(os.environ.get("MAIL_PORT", "587"))
        sender = os.environ["MAIL_FROM"]
        username = os.environ.get("MAIL_USERNAME")
        password = os.environ.get("MAIL_PASSWORD")
        use_tls = os.environ.get("MAIL_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
        message = EmailMessage()
        message["Subject"] = "Security Alert - Suspicious Activity Blocked"
        message["From"] = sender
        message["To"] = customer["email"]
        message.set_content(
            f"""Hello {customer['first_name']},

We detected and blocked suspicious activity associated with your banking account.

Security Event:
{event_id}

Activity:
{_activity_description(attack_type, behavior_detected)}

Detection:
{('Repeated Attack' if behavior_detected else 'Multiple Attacks' if attack_type == 'MULTIPLE_ATTACKS' else 'SQL Injection' if attack_type in {'SQL_INJECTION', 'SQL Injection'} else 'XSS')}

Time:
{timestamp}

Action:
REQUEST BLOCKED

If you performed this activity, no further action is required.

If you did NOT perform this activity, please sign in to your banking application and review your security activity.

This is an automated security notification.
"""
        )
        smtp = smtplib.SMTP(host, port, timeout=10)
        try:
            if use_tls:
                smtp.starttls()
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
        finally:
            smtp.quit()
        _record(db, event_id, customer_id, notification_type, recipient, "SENT", created_text, created_text)
        return "SENT"
    except Exception as error:
        LOGGER.warning("Security email notification failed for event %s: %s", event_id, error)
        _record(db, event_id, customer_id, notification_type, recipient, "FAILED", created_text, failure_reason=str(error)[:200])
        return "FAILED"
