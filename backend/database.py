import sqlite3
import os
from flask import g

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../dataset/banking/banking.db'))


def _ensure_phase9_schema(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(SECURITY_EVENTS)")}
    if "review_status" not in columns:
        db.execute("ALTER TABLE SECURITY_EVENTS ADD COLUMN review_status TEXT NOT NULL DEFAULT 'UNREVIEWED'")
    if "reviewed_at" not in columns:
        db.execute("ALTER TABLE SECURITY_EVENTS ADD COLUMN reviewed_at TEXT")

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS ATTACK_KNOWLEDGE (
            id INTEGER PRIMARY KEY,
            attack_type TEXT NOT NULL,
            normalized_pattern TEXT NOT NULL,
            detection_source TEXT NOT NULL,
            verification_status TEXT NOT NULL CHECK (verification_status = 'CONFIRMED_ATTACK'),
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (attack_type, normalized_pattern)
        );
        CREATE INDEX IF NOT EXISTS idx_attack_knowledge_last_seen
            ON ATTACK_KNOWLEDGE(last_seen);
        CREATE TABLE IF NOT EXISTS ADAPTIVE_RULE_SUGGESTIONS (
            id INTEGER PRIMARY KEY,
            attack_type TEXT NOT NULL,
            rule_pattern TEXT NOT NULL,
            reason TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL,
            source_event_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'SUGGESTED'
                CHECK (status IN ('SUGGESTED', 'APPROVED', 'REJECTED')),
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            UNIQUE (attack_type, rule_pattern),
            FOREIGN KEY(source_event_id) REFERENCES SECURITY_EVENTS(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_adaptive_rules_status
            ON ADAPTIVE_RULE_SUGGESTIONS(status);
        CREATE TABLE IF NOT EXISTS SECURITY_NOTIFICATIONS (
            notification_id INTEGER PRIMARY KEY,
            event_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            notification_type TEXT NOT NULL,
            recipient TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('SENT', 'FAILED', 'NOT_SENT')),
            created_at TEXT NOT NULL,
            sent_at TEXT,
            failure_reason TEXT,
            FOREIGN KEY(event_id) REFERENCES SECURITY_EVENTS(event_id),
            FOREIGN KEY(customer_id) REFERENCES CUSTOMERS(customer_id)
        );
        CREATE INDEX IF NOT EXISTS idx_security_notifications_cooldown
            ON SECURITY_NOTIFICATIONS(customer_id, notification_type, created_at);
        CREATE INDEX IF NOT EXISTS idx_security_notifications_event
            ON SECURITY_NOTIFICATIONS(event_id);
        """
    )
    db.commit()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
        _ensure_phase9_schema(g.db)
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
