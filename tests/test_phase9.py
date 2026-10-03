import json
import shutil
import tempfile
import unittest
from pathlib import Path

from backend import database
from backend.app import create_app
from backend.services.behavior_monitor import (
    BEHAVIOR_WINDOW_SECONDS,
    REPEATED_ATTACK_THRESHOLD,
    analyze_behavior,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase9Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_db_path = database.DB_PATH
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "banking.db"
        shutil.copy(ROOT / "dataset" / "banking" / "banking.db", cls.db_path)
        database.DB_PATH = str(cls.db_path)
        cls.app = create_app()
        cls.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        database.DB_PATH = cls.original_db_path
        cls.temp_dir.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["customer_id"] = 1
        with self.app.app_context():
            db = database.get_db()
            db.execute("DELETE FROM ADAPTIVE_RULE_SUGGESTIONS")
            db.execute("DELETE FROM ATTACK_KNOWLEDGE")
            db.execute("DELETE FROM SECURITY_NOTIFICATIONS")
            db.execute("DELETE FROM SECURITY_EVENTS")
            db.commit()

    def _attack(self, payload):
        return self.client.get("/api/accounts", query_string={"search": payload})

    def test_normal_request_has_no_behavior_alert(self):
        response = self.client.get("/api/accounts")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/security/behavior-alerts").get_json()["alerts"], [])

    def test_single_attacks_keep_phase8_risk(self):
        sql = self._attack("' OR 1=1 --").get_json()
        xss = self._attack("<svg onload=alert(1)>").get_json()
        self.assertEqual(sql["risk_level"], "HIGH")
        self.assertEqual(sql["risk_score"], 0.85)
        self.assertEqual(xss["risk_level"], "HIGH")

    def test_multiple_and_repeated_attacks_are_critical(self):
        multiple = self._attack("' OR 1=1 -- <script>alert(1)</script>").get_json()
        self.assertEqual(multiple["risk_level"], "CRITICAL")
        responses = [
            self._attack("' OR 1=1 --"),
            self._attack("' OR 1=1 --"),
            self._attack("<script>alert(1)</script>"),
            self._attack("' OR 1=1 --"),
            self._attack("<script>alert(1)</script>"),
        ]
        self.assertTrue(responses[-1].get_json()["behavior"]["behavior_detected"])
        self.assertEqual(responses[-1].get_json()["risk_level"], "CRITICAL")
        alerts = self.client.get("/api/security/behavior-alerts").get_json()["alerts"]
        self.assertTrue(alerts)

    def test_old_events_outside_window_do_not_trigger(self):
        with self.app.app_context():
            db = database.get_db()
            db.execute(
                "INSERT INTO SECURITY_EVENTS (timestamp, source_ip, attack_type, action) VALUES (datetime('now', ?), ?, ?, 'BLOCK')",
                (f"-{BEHAVIOR_WINDOW_SECONDS + 1} seconds", "127.0.0.1", "XSS"),
            )
            db.commit()
            result = analyze_behavior(db, "127.0.0.1", None, "XSS")
        self.assertFalse(result["behavior_detected"])

    def test_review_and_knowledge_workflow(self):
        response = self._attack("<script>alert(1)</script>")
        event_id = response.get_json()["event_id"]
        reviewed = self.client.patch(f"/api/security/events/{event_id}/review", json={"status": "CONFIRMED_ATTACK"})
        self.assertEqual(reviewed.status_code, 200)
        with self.app.app_context():
            row = database.get_db().execute("SELECT * FROM ATTACK_KNOWLEDGE").fetchone()
            self.assertEqual(row["verification_status"], "CONFIRMED_ATTACK")

    def test_false_positive_does_not_create_knowledge_or_rule(self):
        event_id = self._attack("<script>alert(1)</script>").get_json()["event_id"]
        response = self.client.patch(f"/api/security/events/{event_id}/review", json={"status": "FALSE_POSITIVE"})
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            db = database.get_db()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ATTACK_KNOWLEDGE").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ADAPTIVE_RULE_SUGGESTIONS").fetchone()[0], 0)

    def test_invalid_statuses_and_authentication_are_rejected(self):
        event_id = self._attack("<script>alert(1)</script>").get_json()["event_id"]
        self.assertEqual(self.client.patch(f"/api/security/events/{event_id}/review", json={"status": "APPROVED"}).status_code, 400)
        self.assertEqual(self.client.patch("/api/security/adaptive-rules/1", json={"status": "CONFIRMED_ATTACK"}).status_code, 400)
        unauthenticated = self.app.test_client()
        self.assertEqual(unauthenticated.get("/api/security/adaptive-rules").status_code, 401)

    def test_repeated_verified_patterns_create_suggestion_and_approval(self):
        for _ in range(2):
            event_id = self._attack("<script>alert(1)</script>").get_json()["event_id"]
            self.assertEqual(
                self.client.patch(f"/api/security/events/{event_id}/review", json={"status": "CONFIRMED_ATTACK"}).status_code,
                200,
            )
        suggestions = self.client.get("/api/security/adaptive-rules").get_json()["suggestions"]
        self.assertEqual(len(suggestions), 1)
        rule_id = suggestions[0]["id"]
        self.assertEqual(self.client.patch(f"/api/security/adaptive-rules/{rule_id}", json={"status": "APPROVED"}).status_code, 200)
        self.assertEqual(self.client.get("/api/security/adaptive-rules").get_json()["suggestions"][0]["status"], "APPROVED")

    def test_security_responses_do_not_expose_sensitive_values(self):
        secret = "<script>alert('secret-token')</script>"
        response = self.client.post("/api/login", json={"username": "user", "password": secret})
        self.assertEqual(response.status_code, 403)
        body = json.dumps(response.get_json())
        self.assertNotIn(secret, body)
        self.assertNotIn("request_value", body)
        self.assertNotIn(secret, json.dumps(self.client.get("/api/security/events").get_json()))


if __name__ == "__main__":
    unittest.main()
