import os
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from backend import database
from backend.app import create_app


ROOT = Path(__file__).resolve().parents[1]


class EmailAlertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_db_path = database.DB_PATH
        cls.original_environment = os.environ.copy()
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "banking.db"
        shutil.copy(ROOT / "dataset" / "banking" / "banking.db", cls.db_path)
        database.DB_PATH = str(cls.db_path)
        cls.app = create_app()
        cls.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls.original_environment)
        database.DB_PATH = cls.original_db_path
        cls.temp_dir.cleanup()

    def setUp(self):
        os.environ.update({
            "MAIL_ENABLED": "false",
            "MAIL_HOST": "smtp.example.test",
            "MAIL_PORT": "587",
            "MAIL_FROM": "security@example.test",
            "MAIL_USERNAME": "mailer",
            "MAIL_PASSWORD": "smtp-secret",
            "MAIL_USE_TLS": "true",
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            db = database.get_db()
            db.execute("DELETE FROM SECURITY_NOTIFICATIONS")
            db.execute("DELETE FROM SECURITY_EVENTS")
            db.commit()

    def _authenticate(self):
        with self.client.session_transaction() as session:
            session["customer_id"] = 1

    def _notification_rows(self):
        with self.app.app_context():
            return database.get_db().execute(
                "SELECT * FROM SECURITY_NOTIFICATIONS ORDER BY notification_id"
            ).fetchall()

    def test_email_disabled_keeps_waf_block_and_records_not_sent(self):
        self._authenticate()
        response = self.client.get("/api/accounts", query_string={"search": "' OR 1=1 --"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["notification_status"], "NOT_SENT")
        self.assertEqual(self._notification_rows()[-1]["status"], "NOT_SENT")

    @patch("backend.services.email_alerts.smtplib.SMTP")
    def test_successful_mocked_email_is_sent(self, smtp_class):
        os.environ["MAIL_ENABLED"] = "true"
        self._authenticate()
        response = self.client.get("/api/accounts", query_string={"search": "' OR 1=1 --"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["notification_status"], "SENT")
        smtp_class.assert_called_once_with("smtp.example.test", 587, timeout=10)
        smtp_class.return_value.send_message.assert_called_once()
        self.assertEqual(self._notification_rows()[-1]["status"], "SENT")

    @patch("backend.services.email_alerts.smtplib.SMTP", side_effect=OSError("SMTP unavailable"))
    def test_smtp_failure_does_not_change_block_response(self, smtp_class):
        os.environ["MAIL_ENABLED"] = "true"
        self._authenticate()
        response = self.client.get("/api/accounts", query_string={"search": "' OR 1=1 --"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["notification_status"], "FAILED")
        self.assertEqual(self._notification_rows()[-1]["status"], "FAILED")

    @patch("backend.services.email_alerts.smtplib.SMTP")
    def test_authenticated_xss_and_sqli_are_attempted(self, smtp_class):
        os.environ["MAIL_ENABLED"] = "true"
        self._authenticate()
        self.assertEqual(self.client.get("/api/accounts", query_string={"search": "<script>alert(1)</script>"}).status_code, 403)
        self.assertEqual(self.client.get("/api/accounts", query_string={"search": "' OR 1=1 -- <script>alert(1)</script>"}).status_code, 403)
        types = [row["notification_type"] for row in self._notification_rows()]
        self.assertIn("XSS", types)
        self.assertIn("MULTIPLE_ATTACKS", types)

    @patch("backend.services.email_alerts.smtplib.SMTP")
    def test_unauthenticated_login_attack_has_no_customer_email(self, smtp_class):
        os.environ["MAIL_ENABLED"] = "true"
        response = self.client.post("/api/login", json={"username": "yash321", "password": "' OR 1=1 --"})
        self.assertEqual(response.status_code, 403)
        smtp_class.assert_not_called()
        self.assertEqual(self._notification_rows(), [])

    @patch("backend.services.email_alerts.smtplib.SMTP")
    def test_cooldown_prevents_repeated_email_spam(self, smtp_class):
        os.environ["MAIL_ENABLED"] = "true"
        self._authenticate()
        first = self.client.get("/api/accounts", query_string={"search": "' OR 1=1 --"})
        second = self.client.get("/api/accounts", query_string={"search": "' OR 1=1 --"})
        self.assertEqual(first.get_json()["notification_status"], "SENT")
        self.assertEqual(second.get_json()["notification_status"], "NOT_SENT")
        self.assertEqual(smtp_class.return_value.send_message.call_count, 1)

    @patch("backend.services.email_alerts.smtplib.SMTP")
    def test_email_is_redacted_and_contains_no_payload_or_secret(self, smtp_class):
        os.environ["MAIL_ENABLED"] = "true"
        self._authenticate()
        payload = "' OR 1=1 -- secret-token"
        response = self.client.get("/api/accounts", query_string={"search": payload})
        self.assertEqual(response.status_code, 403)
        message = smtp_class.return_value.send_message.call_args.args[0]
        body = message.get_content()
        self.assertNotIn(payload, body)
        self.assertNotIn("secret-token", body)
        self.assertNotIn("password", body.lower())
        self.assertNotIn("session", body.lower())
        self.assertNotIn("550857423370", body)
        self.assertIn("Security Event:", body)


if __name__ == "__main__":
    unittest.main()
