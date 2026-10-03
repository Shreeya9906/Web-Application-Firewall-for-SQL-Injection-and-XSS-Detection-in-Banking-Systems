import sqlite3
import unittest
from pathlib import Path

from backend.app import create_app
from backend.xss_detector import detect_xss


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "dataset" / "banking" / "banking.db"


class XssWafTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config.update(TESTING=True)

    def setUp(self):
        self.client = self.app.test_client()

    def test_normal_values_are_not_xss(self):
        for value in (
            "hello",
            "John Doe",
            "Transfer money to savings account",
            "monthly payment",
            "normal banking description",
        ):
            with self.subTest(value=value):
                self.assertFalse(detect_xss(value)["is_xss"])

    def test_xss_payloads_are_blocked_by_real_endpoint(self):
        payloads = (
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            '<iframe src="javascript:alert(1)"></iframe>',
            "%3Cscript%3Ealert(1)%3C/script%3E",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.client.get("/api/accounts", query_string={"search": payload})
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.get_json()["attack_type"], "XSS")

    def test_nested_json_xss_is_blocked_before_route(self):
        response = self.client.post(
            "/api/transfer",
            json={"description": {"memo": "<script>alert(1)</script>"}},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["attack_type"], "XSS")

    def test_xss_is_logged_without_raw_sensitive_values(self):
        response = self.client.post(
            "/api/login",
            json={"username": "not-a-real-user", "password": "<svg onload=alert(1)>"},
        )
        self.assertEqual(response.status_code, 403)

        with sqlite3.connect(DB_PATH) as connection:
            event = connection.execute(
                """
                SELECT attack_type, endpoint, http_method, request_value
                FROM SECURITY_EVENTS
                WHERE attack_type = 'XSS' AND endpoint = '/api/login'
                ORDER BY event_id DESC LIMIT 1
                """
            ).fetchone()
        self.assertIsNotNone(event)
        self.assertEqual(event[:3], ("XSS", "/api/login", "POST"))
        self.assertEqual(event[3], "[REDACTED]")

    def test_sql_injection_regression(self):
        for payload in (
            "' OR 1=1 --",
            "' UNION SELECT NULL --",
            "admin' --",
        ):
            with self.subTest(payload=payload):
                response = self.client.get("/api/accounts", query_string={"search": payload})
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.get_json()["attack_type"], "SQL_INJECTION")

    def test_combined_attack_is_reported(self):
        response = self.client.get(
            "/api/accounts",
            query_string={"search": "' OR 1=1 -- <script>alert(1)</script>"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["attack_type"], "MULTIPLE_ATTACKS")

    def test_normal_endpoint_reaches_route(self):
        response = self.client.get("/api/accounts")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()