import json
import unittest

from backend.app import create_app


class SecurityDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config.update(TESTING=True)

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["customer_id"] = 1

    def test_security_endpoints_require_authentication(self):
        client = self.app.test_client()
        for endpoint in (
            "/api/security/summary",
            "/api/security/events",
            "/api/security/attack-distribution",
            "/api/security/trends",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(client.get(endpoint).status_code, 401)

    def test_controlled_waf_events_are_visible_in_dashboard(self):
        sql_response = self.client.get("/api/accounts", query_string={"search": "' OR 1=1 --"})
        xss_response = self.client.get("/api/accounts", query_string={"search": "<svg onload=alert(1)>"})
        normal_response = self.client.get("/api/accounts")

        self.assertEqual(sql_response.status_code, 403)
        self.assertEqual(xss_response.status_code, 403)
        self.assertEqual(normal_response.status_code, 200)

        events = self.client.get("/api/security/events?limit=10").get_json()["events"]
        attack_types = {event["attack_type"] for event in events}
        self.assertIn("SQL_INJECTION", attack_types)
        self.assertIn("XSS", attack_types)

    def test_summary_and_distribution_use_database_aggregates(self):
        summary_response = self.client.get("/api/security/summary")
        distribution_response = self.client.get("/api/security/attack-distribution")

        self.assertEqual(summary_response.status_code, 200)
        summary = summary_response.get_json()
        self.assertGreaterEqual(summary["total_events"], summary["blocked_events"])
        self.assertGreaterEqual(summary["sql_injection"], 0)
        self.assertGreaterEqual(summary["xss"], 0)

        distribution = distribution_response.get_json()["distribution"]
        distribution_by_type = {item["attack_type"]: item["count"] for item in distribution}
        self.assertNotIn("SQL Injection", distribution_by_type)
        self.assertEqual(
            distribution_by_type.get("SQL_INJECTION", 0),
            summary["sql_injection"],
        )

    def test_events_are_limited_ordered_and_do_not_expose_secrets(self):
        response = self.client.get("/api/security/events?limit=2")
        self.assertEqual(response.status_code, 200)
        events = response.get_json()["events"]
        self.assertLessEqual(len(events), 2)
        self.assertEqual(
            events,
            sorted(events, key=lambda event: (event["timestamp"], event["event_id"]), reverse=True),
        )
        serialized = json.dumps(response.get_json())
        self.assertNotIn("request_value", serialized)
        self.assertNotIn("parameter_name", serialized)
        self.assertNotIn("password_hash", serialized)

    def test_date_filter_can_return_empty_state(self):
        events = self.client.get("/api/security/events?date=1900-01-01").get_json()["events"]
        trends = self.client.get("/api/security/trends?date=1900-01-01").get_json()["trends"]
        self.assertEqual(events, [])
        self.assertEqual(trends, [])

    def test_trends_have_attack_breakdown(self):
        response = self.client.get("/api/security/trends")
        self.assertEqual(response.status_code, 200)
        trends = response.get_json()["trends"]
        if trends:
            self.assertTrue({"date", "count", "sql_injection", "xss", "multiple_attacks"}.issubset(trends[0]))


if __name__ == "__main__":
    unittest.main()