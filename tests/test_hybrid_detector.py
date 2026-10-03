import hashlib
import json
import unittest
from pathlib import Path

from backend.app import create_app
from backend.services.hybrid_detector import analyze_request
from backend.services.waf import get_pipeline


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "artifacts" / "best_waf_model.joblib"


class HybridDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config.update(TESTING=True)
        cls.pipeline = get_pipeline()

    def test_model_artifact_loads_and_is_sql_specific(self):
        self.assertIsNotNone(self.pipeline)
        self.assertTrue(MODEL_PATH.exists())
        self.assertEqual(len(hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()), 64)

    def test_normal_request_allows_with_low_risk(self):
        result = analyze_request([("description", "monthly payment")], self.pipeline)
        self.assertFalse(result["detected"])
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertIn("No SQL Injection", result["explanation"])

    def test_sql_injection_is_ml_high_risk_and_explained(self):
        result = analyze_request([("search", "' OR 1=1 --")], self.pipeline)
        self.assertTrue(result["detected"])
        self.assertEqual(result["attack_type"], "SQL_INJECTION")
        self.assertEqual(result["source"], "ML")
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertTrue(result["reason"])
        self.assertTrue(result["evidence"])

    def test_xss_and_encoded_xss_are_rule_high_risk(self):
        for payload in ("<svg onload=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E"):
            with self.subTest(payload=payload):
                result = analyze_request([("description", payload)], self.pipeline)
                self.assertEqual(result["attack_type"], "XSS")
                self.assertEqual(result["source"], "RULE")
                self.assertEqual(result["risk_level"], "HIGH")
                self.assertIn("pattern", result["reason"])

    def test_combined_attack_is_hybrid_critical(self):
        result = analyze_request(
            [("search", "' OR 1=1 -- <script>alert(1)</script>")],
            self.pipeline,
        )
        self.assertEqual(result["attack_type"], "MULTIPLE_ATTACKS")
        self.assertEqual(result["source"], "HYBRID")
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertIn("SQL Injection and XSS", result["reason"])
        self.assertEqual({item["attack_type"] for item in result["detections"]}, {"SQL_INJECTION", "XSS"})

    def test_flask_block_response_is_explainable_without_raw_input(self):
        client = self.app.test_client()
        payload = "<script>alert('secret')</script>"
        response = client.post(
            "/api/login",
            json={"username": "test-user", "password": payload},
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(body["decision"], "BLOCK")
        self.assertEqual(body["risk_level"], "HIGH")
        self.assertTrue(body["explanation"])
        self.assertNotIn(payload, json.dumps(body))
        self.assertNotIn("request_value", json.dumps(body))


if __name__ == "__main__":
    unittest.main()