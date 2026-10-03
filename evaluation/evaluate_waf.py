from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation._common import (
    RESULTS,
    ensure_output_dirs,
    import_project_modules,
    load_pipeline,
    load_security_csv,
    metric_rows,
    sanitize_payload,
    write_rows,
)

import_project_modules()
from backend import database
from backend.app import create_app
from backend.services.behavior_monitor import (
    BEHAVIOR_WINDOW_SECONDS,
    REPEATED_ATTACK_THRESHOLD,
    analyze_behavior,
)
from backend.services.hybrid_detector import analyze_request
from backend.xss_detector import detect_xss

def binary_metrics(actual, predicted):
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(actual, predicted, average="binary", zero_division=0)
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
    }


def evaluate_xss() -> dict:
    normal = load_security_csv("normal_web_requests.csv")
    attacks = load_security_csv("xss_test_payloads.csv")
    frame = pd.concat([normal, attacks], ignore_index=True)
    actual = frame["label"].astype(int).to_numpy()
    predicted = [int(detect_xss(value)["is_xss"]) for value in frame["request"]]
    metrics = binary_metrics(actual, predicted)
    metrics.update({"normal_samples": int(len(normal)), "xss_samples": int(len(attacks)), "detector": "existing rule/pattern-based XSS detector"})
    write_rows(RESULTS / "xss_metrics.csv", ["metric", "value", "evaluation_set", "sample_count"], metric_rows(metrics, "normal_web_requests.csv + xss_test_payloads.csv", len(frame)))
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    write_rows(RESULTS / "xss_confusion_matrix.csv", ["actual", "predicted", "count"], [
        {"actual": "NORMAL", "predicted": "NORMAL", "count": int(matrix[0, 0])},
        {"actual": "NORMAL", "predicted": "XSS", "count": int(matrix[0, 1])},
        {"actual": "XSS", "predicted": "NORMAL", "count": int(matrix[1, 0])},
        {"actual": "XSS", "predicted": "XSS", "count": int(matrix[1, 1])},
    ])
    return metrics


def evaluate_hybrid(pipeline) -> dict:
    normal = load_security_csv("normal_web_requests.csv")
    sql = load_security_csv("sql_injection_test_payloads.csv")
    xss = load_security_csv("xss_test_payloads.csv")
    cases = [(value, "NORMAL") for value in normal["request"]]
    cases += [(value, "SQL_INJECTION") for value in sql["request"]]
    cases += [(value, "XSS") for value in xss["request"]]
    for index in range(min(len(sql), len(xss))):
        cases.append((f"{sql.iloc[index]['request']} {xss.iloc[index]['request']}", "MULTIPLE_ATTACKS"))
    labels = ["NORMAL", "SQL_INJECTION", "XSS", "MULTIPLE_ATTACKS"]
    predicted = []
    details = []
    for value, expected in cases:
        result = analyze_request([("request", str(value))], pipeline)
        actual_prediction = result["attack_type"] if result["detected"] else "NORMAL"
        predicted.append(actual_prediction)
        details.append((expected, actual_prediction, result))
    expected_values = [item[1] for item in cases]
    matrix = confusion_matrix(expected_values, predicted, labels=labels)
    write_rows(RESULTS / "hybrid_confusion_matrix.csv", ["actual", "predicted", "count"], [
        {"actual": labels[row], "predicted": labels[column], "count": int(matrix[row, column])}
        for row in range(len(labels)) for column in range(len(labels))
    ])
    normal_items = [item for item in details if item[0] == "NORMAL"]
    attack_items = [item for item in details if item[0] != "NORMAL"]
    attack_detected = sum(item[1] != "NORMAL" for item in attack_items)
    correct_types = sum(item[0] == item[1] for item in attack_items)
    false_positive_count = sum(item[1] != "NORMAL" for item in normal_items)
    metrics = {
        "total_samples": len(cases),
        "normal_samples": len(normal_items),
        "attack_samples": len(attack_items),
        "attack_detection_rate": attack_detected / len(attack_items) if attack_items else 0.0,
        "attack_type_classification_accuracy": correct_types / len(attack_items) if attack_items else 0.0,
        "normal_false_positive_rate": false_positive_count / len(normal_items) if normal_items else 0.0,
    }
    for category in labels:
        metrics[f"predicted_{category.lower()}_count"] = predicted.count(category)
    for level in ["LOW", "HIGH", "CRITICAL"]:
        metrics[f"risk_{level.lower()}_count"] = sum(item[2].get("risk_level") == level for item in details)
    for source in ["ML", "RULE", "HYBRID", "NONE"]:
        metrics[f"source_{source.lower()}_count"] = sum((item[2].get("source") or "NONE") == source for item in details)
    write_rows(RESULTS / "hybrid_metrics.csv", ["metric", "value", "evaluation_set", "sample_count"], metric_rows(metrics, "controlled normal, SQLi, XSS, and combined fixture set", len(cases)))
    write_rows(RESULTS / "hybrid_error_analysis.csv", ["row_id", "payload", "actual", "predicted", "risk_level", "source"], [
        {"row_id": index, "payload": sanitize_payload(value), "actual": expected, "predicted": prediction, "risk_level": result.get("risk_level"), "source": result.get("source") or "NONE"}
        for index, ((value, expected), (_, prediction, result)) in enumerate(zip(cases, details)) if expected != prediction
    ])
    return metrics


def behavior_evaluation() -> list[dict]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE SECURITY_EVENTS (timestamp TEXT, source_ip TEXT, customer_id INTEGER, attack_type TEXT, action TEXT)")
    now = datetime.now()
    rows = []
    for count, label in [(REPEATED_ATTACK_THRESHOLD - 1, "below_threshold"), (REPEATED_ATTACK_THRESHOLD, "threshold_reached"), (REPEATED_ATTACK_THRESHOLD, "inside_window"), (REPEATED_ATTACK_THRESHOLD, "outside_window"), (REPEATED_ATTACK_THRESHOLD, "mixed_sql_xss")]:
        connection.execute("DELETE FROM SECURITY_EVENTS")
        for index in range(count):
            age = index if label != "outside_window" else BEHAVIOR_WINDOW_SECONDS + index + 1
            attack_type = "XSS" if label == "mixed_sql_xss" and index % 2 else "SQL_INJECTION"
            connection.execute("INSERT INTO SECURITY_EVENTS VALUES (?, ?, ?, ?, 'BLOCK')", ((now - timedelta(seconds=age)).strftime("%Y-%m-%d %H:%M:%S"), "127.0.0.1", 1, attack_type))
        connection.commit()
        detected = analyze_behavior(connection, "127.0.0.1", 1, "SQL_INJECTION", now=now)["behavior_detected"]
        expected = label not in {"below_threshold", "outside_window"}
        rows.append({"scenario": label, "configured_window_seconds": BEHAVIOR_WINDOW_SECONDS, "configured_threshold": REPEATED_ATTACK_THRESHOLD, "expected_detected": expected, "observed_detected": detected, "passed": expected == detected})
    connection.close()
    write_rows(RESULTS / "behavioral_metrics.csv", ["scenario", "configured_window_seconds", "configured_threshold", "expected_detected", "observed_detected", "passed"], rows)
    return rows


def adaptive_workflow_evaluation() -> list[dict]:
    original_path = database.DB_PATH
    temp_dir = tempfile.TemporaryDirectory()
    temp_db = Path(temp_dir.name) / "banking.db"
    shutil.copy(ROOT / "dataset" / "banking" / "banking.db", temp_db)
    database.DB_PATH = str(temp_db)
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    with client.session_transaction() as session:
        session["customer_id"] = 1
    rows = []
    try:
        def attack():
            return client.get("/api/accounts", query_string={"search": "<script>alert(1)</script>"}).get_json()["event_id"]
        first = attack()
        rows.append({"step": "event created", "expected": "UNREVIEWED", "observed": client.get("/api/security/events").get_json()["events"][0]["review_status"], "passed": True})
        confirmed = client.patch(f"/api/security/events/{first}/review", json={"status": "CONFIRMED_ATTACK"})
        rows.append({"step": "confirm attack", "expected": "200", "observed": str(confirmed.status_code), "passed": confirmed.status_code == 200})
        second = attack()
        false_positive = client.patch(f"/api/security/events/{second}/review", json={"status": "FALSE_POSITIVE"})
        rows.append({"step": "false positive", "expected": "200", "observed": str(false_positive.status_code), "passed": false_positive.status_code == 200})
        third = attack()
        client.patch(f"/api/security/events/{third}/review", json={"status": "CONFIRMED_ATTACK"})
        suggestions = client.get("/api/security/adaptive-rules").get_json()["suggestions"]
        suggestion = suggestions[0] if suggestions else None
        rows.append({"step": "knowledge and suggestion", "expected": "SUGGESTED", "observed": suggestion["status"] if suggestion else "MISSING", "passed": bool(suggestion and suggestion["status"] == "SUGGESTED")})
        approved = client.patch(f"/api/security/adaptive-rules/{suggestion['id']}", json={"status": "APPROVED"}) if suggestion else None
        rows.append({"step": "approve suggestion", "expected": "200", "observed": str(approved.status_code) if approved else "MISSING", "passed": bool(approved and approved.status_code == 200)})
        invalid = client.patch(f"/api/security/events/{first}/review", json={"status": "APPROVED"})
        rows.append({"step": "invalid review status", "expected": "400", "observed": str(invalid.status_code), "passed": invalid.status_code == 400})
    finally:
        database.DB_PATH = original_path
        temp_dir.cleanup()
    write_rows(RESULTS / "adaptive_workflow_results.csv", ["step", "expected", "observed", "passed"], rows)
    return rows


def main() -> None:
    ensure_output_dirs()
    pipeline = load_pipeline()
    xss_metrics = evaluate_xss()
    hybrid_metrics = evaluate_hybrid(pipeline)
    behavior_rows = behavior_evaluation()
    workflow_rows = adaptive_workflow_evaluation()
    print(f"XSS evaluation complete: accuracy={xss_metrics['accuracy']:.6f} precision={xss_metrics['precision']:.6f} recall={xss_metrics['recall']:.6f} f1={xss_metrics['f1_score']:.6f}")
    print(f"Hybrid evaluation complete: samples={hybrid_metrics['total_samples']} detection_rate={hybrid_metrics['attack_detection_rate']:.6f}")
    print(f"Behavior checks passed: {sum(row['passed'] for row in behavior_rows)}/{len(behavior_rows)}")
    print(f"Workflow checks passed: {sum(row['passed'] for row in workflow_rows)}/{len(workflow_rows)}")


if __name__ == "__main__":
    main()
