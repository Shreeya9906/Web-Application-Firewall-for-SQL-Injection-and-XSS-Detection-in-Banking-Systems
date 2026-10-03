from __future__ import annotations

import argparse
import re
from pathlib import Path

import joblib


ROOT_DIR = Path(__file__).resolve().parent
MODEL_PATH = ROOT_DIR / "artifacts" / "best_waf_model.joblib"


XSS_PATTERNS = [
    r"<script",
    r"</script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<img",
    r"<svg",
    r"document\.cookie",
    r"alert\s*\(",
    r"eval\s*\(",
]

SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1=1",
    r"or\s+'1'='1'",
    r"information_schema",
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"--",
    r"/\*",
    r"xp_cmdshell",
    r"drop\s+table",
]


def detect_attack_type(query: str) -> str:
    lowered = query.lower()
    xss_score = sum(bool(re.search(pattern, lowered, flags=re.IGNORECASE)) for pattern in XSS_PATTERNS)
    sqli_score = sum(bool(re.search(pattern, lowered, flags=re.IGNORECASE)) for pattern in SQLI_PATTERNS)

    if xss_score > sqli_score and xss_score > 0:
        return "XSS"
    if sqli_score > 0:
        return "SQL Injection"
    return "Attack"


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict whether a query is normal, SQL Injection, or XSS.")
    parser.add_argument("--query", required=False, help="Query string to classify")
    args = parser.parse_args()

    query = args.query or input("Enter query: ")

    artifact = joblib.load(MODEL_PATH)
    pipeline = artifact["pipeline"]
    label_names = artifact.get("label_names", {0: "Normal", 1: "Attack"})

    prediction = int(pipeline.predict([query])[0])
    if prediction == 0:
        result = label_names.get(0, "Normal")
    else:
        result = detect_attack_type(query)

    print(f"Prediction: {result}")


if __name__ == "__main__":
    main()