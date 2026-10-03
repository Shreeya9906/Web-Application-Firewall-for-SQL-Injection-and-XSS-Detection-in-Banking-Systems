from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation._common import RESULTS, ensure_output_dirs, import_project_modules, load_pipeline, write_rows

import_project_modules()
from backend.services.hybrid_detector import analyze_request


ITERATIONS = 100
CASES = {
    "NORMAL": "monthly payment",
    "SQL_INJECTION": "' OR 1=1 --",
    "XSS": "<script>alert(1)</script>",
    "MULTIPLE_ATTACKS": "' OR 1=1 -- <script>alert(1)</script>",
}


def summarize(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "minimum_ms": min(values),
        "average_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "p95_ms": ordered[max(0, int(len(ordered) * 0.95) - 1)],
        "maximum_ms": max(values),
    }


def main() -> None:
    ensure_output_dirs()
    pipeline = load_pipeline()
    rows = []
    for category, payload in CASES.items():
        baseline_values = []
        waf_values = []
        for _ in range(ITERATIONS):
            start = time.perf_counter_ns()
            tuple(("request", payload) for _ in [0])
            baseline_values.append((time.perf_counter_ns() - start) / 1_000_000)
            start = time.perf_counter_ns()
            result = analyze_request([("request", payload)], pipeline)
            waf_values.append((time.perf_counter_ns() - start) / 1_000_000)
        for mode, values in [("BASELINE_VALUE_ITERATION", baseline_values), ("HYBRID_WAF_DETECTOR", waf_values)]:
            summary = summarize(values)
            rows.append({"category": category, "mode": mode, "iterations": ITERATIONS, "minimum_ms": summary["minimum_ms"], "average_ms": summary["average_ms"], "median_ms": summary["median_ms"], "p95_ms": summary["p95_ms"], "maximum_ms": summary["maximum_ms"], "observed_decision": "ALLOW" if category == "NORMAL" else "BLOCK" if mode == "HYBRID_WAF_DETECTOR" and result.get("detected") else "NOT_APPLICABLE"})
    write_rows(RESULTS / "latency_results.csv", ["category", "mode", "iterations", "minimum_ms", "average_ms", "median_ms", "p95_ms", "maximum_ms", "observed_decision"], rows)
    print(f"Latency evaluation complete: {ITERATIONS} iterations per category and mode")


if __name__ == "__main__":
    main()
