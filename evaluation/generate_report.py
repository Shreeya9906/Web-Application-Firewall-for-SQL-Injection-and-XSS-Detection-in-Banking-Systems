from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation._common import FIGURES, MODEL_PATH, RESULTS, ensure_output_dirs, write_rows

EXPECTED_HASH = "B3C2A0358DF54053C11C19C6C62D2BCFC621F00215BCD6A6E15D7B7AD21E3155"


def read_rows(name: str) -> list[dict[str, str]]:
    with (RESULTS / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def metric(name: str, file_name: str, default: str = "not measured") -> str:
    for row in read_rows(file_name):
        if row.get("metric") == name:
            return row["value"]
    return default


def svg_bar(path: Path, title: str, labels: list[str], values: list[float], unit: str = "") -> None:
    width, height = 900, 500
    maximum = max(values or [1]) or 1
    bars = []
    bar_width = 650 / max(len(labels), 1)
    for index, (label, value) in enumerate(zip(labels, values)):
        x = 140 + index * bar_width
        bar_height = 300 * value / maximum
        y = 390 - bar_height
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width * .65:.1f}" height="{bar_height:.1f}" fill="#276749"/><text x="{x + bar_width * .325:.1f}" y="415" text-anchor="middle" font-size="13">{label}</text><text x="{x + bar_width * .325:.1f}" y="{y - 8:.1f}" text-anchor="middle" font-size="12">{value:.4g}{unit}</text>')
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}"><rect width="100%" height="100%" fill="white"/><text x="450" y="35" text-anchor="middle" font-size="22" font-family="sans-serif">{title}</text><line x1="120" y1="390" x2="820" y2="390" stroke="#333"/><line x1="120" y1="80" x2="120" y2="390" stroke="#333"/><text x="30" y="240" transform="rotate(-90 30 240)" text-anchor="middle" font-size="14">{unit or "Count / score"}</text>{"".join(bars)}</svg>'
    path.write_text(svg, encoding="utf-8")


def svg_heatmap(path: Path, title: str, labels: list[str], matrix: list[list[int]]) -> None:
    cell = 110
    left, top = 190, 100
    maximum = max([value for row in matrix for value in row] or [1])
    cells = []
    for row, values in enumerate(matrix):
        for column, value in enumerate(values):
            shade = 245 - int(180 * value / maximum) if maximum else 245
            x, y = left + column * cell, top + row * cell
            cells.append(f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" fill="rgb({shade},{shade},{shade})" stroke="white"/><text x="{x + cell / 2}" y="{y + cell / 2 + 7}" text-anchor="middle" font-size="18">{value}</text>')
    axis = "".join(f'<text x="{left + i * cell + cell / 2}" y="{top - 12}" text-anchor="middle" font-size="12">{label}</text><text x="{left - 12}" y="{top + i * cell + cell / 2 + 4}" text-anchor="end" font-size="12">{label}</text>' for i, label in enumerate(labels))
    size = left + cell * len(labels) + 30
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}"><rect width="100%" height="100%" fill="white"/><text x="{size / 2}" y="35" text-anchor="middle" font-size="20" font-family="sans-serif">{title}</text><text x="{left + cell * len(labels) / 2}" y="{size - 10}" text-anchor="middle" font-size="13">Predicted</text><text x="25" y="{top + cell * len(labels) / 2}" transform="rotate(-90 25 {top + cell * len(labels) / 2})" text-anchor="middle" font-size="13">Actual</text>{axis}{"".join(cells)}</svg>'
    path.write_text(svg, encoding="utf-8")


def matrix_from_csv(name: str, labels: list[str]) -> list[list[int]]:
    rows = read_rows(name)
    return [[int(next(row["count"] for row in rows if row["actual"] == actual and row["predicted"] == predicted)) for predicted in labels] for actual in labels]


def make_figures() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    svg_heatmap(FIGURES / "sqli_confusion_matrix.svg", "SQL Injection confusion matrix", ["NORMAL", "SQL_INJECTION"], matrix_from_csv("sqli_confusion_matrix.csv", ["NORMAL", "SQL_INJECTION"]))
    svg_heatmap(FIGURES / "xss_confusion_matrix.svg", "XSS rule detector confusion matrix", ["NORMAL", "XSS"], matrix_from_csv("xss_confusion_matrix.csv", ["NORMAL", "XSS"]))
    hybrid_labels = ["NORMAL", "SQL_INJECTION", "XSS", "MULTIPLE_ATTACKS"]
    svg_heatmap(FIGURES / "hybrid_attack_type_confusion_matrix.svg", "Hybrid attack-type confusion matrix", hybrid_labels, matrix_from_csv("hybrid_confusion_matrix.csv", hybrid_labels))
    metric_labels = ["SQLi P", "SQLi R", "SQLi F1", "XSS P", "XSS R", "XSS F1"]
    metric_values = [float(metric("precision", "sqli_metrics.csv")), float(metric("recall", "sqli_metrics.csv")), float(metric("f1_score", "sqli_metrics.csv")), float(metric("precision", "xss_metrics.csv")), float(metric("recall", "xss_metrics.csv")), float(metric("f1_score", "xss_metrics.csv"))]
    svg_bar(FIGURES / "precision_recall_f1_comparison.svg", "Precision, recall, and F1 comparison", metric_labels, metric_values)
    svg_bar(FIGURES / "false_positive_false_negative_comparison.svg", "False-positive and false-negative rates", ["SQLi FPR", "SQLi FNR", "XSS FPR", "XSS FNR", "Hybrid FPR"], [float(metric("false_positive_rate", "sqli_metrics.csv")), float(metric("false_negative_rate", "sqli_metrics.csv")), float(metric("false_positive_rate", "xss_metrics.csv")), float(metric("false_negative_rate", "xss_metrics.csv")), float(metric("normal_false_positive_rate", "hybrid_metrics.csv"))])
    latency_rows = [row for row in read_rows("latency_results.csv") if row["mode"] == "HYBRID_WAF_DETECTOR"]
    svg_bar(FIGURES / "waf_latency_distribution.svg", "Hybrid WAF detector latency (median)", [row["category"] for row in latency_rows], [float(row["median_ms"]) for row in latency_rows], " ms")
    attack_labels = ["NORMAL", "SQLi", "XSS", "MULTIPLE"]
    attack_keys = ["predicted_normal_count", "predicted_sql_injection_count", "predicted_xss_count", "predicted_multiple_attacks_count"]
    svg_bar(FIGURES / "attack_type_distribution.svg", "Hybrid predicted attack-type distribution", attack_labels, [float(metric(key, "hybrid_metrics.csv")) for key in attack_keys])
    risk_keys = ["risk_low_count", "risk_high_count", "risk_critical_count"]
    svg_bar(FIGURES / "risk_level_distribution.svg", "Hybrid risk-level distribution", ["LOW", "HIGH", "CRITICAL"], [float(metric(key, "hybrid_metrics.csv")) for key in risk_keys])
    behavior_rows = read_rows("behavioral_metrics.csv")
    svg_bar(FIGURES / "behavioral_detection_results.svg", "Behavioral detection results", [row["scenario"] for row in behavior_rows], [1.0 if row["observed_detected"] == "True" else 0.0 for row in behavior_rows])


def main() -> None:
    ensure_output_dirs()
    required = ["sqli_metrics.csv", "sqli_confusion_matrix.csv", "sqli_error_analysis.csv", "xss_metrics.csv", "xss_confusion_matrix.csv", "hybrid_metrics.csv", "hybrid_confusion_matrix.csv", "behavioral_metrics.csv", "latency_results.csv", "adaptive_workflow_results.csv"]
    missing = [name for name in required if not (RESULTS / name).exists()]
    if missing:
        raise FileNotFoundError(f"Missing evaluation outputs: {', '.join(missing)}")
    make_figures()
    current_hash = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest().upper()
    hash_status = "UNCHANGED" if current_hash == EXPECTED_HASH else "CHANGED"
    sqli_accuracy = metric("accuracy", "sqli_metrics.csv")
    xss_precision = metric("precision", "xss_metrics.csv")
    xss_recall = metric("recall", "xss_metrics.csv")
    hybrid_rate = metric("attack_detection_rate", "hybrid_metrics.csv")
    hybrid_fpr = metric("normal_false_positive_rate", "hybrid_metrics.csv")
    latency_average = next(row["average_ms"] for row in read_rows("latency_results.csv") if row["mode"] == "HYBRID_WAF_DETECTOR" and row["category"] == "NORMAL")
    behavior_rows = read_rows("behavioral_metrics.csv")
    workflow_rows = read_rows("adaptive_workflow_results.csv")
    docs = f'''# Phase 10: Final Security Testing and Research Results

## Objective

Phase 10 evaluates the completed Phase 1-9 system without changing production WAF behavior or retraining the model.

## Experimental setup

**MEASURED RESULT:** The existing serialized artifact was evaluated with the training-compatible cleaning and stratified cap on `dataset/sql_injections/Test.csv`. XSS was evaluated using the existing rule detector against the normal and XSS security fixtures. Hybrid evaluation used the controlled fixture set formed from normal, SQLi, XSS, and combined payloads.

**IMPLEMENTATION FACT:** The SQLi model is the existing `{metric("model_name", "sqli_metrics.csv")}` pipeline with character TF-IDF preprocessing. XSS remains rule/pattern-based. The latency benchmark measures detector processing with `time.perf_counter_ns`, excluding network, Flask routing, database, and frontend rendering time.

## Dataset description

The held-out SQLi test source contains 32,696 raw rows before training-compatible cleaning and a 10,000-row stratified evaluation cap. Security fixtures contain 4 normal requests, 5 SQLi payloads, and 4 XSS payloads. These fixture counts are small and are not a substitute for a production traffic sample.

## SQLi model evaluation

**MEASURED RESULT:** Accuracy: `{sqli_accuracy}`. Confusion counts, precision, recall, F1, and error examples are in `evaluation/results/sqli_metrics.csv`, `sqli_confusion_matrix.csv`, and `sqli_error_analysis.csv`.

**LIMITATION:** Error examples are sanitized and metrics describe this held-out dataset only.

## XSS detector evaluation

**MEASURED RESULT:** Precision: `{xss_precision}`, recall: `{xss_recall}`. This is explicitly an evaluation of the existing rule/pattern-based XSS detector, not an ML model.

## Hybrid WAF evaluation

**MEASURED RESULT:** Attack detection rate: `{hybrid_rate}`. Normal-request false-positive rate: `{hybrid_fpr}`. The multiclass confusion matrix, risk distribution, and source distribution are in the hybrid CSV outputs.

## False positives and false negatives

**MEASURED RESULT:** SQLi and XSS false-positive/false-negative rates are recorded in their metrics CSVs. Combined-attack misses and incorrect attack-type classifications are recorded in `hybrid_error_analysis.csv`.

**INTERPRETATION:** A measured rate is evidence about these fixtures, not a guarantee about unseen payloads or legitimate banking traffic.

## Latency evaluation

**MEASURED RESULT:** The normal-request hybrid detector average was `{latency_average}` ms over 100 iterations. Minimum, median, p95, maximum, and baseline value-iteration timings are in `latency_results.csv`.

**LIMITATION:** The baseline is a detector-free input iteration, not a complete application-without-WAF deployment. Latency differences are descriptive and do not establish security improvement.

## Behavioral evaluation

**IMPLEMENTATION FACT:** `BEHAVIOR_WINDOW_SECONDS = 300` and `REPEATED_ATTACK_THRESHOLD = 5`.

**MEASURED RESULT:** Threshold, below-threshold, in-window, outside-window, and mixed SQLi/XSS scenarios are recorded in `behavioral_metrics.csv`.

## Adaptive workflow evaluation

**MEASURED RESULT:** The actual Flask application was exercised with an isolated SQLite copy. The workflow verified unreviewed events, confirmation, knowledge creation, false-positive handling, suggestion creation, approval, and invalid status rejection. Results are in `adaptive_workflow_results.csv`.

This is workflow validation, not ML accuracy. Approved suggestions remain stored suggestions and are not automatically activated.

## Regression testing

**MEASURED RESULT:** Run `python -m unittest discover -s tests -p "test_*.py"` after evaluation. The evaluation code does not modify production WAF modules or raw datasets.

## Model integrity

**MEASURED RESULT:** SHA-256: `{current_hash}`. Expected previous hash: `{EXPECTED_HASH}`. Status: **{hash_status}**.

## Limitations

- Security fixtures are small and synthetic.
- XSS coverage is limited to existing patterns and fixtures.
- Behavioral analysis is a configurable heuristic, not a behavioral ML model.
- Latency excludes network and full application overhead.
- Approved adaptive suggestions are not active WAF rules.
- Risk scores are deterministic risk labels, not calibrated probabilities.

## Reproducibility

From the repository root and the project virtual environment:

```powershell
.\\.venv\\Scripts\\python.exe evaluation/evaluate_model.py
.\\.venv\\Scripts\\python.exe evaluation/evaluate_waf.py
.\\.venv\\Scripts\\python.exe evaluation/evaluate_latency.py
.\\.venv\\Scripts\\python.exe evaluation/generate_report.py
.\\.venv\\Scripts\\python.exe -m unittest discover -s tests -p "test_*.py"
Push-Location frontend; npm run build; Pop-Location
```

## Final observations

The evaluated architecture combines SQLi ML detection, XSS rules, hybrid classification, deterministic risk scoring, a repeated-activity signal, and human-reviewed knowledge suggestions. The components have different coverage and evidence sources; this evaluation does not rank them as universally better or worse.
'''
    (ROOT / "docs" / "phase10.md").write_text(docs, encoding="utf-8")
    final = f'''# Final Results

| Metric | Result | Evaluation Set |
|---|---:|---|
| SQLi Accuracy | {sqli_accuracy} | Held-out SQLi test set |
| SQLi Precision | {metric("precision", "sqli_metrics.csv")} | Held-out SQLi test set |
| SQLi Recall | {metric("recall", "sqli_metrics.csv")} | Held-out SQLi test set |
| SQLi F1 | {metric("f1_score", "sqli_metrics.csv")} | Held-out SQLi test set |
| XSS Precision | {xss_precision} | Existing XSS fixture set |
| XSS Recall | {xss_recall} | Existing XSS fixture set |
| Hybrid Detection Rate | {hybrid_rate} | Controlled hybrid fixture set |
| False Positive Rate | {hybrid_fpr} | Normal request fixture set |
| Average WAF Latency | {latency_average} ms | 100 normal detector iterations |

## Component comparison

| Component | Detection mechanism | Coverage | Explainability | Risk / behavior |
|---|---|---|---|---|
| SQLi ML | Existing character TF-IDF and Decision Tree | SQL Injection patterns represented in held-out data | Model prediction and evidence | Deterministic HIGH risk for a single attack |
| XSS Rules | Existing normalized structural patterns | Patterns implemented by the rule detector | Matched pattern name | Deterministic HIGH risk for a single attack |
| Hybrid | Both detectors combined | SQLi, XSS, and simultaneous signals | ML, RULE, or HYBRID source | CRITICAL for multiple attack types |
| Behavioral Layer | Time-window count heuristic | Repeated blocked activity | Threshold, window, and count | Contextual CRITICAL signal; no retraining |

The values above are generated from executed evaluation outputs, not estimated values. See `docs/phase10.md` for setup, limitations, and reproducibility details.
'''
    (ROOT / "docs" / "final_results.md").write_text(final, encoding="utf-8")
    print(f"Report generated: model_hash={current_hash} status={hash_status}; workflow_passed={sum(row['passed'] == 'True' for row in workflow_rows)}/{len(workflow_rows)}; behavior_passed={sum(row['passed'] == 'True' for row in behavior_rows)}/{len(behavior_rows)}")


if __name__ == "__main__":
    main()
