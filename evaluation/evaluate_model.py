from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation._common import RESULTS, ensure_output_dirs, import_project_modules, metric_rows, sanitize_payload, write_rows

import_project_modules()
from train_waf import clean_dataframe, load_csv, stratified_sample


TEST_PATH = ROOT / "dataset" / "sql_injections" / "Test.csv"
MAX_TEST_ROWS = 10000


def main() -> None:
    ensure_output_dirs()
    frame = clean_dataframe(load_csv(TEST_PATH))
    if len(frame) > MAX_TEST_ROWS:
        frame = stratified_sample(frame, MAX_TEST_ROWS)
    frame = frame.reset_index(drop=True)
    artifact = __import__("joblib").load(ROOT / "artifacts" / "best_waf_model.joblib")
    pipeline = artifact["pipeline"]
    predictions = pipeline.predict(frame["Query"].tolist()).astype(int)
    actual = frame["Label"].astype(int).to_numpy()
    matrix = confusion_matrix(actual, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(actual, predictions, average="binary", zero_division=0)
    metrics = {
        "accuracy": float(accuracy_score(actual, predictions)),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "normal_samples": int((actual == 0).sum()),
        "sql_injection_samples": int((actual == 1).sum()),
        "model_name": artifact.get("model_name", "unknown"),
        "preprocessing": "character TF-IDF, ngrams 3-4, lowercase, sublinear TF, max_features=10000, min_df=2",
    }
    write_rows(RESULTS / "sqli_metrics.csv", ["metric", "value", "evaluation_set", "sample_count"], metric_rows(metrics, "dataset/sql_injections/Test.csv after training-compatible cleaning and cap", len(frame)))
    write_rows(RESULTS / "sqli_confusion_matrix.csv", ["actual", "predicted", "count"], [
        {"actual": "NORMAL", "predicted": "NORMAL", "count": int(matrix[0, 0])},
        {"actual": "NORMAL", "predicted": "SQL_INJECTION", "count": int(matrix[0, 1])},
        {"actual": "SQL_INJECTION", "predicted": "NORMAL", "count": int(matrix[1, 0])},
        {"actual": "SQL_INJECTION", "predicted": "SQL_INJECTION", "count": int(matrix[1, 1])},
    ])
    errors = []
    for index, (query, truth, prediction) in enumerate(zip(frame["Query"], actual, predictions)):
        if truth != prediction:
            errors.append({
                "row_id": index,
                "query_or_payload": sanitize_payload(query),
                "actual_label": int(truth),
                "predicted_label": int(prediction),
                "error_type": "FALSE_POSITIVE" if truth == 0 else "FALSE_NEGATIVE",
            })
    write_rows(RESULTS / "sqli_error_analysis.csv", ["row_id", "query_or_payload", "actual_label", "predicted_label", "error_type"], errors)
    write_rows(RESULTS / "sqli_error_aggregate.csv", ["error_type", "count"], [
        {"error_type": "FALSE_POSITIVE", "count": int(fp)},
        {"error_type": "FALSE_NEGATIVE", "count": int(fn)},
    ])
    print(f"SQLi evaluation complete: samples={len(frame)} accuracy={metrics['accuracy']:.6f} precision={precision:.6f} recall={recall:.6f} f1={f1:.6f}")


if __name__ == "__main__":
    main()
