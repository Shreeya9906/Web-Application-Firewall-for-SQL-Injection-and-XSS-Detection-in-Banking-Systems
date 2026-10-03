from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "results"
FIGURES = RESULTS / "figures"
MODEL_PATH = ROOT / "artifacts" / "best_waf_model.joblib"


def ensure_output_dirs() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)


def load_pipeline():
    return joblib.load(MODEL_PATH)["pipeline"]


def load_security_csv(name: str) -> pd.DataFrame:
    return pd.read_csv(ROOT / "dataset" / "security" / name, engine="python", on_bad_lines="skip")


def sanitize_payload(value: object, limit: int = 240) -> str:
    value = re.sub(r"\s+", " ", str(value)).strip()
    value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL]", value)
    value = re.sub(r"\b\d{4,}\b", "[NUMBER]", value)
    return value[:limit]


def write_rows(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def metric_rows(metrics: dict[str, object], evaluation_set: str, sample_count: int) -> list[dict]:
    return [
        {"metric": name, "value": value, "evaluation_set": evaluation_set, "sample_count": sample_count}
        for name, value in metrics.items()
    ]


def import_project_modules():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
