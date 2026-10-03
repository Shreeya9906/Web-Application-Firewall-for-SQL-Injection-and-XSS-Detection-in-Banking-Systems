from __future__ import annotations

import time
from pathlib import Path

import joblib
import pandas as pd

from sklearn.base import clone
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

# ============================================================
# Paths
# ============================================================

ROOT_DIR = Path(__file__).resolve().parent

DATA_DIR = ROOT_DIR / "datasets"
ARTIFACT_DIR = ROOT_DIR / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "best_waf_model.joblib"

MAX_TRAIN_ROWS = 30000
MAX_VALIDATION_ROWS = 10000
MAX_TEST_ROWS = 10000

# ============================================================
# Labels
# ============================================================

LABEL_NAMES = {
    0: "Normal",
    1: "SQL Injection",
}

# ============================================================
# Load CSV
# ============================================================

def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(
        path,
        engine="python",
        on_bad_lines="skip",
    )

    df.columns = [column.strip() for column in df.columns]

    return df


# ============================================================
# Clean Dataset
# ============================================================

def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:

    cleaned = df.copy()

    cleaned = cleaned.dropna(subset=["Query", "Label"])

    cleaned["Query"] = (
        cleaned["Query"]
        .astype(str)
        .str.lower()
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )

    cleaned["Label"] = pd.to_numeric(
        cleaned["Label"],
        errors="coerce",
    )

    cleaned = cleaned.dropna(subset=["Label"])

    cleaned["Label"] = cleaned["Label"].astype(int)

    cleaned = cleaned[cleaned["Query"] != ""]

    cleaned = cleaned.drop_duplicates(
        subset=["Query", "Label"]
    ).reset_index(drop=True)

    return cleaned


# ============================================================
# Dataset Exploration
# ============================================================

def explore_dataset(name: str, df: pd.DataFrame):

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    print("Shape:")
    print(df.shape)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nMissing Values:")
    print(df.isnull().sum())

    print("\nDuplicate Rows:")
    print(df.duplicated().sum())

    print("\nLabel Distribution:")
    print(df["Label"].value_counts())

    print("\nSample Queries")

    for label in sorted(df["Label"].unique()):

        print(f"\n{LABEL_NAMES.get(label,label)}")

        sample = (
            df[df["Label"] == label]["Query"]
            .head(3)
            .tolist()
        )

        for q in sample:
            print("-", q[:180])


# ============================================================
# Build ML Pipeline
# ============================================================

def build_pipeline(classifier):

    return Pipeline(

        steps=[

            (

                "tfidf",

                TfidfVectorizer(

                    analyzer="char",

                    ngram_range=(3,4),

                    lowercase=True,

                    sublinear_tf=True,

                    max_features=10000,

                    min_df=2,

                ),

            ),

            (

                "classifier",

                classifier,

            ),

        ]

    )


def stratified_sample(df: pd.DataFrame, max_rows: int, random_state: int = 42) -> pd.DataFrame:

    if len(df) <= max_rows:
        return df.reset_index(drop=True)

    sample_parts = []

    for _, group in df.groupby("Label", sort=True):
        proportion = len(group) / len(df)
        n_rows = max(1, int(round(max_rows * proportion)))
        n_rows = min(n_rows, len(group))
        sample_parts.append(group.sample(n=n_rows, random_state=random_state))

    sampled = pd.concat(sample_parts, ignore_index=True)

    return sampled.sample(frac=1, random_state=random_state).reset_index(drop=True)


# ============================================================
# Metrics
# ============================================================

def summarize_metrics(y_true, y_pred):

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    precision, recall, f1, _ = precision_recall_fscore_support(

        y_true,

        y_pred,

        average="weighted",

        zero_division=0,

    )

    return {

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1,

        "confusion_matrix": confusion_matrix(
            y_true,
            y_pred,
        ),

    }


def print_metrics(title, y_true, y_pred):

    metrics = summarize_metrics(
        y_true,
        y_pred,
    )

    print("\n" + "=" * 60)

    print(title)

    print("=" * 60)

    print(f"Accuracy : {metrics['accuracy']:.4f}")

    print(f"Precision: {metrics['precision']:.4f}")

    print(f"Recall   : {metrics['recall']:.4f}")

    print(f"F1 Score : {metrics['f1']:.4f}")

    print("\nConfusion Matrix")

    cm = pd.DataFrame(

        metrics["confusion_matrix"],

        columns=["Pred 0", "Pred 1"],

        index=["Actual 0", "Actual 1"],

    )

    print(cm)

    print("\nClassification Report\n")

    print(

        classification_report(

            y_true,

            y_pred,

            target_names=[

                LABEL_NAMES[0],

                LABEL_NAMES[1],

            ],

            zero_division=0,

        )

    )

    return metrics
# ============================================================
# Main
# ============================================================

def main():

    print("\nLoading datasets...")

    train_df = clean_dataframe(load_csv(DATA_DIR / "Train.csv"))
    validation_df = clean_dataframe(load_csv(DATA_DIR / "Validation.csv"))
    test_df = clean_dataframe(load_csv(DATA_DIR / "Test.csv"))

    print("\nPreparing training data...")
    print(f"Training samples before sampling: {len(train_df)}")
    print(f"Validation samples before sampling: {len(validation_df)}")
    print(f"Test samples before sampling: {len(test_df)}")

    train_df = stratified_sample(train_df, MAX_TRAIN_ROWS)
    validation_df = stratified_sample(validation_df, MAX_VALIDATION_ROWS)
    test_df = stratified_sample(test_df, MAX_TEST_ROWS)

    print(f"Training samples used: {len(train_df)}")
    print(f"Validation samples used: {len(validation_df)}")
    print(f"Test samples used: {len(test_df)}")

    print("Datasets loaded successfully!")

    # --------------------------------------------------------

    explore_dataset("TRAIN DATASET", train_df)

    # --------------------------------------------------------

    X_train = train_df["Query"]
    y_train = train_df["Label"]

    X_validation = validation_df["Query"]
    y_validation = validation_df["Label"]

    X_test = test_df["Query"]
    y_test = test_df["Label"]

    print("Preparing training data...")
    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_validation)}")

    # ========================================================

    candidates = {

        "Decision Tree": build_pipeline(

            DecisionTreeClassifier(

                max_depth=15,
                min_samples_split=20,
                min_samples_leaf=10,

                class_weight="balanced",

                random_state=42,

            )

        ),

        "Random Forest": build_pipeline(

            RandomForestClassifier(

                n_estimators=30,

                max_depth=15,

                min_samples_split=20,

                min_samples_leaf=10,

                random_state=42,

                n_jobs=-1,

                class_weight="balanced_subsample",

            )

        ),

    }

    # ========================================================

    validation_results = []

    fitted_models = {}

    # ========================================================

    for model_name, pipeline in candidates.items():

        print("\n" + "=" * 70)
        print(f"Training {model_name}")
        print("=" * 70)

        start = time.time()

        print("Starting model training...")

        model = clone(pipeline)

        model.fit(X_train, y_train)

        end = time.time()

        print(f"{model_name} trained in {(end-start):.2f} seconds")

        fitted_models[model_name] = model

        predictions = model.predict(X_validation)

        metrics = print_metrics(

            f"Validation Results - {model_name}",

            y_validation,

            predictions,

        )

        validation_results.append(

            (

                model_name,

                metrics,

                model,

            )

        )

    # ========================================================

    comparison = pd.DataFrame(

        [

            {

                "Model": name,

                "Accuracy": metrics["accuracy"],

                "Precision": metrics["precision"],

                "Recall": metrics["recall"],

                "F1 Score": metrics["f1"],

            }

            for name, metrics, _ in validation_results

        ]

    )

    comparison = comparison.sort_values(

        by=["Accuracy", "F1 Score"],

        ascending=False,

    )

    print("\n")
    print("=" * 70)
    print("MODEL COMPARISON")
    print("=" * 70)

    print(comparison)

    # ========================================================

    best_model_name = comparison.iloc[0]["Model"]

    print(f"\nBest Model : {best_model_name}")

    best_pipeline = clone(

        fitted_models[best_model_name]

    )

    # ========================================================

    print("\nRetraining on Train + Validation datasets...")

    combined = pd.concat(

        [

            train_df,

            validation_df,

        ],

        ignore_index=True,

    )

    best_pipeline.fit(

        combined["Query"],

        combined["Label"],

    )

    print("Retraining Completed!")

    # ========================================================

    print("\nEvaluating on Test Dataset...")

    test_predictions = best_pipeline.predict(

        X_test

    )

    print_metrics(

        f"Final Test Results - {best_model_name}",

        y_test,

        test_predictions,

    )

    # ========================================================

    ARTIFACT_DIR.mkdir(

        parents=True,

        exist_ok=True,

    )

    artifact = {

        "pipeline": best_pipeline,

        "model_name": best_model_name,

        "labels": LABEL_NAMES,

        "comparison": comparison,

    }

    joblib.dump(

        artifact,

        MODEL_PATH,

    )

    print("\n")
    print("=" * 70)
    print("MODEL SAVED SUCCESSFULLY")
    print("=" * 70)
    print(MODEL_PATH)

    print("\nProject Completed Successfully!")


# ============================================================

if __name__ == "__main__":

    main()