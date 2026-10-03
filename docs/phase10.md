# Phase 10: Final Security Testing and Research Results

## Objective

Phase 10 evaluates the completed Phase 1-9 system without changing production WAF behavior or retraining the model.

## Experimental setup

**MEASURED RESULT:** The existing serialized artifact was evaluated with the training-compatible cleaning and stratified cap on `dataset/sql_injections/Test.csv`. XSS was evaluated using the existing rule detector against the normal and XSS security fixtures. Hybrid evaluation used the controlled fixture set formed from normal, SQLi, XSS, and combined payloads.

**IMPLEMENTATION FACT:** The SQLi model is the existing `Decision Tree` pipeline with character TF-IDF preprocessing. XSS remains rule/pattern-based. The latency benchmark measures detector processing with `time.perf_counter_ns`, excluding network, Flask routing, database, and frontend rendering time.

## Dataset description

The held-out SQLi test source contains 32,696 raw rows before training-compatible cleaning and a 10,000-row stratified evaluation cap. Security fixtures contain 4 normal requests, 5 SQLi payloads, and 4 XSS payloads. These fixture counts are small and are not a substitute for a production traffic sample.

## SQLi model evaluation

**MEASURED RESULT:** Accuracy: `0.9924`. Confusion counts, precision, recall, F1, and error examples are in `evaluation/results/sqli_metrics.csv`, `sqli_confusion_matrix.csv`, and `sqli_error_analysis.csv`.

**LIMITATION:** Error examples are sanitized and metrics describe this held-out dataset only.

## XSS detector evaluation

**MEASURED RESULT:** Precision: `1.0`, recall: `1.0`. This is explicitly an evaluation of the existing rule/pattern-based XSS detector, not an ML model.

## Hybrid WAF evaluation

**MEASURED RESULT:** Attack detection rate: `0.7692307692307693`. Normal-request false-positive rate: `0.0`. The multiclass confusion matrix, risk distribution, and source distribution are in the hybrid CSV outputs.

## False positives and false negatives

**MEASURED RESULT:** SQLi and XSS false-positive/false-negative rates are recorded in their metrics CSVs. Combined-attack misses and incorrect attack-type classifications are recorded in `hybrid_error_analysis.csv`.

**INTERPRETATION:** A measured rate is evidence about these fixtures, not a guarantee about unseen payloads or legitimate banking traffic.

## Latency evaluation

**MEASURED RESULT:** The normal-request hybrid detector average was `0.731098` ms over 100 iterations. Minimum, median, p95, maximum, and baseline value-iteration timings are in `latency_results.csv`.

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

**MEASURED RESULT:** SHA-256: `B3C2A0358DF54053C11C19C6C62D2BCFC621F00215BCD6A6E15D7B7AD21E3155`. Expected previous hash: `B3C2A0358DF54053C11C19C6C62D2BCFC621F00215BCD6A6E15D7B7AD21E3155`. Status: **UNCHANGED**.

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
.\.venv\Scripts\python.exe evaluation/evaluate_model.py
.\.venv\Scripts\python.exe evaluation/evaluate_waf.py
.\.venv\Scripts\python.exe evaluation/evaluate_latency.py
.\.venv\Scripts\python.exe evaluation/generate_report.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
Push-Location frontend; npm run build; Pop-Location
```

## Final observations

The evaluated architecture combines SQLi ML detection, XSS rules, hybrid classification, deterministic risk scoring, a repeated-activity signal, and human-reviewed knowledge suggestions. The components have different coverage and evidence sources; this evaluation does not rank them as universally better or worse.
