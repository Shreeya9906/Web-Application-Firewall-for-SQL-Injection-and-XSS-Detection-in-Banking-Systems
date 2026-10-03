import logging
from pathlib import Path
from threading import Lock

import joblib
from backend.services.hybrid_detector import analyze_request

LOGGER = logging.getLogger(__name__)
MODEL_PATH = Path(__file__).resolve().parents[2] / "artifacts" / "best_waf_model.joblib"
_pipeline = None
_model_error = None
_pipeline_lock = Lock()

def get_pipeline():
    global _pipeline, _model_error
    if _pipeline is not None or _model_error is not None:
        return _pipeline

    with _pipeline_lock:
        if _pipeline is None and _model_error is None:
            try:
                artifact = joblib.load(MODEL_PATH)
                _pipeline = artifact["pipeline"]
            except Exception as error:
                _model_error = error
                LOGGER.exception("Unable to load WAF model from %s", MODEL_PATH)
    return _pipeline


def _iter_request_values(request):
    for parameter_name, values in request.args.lists():
        for value in values:
            yield parameter_name, value

    for parameter_name, values in request.form.lists():
        for value in values:
            yield parameter_name, value

    if request.is_json:
        json_data = request.get_json(silent=True)
        if isinstance(json_data, dict):
            yield from _iter_json_values(json_data)

    if request.view_args:
        for parameter_name, value in request.view_args.items():
            if isinstance(value, (str, int, float)):
                yield parameter_name, str(value)


def _iter_json_values(value, parameter_name=None):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_json_values(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_json_values(child, parameter_name)
    elif isinstance(value, str) and parameter_name is not None:
        yield parameter_name, value


def check_request_for_sqli(request):
    pipeline = get_pipeline()
    if not pipeline:
        return {
            "blocked": True,
            "error": True,
            "attack_type": "System Error",
            "parameter_name": "unknown",
            "request_value": "",
            "reason": "WAF model unavailable",
            "model_error": str(_model_error),
        }

    for param_name, value in _iter_request_values(request):
        if not value.strip():
            continue

        result = analyze_request(((param_name, value),), pipeline)
        if result["detected"] and result["attack_type"] == "SQL_INJECTION":
            detection = result["detections"][0]
            return {
                "blocked": True,
                "attack_type": "SQL_INJECTION",
                "confidence": detection["confidence"],
                "parameter_name": param_name,
                "request_value": value,
                "reason": detection["reason"],
            }

    return {"blocked": False}


def check_request(request):
    """Run the hybrid detector over all request values."""
    pipeline = get_pipeline()
    if not pipeline:
        return check_request_for_sqli(request)

    result = analyze_request(_iter_request_values(request), pipeline)
    if not result["detected"]:
        return {"blocked": False, **result}

    first_detection = result["detections"][0]
    safe_detections = [
        {key: value for key, value in detection.items() if key != "request_value"}
        for detection in result["detections"]
    ]
    return {
        "blocked": True,
        "attack_type": result["attack_type"],
        "confidence": result.get("risk_score"),
        "risk_score": result.get("risk_score"),
        "risk_level": result.get("risk_level"),
        "decision": result.get("decision", "BLOCK"),
        "source": result.get("source"),
        "parameter_name": ", ".join(
            detection["parameter_name"] for detection in result["detections"]
        ),
        "request_value": first_detection["request_value"],
        "reason": result["reason"],
        "explanation": result["explanation"],
        "evidence": result["evidence"],
        "detections": safe_detections,
    }
