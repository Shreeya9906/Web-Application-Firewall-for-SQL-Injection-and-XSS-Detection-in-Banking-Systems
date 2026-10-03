from collections.abc import Iterable

from backend.xss_detector import detect_xss


def calculate_risk(detections):
    """Return a transparent, non-calibrated risk score and level."""
    attack_types = {detection["attack_type"] for detection in detections}
    if not attack_types:
        return {"risk_score": 0.0, "risk_level": "LOW"}
    if len(attack_types) > 1:
        return {"risk_score": 1.0, "risk_level": "CRITICAL"}
    return {"risk_score": 0.85, "risk_level": "HIGH"}


def _model_probability(pipeline, value):
    if not hasattr(pipeline, "predict_proba"):
        return None

    probabilities = pipeline.predict_proba([value])[0]
    classes = getattr(pipeline, "classes_", None)
    if classes is None:
        steps = getattr(pipeline, "steps", [])
        if steps:
            classes = getattr(steps[-1][1], "classes_", None)
    if classes is None or 1 not in classes:
        return None
    return float(probabilities[list(classes).index(1)])


def _detect_sql_injection(pipeline, parameter_name, value):
    if pipeline.predict([value])[0] != 1:
        return None

    model_probability = _model_probability(pipeline, value)
    evidence = ["model_prediction=1"]
    if model_probability is not None:
        evidence.append(f"model_probability={model_probability:.4f} (not calibrated)")

    return {
        "detected": True,
        "attack_type": "SQL_INJECTION",
        "confidence": model_probability,
        "confidence_type": "uncalibrated_model_probability" if model_probability is not None else "confidence_unavailable",
        "source": "ML",
        "parameter_name": parameter_name,
        "request_value": value,
        "reason": "SQL Injection detected by the trained character-level ML classifier.",
        "evidence": evidence,
    }


def _detect_xss(parameter_name, value):
    result = detect_xss(value)
    if not result["is_xss"]:
        return None

    return {
        "detected": True,
        "attack_type": "XSS",
        "confidence": result["confidence"],
        "confidence_type": "rule_match_strength",
        "source": "RULE",
        "parameter_name": parameter_name,
        "request_value": value,
        "reason": f"XSS detected because the {result['pattern']} pattern was found after normalization.",
        "evidence": [result["pattern"]],
    }


def analyze_request(values: Iterable[tuple[str, str]], pipeline):
    """Combine the existing SQL model and XSS rules without exposing input values."""
    detections = []
    sql_seen = False
    xss_seen = False

    for parameter_name, value in values:
        if not isinstance(value, str) or not value.strip():
            continue

        if not sql_seen:
            sql_detection = _detect_sql_injection(pipeline, parameter_name, value)
            if sql_detection:
                detections.append(sql_detection)
                sql_seen = True

        if not xss_seen:
            xss_detection = _detect_xss(parameter_name, value)
            if xss_detection:
                detections.append(xss_detection)
                xss_seen = True

    risk = calculate_risk(detections)
    if not detections:
        return {
            "detected": False,
            "attack_type": None,
            "source": None,
            "decision": "ALLOW",
            "reason": "No SQL Injection or XSS indicators detected.",
            "explanation": "No SQL Injection or XSS indicators detected.",
            "evidence": [],
            "detections": [],
            **risk,
        }

    attack_types = {detection["attack_type"] for detection in detections}
    if len(attack_types) > 1:
        attack_type = "MULTIPLE_ATTACKS"
        source = "HYBRID"
        reason = "Multiple attack indicators detected: SQL Injection and XSS."
    else:
        detection = detections[0]
        attack_type = detection["attack_type"]
        source = detection["source"]
        reason = detection["reason"]

    return {
        "detected": True,
        "attack_type": attack_type,
        "source": source,
        "decision": "BLOCK",
        "reason": reason,
        "explanation": reason,
        "evidence": [evidence for detection in detections for evidence in detection["evidence"]][:8],
        "detections": detections,
        **risk,
    }