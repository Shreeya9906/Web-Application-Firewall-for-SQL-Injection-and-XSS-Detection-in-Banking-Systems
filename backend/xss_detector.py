from html import unescape
from urllib.parse import unquote_plus


_STRUCTURED_PATTERNS = (
    ("script_tag", r"<\s*/?\s*script\b"),
    ("script_protocol", r"\bjavascript\s*:"),
    ("event_handler", r"\bon\s*(?:error|load|click|mouseover)\s*="),
    ("embedded_element", r"<\s*(?:iframe|object|embed|svg)\b"),
    ("cookie_or_location_access", r"\b(?:document\s*\.\s*cookie|document\s*\.\s*location|window\s*\.\s*location)\b"),
    ("script_dialog", r"\b(?:alert|prompt|confirm)\s*\("),
)


def normalize_xss_value(value):
    """Decode common transport encodings without executing the result."""
    normalized = str(value)
    for _ in range(2):
        decoded = unquote_plus(unescape(normalized))
        if decoded == normalized:
            break
        normalized = decoded
    return " ".join(normalized.split()).casefold()


def detect_xss(value):
    """Return structured XSS evidence for a single request value."""
    import re

    normalized = normalize_xss_value(value)
    for pattern_name, pattern in _STRUCTURED_PATTERNS:
        if re.search(pattern, normalized):
            return {
                "is_xss": True,
                "reason": "Structured XSS pattern detected",
                "pattern": pattern_name,
                "confidence": 1.0,
            }

    return {
        "is_xss": False,
        "reason": "No structured XSS pattern detected",
        "pattern": None,
        "confidence": 0.0,
    }