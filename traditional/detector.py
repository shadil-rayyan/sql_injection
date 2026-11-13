
import re


# Suspicious SQL injection patterns.
# These patterns are intended for basic detection, not complete SQL parsing.
SQLI_PATTERNS = [
    (
        "Boolean-based injection",
        re.compile(
            r"""(?is)(?:['"]\s*)?(?:or|and)\s+
            (?:['"]?\w+['"]?\s*=\s*['"]?\w+['"]?|
            \d+\s*=\s*\d+)"""
        ),
    ),
    (
        "UNION-based injection",
        re.compile(r"(?is)\bunion\s+(?:all\s+)?select\b"),
    ),
    (
        "SQL comment sequence",
        re.compile(r"(?is)(?:--|/\*|\*/)"),
    ),
    (
        "Stacked query pattern",
        re.compile(
            r"(?is);\s*(?:select|insert|update|delete|drop|alter)\b"
        ),
    ),
    (
        "Dangerous SQL statement",
        re.compile(
            r"(?is)\b(?:drop\s+table|alter\s+table|"
            r"truncate\s+table|exec(?:ute)?\s*\()\b"
        ),
    ),
]


def detect_sqli(value):
    """
    Check a single user input value for common SQL injection patterns.

    Returns:
        (True, reason)  if a suspicious pattern is detected.
        (False, None)   if no known pattern is detected.
    """

    if not isinstance(value, str):
        return False, None

    for reason, pattern in SQLI_PATTERNS:
        if pattern.search(value):
            return True, reason

    return False, None


def detect_request(data):
    """
    Check all string values in a request dictionary.

    Returns:
        (True, field_name, reason) if suspicious input is found.
        (False, None, None) otherwise.
    """

    if not isinstance(data, dict):
        raise ValueError("Request data must be a dictionary.")

    for field, value in data.items():
        is_suspicious, reason = detect_sqli(value)

        if is_suspicious:
            return True, field, reason

    return False, None, None
