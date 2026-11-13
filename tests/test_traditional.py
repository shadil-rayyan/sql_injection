
import pytest

from traditional.detector import detect_sqli
from traditional.executor import (
    search_students,
    SuspiciousInputError
)


def test_detect_boolean_injection():
    result, reason = detect_sqli("' OR 1=1 --")

    assert result is True
    assert reason is not None


def test_detect_union_injection():
    result, reason = detect_sqli("' UNION SELECT * FROM students --")

    assert result is True


def test_accept_normal_name():
    result, reason = detect_sqli("Akhil")

    assert result is False


def test_accept_apostrophe_in_name():
    result, reason = detect_sqli("O'Neil")

    assert result is False


def test_search_legitimate_student():
    results = search_students(name="Akhil")

    assert isinstance(results, list)


def test_block_injection_request():
    with pytest.raises(SuspiciousInputError):
        search_students(name="' OR 1=1 --")
