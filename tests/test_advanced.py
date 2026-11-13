
import pytest

from advanced.ast_analyzer import (
    analyze_query,
    QueryValidationError
)
from advanced.query_policy import APPROVED_FINGERPRINTS
from advanced.secure_executor import (
    search_students_advanced,
    AdvancedSecurityError
)

def test_approved_select_query():
    query = """
        SELECT student_id, name, department, semester,
               cgpa, email, admission_year
        FROM students
        ORDER BY student_id
        LIMIT 100
    """

    result = analyze_query(query)

    assert result["valid"] is True
    assert result["fingerprint"] in APPROVED_FINGERPRINTS


def test_reject_update_query():
    query = "UPDATE students SET cgpa = 10"

    with pytest.raises(QueryValidationError):
        analyze_query(query)


def test_reject_unapproved_table():
    query = "SELECT * FROM security_events"

    with pytest.raises(QueryValidationError):
        analyze_query(query)

def test_reject_unapproved_function():
    query = "SELECT random() FROM students"

    with pytest.raises(QueryValidationError):
        analyze_query(query)

def test_reject_load_extension_function():
    query = "SELECT load_extension('test') FROM students"

    with pytest.raises(QueryValidationError):
        analyze_query(query)


def test_advanced_legitimate_search():
    results = search_students_advanced(name="Akhil")

    assert isinstance(results, list)


def test_advanced_accepts_apostrophe():
    results = search_students_advanced(name="O'Neil")

    assert isinstance(results, list)


def test_advanced_handles_injection_payload_as_data():
    # The payload is bound as a value, not executed as SQL.
    results = search_students_advanced(name="' OR 1=1 --")

    assert isinstance(results, list)
