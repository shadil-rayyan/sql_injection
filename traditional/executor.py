
import time

from database import get_connection
from traditional.detector import detect_request


class SuspiciousInputError(Exception):
    """Raised when suspicious SQL injection input is detected."""
    pass


def log_security_event(
    configuration,
    event_type,
    detection_result,
    prevention_action,
    reason,
    execution_time_ms
):
    """Store a security event in the SQLite database."""

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO security_events (
                timestamp,
                configuration,
                event_type,
                detection_result,
                prevention_action,
                reason,
                execution_time_ms
            )
            VALUES (
                datetime('now'),
                ?, ?, ?, ?, ?, ?
            )
            """,
            (
                configuration,
                event_type,
                detection_result,
                prevention_action,
                reason,
                execution_time_ms
            )
        )

        connection.commit()

    finally:
        connection.close()


def search_students(name=None, department=None, semester=None):
    """
    Search students using traditional SQL injection protection.

    1. Check inputs using regex.
    2. Block suspicious requests.
    3. Execute legitimate requests using parameterized SQL.
    4. Record security events.
    """

    start_time = time.perf_counter()

    request_data = {
        "name": name,
        "department": department,
        "semester": semester
    }

    # Step 1: Regex-based detection
    is_suspicious, field, reason = detect_request(request_data)

    if is_suspicious:
        execution_time = (
            time.perf_counter() - start_time
        ) * 1000

        log_security_event(
            configuration="Traditional",
            event_type="SQL_INJECTION_ATTEMPT",
            detection_result="Detected",
            prevention_action="Blocked",
            reason=f"Suspicious input in {field}: {reason}",
            execution_time_ms=execution_time
        )

        raise SuspiciousInputError(
            f"Request blocked: suspicious input detected in {field}."
        )

    # Step 2: Construct query using fixed SQL fragments.
    # User values are never inserted directly into the SQL string.
    query = """
        SELECT student_id, name, department, semester,
               cgpa, email, admission_year
        FROM students
    """

    conditions = []
    parameters = []

    if name is not None:
        conditions.append("name LIKE ?")
        parameters.append(f"%{name}%")

    if department is not None:
        conditions.append("department = ?")
        parameters.append(department)

    if semester is not None:
        try:
            semester = int(semester)
        except (TypeError, ValueError):
            raise ValueError("Semester must be a valid integer.")

        if not 1 <= semester <= 8:
            raise ValueError("Semester must be between 1 and 8.")

        conditions.append("semester = ?")
        parameters.append(semester)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY student_id LIMIT 100"

    # Step 3: Execute parameterized query.
    connection = get_connection()

    try:
        cursor = connection.execute(query, parameters)
        results = [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()

    # Step 4: Log successful request.
    execution_time = (
        time.perf_counter() - start_time
    ) * 1000

    log_security_event(
        configuration="Traditional",
        event_type="NORMAL_REQUEST",
        detection_result="Not detected",
        prevention_action="Parameterized query executed",
        reason="No suspicious pattern detected",
        execution_time_ms=execution_time
    )

    return results
