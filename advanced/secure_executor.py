
import time

from database import get_connection
from advanced.ast_analyzer import (
    analyze_query,
    QueryValidationError
)
from advanced.query_policy import (
    build_approved_query,
    APPROVED_FINGERPRINTS
)
from advanced.db_authorizer import (
    enable_read_only_authorization
)
from traditional.executor import log_security_event


class AdvancedSecurityError(Exception):
    pass


def search_students_advanced(
    name=None,
    department=None,
    semester=None
):
    """
    Advanced SQL injection protection:
    1. Build SQL using approved query fragments.
    2. Parse and inspect its AST.
    3. Validate its fingerprint.
    4. Apply SQLite runtime authorization.
    5. Execute using bound parameters.
    """

    start_time = time.perf_counter()

    filter_names = set()
    parameters = []

    if name is not None:
        filter_names.add("name")
        parameters.append(f"%{name}%")

    if department is not None:
        filter_names.add("department")
        parameters.append(department)

    if semester is not None:
        try:
            semester = int(semester)
        except (TypeError, ValueError):
            raise ValueError("Semester must be a valid integer.")

        if not 1 <= semester <= 8:
            raise ValueError("Semester must be between 1 and 8.")

        filter_names.add("semester")
        parameters.append(semester)

    query = build_approved_query(filter_names)

    try:
        # Step 1: Parse and analyze SQL structure.
        analysis = analyze_query(query)

        # Step 2: Verify the query fingerprint.
        if analysis["fingerprint"] not in APPROVED_FINGERPRINTS:
            raise AdvancedSecurityError(
                "Query does not match an approved query structure."
            )

        # Step 3: Open connection and enable runtime authorization.
        connection = get_connection()

        try:
            enable_read_only_authorization(connection)

            # Step 4: Execute using bound parameters.
            cursor = connection.execute(query, parameters)
            results = [dict(row) for row in cursor.fetchall()]

        finally:
            connection.close()

        execution_time = (
            time.perf_counter() - start_time
        ) * 1000

        log_security_event(
            configuration="Advanced",
            event_type="NORMAL_REQUEST",
            detection_result="Approved",
            prevention_action="AST validation and parameterized execution",
            reason="Query structure and fingerprint approved",
            execution_time_ms=execution_time
        )

        return results

    except Exception as error:
        execution_time = (
            time.perf_counter() - start_time
        ) * 1000

        log_security_event(
            configuration="Advanced",
            event_type="SECURITY_EVENT",
            detection_result="Rejected",
            prevention_action="Request rejected",
            reason=str(error),
            execution_time_ms=execution_time
        )

        if isinstance(error, (ValueError, AdvancedSecurityError)):
            raise

        if isinstance(error, QueryValidationError):
            raise AdvancedSecurityError(str(error)) from error

        raise AdvancedSecurityError(
            "Advanced query execution was rejected."
        ) from error
