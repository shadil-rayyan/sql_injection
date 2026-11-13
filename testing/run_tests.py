
import csv
import time
from pathlib import Path

from database import get_connection

from testing.attack_dataset import (
    TEST_CASES,
    validate_dataset
)

from testing.database_reset import (
    get_student_hash,
    verify_student_integrity
)

from traditional.detector import detect_request
from traditional.executor import (
    search_students,
    SuspiciousInputError
)

from advanced.secure_executor import (
    search_students_advanced,
    AdvancedSecurityError
)


RESULTS_DIR = Path("results/csv")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = RESULTS_DIR / "test_case_results.csv"


def get_request_arguments(case):
    """Convert a dataset case into executor arguments."""

    field = case["input_field"]
    value = case["input_value"]

    if field == "name":
        return {"name": value}

    if field == "department":
        return {"department": value}

    if field == "semester":
        return {"semester": value}

    raise ValueError(f"Unknown input field: {field}")


def get_reference_results(arguments):
    """
    Execute the intended search using a safe parameterized query.

    Invalid semester values return an empty reference result
    instead of interrupting the evaluation.
    """

    query = """
        SELECT student_id, name, department, semester,
               cgpa, email, admission_year
        FROM students
    """

    conditions = []
    parameters = []

    if arguments.get("name") is not None:
        conditions.append("name LIKE ?")
        parameters.append(f"%{arguments['name']}%")

    if arguments.get("department") is not None:
        conditions.append("department = ?")
        parameters.append(arguments["department"])

    if arguments.get("semester") is not None:

        try:
            semester = int(arguments["semester"])
        except (ValueError, TypeError):
            return []

        conditions.append("semester = ?")
        parameters.append(semester)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY student_id LIMIT 100"

    connection = get_connection()

    try:
        cursor = connection.execute(query, parameters)
        return [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()


def run_configuration(case, configuration, original_hash):
    """Run one test case against one security configuration."""

    arguments = get_request_arguments(case)

    expected_results = get_reference_results(arguments)

    start_time = time.perf_counter()

    input_detected = None
    blocked = False
    safe_execution = False
    execution_error = ""
    actual_results = []

    try:

        if configuration == "Traditional":

            input_detected, field, reason = detect_request(arguments)

            actual_results = search_students(**arguments)

        elif configuration == "Advanced":

            # Advanced configuration validates SQL query structure.
            # It does not classify input values as malicious.
            actual_results = search_students_advanced(**arguments)

        else:
            raise ValueError("Unknown configuration")

        # Check whether execution produced the same results
        # as the safe reference query.
        result_ids = [
            row["student_id"] for row in actual_results
        ]

        expected_ids = [
            row["student_id"] for row in expected_results
        ]

        safe_execution = result_ids == expected_ids

    except SuspiciousInputError as error:

        blocked = True
        execution_error = str(error)

        if configuration == "Traditional":
            input_detected = True

    except AdvancedSecurityError as error:

        blocked = True
        execution_error = str(error)

    except Exception as error:

        blocked = True
        execution_error = str(error)

    elapsed_ms = (
        time.perf_counter() - start_time
    ) * 1000

    integrity_ok = verify_student_integrity(original_hash)

    legitimate_success = (
        case["label"] == "legitimate"
        and not blocked
        and safe_execution
        and integrity_ok
    )

    # This field only confirms safe literal-value handling.
    # It does not claim that an actual SQL injection attack
    # was executed and prevented.
    safe_parameter_handling = (
        not blocked
        and safe_execution
        and integrity_ok
    )

    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "label": case["label"],
        "input_field": case["input_field"],
        "input_value": str(case["input_value"]),
        "configuration": configuration,
        "input_detected": (
            input_detected
            if input_detected is not None
            else "N/A"
        ),
        "blocked": blocked,
        "safe_execution": safe_execution,
        "safe_parameter_handling": safe_parameter_handling,
        "legitimate_success": legitimate_success,
        "database_integrity": integrity_ok,
        "execution_time_ms": round(elapsed_ms, 4),
        "error": execution_error
    }


def main():

    validate_dataset()

    print("Starting SQL injection evaluation...")
    print("Total test cases:", len(TEST_CASES))

    original_hash = get_student_hash()

    all_results = []

    configurations = [
        "Traditional",
        "Advanced"
    ]

    for configuration in configurations:

        print(f"\nTesting {configuration} configuration...")

        for index, case in enumerate(TEST_CASES, start=1):

            result = run_configuration(
                case,
                configuration,
                original_hash
            )

            all_results.append(result)

            if index % 25 == 0:
                print(
                    f"{configuration}: "
                    f"{index}/{len(TEST_CASES)} cases completed"
                )

    if not all_results:
        raise RuntimeError("No test results were generated.")

    # Save all 400 configuration-case results.
    fieldnames = list(all_results[0].keys())

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(all_results)

    print("\nEvaluation completed.")
    print("Total executions:", len(all_results))
    print("Results saved to:", OUTPUT_FILE)

    final_integrity = verify_student_integrity(original_hash)

    print("Final student database integrity:", final_integrity)

    if not final_integrity:
        raise RuntimeError(
            "Student database changed during evaluation."
        )


if __name__ == "__main__":
    main()
