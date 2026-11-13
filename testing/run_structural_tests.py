
import csv
from pathlib import Path

from database import get_connection

from testing.structural_attack_dataset import (
    STRUCTURAL_ATTACKS,
    validate_structural_dataset
)

from advanced.ast_analyzer import analyze_query, QueryValidationError

from advanced.query_policy import APPROVED_FINGERPRINTS

from advanced.db_authorizer import (
    enable_read_only_authorization
)


OUTPUT_DIR = Path("results/csv")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DETAIL_FILE = OUTPUT_DIR / "structural_attack_results.csv"
SUMMARY_FILE = OUTPUT_DIR / "structural_comparison.csv"


def test_ast_and_fingerprint(sql):
    """
    Test AST validation and fingerprint approval separately.

    Fingerprint validation is performed only when AST validation
    succeeds and produces a normalized query fingerprint.
    """

    try:
        analysis = analyze_query(sql)

        ast_accepted = True

        fingerprint_approved = (
            analysis["fingerprint"] in APPROVED_FINGERPRINTS
        )

        return ast_accepted, fingerprint_approved, ""

    except QueryValidationError as error:
        return False, None, str(error)

    except Exception as error:
        return False, None, str(error)


def test_sqlite_authorizer(sql):
    """
    Test SQLite authorization on a separate in-memory database.

    This prevents structural test statements from modifying the
    project's actual students database.
    """

    connection = get_connection()

    try:
        # Use a temporary in-memory database instead of the real DB.
        connection.close()

        import sqlite3

        connection = sqlite3.connect(":memory:")

        # Create only the table required by the test statements.
        connection.execute("""
            CREATE TABLE students (
                student_id INTEGER PRIMARY KEY,
                name TEXT,
                department TEXT,
                semester INTEGER,
                cgpa REAL,
                email TEXT,
                admission_year INTEGER
            )
        """)

        enable_read_only_authorization(connection)

        try:
            connection.execute(sql)
            connection.rollback()

            return True, "Statement permitted by authorizer"

        except sqlite3.Error as error:
            connection.rollback()

            message = str(error)
            lower_message = message.lower()

            if (
                "not authorized" in lower_message
                or "prohibited" in lower_message
            ):
                return False, message

            return None, message

    finally:
        connection.close()


def calculate_summary(results):
    """Calculate structural security metrics."""

    total = len(results)

    ast_rejected = sum(
        not row["ast_accepted"]
        for row in results
    )

    ast_accepted = sum(
        row["ast_accepted"]
        for row in results
    )

    fingerprint_tested = [
        row for row in results
        if row["fingerprint_approved"] is not None
    ]

    fingerprint_rejected = sum(
        not row["fingerprint_approved"]
        for row in fingerprint_tested
    )

    policy_rejected = sum(
        not row["query_policy_accepted"]
        for row in results
    )

    authorizer_denied = sum(
        row["authorizer_accepted"] is False
        for row in results
    )

    authorizer_allowed = sum(
        row["authorizer_accepted"] is True
        for row in results
    )

    authorizer_inconclusive = sum(
        row["authorizer_accepted"] is None
        for row in results
    )

    return [
        {
            "Metric": "Total structural test cases",
            "Count": total,
            "Percentage": 100.0
        },
        {
            "Metric": "AST rejected",
            "Count": ast_rejected,
            "Percentage": round(ast_rejected / total * 100, 2)
        },
        {
            "Metric": "AST accepted",
            "Count": ast_accepted,
            "Percentage": round(ast_accepted / total * 100, 2)
        },
        {
            "Metric": "Fingerprint tested",
            "Count": len(fingerprint_tested),
            "Percentage": round(
                len(fingerprint_tested) / total * 100, 2
            )
        },
        {
            "Metric": "Fingerprint rejected among tested",
            "Count": fingerprint_rejected,
            "Percentage": round(
                fingerprint_rejected / len(fingerprint_tested) * 100,
                2
            ) if fingerprint_tested else 0
        },
        {
            "Metric": "Combined query policy rejected",
            "Count": policy_rejected,
            "Percentage": round(policy_rejected / total * 100, 2)
        },
        {
            "Metric": "SQLite authorizer denied",
            "Count": authorizer_denied,
            "Percentage": round(
                authorizer_denied / total * 100, 2
            )
        },
        {
            "Metric": "SQLite authorizer allowed",
            "Count": authorizer_allowed,
            "Percentage": round(
                authorizer_allowed / total * 100, 2
            )
        },
        {
            "Metric": "SQLite authorizer inconclusive",
            "Count": authorizer_inconclusive,
            "Percentage": round(
                authorizer_inconclusive / total * 100, 2
            )
        }
    ]


def main():

    validate_structural_dataset()

    results = []

    print("Starting structural security evaluation...")
    print("Total structural cases:", len(STRUCTURAL_ATTACKS))

    for case in STRUCTURAL_ATTACKS:

        sql = case["sql"]

        ast_accepted, fingerprint_approved, ast_error = (
            test_ast_and_fingerprint(sql)
        )

        authorizer_accepted, authorizer_message = (
            test_sqlite_authorizer(sql)
        )

        # The combined query policy accepts a query only when
        # both AST validation and fingerprint approval succeed.
        query_policy_accepted = (
            ast_accepted
            and fingerprint_approved is True
        )

        result = {
            "case_id": case["case_id"],
            "category": case["category"],
            "sql": sql,
            "ast_accepted": ast_accepted,
            "fingerprint_approved": (
                fingerprint_approved
                if fingerprint_approved is not None
                else "N/A"
            ),
            "query_policy_accepted": query_policy_accepted,
            "authorizer_accepted": (
                authorizer_accepted
                if authorizer_accepted is not None
                else "N/A"
            ),
            "ast_error": ast_error,
            "authorizer_message": authorizer_message
        }

        results.append(result)

        print(
            case["case_id"],
            "| AST:", ast_accepted,
            "| Fingerprint:", fingerprint_approved,
            "| Policy:", query_policy_accepted,
            "| Authorizer:", authorizer_accepted
        )

    # Save detailed results.
    with open(
        DETAIL_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=list(results[0].keys())
        )

        writer.writeheader()
        writer.writerows(results)

    # Calculate summary metrics.
    summary = calculate_summary([
        {
            **row,
            "fingerprint_approved": (
                row["fingerprint_approved"] is True
                if row["fingerprint_approved"] != "N/A"
                else None
            ),
            "authorizer_accepted": (
                row["authorizer_accepted"] is True
                if row["authorizer_accepted"] is True
                else (
                    False
                    if row["authorizer_accepted"] is False
                    else None
                )
            )
        }
        for row in results
    ])

    with open(
        SUMMARY_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=["Metric", "Count", "Percentage"]
        )

        writer.writeheader()
        writer.writerows(summary)

    print("\nSTRUCTURAL EVALUATION SUMMARY")
    print("=" * 60)

    for row in summary:
        print(
            f'{row["Metric"]}: '
            f'{row["Count"]} ({row["Percentage"]}%)'
        )

    print("\nStructural evaluation completed.")
    print("Detailed results:", DETAIL_FILE)
    print("Summary results:", SUMMARY_FILE)


if __name__ == "__main__":
    main()
