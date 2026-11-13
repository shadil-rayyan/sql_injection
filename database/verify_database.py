"""Verify record count, required fields, and basic value constraints."""
from database import get_connection


def verify_database():
    conn = get_connection()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        invalid = conn.execute("""
            SELECT COUNT(*) FROM students
            WHERE name IS NULL OR department IS NULL OR email IS NULL
               OR semester NOT BETWEEN 1 AND 8
               OR cgpa NOT BETWEEN 0 AND 10
        """).fetchone()[0]

        duplicate_emails = conn.execute("""
            SELECT COUNT(*) FROM (
                SELECT email FROM students
                GROUP BY email HAVING COUNT(*) > 1
            )
        """).fetchone()[0]

        print("\nDATABASE VERIFICATION")
        print("---------------------")
        print(f"Total students: {total:,}")
        print(f"Invalid records: {invalid}")
        print(f"Duplicate email groups: {duplicate_emails}")
        print("\nDepartment distribution:")
        for row in conn.execute("""
            SELECT department, COUNT(*) AS total
            FROM students GROUP BY department ORDER BY department
        """):
            print(f"{row['department']}: {row['total']}")

        success = total == 10_000 and invalid == 0 and duplicate_emails == 0
        print("\nDatabase verification:", "PASSED" if success else "FAILED")
        return success
    finally:
        conn.close()


if __name__ == "__main__":
    verify_database()
