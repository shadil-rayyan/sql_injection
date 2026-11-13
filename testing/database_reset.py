
import hashlib
import json

from database import get_connection


def get_student_snapshot():
    """
    Return a consistent representation of all student records.
    """

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT student_id, name, department, semester,
                   cgpa, email, admission_year
            FROM students
            ORDER BY student_id
            """
        ).fetchall()

        records = [tuple(row) for row in rows]

        return records

    finally:
        connection.close()


def get_student_hash():
    """
    Generate a SHA-256 hash of the complete student dataset.
    """

    records = get_student_snapshot()

    serialized = json.dumps(
        records,
        ensure_ascii=False,
        default=str
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def verify_student_integrity(original_hash):
    """
    Check whether the student database remains unchanged.
    """

    current_hash = get_student_hash()

    return current_hash == original_hash


if __name__ == "__main__":
    records = get_student_snapshot()

    print("Total student records:", len(records))
    print("Student data hash:", get_student_hash())
