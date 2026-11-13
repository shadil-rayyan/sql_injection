
from itertools import product

from advanced.query_fingerprint import generate_fingerprint
import sqlglot


BASE_QUERY = """
    SELECT student_id, name, department, semester,
           cgpa, email, admission_year
    FROM students
"""

FILTERS = {
    "name": "name LIKE ?",
    "department": "department = ?",
    "semester": "semester = ?"
}


def build_approved_query(filter_names):
    """Build a query using only predefined SQL fragments."""

    conditions = [
        FILTERS[name]
        for name in ("name", "department", "semester")
        if name in filter_names
    ]

    query = BASE_QUERY

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY student_id LIMIT 100"

    return query


def create_approved_fingerprints():
    """Generate fingerprints for all eight filter combinations."""

    approved = set()
    filter_names = list(FILTERS.keys())

    for combination in product([False, True], repeat=3):
        selected = {
            name
            for name, enabled in zip(filter_names, combination)
            if enabled
        }

        query = build_approved_query(selected)
        tree = sqlglot.parse_one(query, read="sqlite")

        approved.add(generate_fingerprint(query, tree))

    return approved


APPROVED_FINGERPRINTS = create_approved_fingerprints()
