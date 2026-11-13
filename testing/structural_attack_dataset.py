
"""
SQL structure attack test cases.

These are SQL statements used to test the advanced
query parser, fingerprint policy and SQLite authorizer.

They are never executed without the security controls.
"""

STRUCTURAL_ATTACKS = [
    {
        "case_id": "STR-01",
        "category": "Unauthorized table access",
        "sql": "SELECT * FROM security_events"
    },
    {
        "case_id": "STR-02",
        "category": "UPDATE operation",
        "sql": "UPDATE students SET cgpa = 0"
    },
    {
        "case_id": "STR-03",
        "category": "DELETE operation",
        "sql": "DELETE FROM students"
    },
    {
        "case_id": "STR-04",
        "category": "DROP operation",
        "sql": "DROP TABLE students"
    },
    {
        "case_id": "STR-05",
        "category": "ALTER operation",
        "sql": "ALTER TABLE students ADD COLUMN test TEXT"
    },
    {
        "case_id": "STR-06",
        "category": "UNION query",
        "sql": (
            "SELECT name FROM students "
            "UNION SELECT name FROM security_events"
        )
    },
    {
        "case_id": "STR-07",
        "category": "Multiple SQL statements",
        "sql": (
            "SELECT name FROM students; "
            "DELETE FROM students"
        )
    },
    {
        "case_id": "STR-08",
        "category": "Unapproved SQL function",
        "sql": "SELECT random() FROM students"
    },
    {
        "case_id": "STR-09",
        "category": "Dangerous SQL function",
        "sql": "SELECT load_extension('test') FROM students"
    },
    {
        "case_id": "STR-10",
        "category": "Modified query structure",
        "sql": "SELECT cgpa FROM students WHERE cgpa > 8"
    },
    {
        "case_id": "STR-11",
        "category": "Unapproved query structure",
        "sql": "SELECT name FROM students"
    },
    {
        "case_id": "STR-12",
        "category": "Unauthorized database attachment",
        "sql": "ATTACH DATABASE 'other.db' AS other"
    }
]


def validate_structural_dataset():
    assert len(STRUCTURAL_ATTACKS) == 12

    ids = [
        case["case_id"]
        for case in STRUCTURAL_ATTACKS
    ]

    assert len(ids) == len(set(ids))

    return True


if __name__ == "__main__":
    validate_structural_dataset()

    print("Structural dataset validation successful")
    print("Total structural test cases:", len(STRUCTURAL_ATTACKS))

    for case in STRUCTURAL_ATTACKS:
        print(case["case_id"], "-", case["category"])
