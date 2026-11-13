from database.database import create_tables, get_connection


def test_students_table_exists():
    create_tables()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='students'"
        ).fetchone()
        assert row is not None
    finally:
        conn.close()
