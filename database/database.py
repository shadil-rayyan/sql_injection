"""SQLite schema and connection helpers."""
import sqlite3
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DB_DIR = Path(__file__).resolve().parent
DB_NAME = DB_DIR / "students.db"


def get_connection():
    """Open a connection to the project database."""
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    """Create application and research-support tables."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS students (
                student_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 8),
                cgpa REAL NOT NULL CHECK (cgpa BETWEEN 0 AND 10),
                email TEXT NOT NULL UNIQUE,
                admission_year INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                configuration TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detection_result TEXT,
                prevention_action TEXT,
                reason TEXT,
                execution_time_ms REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS query_templates (
                template_id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_name TEXT NOT NULL UNIQUE,
                sql_template TEXT NOT NULL,
                fingerprint TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    create_tables()
    print(f"Database tables created at: {DB_NAME}")
