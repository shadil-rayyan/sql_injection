"""Generate exactly 10,000 reproducible synthetic student records."""
import random
from database import get_connection, create_tables

NUMBER_OF_STUDENTS = 10_000
START_ID = 100_001
RANDOM_SEED = 42

FIRST_NAMES = [
    "Akhil", "Rahul", "Anjali", "Arun", "Meera", "Nikhil", "Priya",
    "Dev", "Aditya", "Sneha", "Vishnu", "Amal", "Neha", "Kiran",
    "Asha", "Rohit", "Anu", "Vivek", "Manu", "Diya"
]
LAST_NAMES = [
    "Kumar", "Nair", "Menon", "Sharma", "Das",
    "Thomas", "Reddy", "Patel", "Varma", "Singh"
]
DEPARTMENTS = ["CSE", "ECE", "EEE", "IT", "ME", "CE"]


def populate_database():
    create_tables()
    rng = random.Random(RANDOM_SEED)
    records = []

    for offset in range(NUMBER_OF_STUDENTS):
        student_id = START_ID + offset
        name = f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"
        department = rng.choice(DEPARTMENTS)
        semester = rng.randint(1, 8)
        cgpa = round(rng.uniform(5.0, 10.0), 2)
        admission_year = rng.randint(2020, 2025)
        email = f"student{student_id}@example.test"
        records.append((
            student_id, name, department, semester,
            cgpa, email, admission_year
        ))

    conn = get_connection()
    try:
        # Make repeated runs deterministic: replace only generated ID range.
        conn.execute(
            "DELETE FROM students WHERE student_id BETWEEN ? AND ?",
            (START_ID, START_ID + NUMBER_OF_STUDENTS - 1)
        )
        conn.executemany("""
            INSERT INTO students
            (student_id, name, department, semester, cgpa, email, admission_year)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, records)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_students_name ON students(name)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_students_department
            ON students(department)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_students_semester
            ON students(semester)
        """)
        conn.commit()
    finally:
        conn.close()

    print(f"Successfully generated {NUMBER_OF_STUDENTS:,} students.")


if __name__ == "__main__":
    populate_database()
