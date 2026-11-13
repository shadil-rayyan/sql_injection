
"""
Manually reviewed SQL injection and legitimate-input test cases.

Dataset:
100 malicious cases:
  Boolean-based:       20
  UNION-based:         20
  Comment-based:       15
  Error-based:         15
  Stacked queries:     10
  UPDATE/DELETE:       10
  Schema manipulation: 10

100 legitimate cases:
  Names:               50
  Departments:         25
  Semesters:           25
"""


def make_cases(category, values, label):
    return [
        {
            "case_id": f"{category[:3].upper()}-{i:02d}",
            "category": category,
            "input_field": "name",
            "input_value": value,
            "label": label
        }
        for i, value in enumerate(values, start=1)
    ]


ATTACKS = {
    "Boolean-based": [
        "' OR 1=1 --",
        "' OR '1'='1",
        '" OR "1"="1',
        "admin' OR '1'='1",
        "' OR 1=1#",
        "') OR ('1'='1",
        "' OR 2>1 --",
        "1 OR 1=1",
        "' AND 1=1 --",
        "' OR 'a'='a",
        "') OR 1=1 --",
        "admin') OR ('x'='x",
        "' OR 5=5 --",
        "' OR 7>3 --",
        "' AND 'x'='x",
        "1' OR '1'='1' --",
        "') OR ('a'='a",
        "' OR 9=9#",
        "' OR 4<5 --",
        "' OR TRUE --"
    ],

    "UNION-based": [
        "' UNION SELECT NULL --",
        "' UNION SELECT 1,2,3 --",
        "' UNION ALL SELECT NULL --",
        "' UNION SELECT name FROM students --",
        "' UNION SELECT student_id FROM students --",
        "' UNION SELECT email FROM students --",
        "' UNION SELECT 1,2,3,4 --",
        "' UNION ALL SELECT 1,2 --",
        "' UNION SELECT department FROM students --",
        "' UNION SELECT cgpa FROM students --",
        "' UNION SELECT semester FROM students --",
        "' UNION SELECT admission_year FROM students --",
        "' UNION SELECT NULL,NULL --",
        "' UNION ALL SELECT name,email FROM students --",
        "' UNION SELECT student_id,name FROM students --",
        "' UNION SELECT 1 --",
        "' UNION SELECT 'test' --",
        "' UNION ALL SELECT department FROM students --",
        "' UNION SELECT email, name FROM students --",
        "' UNION SELECT NULL,NULL,NULL --"
    ],

    "Comment-based": [
        "admin'--",
        "admin' #",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "test'/*",
        "name'-- ",
        "';--",
        "'#",
        "admin')--",
        "' OR 'x'='x'--",
        "student'/*comment*/",
        "' AND 1=1--",
        "test'/**/--",
        "' OR 2=2#",
        "user'--comment"
    ],

    "Error-based": [
        "' AND 1=CAST('x' AS INTEGER) --",
        "' AND abs(-9223372036854775808) --",
        "' AND load_extension('x') --",
        "' AND randomblob(100000000) --",
        "' AND json_extract('invalid','$.x') --",
        "' AND zeroblob(-1) --",
        "' AND substr('x',-1,-1) --",
        "' AND unicode('x')=1 --",
        "' AND printf('%999999999s','x') --",
        "' AND json('invalid') --",
        "' AND date('invalid')='x' --",
        "' AND char(-1)='x' --",
        "' AND hex(randomblob(10))='x' --",
        "' AND replace('x','x','y')='z' --",
        "' AND lower('X')='x' --"
    ],

    "Stacked queries": [
        "'; SELECT * FROM students;--",
        "'; SELECT 1;--",
        "'; DELETE FROM students;--",
        "'; UPDATE students SET cgpa=0;--",
        "'; INSERT INTO students VALUES(1);--",
        "'; DROP TABLE students;--",
        "'; ALTER TABLE students ADD COLUMN test TEXT;--",
        "'; CREATE TABLE injected(id INTEGER);--",
        "'; DELETE FROM security_events;--",
        "'; UPDATE students SET name='test';--"
    ],

    "UPDATE/DELETE": [
        "'; UPDATE students SET cgpa=0 WHERE student_id=100001;--",
        "'; DELETE FROM students WHERE student_id=100001;--",
        "' OR 1=1; UPDATE students SET cgpa=0;--",
        "'; DELETE FROM students;--",
        "'; UPDATE students SET semester=1;--",
        "'; DELETE FROM students WHERE department='CSE';--",
        "'; UPDATE students SET email='x@example.test';--",
        "'; DELETE FROM students WHERE cgpa<5;--",
        "'; UPDATE students SET name='changed';--",
        "'; DELETE FROM students WHERE semester=8;--"
    ],

    "Schema manipulation": [
        "'; DROP TABLE students;--",
        "'; ALTER TABLE students ADD COLUMN hacked TEXT;--",
        "'; CREATE TABLE hacked(id INTEGER);--",
        "'; DROP TABLE security_events;--",
        "'; CREATE TABLE users(id INTEGER);--",
        "'; ALTER TABLE students RENAME TO old_students;--",
        "'; DROP INDEX idx_students_name;--",
        "'; CREATE INDEX hacked_idx ON students(name);--",
        "'; ATTACH DATABASE 'other.db' AS other;--",
        "'; DETACH DATABASE main;--"
    ]
}


LEGITIMATE_NAMES = [
    "Akhil", "Arun", "Ananya", "Rahul", "Sneha",
    "John", "Mary", "David", "Priya", "Meera",
    "O'Neil", "D'Souza", "Anne-Marie", "Jean Paul",
    "Mary Jane", "Ravi Kumar", "Akhil V A", "Jose",
    "Ibrahim", "Thomas", "Nikhil", "Sanjay",
    "Asha", "Neha", "Vishnu", "Adithya",
    "Riya", "Alan", "Kevin", "Mathew",
    "Sara", "Mohan", "Lakshmi", "Divya",
    "Kiran", "Anil", "Sreya", "Fathima",
    "George", "Binu", "Rohit", "Aparna",
    "Suresh", "Manu", "Nandana", "Hari",
    "Jithin", "Anoop", "Nisha", "Reshma"
]

DEPARTMENTS = [
    "CSE", "ECE", "EEE", "IT", "ME", "CE"
]

LEGITIMATE = []

for i, value in enumerate(LEGITIMATE_NAMES, start=1):
    LEGITIMATE.append({
        "case_id": f"LEG-NAME-{i:02d}",
        "category": "Legitimate",
        "input_field": "name",
        "input_value": value,
        "label": "legitimate"
    })

for i in range(25):
    value = DEPARTMENTS[i % len(DEPARTMENTS)]
    LEGITIMATE.append({
        "case_id": f"LEG-DEPT-{i + 1:02d}",
        "category": "Legitimate",
        "input_field": "department",
        "input_value": value,
        "label": "legitimate"
    })

for i in range(25):
    value = (i % 8) + 1
    LEGITIMATE.append({
        "case_id": f"LEG-SEM-{i + 1:02d}",
        "category": "Legitimate",
        "input_field": "semester",
        "input_value": value,
        "label": "legitimate"
    })


ATTACK_CASES = []

for category, values in ATTACKS.items():
    ATTACK_CASES.extend(
        make_cases(category, values, "malicious")
    )


TEST_CASES = ATTACK_CASES + LEGITIMATE


def validate_dataset():
    assert len(ATTACK_CASES) == 100
    assert len(LEGITIMATE) == 100
    assert len(TEST_CASES) == 200

    assert len({
        case["case_id"] for case in TEST_CASES
    }) == 200

    return True


if __name__ == "__main__":
    validate_dataset()

    print("Dataset validation successful")
    print("Malicious cases:", len(ATTACK_CASES))
    print("Legitimate cases:", len(LEGITIMATE))
    print("Total cases:", len(TEST_CASES))

    for category, values in ATTACKS.items():
        print(f"{category}: {len(values)}")
