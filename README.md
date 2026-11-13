# SQL Injection Detection and Prevention Project

## Current implementation status
Phase 1 scaffold: SQLite database and reproducible synthetic student dataset.

## Setup
1. Create and activate a virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Create tables: `python -m database.database`
4. Populate 10,000 students: `python -m database.populate_database`
5. Verify the dataset: `python -m database.verify_database`

The generated student data is fictional. The database file is created at
`database/students.db`.

## Planned modules
- `traditional/`: regex-based baseline and parameterized executor.
- `advanced/`: SQL parsing, AST analysis, query policies, runtime monitoring,
  secure execution, and SQLite authorizer.
- `monitoring/`: security event logging.
- `testing/`: manually reviewed labelled attack corpus and experiment runner.
- `results/`: generated CSV files and graphs.
- `templates/`, `static/`: Flask interface.

Do not expose intentionally vulnerable test code to a public network. Run all
attack experiments only against isolated local test databases.
