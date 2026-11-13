from database import get_connection
from flask import Flask, render_template
from flask import request

import csv
from pathlib import Path
from flask import send_from_directory

import time

from flask import request, render_template

from traditional.detector import detect_request
from traditional.executor import (
    search_students,
    SuspiciousInputError
)

from advanced.secure_executor import (
    search_students_advanced,
    AdvancedSecurityError
)

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():

    connection = get_connection()

    try:
        total_students = connection.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        total_departments = connection.execute(
            "SELECT COUNT(DISTINCT department) FROM students"
        ).fetchone()[0]

        total_events = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

    finally:
        connection.close()

    return render_template(
        "dashboard.html",
        total_students=total_students,
        total_departments=total_departments,
        total_events=total_events
    )



@app.route("/students")
def students():

    connection = get_connection()

    try:
        # Read search filters
        name = request.args.get("name", "").strip()
        department = request.args.get("department", "").strip()
        semester = request.args.get("semester", "").strip()

        # Pagination
        page = request.args.get("page", 1, type=int)
        page = max(page, 1)

        per_page = 20
        offset = (page - 1) * per_page

        # Build safe parameterized query
        conditions = []
        parameters = []

        if name:
            conditions.append("name LIKE ?")
            parameters.append(f"%{name}%")

        if department:
            conditions.append("department = ?")
            parameters.append(department)

        if semester:
            try:
                semester_value = int(semester)
                conditions.append("semester = ?")
                parameters.append(semester_value)
            except ValueError:
                semester = ""
        
        where_clause = ""

        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)

        # Total matching records
        count_query = (
            "SELECT COUNT(*) FROM students" + where_clause
        )

        total_records = connection.execute(
            count_query, parameters
        ).fetchone()[0]

        total_pages = max(
            1, (total_records + per_page - 1) // per_page
        )

        page = min(page, total_pages)
        offset = (page - 1) * per_page

        # Fetch student records
        student_query = """
            SELECT student_id, name, department, semester,
                   cgpa, email, admission_year
            FROM students
        """ + where_clause + """
            ORDER BY student_id
            LIMIT ? OFFSET ?
        """

        students_data = connection.execute(
            student_query,
            parameters + [per_page, offset]
        ).fetchall()

        # Department filter options
        departments = connection.execute(
            "SELECT DISTINCT department FROM students ORDER BY department"
        ).fetchall()

    finally:
        connection.close()

    return render_template(
        "students.html",
        students=students_data,
        departments=departments,
        selected_name=name,
        selected_department=department,
        selected_semester=semester,
        page=page,
        total_pages=total_pages,
        total_records=total_records
    )

@app.route("/testing", methods=["GET", "POST"])
def testing():

    results = []
    submitted = False

    if request.method == "POST":

        submitted = True

        input_field = request.form.get("input_field", "name")
        input_value = request.form.get("input_value", "").strip()
        configuration = request.form.get(
            "configuration", "Traditional"
        )

        allowed_fields = ["name", "department", "semester"]
        allowed_configurations = [
            "Traditional", "Advanced", "Both"
        ]

        if input_field not in allowed_fields:
            error_message = "Invalid input field."

        elif configuration not in allowed_configurations:
            error_message = "Invalid configuration."

        elif not input_value:
            error_message = "Please enter a test value."

        else:
            error_message = ""

        if not error_message:

            arguments = {
                input_field: input_value
            }

            selected_configurations = (
                ["Traditional", "Advanced"]
                if configuration == "Both"
                else [configuration]
            )

            for selected in selected_configurations:

                result = execute_security_test(
                    selected,
                    arguments
                )

                results.append(result)

    return render_template(
        "testing.html",
        results=results,
        submitted=submitted,
        error_message=error_message if submitted else ""
    )




# Project directories
PROJECT_DIR = Path(__file__).resolve().parent
CSV_DIR = PROJECT_DIR / "results" / "csv"
GRAPH_DIR = PROJECT_DIR / "results" / "graphs"


def read_csv_file(filename):
    """Read a CSV file and return its rows as dictionaries."""

    file_path = CSV_DIR / filename

    if not file_path.exists():
        return []

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


@app.route("/results")
def results():

    # Read experimental CSV files
    comparison = read_csv_file("detection_comparison.csv")
    structural = read_csv_file("structural_comparison.csv")
    categories = read_csv_file("category_comparison.csv")

    # Names of the seven generated graphs
    graph_files = [
        {
            "filename": "input_detection_metrics.png",
            "title": "Input Detection Metrics",
            "description": "Detection rate, false-positive rate and precision."
        },
        {
            "filename": "category_detection.png",
            "title": "Detection by Attack Category",
            "description": "Traditional detector performance across attack categories."
        },
        {
            "filename": "ast_validation.png",
            "title": "AST Validation",
            "description": "Accepted and rejected SQL statements."
        },
        {
            "filename": "fingerprint_validation.png",
            "title": "Query Fingerprint Validation",
            "description": "Approved and rejected query fingerprints."
        },
        {
            "filename": "combined_query_policy.png",
            "title": "Combined Query Policy",
            "description": "Results of combined AST and fingerprint validation."
        },
        {
            "filename": "sqlite_authorizer.png",
            "title": "SQLite Authorizer",
            "description": "Database authorization outcomes."
        },
        {
            "filename": "execution_time_comparison.png",
            "title": "Execution Time Comparison",
            "description": "Average execution time of both configurations."
        }
    ]

    # Only show graphs that actually exist.
    available_graphs = [
        graph for graph in graph_files
        if (GRAPH_DIR / graph["filename"]).is_file()
    ]

    return render_template(
        "results.html",
        comparison=comparison,
        structural=structural,
        categories=categories,
        graphs=available_graphs
    )


@app.route("/results/graphs/<path:filename>")
def result_graph(filename):
    """Serve generated experimental graphs."""

    allowed_graphs = {
        "input_detection_metrics.png",
        "category_detection.png",
        "ast_validation.png",
        "fingerprint_validation.png",
        "combined_query_policy.png",
        "sqlite_authorizer.png",
        "execution_time_comparison.png"
    }

    if filename not in allowed_graphs:
        return "Graph not found", 404

    return send_from_directory(GRAPH_DIR, filename)



def execute_security_test(configuration, arguments):
    """Execute a request using the selected security configuration."""

    start_time = time.perf_counter()

    detected = "N/A"
    blocked = False
    error_message = ""
    student_records = []

    try:
        if configuration == "Traditional":

            detected, field, reason = detect_request(arguments)

            student_records = search_students(**arguments)

        elif configuration == "Advanced":

            # Advanced validates SQL structure and approved
            # query fingerprints. It does not classify input values.
            student_records = search_students_advanced(**arguments)

        else:
            raise ValueError("Invalid security configuration.")

    except SuspiciousInputError as error:
        blocked = True
        detected = True
        error_message = str(error)

    except AdvancedSecurityError as error:
        blocked = True
        error_message = str(error)

    except Exception as error:
        blocked = True
        error_message = str(error)

    execution_time = (
        time.perf_counter() - start_time
    ) * 1000

    return {
        "configuration": configuration,
        "detected": detected,
        "blocked": blocked,
        "records": [dict(row) for row in student_records],
        "record_count": len(student_records),
        "execution_time": round(execution_time, 4),
        "error": error_message
    }


if __name__ == "__main__":
    app.run(debug=True)
