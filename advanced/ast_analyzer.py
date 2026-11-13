
import sqlglot
from sqlglot import exp

from advanced.query_fingerprint import generate_fingerprint


ALLOWED_TABLES = {"students"}

ALLOWED_COLUMNS = {
    "student_id",
    "name",
    "department",
    "semester",
    "cgpa",
    "email",
    "admission_year"
}

ALLOWED_FUNCTIONS = {
    "like"
}


class QueryValidationError(Exception):
    pass


def analyze_query(sql):
    """
    Parse and validate the SQL query using SQLGlot.

    Only approved SELECT query structures are accepted.
    """

    try:
        parsed_queries = sqlglot.parse(sql, read="sqlite")

    except sqlglot.errors.ParseError as error:
        raise QueryValidationError("Invalid SQL syntax.") from error

    if len(parsed_queries) != 1 or parsed_queries[0] is None:
        raise QueryValidationError("Only one SQL statement is permitted.")

    tree = parsed_queries[0]

    # Only SELECT queries are allowed.
    if not isinstance(tree, exp.Select):
        raise QueryValidationError("Only SELECT queries are permitted.")

    # Disallow joins, subqueries, unions and nested queries.
    forbidden_nodes = (
        exp.Join,
        exp.Subquery,
        exp.Union,
        exp.Insert,
        exp.Update,
        exp.Delete,
        exp.Drop,
        exp.Alter,
        exp.Command
    )

    for node_type in forbidden_nodes:
        if tree.find(node_type):
            raise QueryValidationError(
                f"Forbidden SQL structure: {node_type.__name__}"
            )

    # Check the tables referenced by the query.
    tables = {
        table.name.lower()
        for table in tree.find_all(exp.Table)
    }

    if not tables or not tables.issubset(ALLOWED_TABLES):
        raise QueryValidationError("Access to an unapproved table.")

    # Check referenced columns.
    for column in tree.find_all(exp.Column):
        if column.name.lower() not in ALLOWED_COLUMNS:
            raise QueryValidationError(
                f"Unapproved column: {column.name}"
            )

        if column.table and column.table.lower() != "students":
            raise QueryValidationError("Unapproved table alias.")
   
    # Allow only explicitly approved SQL functions.
    for function in tree.find_all(exp.Func):

        function_name = function.sql_name().lower()

        if function_name not in ALLOWED_FUNCTIONS:
            raise QueryValidationError(
                f"Unapproved SQL function: {function_name}"
            )
    fingerprint = generate_fingerprint(sql, tree)

    return {
        "valid": True,
        "fingerprint": fingerprint,
        "normalized_sql": tree.sql(dialect="sqlite", normalize=True)
    }
