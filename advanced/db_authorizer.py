
import sqlite3


ALLOWED_FUNCTIONS = {"like"}


def student_read_only_authorizer(
    action, arg1, arg2, database_name, trigger_name
):
    """
    Allow approved read-only student queries.

    Deny database modification and unauthorized access.
    """

    # Allow SELECT operations.
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK

    # Allow reading only from the students table.
    if action == sqlite3.SQLITE_READ:
        if arg1 == "students" and database_name == "main":
            return sqlite3.SQLITE_OK

        return sqlite3.SQLITE_DENY

    # Allow only explicitly approved SQL functions.
    if action == sqlite3.SQLITE_FUNCTION:
        function_name = (arg2 or "").lower()

        if function_name in ALLOWED_FUNCTIONS:
            return sqlite3.SQLITE_OK

        return sqlite3.SQLITE_DENY

    # Reject all other database operations.
    return sqlite3.SQLITE_DENY


def enable_read_only_authorization(connection):
    connection.set_authorizer(student_read_only_authorizer)
