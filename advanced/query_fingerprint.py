
import hashlib


def generate_fingerprint(sql, sqlglot_expression):
    """
    Generate a SHA-256 fingerprint from a normalized SQL query.
    """

    normalized_sql = sqlglot_expression.sql(
        dialect="sqlite",
        normalize=True
    )

    return hashlib.sha256(
        normalized_sql.encode("utf-8")
    ).hexdigest()
