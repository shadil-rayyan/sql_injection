
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


CSV_DIR = Path("results/csv")
GRAPH_DIR = Path("results/graphs")

GRAPH_DIR.mkdir(parents=True, exist_ok=True)


def save_graph(filename):
    """Save the current graph as a high-resolution image."""

    plt.tight_layout()

    plt.savefig(
        GRAPH_DIR / filename,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print("Generated:", filename)


def plot_detection_metrics():
    """Plot Traditional input-level detection metrics."""

    data = pd.read_csv(
        CSV_DIR / "detection_comparison.csv"
    )

    traditional = data[
        data["Configuration"] == "Traditional"
    ].iloc[0]

    metrics = [
        "Detection Rate",
        "False Positive Rate",
        "Precision"
    ]

    values = [
        traditional["Detection_Rate_Percent"],
        traditional["False_Positive_Rate_Percent"],
        traditional["Precision_Percent"]
    ]

    plt.figure(figsize=(8, 5))

    bars = plt.bar(metrics, values)

    plt.title("Traditional Configuration - Input Detection")
    plt.ylabel("Percentage (%)")
    plt.ylim(0, 110)

    for bar, value in zip(bars, values):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2,
            f"{value:.2f}%",
            ha="center"
        )

    save_graph("input_detection_metrics.png")


def plot_category_detection():
    """Plot detection rate for each malicious input category."""

    data = pd.read_csv(
        CSV_DIR / "category_comparison.csv"
    )

    plt.figure(figsize=(10, 6))

    bars = plt.bar(
        data["category"],
        data["Detection_Rate_Percent"]
    )

    plt.title("Traditional Detection by Attack Category")
    plt.xlabel("Attack Category")
    plt.ylabel("Detection Rate (%)")
    plt.ylim(0, 110)

    plt.xticks(rotation=35, ha="right")

    for bar, value in zip(
        bars,
        data["Detection_Rate_Percent"]
    ):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2,
            f"{value:.1f}%",
            ha="center"
        )

    save_graph("category_detection.png")


def plot_ast_results():
    """Plot AST acceptance and rejection."""

    data = pd.read_csv(
        CSV_DIR / "structural_comparison.csv"
    )

    metrics = [
        "AST accepted",
        "AST rejected"
    ]

    values = []

    for metric in metrics:
        value = data.loc[
            data["Metric"] == metric,
            "Count"
        ].iloc[0]

        values.append(value)

    plt.figure(figsize=(7, 5))

    plt.bar(metrics, values)

    plt.title("AST Validation Results")
    plt.ylabel("Number of SQL Statements")

    for index, value in enumerate(values):
        plt.text(index, value + 0.2, str(value), ha="center")

    plt.ylim(0, max(values) + 2)

    save_graph("ast_validation.png")


def plot_fingerprint_results():
    """Plot fingerprint approval and rejection."""

    data = pd.read_csv(
        CSV_DIR / "structural_attack_results.csv"
    )

    tested = data[
        data["fingerprint_approved"].astype(str).str.lower()
        .isin(["true", "false"])
    ]

    approved = (
        tested["fingerprint_approved"]
        .astype(str).str.lower() == "true"
    ).sum()

    rejected = (
        tested["fingerprint_approved"]
        .astype(str).str.lower() == "false"
    ).sum()

    metrics = ["Approved", "Rejected"]
    values = [approved, rejected]

    plt.figure(figsize=(7, 5))

    plt.bar(metrics, values)

    plt.title("Query Fingerprint Validation")
    plt.ylabel("Number of SQL Statements")

    for index, value in enumerate(values):
        plt.text(index, value + 0.1, str(value), ha="center")

    plt.ylim(0, max(values) + 2)

    save_graph("fingerprint_validation.png")


def plot_query_policy():
    """Plot combined query policy results."""

    data = pd.read_csv(
        CSV_DIR / "structural_comparison.csv"
    )

    metrics = [
        "Combined query policy rejected"
    ]

    values = [
        data.loc[
            data["Metric"] == metric,
            "Count"
        ].iloc[0]
        for metric in metrics
    ]

    accepted = 12 - values[0]

    plt.figure(figsize=(7, 5))

    plt.bar(
        ["Rejected", "Accepted"],
        [values[0], accepted]
    )

    plt.title("Combined Query Policy Results")
    plt.ylabel("Number of SQL Statements")

    plt.ylim(0, 14)

    plt.text(0, values[0] + 0.2, str(values[0]), ha="center")
    plt.text(1, accepted + 0.2, str(accepted), ha="center")

    save_graph("combined_query_policy.png")


def plot_authorizer_results():
    """Plot SQLite authorizer outcomes."""

    data = pd.read_csv(
        CSV_DIR / "structural_comparison.csv"
    )

    metrics = [
        "SQLite authorizer denied",
        "SQLite authorizer allowed",
        "SQLite authorizer inconclusive"
    ]

    labels = [
        "Denied",
        "Allowed",
        "Inconclusive"
    ]

    values = [
        data.loc[
            data["Metric"] == metric,
            "Count"
        ].iloc[0]
        for metric in metrics
    ]

    plt.figure(figsize=(8, 5))

    plt.bar(labels, values)

    plt.title("SQLite Authorizer Results")
    plt.ylabel("Number of SQL Statements")

    for index, value in enumerate(values):
        plt.text(index, value + 0.2, str(value), ha="center")

    plt.ylim(0, max(values) + 2)

    save_graph("sqlite_authorizer.png")


def plot_execution_time():
    """Compare average execution time of both configurations."""

    data = pd.read_csv(
        CSV_DIR / "detection_comparison.csv"
    )

    configurations = data["Configuration"]
    execution_times = data["Average_Execution_Time_ms"]

    plt.figure(figsize=(7, 5))

    bars = plt.bar(
        configurations,
        execution_times
    )

    plt.title("Average Execution Time Comparison")
    plt.ylabel("Execution Time (ms)")

    for bar, value in zip(bars, execution_times):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            f"{value:.4f} ms",
            ha="center"
        )

    plt.ylim(0, max(execution_times) * 1.2)

    save_graph("execution_time_comparison.png")


def main():

    print("Starting graph generation...")

    plot_detection_metrics()
    plot_category_detection()
    plot_ast_results()
    plot_fingerprint_results()
    plot_query_policy()
    plot_authorizer_results()
    plot_execution_time()

    print("\nAll graphs generated successfully.")
    print("Graph location:", GRAPH_DIR)


if __name__ == "__main__":
    main()
