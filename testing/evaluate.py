
import pandas as pd
from pathlib import Path


INPUT_FILE = Path("results/csv/test_case_results.csv")

OUTPUT_DIR = Path("results/csv")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def calculate_detection_metrics(data):
    """
    Calculate input-level detection metrics.

    These metrics apply only to the Traditional
    regex-based detector.
    """

    actual = data["label"] == "malicious"

    predicted = (
        data["input_detected"]
        .astype(str)
        .str.lower()
        .eq("true")
    )

    tp = int((actual & predicted).sum())
    fn = int((actual & ~predicted).sum())
    fp = int((~actual & predicted).sum())
    tn = int((~actual & ~predicted).sum())

    detection_rate = (
        tp / (tp + fn) * 100
        if tp + fn else 0
    )

    false_positive_rate = (
        fp / (fp + tn) * 100
        if fp + tn else 0
    )

    precision = (
        tp / (tp + fp) * 100
        if tp + fp else None
    )

    return {
        "TP": tp,
        "FN": fn,
        "FP": fp,
        "TN": tn,
        "Detection_Rate_Percent": round(detection_rate, 2),
        "False_Positive_Rate_Percent": round(
            false_positive_rate, 2
        ),
        "Precision_Percent": (
            round(precision, 2)
            if precision is not None else "N/A"
        )
    }


def evaluate_configuration(data, configuration):

    subset = data[
        data["configuration"] == configuration
    ].copy()

    malicious = subset[
        subset["label"] == "malicious"
    ]

    legitimate = subset[
        subset["label"] == "legitimate"
    ]

    safe_handling_count = (
        malicious["safe_parameter_handling"]
        .astype(bool)
        .sum()
    )

    safe_handling_rate = (
        safe_handling_count / len(malicious) * 100
        if len(malicious) else 0
    )

    legitimate_success_count = (
        legitimate["legitimate_success"]
        .astype(bool)
        .sum()
    )

    legitimate_success_rate = (
        legitimate_success_count / len(legitimate) * 100
        if len(legitimate) else 0
    )

    integrity_count = (
        subset["database_integrity"]
        .astype(bool)
        .sum()
    )

    integrity_rate = (
        integrity_count / len(subset) * 100
        if len(subset) else 0
    )

    average_time = subset["execution_time_ms"].mean()
    median_time = subset["execution_time_ms"].median()

    result = {
        "Configuration": configuration,
        "Total_Executions": len(subset),
        "Malicious_Input_Cases": len(malicious),
        "Legitimate_Input_Cases": len(legitimate),
        "Safe_Parameter_Handling_Percent": round(
            safe_handling_rate, 2
        ),
        "Legitimate_Request_Success_Percent": round(
            legitimate_success_rate, 2
        ),
        "Database_Integrity_Percent": round(
            integrity_rate, 2
        ),
        "Average_Execution_Time_ms": round(
            average_time, 4
        ),
        "Median_Execution_Time_ms": round(
            median_time, 4
        )
    }

    if configuration == "Traditional":

        result.update(
            calculate_detection_metrics(subset)
        )

    return result


def main():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "Test results not found. "
            "Run testing.run_tests first."
        )

    data = pd.read_csv(INPUT_FILE)

    if len(data) != 400:
        raise ValueError(
            f"Expected 400 executions, found {len(data)}."
        )

    required_columns = [
        "case_id",
        "category",
        "label",
        "configuration",
        "input_detected",
        "safe_parameter_handling",
        "legitimate_success",
        "database_integrity",
        "execution_time_ms"
    ]

    missing_columns = [
        column for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing CSV columns: {missing_columns}"
        )

    results = []

    for configuration in ["Traditional", "Advanced"]:

        result = evaluate_configuration(
            data,
            configuration
        )

        results.append(result)

    summary = pd.DataFrame(results)

    summary_file = (
        OUTPUT_DIR / "detection_comparison.csv"
    )

    summary.to_csv(summary_file, index=False)

    print("\nSECURITY CONFIGURATION COMPARISON")
    print("=" * 90)
    print(summary.to_string(index=False))

    # Calculate performance overhead.
    traditional_time = summary.loc[
        summary["Configuration"] == "Traditional",
        "Average_Execution_Time_ms"
    ].iloc[0]

    advanced_time = summary.loc[
        summary["Configuration"] == "Advanced",
        "Average_Execution_Time_ms"
    ].iloc[0]

    print("\nADVANCED CONFIGURATION PERFORMANCE OVERHEAD")

    if traditional_time > 0:

        overhead = (
            (advanced_time - traditional_time)
            / traditional_time
        ) * 100

        print(f"{overhead:.2f}%")

    else:
        print("Cannot calculate because traditional time is zero.")

    # Category-wise input detection for Traditional only.
    traditional_data = data[
        data["configuration"] == "Traditional"
    ].copy()

    traditional_data["detected_boolean"] = (
        traditional_data["input_detected"]
        .astype(str)
        .str.lower()
        .eq("true")
    )

    category_results = (
        traditional_data[
            traditional_data["label"] == "malicious"
        ]
        .groupby("category")
        .agg(
            Total_Cases=("case_id", "count"),
            Detected=("detected_boolean", "sum"),
            Average_Time_ms=("execution_time_ms", "mean")
        )
        .reset_index()
    )

    category_results["Detection_Rate_Percent"] = (
        category_results["Detected"]
        / category_results["Total_Cases"] * 100
    ).round(2)

    category_file = (
        OUTPUT_DIR / "category_comparison.csv"
    )

    category_results.to_csv(
        category_file, index=False
    )

    print("\nFILES GENERATED")
    print("- detection_comparison.csv")
    print("- category_comparison.csv")


if __name__ == "__main__":
    main()
