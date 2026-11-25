import argparse
from datetime import datetime
from pathlib import Path

from agentward.reader import identify_scenario, read_adop_records
from agentward.evaluator import evaluate_records
from agentward.report import generate_report, save_report


# Analyze an ADOP JSONL file with AgentWard policies.
def analyze(input_file: str, output_file: str | None = None) -> None:
    input_path = Path(input_file)

    if not input_path.exists():
        print(f"Error: ADOP record file not found: {input_path}")
        return

    records = read_adop_records(str(input_path))
    findings = evaluate_records(records)
    report = generate_report(records, findings)

    if output_file is None:
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        scenario = identify_scenario(records)

        # Include the scenario, date, and time in the report filename.
        timestamp = datetime.now().strftime("%m-%d-%Y_%H-%M-%S")
        base_name = f"{input_path.stem}-{scenario}-assessment-{timestamp}"

        output_path = reports_dir / f"{base_name}.txt"
        counter = 1

        # Prevent existing reports from being overwritten.
        while output_path.exists():
            output_path = reports_dir / f"{base_name}-{counter}.txt"
            counter += 1

    else:
        output_path = Path(output_file)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    save_report(report, str(output_path))

    print(report)
    print()
    print(f"Report saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentWard v3 - Analyze ADOP security records"
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an ADOP JSONL record file",
    )

    analyze_parser.add_argument(
        "input_file",
        help="Path to the ADOP JSONL file",
    )

    analyze_parser.add_argument(
        "-o",
        "--output",
        help="Optional path for the generated report",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        analyze(args.input_file, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
