import argparse
from pathlib import Path

from agentward.reader import read_adop_records
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

        base_name = f"{input_path.stem}-assessment"
        counter = 1

        while True:
            output_path = reports_dir / f"{base_name}-{counter}.txt"

            if not output_path.exists():
                break

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
        description="AgentWard v1 - Analyze ADOP security records"
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