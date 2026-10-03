import json
from pathlib import Path
from typing import Any

# Read ADOP JSONL telemetry records. 
# Each line in an ADOP .jsonl file represents one telemetry record.
def read_adop_records(file_path: str | Path) -> list[dict[str, Any]]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"ADOP record file not found: {path}")

    records: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} of {path}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected a JSON object on line {line_number} of {path}"
                )

            records.append(record)

    return records

# Print a summary of ADOP telemetry records.
def summarize_records(records: list[dict[str, Any]]) -> None:
    for record in records:
        print(
            f"[{record.get('scenario_tag', 'unknown')}] "
            f"{record.get('task_id', 'unknown')} | "
            f"{record.get('server', 'unknown')} | "
            f"{record.get('tool_name', 'unknown')} | "
            f"{record.get('target_resource', 'unknown')} | "
            f"{record.get('result_status', 'unknown')}"
        )