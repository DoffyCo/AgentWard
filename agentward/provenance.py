from typing import Any

from .config import APPROVED_EXTERNAL_SOURCES


def _find_prior_sources(
    record: dict[str, Any], records: list[dict[str, Any]],
    matches: list[dict[str, str]],
) -> list[dict[str, Any]]:
    # Only correlate findings involving resource access, data movement,
    # sensitive content, or dependency integrity.
    relevant_policies = {"AW-001", "AW-002", "AW-003", "AW-005", "AW-006"}
    if not any(match["policy_id"] in relevant_policies for match in matches):
        return []

    session = record.get("session_id")
    task = record.get("task_id")
    sequence = record.get("seq")
    if not isinstance(session, str) or not session.strip():
        return []
    if not isinstance(task, str) or not task.strip():
        return []
    if type(sequence) is not int or sequence < 1:
        return []

    # Use sequence numbers rather than the order of lines in the file.
    task_records = []
    for event in records:
        if event.get("session_id") == session and event.get("task_id") == task:
            task_records.append(event)

    # Do not infer an ordering when sequence numbers are ambiguous.
    sequences = [event.get("seq") for event in task_records]
    if any(type(value) is not int or value < 1 for value in sequences):
        return []
    if len(sequences) != len(set(sequences)) or sequence not in sequences:
        return []

    sources = []
    for event in sorted(task_records, key=lambda event: event["seq"]):
        if event["seq"] >= sequence:
            break
        if event.get("server") != "fetch" or event.get("tool_name") != "fetch":
            continue
        if event.get("result_status") != "success":
            continue
        arguments = event.get("arguments")
        if not isinstance(arguments, dict):
            continue
        url = arguments.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        if url in APPROVED_EXTERNAL_SOURCES:
            continue

        # Retain source evidence without copying retrieved content.
        sources.append({
            "seq": event["seq"],
            "timestamp": event.get("timestamp", ""),
            "url": url,
            "result_status": "success",
        })

    return sources
