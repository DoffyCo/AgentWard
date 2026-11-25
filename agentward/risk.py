from typing import Any


SEVERITY_POINTS = {"high": 30, "medium": 15, "low": 5}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Group only findings with complete matching event identifiers.
    groups = {}
    for index, finding in enumerate(findings):
        fields = tuple(
            finding.get(field)
            for field in ("session_id", "task_id", "server", "tool", "target")
        )
        if all(isinstance(value, str) and value.strip() for value in fields):
            key = fields
        else:
            key = (index,)
        groups.setdefault(key, []).append(finding)

    # Retain the highest severity and all individual events in each group.
    alerts = []
    for events in groups.values():
        strongest = max(events, key=lambda event: SEVERITY_RANK[event["severity"]])
        alert = dict(strongest)
        policies = {}
        for event in events:
            for match in event["policies"]:
                policy_id = match["policy_id"]
                if (
                    policy_id not in policies
                    or SEVERITY_RANK[match["severity"]]
                    > SEVERITY_RANK[policies[policy_id]["severity"]]
                ):
                    policies[policy_id] = match
        if all(event["provenance_flag"] == "TRACEABLE" for event in events):
            provenance_flag = "TRACEABLE"
        else:
            provenance_flag = "INCOMPLETE"

        alert.update(
            events=events,
            occurrence_count=len(events),
            correlated_event_count=sum(
                bool(event.get("prior_sources")) for event in events
            ),
            prior_sources=[],
            policies=list(policies.values()),
            policy_id=", ".join(policies),
            policy_name=", ".join(match["policy_name"] for match in policies.values()),
            reason=" ".join(dict.fromkeys(event["reason"] for event in events)),
            provenance_flag=provenance_flag,
        )
        alerts.append(alert)
    # Rank by descending risk points, then task and target.
    alerts.sort(
        key=lambda alert: (
            -alert["risk_points"],
            str(alert.get("task_id")),
            str(alert.get("target")),
        )
    )
    for rank, alert in enumerate(alerts, 1):
        alert["rank"] = rank
    return alerts


def calculate_risk_score(findings: list[dict[str, Any]]) -> int:
    return sum(finding["risk_points"] for finding in findings)


def classify_risk(findings: list[dict[str, Any]]) -> str:
    return max(
        (finding["severity"] for finding in findings),
        key=SEVERITY_RANK.get,
        default="low",
    ).capitalize()
