from typing import Any


SEVERITY_POINTS = {"high": 30, "medium": 15, "low": 5}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = {}
    for index, finding in enumerate(findings):
        fields = tuple(finding.get(k) for k in ("session_id", "task_id", "server", "tool", "target"))
        key = fields if all(isinstance(v, str) and v.strip() for v in fields) else (index,)
        groups.setdefault(key, []).append(finding)

    alerts = []
    for events in groups.values():
        strongest = max(events, key=lambda e: SEVERITY_RANK[e["severity"]])
        alert = dict(strongest)
        policies = {}
        for event in events:
            for match in event["policies"]:
                pid = match["policy_id"]
                if pid not in policies or SEVERITY_RANK[match["severity"]] > SEVERITY_RANK[policies[pid]["severity"]]:
                    policies[pid] = match
        alert.update(
            events=events, occurrence_count=len(events),
            correlated_event_count=sum(bool(event.get("prior_sources")) for event in events),
            prior_sources=[],
            policies=list(policies.values()),
            policy_id=", ".join(policies),
            policy_name=", ".join(m["policy_name"] for m in policies.values()),
            reason=" ".join(dict.fromkeys(e["reason"] for e in events)),
            provenance_flag="TRACEABLE" if all(e["provenance_flag"] == "TRACEABLE" for e in events) else "INCOMPLETE",
        )
        alerts.append(alert)
    alerts.sort(key=lambda f: (-f["risk_points"], str(f.get("task_id")), str(f.get("target"))))
    for rank, alert in enumerate(alerts, 1):
        alert["rank"] = rank
    return alerts


def calculate_risk_score(findings: list[dict[str, Any]]) -> int:
    return sum(f["risk_points"] for f in findings)


def classify_risk(findings: list[dict[str, Any]]) -> str:
    return max((f["severity"] for f in findings), key=SEVERITY_RANK.get, default="low").capitalize()
