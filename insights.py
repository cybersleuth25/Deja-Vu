"""Patterns computed from the incident records (never hard-coded), plus a Hindsight reflect summary.

Patterns are computed over resolved incidents: an open incident has no outcome yet.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

REFLECT_QUERY = ("Across all incidents, which remediation fixes keep failing, which fixes reliably work, "
                 "and what recurring patterns (attackers, risky code areas, timing) should the team act on? "
                 "Cite incident ids.")


def is_tuesday_evening(opened_at: str) -> bool:
    dt = datetime.fromisoformat(opened_at)
    return dt.weekday() == 1 and 17 <= dt.hour < 22


def is_auth_file(path: str) -> bool:
    return path.startswith("auth/") or path.startswith("middleware/jwt")


def is_auth_change(prior_change: dict | None, within_hours: int = 48) -> bool:
    if not prior_change or prior_change.get("hours_before", 10**6) > within_hours:
        return False
    return any(is_auth_file(f) for f in prior_change.get("files", []))


def tuesday_evening(incidents: list[dict]) -> dict:
    sec = [i for i in incidents if i["type"] == "security"]
    hits = [i["id"] for i in sec if is_tuesday_evening(i["opened_at"])]
    return {"key": "tuesday_evening", "count": len(hits), "total": len(sec), "ids": hits,
            "text": f"{len(hits)} of {len(sec)} security incidents started on a Tuesday evening (17:00-22:00)."}


def auth_precursor(incidents: list[dict], last_n: int = 6) -> dict:
    outages = sorted([i for i in incidents if i["type"] == "outage"], key=lambda i: i["opened_at"])[-last_n:]
    hits = [i["id"] for i in outages if is_auth_change(i.get("prior_change"))]
    return {"key": "auth_precursor", "count": len(hits), "total": len(outages), "ids": hits,
            "window_ids": [i["id"] for i in outages],
            "text": f"{len(hits)} of the last {len(outages)} outages were preceded by an auth-related change "
                    f"(auth/*, middleware/jwt*) within 48h."}


def action_stats(incidents: list[dict]) -> dict[str, dict]:
    stats: dict[str, dict] = defaultdict(lambda: {"tried": 0, "worked": 0, "worked_in": [], "failed_in": []})
    for i in incidents:
        for a in i.get("actions", []):
            s = stats[a["action"]]
            s["tried"] += 1
            if a["worked"]:
                s["worked"] += 1; s["worked_in"].append(i["id"])
            else:
                s["failed_in"].append(i["id"])
    return stats


def always_fail(incidents: list[dict], min_tried: int = 2) -> list[dict]:
    rows = [{"action": a, **s} for a, s in action_stats(incidents).items() if s["worked"] == 0 and s["tried"] >= min_tried]
    return sorted(rows, key=lambda r: -r["tried"])


def reliable(incidents: list[dict], min_tried: int = 3, min_rate: float = 0.75) -> list[dict]:
    rows = [{"action": a, **s, "rate": s["worked"] / s["tried"]} for a, s in action_stats(incidents).items()
            if s["tried"] >= min_tried and s["worked"] / s["tried"] >= min_rate]
    return sorted(rows, key=lambda r: (-r["rate"], -r["tried"]))


def recurring_asns(incidents: list[dict]) -> list[dict]:
    by: dict[str, list[str]] = defaultdict(list)
    for i in incidents:
        if i.get("asn"):
            by[i["asn"]].append(i["id"])
    return sorted([{"asn": a, "count": len(ids), "ids": ids} for a, ids in by.items() if len(ids) >= 2],
                  key=lambda r: -r["count"])


def hot_files(incidents: list[dict], top: int = 6) -> list[dict]:
    by: dict[str, set] = defaultdict(set)
    for i in incidents:
        for f in i.get("files", []) + ((i.get("prior_change") or {}).get("files") or []):
            by[f].add(i["id"])
    rows = [{"file": f, "count": len(ids), "ids": sorted(ids)} for f, ids in by.items() if len(ids) >= 2]
    return sorted(rows, key=lambda r: (-r["count"], r["file"]))[:top]


def compute(incidents: list[dict]) -> dict:
    resolved = [i for i in incidents if i.get("status", "resolved") == "resolved"]
    return {
        "resolved_count": len(resolved),
        "tuesday_evening": tuesday_evening(resolved),
        "auth_precursor": auth_precursor(resolved),
        "always_fail": always_fail(resolved),
        "reliable": reliable(resolved),
        "recurring_asns": recurring_asns(resolved),
        "hot_files": hot_files(resolved),
    }


def reflect_summary(memory) -> dict:
    """Hindsight reflect synthesis. Never raises."""
    if memory is None:
        return {"text": "", "error": "No memory backend configured."}
    try:
        return {"text": memory.reflect(REFLECT_QUERY), "error": None, "backend": memory.name}
    except Exception as exc:
        return {"text": "", "error": f"reflect failed: {exc}", "backend": memory.name}
