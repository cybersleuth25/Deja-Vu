"""PR risk check: which changed files have incident history. Reads only the JSON store (no network)."""
from __future__ import annotations

from collections import defaultdict

import insights

MARKER = "<!-- dejavu-pr-warning -->"


def _norm(path: str) -> str:
    path = path.strip().replace("\\", "/")
    return path[2:] if path.startswith("./") else path


def check(changed_files: list[str], incidents: list[dict]) -> dict:
    changed = [f for f in dict.fromkeys(_norm(f) for f in changed_files) if f]
    findings = []
    for f in changed:
        hits = []
        for inc in incidents:
            role = None
            if f in inc.get("files", []):
                role = "involved"
            elif f in ((inc.get("prior_change") or {}).get("files") or []):
                role = "changed before"
            if role:
                hits.append({"id": inc["id"], "type": inc["type"], "title": inc["title"],
                             "opened_at": inc["opened_at"], "severity": inc.get("severity"), "role": role,
                             "prior_change": (inc.get("prior_change") or {}).get("summary")})
        if not hits:
            continue
        ids = {h["id"] for h in hits}
        failed: dict[str, list[str]] = defaultdict(list)
        worked: dict[str, list[str]] = defaultdict(list)
        for inc in incidents:
            if inc["id"] in ids:
                for a in inc.get("actions", []):
                    (worked if a["worked"] else failed)[a["action"]].append(inc["id"])
        findings.append({
            "file": f,
            "incidents": sorted(hits, key=lambda h: h["opened_at"]),
            "outages": sum(h["type"] == "outage" for h in hits),
            "security": sum(h["type"] == "security" for h in hits),
            "failed_fixes": [{"action": a, "ids": v} for a, v in failed.items() if a not in worked],
            "worked_fixes": [{"action": a, "ids": v} for a, v in worked.items()],
        })
    pattern = None
    if any(insights.is_auth_file(f) for f in changed):
        p = insights.auth_precursor([i for i in incidents if i.get("status", "resolved") == "resolved"])
        if p["count"]:
            pattern = {**p, "text": p["text"] + f" ({', '.join(p['ids'])})"}
    return {"changed_files": changed, "findings": findings, "pattern": pattern}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def render_markdown(result: dict) -> str:
    lines = [MARKER, "## DejaVu: incident history for this pull request", ""]
    if not result["findings"]:
        lines.append("No changed file has incident history. ✅")
        return "\n".join(lines) + "\n"
    for fd in result["findings"]:
        parts = []
        if fd["outages"]:
            parts.append(_plural(fd["outages"], "outage"))
        if fd["security"]:
            parts.append(_plural(fd["security"], "security incident"))
        lines.append(f"### ⚠️ `{fd['file']}` was involved in {' and '.join(parts)}")
        for h in fd["incidents"]:
            extra = f" (after change: {h['prior_change']})" if h["role"] == "changed before" and h["prior_change"] else ""
            lines.append(f"- **{h['id']}** {h['opened_at'][:10]} {h['severity'] or ''}: {h['title']}{extra}")
        if fd["failed_fixes"]:
            lines.append("")
            lines.append("Fixes that did not work for these incidents: "
                         + "; ".join(f"{x['action']} ({', '.join(x['ids'])})" for x in fd["failed_fixes"]))
        lines.append("")
    if result.get("pattern"):
        lines.append(f"**Pattern:** {result['pattern']['text']}")
        lines.append("")
    lines.append("_Recommendation only. Consider extra review and tests for these paths before merging._")
    return "\n".join(lines) + "\n"
