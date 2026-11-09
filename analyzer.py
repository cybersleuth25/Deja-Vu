"""Investigation: recall similar incidents, score them, rank actions by track record, narrate.

Scoring (tech spec section 6), applied to every resolved incident in the JSON store:
  +2 same type, +2 same service, +3 per shared file, +3 same ASN,
  +0.5 per overlapping keyword (at most 8 keywords counted), +4 if Hindsight recalled it.
Incidents scoring at least 5 are kept (top 5). On top of the spec we also drop matches scoring
under half of the best match (RELATIVE_CUTOFF), so a strong deja vu is not diluted by incidents
that only share the type and a loose recall hit.

Action ranking: rate = worked / tried. "Do first" = rate >= 0.5, top 3. "Avoid" = worked 0 and
tried >= 1. Ties in the "do first" order use a smoothed rate (worked+1)/(tried+2) and then the
number of successes, then the similarity of the incidents it worked in, so a fix that worked 3 of 4 times is not outranked by a 1-of-1 fluke.
"""
from __future__ import annotations

import re
from collections import defaultdict

from memory_backend import INC_RE, Memory

MIN_SCORE = 5
TOP_K = 5
RELATIVE_CUTOFF = 0.5
KEYWORD_CAP = 8

STOP = {
    "the", "and", "for", "from", "with", "after", "into", "against", "over", "each", "this", "that",
    "rate", "reached", "error", "errors", "failed", "failing", "http", "requests", "minutes", "min",
}
WORD = re.compile(r"[a-z][a-z0-9_]{2,}")

# What a model with no history would say. Deliberately the "obvious" first moves.
GENERIC = {
    "pool_saturation": ["Restart connection pool", "Restart service", "Increase pool size"],
    "error_spike": ["Restart service", "Scale up replicas", "Check recent deploys"],
    "failed_login_burst": ["Per-IP rate limit", "Reset passwords for affected accounts", "Monitor login failures"],
    "password_spray": ["Per-IP rate limit", "Reset passwords for affected accounts", "Monitor login failures"],
    "port_scan": ["Block source IP at firewall", "Review exposed ports", "Monitor for follow-up traffic"],
}
GENERIC_DEFAULT = ["Restart service", "Check recent deploys", "Escalate to the service owner"]


def keywords(text: str) -> set[str]:
    return {w for w in WORD.findall(text.lower()) if w not in STOP}


def build_query(alert: dict) -> str:
    parts = [alert["title"], alert.get("signal", ""), f"service {alert['service']}"]
    if alert.get("files"):
        parts.append("files " + ", ".join(alert["files"]))
    if alert.get("asn"):
        parts.append(f"attacker ASN {alert['asn']}")
    parts.append("Which remediation actions worked and which failed in similar past incidents?")
    return ". ".join(parts)


def score_incident(alert: dict, inc: dict, recalled: set[str],
                   recall_label: str = "recalled by Hindsight") -> tuple[float, list[str]]:
    score, why = 0.0, []
    if inc["type"] == alert["type"]:
        score += 2; why.append(f"same type ({inc['type']})")
    if inc["service"] == alert["service"]:
        score += 2; why.append(f"same service ({inc['service']})")
    shared = sorted(set(inc.get("files", [])) & set(alert.get("files", [])))
    if shared:
        score += 3 * len(shared); why.append("shared files: " + ", ".join(shared))
    if alert.get("asn") and inc.get("asn") == alert["asn"]:
        score += 3; why.append(f"same ASN ({inc['asn']})")
    kw = keywords(f"{alert['title']} {alert.get('signal', '')}") & keywords(f"{inc['title']} {inc.get('signal', '')}")
    if kw:
        n = min(len(kw), KEYWORD_CAP)
        score += 0.5 * n; why.append(f"{n} shared keywords")
    if inc["id"] in recalled:
        score += 4; why.append(recall_label)
    return score, why


def find_similar(alert: dict, incidents: list[dict], recalled: set[str], exclude: str | None = None,
                 recall_label: str = "recalled by Hindsight") -> list[dict]:
    rows = []
    for inc in incidents:
        if inc.get("status") != "resolved" or inc["id"] == exclude:
            continue
        s, why = score_incident(alert, inc, recalled, recall_label)
        if s >= MIN_SCORE:
            rows.append({"id": inc["id"], "score": s, "why": why, "incident": inc})
    rows.sort(key=lambda r: (-r["score"], r["id"]))
    if rows:
        floor = rows[0]["score"] * RELATIVE_CUTOFF
        rows = [r for r in rows if r["score"] >= floor]
    return rows[:TOP_K]


def rank_actions(matches: list[dict]) -> dict:
    agg: dict[str, dict] = defaultdict(lambda: {"tried": 0, "worked": 0, "worked_in": [], "failed_in": [], "evidence": 0.0})
    for m in matches:
        for a in m["incident"].get("actions", []):
            row = agg[a["action"]]
            row["tried"] += 1
            if a["worked"]:
                row["worked"] += 1; row["worked_in"].append(m["id"])
                row["evidence"] += m["score"]
            else:
                row["failed_in"].append(m["id"])
    actions = []
    for name, r in agg.items():
        actions.append({"action": name, **r, "rate": r["worked"] / r["tried"]})
    smooth = lambda a: (a["worked"] + 1) / (a["tried"] + 2)
    do_first = sorted([a for a in actions if a["rate"] >= 0.5],
                      key=lambda a: (-smooth(a), -a["worked"], -a["evidence"], a["action"]))[:3]
    avoid = sorted([a for a in actions if a["worked"] == 0 and a["tried"] >= 1],
                   key=lambda a: (-a["tried"], a["action"]))
    return {"all": sorted(actions, key=lambda a: (-a["rate"], -a["tried"])), "do_first": do_first, "avoid": avoid}


def prior_change_hint(alert: dict, matches: list[dict]) -> str | None:
    pc = alert.get("prior_change")
    if not pc:
        return None
    hits = [m["id"] for m in matches
            if set((m["incident"].get("prior_change") or {}).get("files", [])) & set(pc["files"])]
    if not hits:
        return None
    return (f"The change \"{pc['summary']}\" touched {', '.join(pc['files'])} {pc['hours_before']}h ago; "
            f"a change to the same files preceded {', '.join(hits)}.")


# ---------- narrative ----------
def _times(n: int) -> str:
    return "time" if n == 1 else "times"


def template_narrative(alert: dict, matches: list[dict], ranked: dict, hint: str | None) -> str:
    """Short on purpose: the Do first and failed lists carry the detail, this states the verdict."""
    ids = ", ".join(m["id"] for m in matches)
    kind = "security incident" if alert["type"] == "security" else alert["type"]
    n = len(matches)
    out = [f"This {kind} on {alert['service']} matches {n} past incident{'' if n == 1 else 's'}: {ids}."]
    verdict = []
    for a in ranked["do_first"][:1]:
        verdict.append(f"{a['action']} worked {a['worked']} of {a['tried']} {_times(a['tried'])}")
    for a in ranked["avoid"][:1]:
        verdict.append(f"{a['action']} failed {a['tried']} of {a['tried']}")
    if verdict:
        out.append("; ".join(verdict) + ".")
    if hint:
        out.append(hint)
    return " ".join(out)


def generic_template(alert: dict, steps: list[str]) -> str:
    return (f"{alert['title']} on {alert['service']}. Standard first steps: "
            + "; ".join(steps) + ". No incident history was consulted.")


SYSTEM = ("You are DejaVu, an incident-response assistant. You only recommend; a human decides. "
          "Write plain text, at most 110 words, no markdown headings or bullet lists.")


def llm_narrative(llm, alert: dict, matches: list[dict], ranked: dict, hint: str | None) -> str:
    facts = [f"- {m['id']}: {m['incident']['title']} ({m['incident']['opened_at']}); root cause: "
             f"{m['incident'].get('root_cause', '')}" for m in matches]
    acts = [f"- {a['action']}: worked {a['worked']} of {a['tried']} (worked in {', '.join(a['worked_in']) or 'none'}; "
            f"failed in {', '.join(a['failed_in']) or 'none'})" for a in ranked["all"]]
    user = (f"New alert: {alert['title']} on {alert['service']}. Signal: {alert.get('signal', '')}\n"
            f"Similar past incidents:\n" + "\n".join(facts) + "\nAction track record:\n" + "\n".join(acts)
            + (f"\nRecent change: {hint}" if hint else "")
            + "\n\nTell the on-call engineer what to do first and what not to repeat, citing incident ids "
              "in parentheses. Use only the ids and numbers above.")
    text = llm.complete(SYSTEM, user)
    return re.sub(r"\bINC[\u2010-\u2015\u2212](\d{4})\b", r"INC-\1", text)


def investigate(alert: dict, incidents: list[dict], memory: Memory | None, use_memory: bool = True,
                llm=None, exclude: str | None = None) -> dict:
    warnings: list[str] = []
    if not use_memory:
        steps = GENERIC.get(alert.get("rule"), GENERIC_DEFAULT)
        narrative, source = generic_template(alert, steps), "template"
        if llm is not None:
            try:
                text = llm.complete(SYSTEM, f"Alert: {alert['title']} on {alert['service']}. Signal: "
                                            f"{alert.get('signal', '')}\nGive generic first-response advice.")
                if not INC_RE.search(text):
                    narrative, source = text, "llm"
            except Exception as exc:
                warnings.append(f"LLM unavailable, used template: {exc}")
        return {"use_memory": False, "deja_vu": False, "matches": [], "recalled_ids": [],
                "do_first": [{"action": s, "worked": None, "tried": 0, "rate": None, "worked_in": [], "failed_in": []}
                             for s in steps],
                "avoid": [], "narrative": narrative, "narrative_source": source, "hint": None,
                "warnings": warnings, "query": None}

    query = build_query(alert)
    recalled: list[str] = []
    facts: list[dict] = []
    if memory is not None:
        try:
            res = memory.recall(query)
            recalled, facts = res["incident_ids"], res.get("facts", [])
        except Exception as exc:  # MemoryUnavailable or anything unexpected: degrade, never break
            warnings.append(f"Memory recall failed; using the incident store only. ({exc})")
    else:
        warnings.append("No memory backend configured; using the incident store only.")

    backend = getattr(memory, "name", "none")
    label = "recalled by Hindsight" if backend.startswith("hindsight") else f"recalled from memory ({backend})"
    matches = find_similar(alert, incidents, set(recalled), exclude=exclude, recall_label=label)
    ranked = rank_actions(matches)
    hint = prior_change_hint(alert, matches)
    match_ids = {m["id"] for m in matches}

    if matches:
        narrative, source = template_narrative(alert, matches, ranked, hint), "template"
        if llm is not None:
            try:
                text = llm_narrative(llm, alert, matches, ranked, hint)
                cited = set(INC_RE.findall(text))
                if cited and cited <= match_ids:
                    narrative, source = text, "llm"
                else:
                    warnings.append("LLM narrative cited no or unknown incidents; used template.")
            except Exception as exc:
                warnings.append(f"LLM unavailable, used template: {exc}")
    else:
        narrative = "No similar incidents in memory. " + generic_template(
            alert, GENERIC.get(alert.get("rule"), GENERIC_DEFAULT))
        source = "template"

    return {
        "use_memory": True,
        "deja_vu": bool(matches),
        "matches": [{"id": m["id"], "score": m["score"], "why": m["why"], "title": m["incident"]["title"],
                     "opened_at": m["incident"]["opened_at"], "service": m["incident"]["service"],
                     "type": m["incident"]["type"], "root_cause": m["incident"].get("root_cause", ""),
                     "actions": m["incident"].get("actions", [])} for m in matches],
        "recalled_ids": recalled,
        "memory_backend": backend,
        "recalled_facts": facts[:6],
        "do_first": ranked["do_first"] if matches else
            [{"action": s, "worked": None, "tried": 0, "rate": None, "worked_in": [], "failed_in": []}
             for s in GENERIC.get(alert.get("rule"), GENERIC_DEFAULT)],
        "avoid": ranked["avoid"],
        "narrative": narrative,
        "narrative_source": source,
        "hint": hint,
        "warnings": warnings,
        "query": query,
    }
