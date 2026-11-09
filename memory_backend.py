"""Long-term memory for DejaVu.

Two implementations share one small interface:

* HindsightMemory - the real backend. Uses hindsight-client 1.2.0 (`Hindsight.create_bank`,
  `retain`, `retain_batch`, `recall`, `reflect`). Every parameter used below was checked
  against `inspect.signature` of the installed client.
* MockMemory - an in-process keyword index with the same interface, for tests and offline use.

Every retained text contains the incident id (for example "INC-0016") so recalled facts and
chunks can be mapped back to structured records in the JSON store.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from datetime import datetime, timezone

INC_RE = re.compile(r"\bINC-\d{4}\b")

MISSION = (
    "You are the long-term memory of an incident-response team. Remember every outage and "
    "security incident: the service, the files involved, the attacker ASN, the change that "
    "preceded it, and above all which remediation actions worked and which failed. Always keep "
    "the incident id (INC-xxxx) attached to each fact."
)

WORD_RE = re.compile(r"[a-z0-9_./-]{3,}")
STOPWORDS = {
    "the", "and", "for", "from", "with", "into", "that", "this", "was", "were", "after", "before",
    "incident", "opened", "actions", "action", "worked", "failed", "note", "root", "cause", "files",
    "service", "signal", "type", "severity", "prior", "change", "hours", "none", "status", "resolved",
}


class MemoryUnavailable(Exception):
    """Raised when the memory backend cannot complete a call."""


# ---------- text rendering ----------
def incident_to_text(inc: dict) -> str:
    """Render an incident as a postmortem paragraph. The id is repeated so every chunk keeps it."""
    iid = inc["id"]
    lines = [
        f"Incident {iid} ({inc['type']}, {inc.get('severity', 'SEV?')}) on service {inc['service']}, "
        f"opened {inc['opened_at']}, status {inc.get('status', 'resolved')}.",
        f"{iid} title: {inc['title']}.",
        f"{iid} signal: {inc.get('signal', '')}",
    ]
    if inc.get("files"):
        lines.append(f"{iid} files involved: {', '.join(inc['files'])}.")
    if inc.get("asn"):
        lines.append(f"{iid} attacker ASN: {inc['asn']}.")
    pc = inc.get("prior_change")
    if pc:
        lines.append(f"{iid} was preceded {pc['hours_before']}h earlier by the change "
                     f"\"{pc['summary']}\" touching {', '.join(pc['files'])}.")
    if inc.get("root_cause"):
        lines.append(f"{iid} root cause: {inc['root_cause']}")
    for a in inc.get("actions", []):
        verdict = "WORKED" if a["worked"] else "FAILED"
        note = f" ({a['note']})" if a.get("note") else ""
        lines.append(f"In {iid} the action \"{a['action']}\" {verdict}{note}.")
    return "\n".join(lines)


def verdict_to_text(inc: dict, action: str, worked: bool, note: str = "") -> str:
    verdict = "WORKED" if worked else "FAILED"
    extra = f" Note: {note}" if note else ""
    return (f"During incident {inc['id']} ({inc['type']} on {inc['service']}: {inc['title']}) the "
            f"engineer marked the action \"{action}\" as {verdict}.{extra}")


def incident_tags(inc: dict) -> list[str]:
    tags = [f"type:{inc['type']}", f"svc:{inc['service']}"]
    tags += [f"file:{f}" for f in inc.get("files", [])]
    if inc.get("asn"):
        tags.append(f"asn:{inc['asn']}")
    return tags


def _ts(opened_at: str) -> str:
    """ISO-8601 string with timezone (the client accepts `datetime | str`; a string serialises safely)."""
    dt = datetime.fromisoformat(opened_at)
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def extract_ids(texts: list[str]) -> list[str]:
    """Incident ids in order of first appearance."""
    seen: dict[str, None] = {}
    for t in texts:
        for m in INC_RE.findall(t or ""):
            seen.setdefault(m, None)
    return list(seen)


# ---------- interface ----------
class Memory:
    name = "base"

    def ensure_bank(self) -> None: ...
    def retain_incident(self, inc: dict, retain_async: bool = False) -> None: ...
    def retain_many(self, incidents: list[dict], retain_async: bool = True) -> None:
        for inc in incidents:
            self.retain_incident(inc, retain_async=retain_async)
    def retain_verdict(self, inc: dict, action: str, worked: bool, note: str = "") -> None: ...
    def recall(self, query: str, max_tokens: int = 3000) -> dict: ...
    def reflect(self, query: str) -> str: ...
    def reset(self) -> None: ...


# ---------- Hindsight ----------
class HindsightMemory(Memory):
    name = "hindsight"

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 bank_id: str | None = None, timeout: float = 60.0):
        from hindsight_client import Hindsight  # imported lazily so tests run without network

        self.base_url = base_url or os.environ.get("HINDSIGHT_BASE_URL", "")
        if not self.base_url:
            raise MemoryUnavailable("HINDSIGHT_BASE_URL is not set")
        self.bank_id = bank_id or os.environ.get("DEJAVU_BANK", "dejavu-prod")
        self.client = Hindsight(base_url=self.base_url,
                                api_key=api_key or os.environ.get("HINDSIGHT_API_KEY") or None,
                                timeout=timeout)

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # network, auth, server errors
            raise MemoryUnavailable(f"Hindsight {getattr(fn, '__name__', 'call')} failed: {exc}") from exc

    def ensure_bank(self) -> None:
        # create_bank maps to create_or_update_bank on the server, so it is safe to call repeatedly.
        self._call(self.client.create_bank, bank_id=self.bank_id, name="DejaVu incident memory",
                   mission=MISSION, disposition_skepticism=4, disposition_literalism=4,
                   disposition_empathy=2)

    def _item(self, inc: dict) -> dict:
        return {
            "content": incident_to_text(inc),
            "timestamp": _ts(inc["opened_at"]),
            "context": "incident postmortem",
            "document_id": inc["id"],
            "tags": incident_tags(inc),
            "metadata": {"incident_id": inc["id"], "type": inc["type"], "service": inc["service"]},
        }

    def retain_incident(self, inc: dict, retain_async: bool = False) -> None:
        item = self._item(inc)
        content = item.pop("content")
        self._call(self.client.retain, bank_id=self.bank_id, content=content,
                   update_mode="replace", retain_async=retain_async, **item)

    def retain_many(self, incidents: list[dict], retain_async: bool = True) -> None:
        items = [self._item(i) for i in incidents]
        self._call(self.client.retain_batch, bank_id=self.bank_id, items=items,
                   retain_async=retain_async)

    def retain_verdict(self, inc: dict, action: str, worked: bool, note: str = "") -> None:
        self._call(self.client.retain, bank_id=self.bank_id,
                   content=verdict_to_text(inc, action, worked, note),
                   timestamp=datetime.now(timezone.utc).isoformat(), context="remediation verdict",
                   tags=incident_tags(inc) + [f"action:{action}"],
                   metadata={"incident_id": inc["id"], "action": action,
                             "worked": "true" if worked else "false"})

    def recall(self, query: str, max_tokens: int = 3000) -> dict:
        res = self._call(self.client.recall, bank_id=self.bank_id, query=query,
                         max_tokens=max_tokens, budget="mid", include_chunks=True)
        texts, facts = [], []
        for r in res.results or []:
            meta_id = (r.metadata or {}).get("incident_id") if r.metadata else None
            ids = extract_ids([r.text, r.document_id or "", meta_id or ""])
            facts.append({"text": r.text, "incident_ids": ids})
            texts += [r.text, r.document_id or "", meta_id or ""]
        for ch in (res.chunks or {}).values():
            texts.append(ch.text)
        return {"incident_ids": extract_ids(texts), "facts": facts}

    def reflect(self, query: str) -> str:
        ans = self._call(self.client.reflect, bank_id=self.bank_id, query=query, budget="low")
        return ans.text or ""

    def reset(self) -> None:
        # The live bank is long-term memory; resetting the app's state does not wipe it.
        pass


# ---------- Mock ----------
def _tokens(text: str) -> list[str]:
    return [w.strip("./-") for w in WORD_RE.findall(text.lower()) if w not in STOPWORDS]


class MockMemory(Memory):
    """Keyword-overlap memory. Good enough to exercise the full flow without a network."""

    name = "mock"

    def __init__(self):
        self.docs: list[dict] = []

    def ensure_bank(self) -> None:
        pass

    def retain_incident(self, inc: dict, retain_async: bool = False) -> None:
        self.docs = [d for d in self.docs if d.get("document_id") != inc["id"]]
        self.docs.append({"document_id": inc["id"], "text": incident_to_text(inc)})

    def retain_verdict(self, inc: dict, action: str, worked: bool, note: str = "") -> None:
        self.docs.append({"document_id": None, "text": verdict_to_text(inc, action, worked, note)})

    def recall(self, query: str, max_tokens: int = 3000) -> dict:
        q = Counter(_tokens(query))
        scored = []
        for d in self.docs:
            toks = set(_tokens(d["text"]))
            s = sum(1 for w in q if w in toks)
            if s >= 3:
                scored.append((s, d))
        scored.sort(key=lambda x: -x[0])
        top = [d for _, d in scored[:8]]
        facts = [{"text": d["text"].split("\n")[0], "incident_ids": extract_ids([d["text"]])} for d in top]
        return {"incident_ids": extract_ids([d["text"] for d in top]), "facts": facts}

    def reflect(self, query: str) -> str:
        fails: Counter = Counter()
        works: Counter = Counter()
        for d in self.docs:
            for m in re.finditer(r'the action "([^"]+)" (WORKED|FAILED)', d["text"]):
                (works if m.group(2) == "WORKED" else fails)[m.group(1)] += 1
        always_fail = [a for a, n in fails.most_common() if works[a] == 0 and n >= 2]
        best = [a for a, n in works.most_common(3)]
        if not self.docs:
            return "No memories retained yet."
        return (f"(offline mock reflect over {len(self.docs)} memories) Fixes that keep failing: "
                f"{', '.join(always_fail) or 'none'}. Fixes that most often worked: {', '.join(best) or 'none'}.")

    def reset(self) -> None:
        self.docs = []


def get_memory() -> Memory:
    """Hindsight when configured (or DEJAVU_MEMORY=hindsight), otherwise the offline mock."""
    mode = os.environ.get("DEJAVU_MEMORY", "").lower()
    if mode == "mock":
        return MockMemory()
    if mode == "hindsight" or os.environ.get("HINDSIGHT_BASE_URL"):
        return HindsightMemory()
    return MockMemory()
