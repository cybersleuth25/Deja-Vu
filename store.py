"""JSON system of record.

data/incidents.json is the seed history (read-only at runtime). data/state.json holds the live
copy, including incidents opened from the UI. Success rates are computed from this store, so
they are exact and do not depend on the memory backend being reachable.
"""
from __future__ import annotations

import copy
import json
import threading
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent
SEED_PATH = ROOT / "data" / "incidents.json"
STATE_PATH = ROOT / "data" / "state.json"


def load_seed(path: Path = SEED_PATH) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


class Store:
    def __init__(self, seed_path: Path = SEED_PATH, state_path: Path | None = STATE_PATH):
        self.seed_path = Path(seed_path)
        self.state_path = Path(state_path) if state_path else None  # None = in-memory only
        self._lock = threading.Lock()
        self.incidents: list[dict] = []
        self._load()

    # ---- persistence ----
    def _load(self) -> None:
        if self.state_path and self.state_path.exists():
            self.incidents = json.loads(self.state_path.read_text(encoding="utf-8"))["incidents"]
        else:
            self.incidents = load_seed(self.seed_path)
            self._save()

    def _save(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"incidents": self.incidents}, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    def reset(self) -> None:
        with self._lock:
            self.incidents = load_seed(self.seed_path)
            self._save()

    # ---- queries ----
    # Reads take the lock too: copying while another request mutates the list could see a
    # half-applied change.
    def all(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self.incidents)

    def resolved(self) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(i) for i in self.incidents if i.get("status") == "resolved"]

    def get(self, iid: str) -> dict | None:
        with self._lock:
            for i in self.incidents:
                if i["id"] == iid:
                    return copy.deepcopy(i)
        return None

    # ---- mutations ----
    def _next_id(self) -> str:
        n = max((int(i["id"].split("-")[1]) for i in self.incidents), default=0) + 1
        return f"INC-{n:04d}"

    def create(self, alert: dict, opened_at: str | None = None) -> dict:
        with self._lock:
            inc = {
                "id": self._next_id(),
                "type": alert["type"],
                "status": "open",
                "opened_at": opened_at or datetime.now().strftime("%Y-%m-%dT%H:%M"),
                "service": alert["service"],
                "title": alert["title"],
                "signal": alert["signal"],
                "files": list(alert.get("files", [])),
                "root_cause": "",
                "actions": [],
                "severity": alert.get("severity", "SEV2"),
                "prior_change": alert.get("prior_change"),
                "asn": alert.get("asn"),
                "rule": alert.get("rule"),
            }
            self.incidents.append(inc)
            self._save()
            return copy.deepcopy(inc)

    def update(self, iid: str, **fields) -> dict:
        with self._lock:
            for i in self.incidents:
                if i["id"] == iid:
                    i.update(fields)
                    self._save()
                    return copy.deepcopy(i)
        raise KeyError(iid)

    def record_action(self, iid: str, action: str, worked: bool, note: str = "") -> dict:
        """Upsert a verdict for one action (one row per canonical action string)."""
        with self._lock:
            for i in self.incidents:
                if i["id"] == iid:
                    i["actions"] = [a for a in i["actions"] if a["action"] != action]
                    i["actions"].append({"action": action, "worked": bool(worked), "note": note})
                    self._save()
                    return copy.deepcopy(i)
        raise KeyError(iid)
