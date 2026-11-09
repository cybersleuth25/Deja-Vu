"""Learning curve: the same Checkout 500s outage handled with 0, 5 and 20 incidents of memory.

Memory at step N = the first N incidents in chronological order (INC-0001 .. INC-000N). Both the
structured store and the recall backend only see those N incidents.

    python demo_curve.py                 # offline mock recall (deterministic)
    python demo_curve.py --live          # recall from the Hindsight bank in DEJAVU_BANK; recalled ids
                                         # outside the first N are discarded so the curve stays honest
    python demo_curve.py --steps 0 5 10 20 32
"""
from __future__ import annotations

import argparse
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import analyzer
import detector
import sim_events
from memory_backend import HindsightMemory, MockMemory
from store import load_seed


class WindowedMemory:
    """Wrap a live backend so recall only reports incidents inside the memory window."""

    name = "hindsight-windowed"

    def __init__(self, inner, allowed: set[str]):
        self.inner, self.allowed = inner, allowed

    def recall(self, query: str, max_tokens: int = 3000) -> dict:
        res = self.inner.recall(query, max_tokens=max_tokens)
        return {"incident_ids": [i for i in res["incident_ids"] if i in self.allowed], "facts": []}


def run(steps: list[int], live: bool = False, scenario: str = "checkout_500s") -> list[dict]:
    history = sorted(load_seed(), key=lambda i: i["opened_at"])
    alert = detector.primary_alert(sim_events.generate(scenario))
    live_mem = HindsightMemory() if live else None
    rows = []
    for n in steps:
        window = history[:n]
        if live_mem:
            mem = WindowedMemory(live_mem, {i["id"] for i in window})
        else:
            mem = MockMemory()
            mem.retain_many(window)
        result = analyzer.investigate(alert, window, mem, use_memory=True, llm=None)
        rows.append({"n": n, **result})
    return rows


def show(rows: list[dict], alert_title: str) -> None:
    print(f"Alert: {alert_title}\n")
    for r in rows:
        print("=" * 78)
        print(f"Memory: {r['n']} incidents" + ("  ->  Déjà vu detected" if r["deja_vu"] else ""))
        print("-" * 78)
        print("Matched:", ", ".join(m["id"] for m in r["matches"]) or "none")
        print("Do first:", "; ".join(
            f"{a['action']} ({a['worked']}/{a['tried']})" if a["tried"] else f"{a['action']} (generic)"
            for a in r["do_first"]) or "none")
        print("Avoid:   ", "; ".join(f"{a['action']} (failed {a['tried']}/{a['tried']})" for a in r["avoid"]) or "none")
        print("Answer:  ", r["narrative"])
        for w in r["warnings"]:
            print("Warning: ", w)
        print()


def main() -> None:
    ap = argparse.ArgumentParser(description="0 / 5 / 20 incident learning curve")
    ap.add_argument("--steps", type=int, nargs="+", default=[0, 5, 20])
    ap.add_argument("--live", action="store_true", help="recall from the live Hindsight bank")
    ap.add_argument("--scenario", default="checkout_500s", choices=[s for s in sim_events.SCENARIOS if s != "normal"])
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    rows = run(args.steps, live=args.live, scenario=args.scenario)
    show(rows, detector.primary_alert(sim_events.generate(args.scenario))["title"])


if __name__ == "__main__":
    main()
