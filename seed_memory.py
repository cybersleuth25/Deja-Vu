"""Seed the Hindsight bank with the incident history in data/incidents.json.

    python seed_memory.py            # create/update the bank, retain all resolved incidents (async batch)
    python seed_memory.py --sync     # retain one by one and wait for each (slower, easier to debug)
    python seed_memory.py --check    # only run a recall and show which incident ids come back

Reads HINDSIGHT_BASE_URL, HINDSIGHT_API_KEY and DEJAVU_BANK from the environment (or .env).
Hindsight consolidates observations in the background; wait about a minute before using reflect.
"""
from __future__ import annotations

import argparse
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from memory_backend import HindsightMemory, MemoryUnavailable
from store import load_seed

CHECK_QUERY = ("Checkout 500s on payments-api, QueuePool limit reached in db/pool.py. "
               "Which fixes worked and which failed before?")


def check(mem: HindsightMemory) -> int:
    res = mem.recall(CHECK_QUERY)
    print(f"recall returned {len(res['facts'])} facts; incident ids: {', '.join(res['incident_ids']) or 'none'}")
    for f in res["facts"][:5]:
        print("  -", f["text"][:140])
    return 0 if res["incident_ids"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed DejaVu incident memory in Hindsight")
    ap.add_argument("--sync", action="store_true", help="retain incidents one at a time, synchronously")
    ap.add_argument("--check", action="store_true", help="only run a recall check")
    ap.add_argument("--bank", help="override DEJAVU_BANK")
    args = ap.parse_args()
    try:
        mem = HindsightMemory(bank_id=args.bank)
        print(f"Hindsight at {mem.base_url}, bank '{mem.bank_id}'")
        if args.check:
            return check(mem)
        mem.ensure_bank()
        incidents = [i for i in load_seed() if i["status"] == "resolved"]
        if args.sync:
            for n, inc in enumerate(incidents, 1):
                mem.retain_incident(inc)
                print(f"  [{n}/{len(incidents)}] retained {inc['id']}: {inc['title']}")
        else:
            mem.retain_many(incidents, retain_async=True)
            print(f"queued {len(incidents)} incidents for async retain")
        print("Done. Give Hindsight about a minute to extract and consolidate, then run: "
              "python seed_memory.py --check")
        return 0
    except MemoryUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
