"""Two DejaVu agents for a Band room: SecurityAgent and ReliabilityAgent.

Both agents read and write the SAME Hindsight bank (DEJAVU_BANK), so what one learns the other
can recall. Each answers alerts in its own domain and hands off to the other with an @mention
(the `mentions` list of `tools.send_message`, which is what triggers an agent in Band):

  * SecurityAgent answers attacks. If the attacked code has outage history, it mentions
    ReliabilityAgent so the code-risk side is covered.
  * ReliabilityAgent answers outages. If the alert is an attack, it hands off to SecurityAgent.
  * A message from the other agent is never handed back, which prevents ping-pong loops.

Built on band-sdk 8.1.0 (pinned): `band.core.SimpleAdapter.on_message`, `tools.send_message(content,
mentions)` and `Agent.from_config(name, adapter=...)`. These were checked with inspect.signature
against the installed package and match https://docs.band.ai/advanced/creating-adapters.

Setup:
  1. In Band (https://app.band.ai > Agents > Connect remote agent), create "SecurityAgent" and
     "ReliabilityAgent". Copy each ID and API key (the key is shown only once).
  2. Put them in agent_config.yaml (git-ignored), see agent_config.example.yaml.
  3. Run each agent in its own terminal:
        python band_agents.py security
        python band_agents.py reliability
  4. In a Band room, add both agents and mention one, e.g.
        "@SecurityAgent credential stuffing on /api/v1/login from AS14061"
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()  # Agent.create() does not read .env itself
except ImportError:
    pass

import analyzer
import detector
import prcheck
import sim_events
from memory_backend import get_memory
from store import Store

ROOT = Path(__file__).parent
CONFIG_PATH = Path(os.environ.get("BAND_AGENT_CONFIG", ROOT / "agent_config.yaml"))
ROLES = {"security": "security_agent", "reliability": "reliability_agent"}

# Message text -> simulated scenario. The agents reuse the same detector and analyzer as the app.
KEYWORDS = [
    ("password_spray", ("spray",)),
    ("credential_stuffing", ("stuffing", "failed login", "brute", "login burst")),
    ("port_scan", ("port scan", "portscan", "syn flood", "scan")),
    ("checkout_500s", ("pool", "queuepool", "checkout", "connection pool")),
    ("api_5xx_spike", ("5xx", "502", "503", "error spike", "gateway")),
]


def classify(text: str) -> str | None:
    t = text.lower()
    for scenario, words in KEYWORDS:
        if any(w in t for w in words):
            return scenario
    return None


def format_answer(alert: dict, result: dict) -> str:
    lines = [f"{alert['title']} ({alert['service']})", result["narrative"]]
    if result["do_first"]:
        lines.append("Do first: " + "; ".join(
            f"{a['action']} ({a['worked']}/{a['tried']})" if a["tried"] else a["action"] for a in result["do_first"]))
    if result["avoid"]:
        lines.append("We tried this before and it failed: " + "; ".join(
            f"{a['action']} (failed {a['tried']}/{a['tried']}, {', '.join(a['failed_in'])})" for a in result["avoid"]))
    for w in result["warnings"]:
        lines.append(f"(warning: {w})")
    lines.append("Recommendation only; a human decides.")
    return "\n".join(lines)


def decide(role: str, text: str, from_agent: bool, store: Store, memory, llm=None) -> dict:
    """Pure decision logic (no Band I/O) so it can be tested offline.

    Returns {"reply": str, "handoff": str | None}. handoff is the role to mention next.
    """
    scenario = classify(text)
    if scenario is None:
        return {"reply": "I could not tell which incident this is. Describe the alert, e.g. "
                         "'checkout 500s, connection pool exhausted' or 'credential stuffing from AS14061'.",
                "handoff": None}
    alert = detector.primary_alert(sim_events.generate(scenario))
    mine = (alert["type"] == "security") == (role == "security")
    if not mine:
        if from_agent:
            return {"reply": f"This is a {alert['type']} incident; already routed, not handing back.", "handoff": None}
        other = "security" if role == "reliability" else "reliability"
        return {"reply": f"This looks like a {alert['type']} incident ({alert['title']}). "
                         f"Handing off to the {other.capitalize()}Agent.", "handoff": other}
    result = analyzer.investigate(alert, store.all(), memory, use_memory=True, llm=llm)
    reply = format_answer(alert, result)
    handoff = None
    if role == "security" and not from_agent:
        # Link the attacker to our own code: does the attacked code have outage history?
        pr = prcheck.check(alert.get("files", []), [i for i in store.all() if i["type"] == "outage"])
        if pr["findings"]:
            f = pr["findings"][0]
            ids = ", ".join(h["id"] for h in f["incidents"])
            reply += (f"\n{f['file']} also has outage history ({ids}). Asking ReliabilityAgent to review "
                      f"code risk before anyone ships a fix there.")
            handoff = "reliability"
    return {"reply": reply, "handoff": handoff}


def load_ids(config_path: Path = CONFIG_PATH) -> dict[str, str]:
    """agent_id per role, so an agent can mention its peer by exact id."""
    import yaml  # PyYAML is a band-sdk dependency

    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return {role: (data.get(key) or {}).get("agent_id", "") for role, key in ROLES.items()}


def make_adapter(role: str, store: Store, memory, peer_ids: dict[str, str], llm=None):
    from band.core import SimpleAdapter

    class DejaVuAdapter(SimpleAdapter):
        async def on_message(self, msg, tools, history, participants_msg, contacts_msg, *,
                             is_session_bootstrap, room_id):
            from_agent = (msg.sender_type or "").lower() == "agent"
            try:
                out = await asyncio.to_thread(decide, role, msg.content or "", from_agent, store, memory, llm)
            except Exception as exc:  # never crash the agent loop
                out = {"reply": f"DejaVu could not investigate this alert: {exc}", "handoff": None}
            mentions = [msg.sender_id]
            if out["handoff"] and peer_ids.get(out["handoff"]):
                mentions.append(peer_ids[out["handoff"]])
            await tools.send_message(out["reply"], mentions=mentions)

    return DejaVuAdapter()


async def run_agent(role: str) -> None:
    from band import Agent

    from llm import get_llm

    store, memory = Store(), get_memory()
    if memory.name == "mock":
        memory.retain_many(store.resolved())
        print("warning: HINDSIGHT_BASE_URL not set; using offline mock memory (not shared between agents)")
    peers = load_ids()
    adapter = make_adapter(role, store, memory, peers, llm=get_llm())
    agent = Agent.from_config(ROLES[role], adapter=adapter, config_path=CONFIG_PATH)
    print(f"{role} agent connected with memory={memory.name} bank={getattr(memory, 'bank_id', '-')}")
    await agent.run()


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a DejaVu agent in Band")
    ap.add_argument("role", choices=sorted(ROLES))
    args = ap.parse_args()
    if not CONFIG_PATH.exists():
        print(f"missing {CONFIG_PATH}; copy agent_config.example.yaml and fill in the Band IDs and keys")
        return 2
    asyncio.run(run_agent(args.role))
    return 0


if __name__ == "__main__":
    sys.exit(main())
