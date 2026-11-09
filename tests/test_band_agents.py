"""Band agents: decision logic and hand-off mentions, tested without a Band connection."""
import asyncio
from datetime import datetime, timezone

import pytest

import band_agents

band = pytest.importorskip("band")
from band.core.types import PlatformMessage  # noqa: E402

PEERS = {"security": "sec-agent-id", "reliability": "rel-agent-id"}


def test_security_agent_answers_attack_and_hands_off_code_risk(store, memory):
    out = band_agents.decide("security", "credential stuffing on /api/v1/login from AS14061", False, store, memory)
    assert "Block ASN at WAF" in out["reply"] and "Per-IP rate limit" in out["reply"]
    assert "INC-0002" in out["reply"]
    assert out["handoff"] is None  # auth/login.py has no outage history in the seed data


def test_reliability_agent_hands_attack_to_security(store, memory):
    out = band_agents.decide("reliability", "port scan on the edge lb", False, store, memory)
    assert out["handoff"] == "security"


def test_security_agent_hands_outage_to_reliability(store, memory):
    out = band_agents.decide("security", "checkout 500s, connection pool exhausted", False, store, memory)
    assert out["handoff"] == "reliability"


def test_no_hand_back_between_agents(store, memory):
    out = band_agents.decide("reliability", "credential stuffing burst", True, store, memory)
    assert out["handoff"] is None


def test_reliability_agent_answers_outage(store, memory):
    out = band_agents.decide("reliability", "QueuePool limit reached, checkout 500s", False, store, memory)
    assert "Roll back pool config" in out["reply"] and "Restart connection pool" in out["reply"]


class FakeTools:
    def __init__(self):
        self.sent = []

    async def send_message(self, content, mentions=None):
        self.sent.append((content, mentions))


def _msg(text, sender_type="User", sender_id="human-1"):
    return PlatformMessage(id="m1", room_id="r1", content=text, sender_id=sender_id, sender_type=sender_type,
                           sender_name="On-call", message_type="text", metadata={},
                           created_at=datetime.now(timezone.utc))


def test_adapter_mentions_sender_and_peer_on_handoff(store, memory):
    adapter = band_agents.make_adapter("reliability", store, memory, PEERS)
    tools = FakeTools()
    asyncio.run(adapter.on_message(_msg("credential stuffing from AS14061"), tools, [], None, None,
                                   is_session_bootstrap=False, room_id="r1"))
    content, mentions = tools.sent[0]
    assert mentions == ["human-1", "sec-agent-id"] and "Handing off" in content


def test_adapter_replies_only_to_sender_without_handoff(store, memory):
    adapter = band_agents.make_adapter("security", store, memory, PEERS)
    tools = FakeTools()
    asyncio.run(adapter.on_message(_msg("credential stuffing from AS14061", "Agent", "rel-agent-id"), tools, [],
                                   None, None, is_session_bootstrap=False, room_id="r1"))
    assert tools.sent[0][1] == ["rel-agent-id"]
