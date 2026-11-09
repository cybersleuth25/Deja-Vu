"""HindsightMemory against a fake client whose methods enforce the REAL hindsight-client signatures.

If memory_backend passes a parameter the installed client does not accept, inspect.signature().bind
raises TypeError and these tests fail.
"""
import inspect
from types import SimpleNamespace

import pytest
from hindsight_client import Hindsight

import memory_backend
from memory_backend import HindsightMemory, MemoryUnavailable, extract_ids, incident_to_text


class SignatureCheckedClient:
    def __init__(self, recall_response=None, fail=False):
        self.calls = []
        self.recall_response = recall_response
        self.fail = fail

    def _record(self, name, args, kwargs):
        inspect.signature(getattr(Hindsight, name)).bind(None, *args, **kwargs)  # None stands in for self
        self.calls.append((name, kwargs))
        if self.fail:
            raise ConnectionError("connection refused")

    def create_bank(self, *a, **k):
        self._record("create_bank", a, k)

    def retain(self, *a, **k):
        self._record("retain", a, k)

    def retain_batch(self, *a, **k):
        self._record("retain_batch", a, k)

    def recall(self, *a, **k):
        self._record("recall", a, k)
        return self.recall_response

    def reflect(self, *a, **k):
        self._record("reflect", a, k)
        return SimpleNamespace(text="Restart connection pool failed in INC-0004 and INC-0009.")


@pytest.fixture
def hs(monkeypatch):
    monkeypatch.setenv("HINDSIGHT_BASE_URL", "http://hindsight.invalid")
    monkeypatch.setenv("DEJAVU_BANK", "dejavu-test")
    mem = HindsightMemory()
    return mem


def test_calls_match_installed_client_signatures(hs, incidents):
    resp = SimpleNamespace(
        results=[SimpleNamespace(text="In INC-0020 the action Restart connection pool FAILED", document_id="INC-0020",
                                 metadata={"incident_id": "INC-0020"}),
                 SimpleNamespace(text="Pool config rollback worked", document_id=None, metadata={"incident_id": "INC-0009"})],
        chunks={"c1": SimpleNamespace(text="Incident INC-0004 (outage, SEV1) ...")},
    )
    hs.client = SignatureCheckedClient(resp)
    hs.ensure_bank()
    hs.retain_incident(incidents[0])
    hs.retain_many(incidents[:3])
    hs.retain_verdict(incidents[3], "Roll back pool config", True, "worked again")
    out = hs.recall("checkout pool exhausted")
    assert out["incident_ids"] == ["INC-0020", "INC-0009", "INC-0004"]
    assert "INC-0004" in hs.reflect("Which fixes keep failing?")

    names = [c[0] for c in hs.client.calls]
    assert names == ["create_bank", "retain", "retain_batch", "retain", "recall", "reflect"]
    recall_kwargs = hs.client.calls[4][1]
    assert recall_kwargs["include_chunks"] is True and recall_kwargs["bank_id"] == "dejavu-test"
    retain_kwargs = hs.client.calls[1][1]
    assert retain_kwargs["document_id"] == "INC-0001" and "INC-0001" in retain_kwargs["content"]
    assert retain_kwargs["metadata"]["incident_id"] == "INC-0001"
    batch_items = hs.client.calls[2][1]["items"]
    assert all(i["document_id"] in i["content"] for i in batch_items)


def test_errors_are_wrapped(hs, incidents):
    hs.client = SignatureCheckedClient(fail=True)
    with pytest.raises(MemoryUnavailable):
        hs.retain_verdict(incidents[0], "Restart service", False)
    with pytest.raises(MemoryUnavailable):
        hs.recall("x")


def test_missing_base_url_raises(monkeypatch):
    monkeypatch.delenv("HINDSIGHT_BASE_URL", raising=False)
    with pytest.raises(MemoryUnavailable):
        HindsightMemory()


def test_get_memory_defaults_to_mock_without_config(monkeypatch):
    monkeypatch.delenv("HINDSIGHT_BASE_URL", raising=False)
    monkeypatch.delenv("DEJAVU_MEMORY", raising=False)
    assert memory_backend.get_memory().name == "mock"


def test_every_retained_text_carries_its_id(incidents):
    for inc in incidents:
        text = incident_to_text(inc)
        assert all(inc["id"] in line for line in text.splitlines())
        assert extract_ids([text])[0] == inc["id"]
