import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from memory_backend import MockMemory  # noqa: E402
from store import Store, load_seed  # noqa: E402


@pytest.fixture
def incidents():
    return load_seed()


@pytest.fixture
def store():
    return Store(state_path=None)  # in-memory: tests never touch data/state.json


@pytest.fixture
def memory(store):
    m = MockMemory()
    m.retain_many(store.resolved())
    return m


@pytest.fixture
def client(store, memory):
    return create_app(store=store, memory=memory, llm=None).test_client()
