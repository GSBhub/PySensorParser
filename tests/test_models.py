"""Unit tests for models.py — no r2pipe required."""
from pysensorparser.models import Callee, Caller


def test_callee_stores_addresses():
    c = Callee(0x9300, 0x93C1)
    assert c.source_addr == 0x9300
    assert c.dest_addr == 0x93C1


def test_caller_initialises_with_one_site():
    callee = Callee(0x9300, 0x93C1)
    caller = Caller(0x9300, callee)
    assert caller.base_addr == 0x9300
    assert caller.count == 1
    assert 0x9300 in caller.callees


def test_caller_push_increments_count():
    callee1 = Callee(0x9300, 0x93C1)
    callee2 = Callee(0x9305, 0x93C2)
    caller = Caller(0x9300, callee1)
    caller.push(0x9305, callee2)
    assert caller.count == 2
    assert 0x9305 in caller.callees


def test_caller_push_duplicate_does_not_increment():
    callee1 = Callee(0x9300, 0x93C1)
    caller = Caller(0x9300, callee1)
    caller.push(0x9300, callee1)  # same address
    assert caller.count == 1


def test_caller_push_multiple_unique_sites():
    base = Callee(0x9300, 0x93C1)
    caller = Caller(0x9300, base)
    for i in range(1, 5):
        caller.push(0x9300 + i * 5, Callee(0x9300 + i * 5, 0x93C1 + i))
    assert caller.count == 5
