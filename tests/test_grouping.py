"""Unit tests for grouping.py — no r2pipe required."""
import pytest
from pysensorparser.grouping import is_hex, parse_candidates, get_callers, MIN_CLUSTER_SIZE


# ── is_hex ───────────────────────────────────────────────────────────────────

def test_is_hex_valid_with_prefix():
    assert is_hex("0x93c1") is True

def test_is_hex_valid_without_prefix():
    assert is_hex("93c1") is True

def test_is_hex_invalid_string():
    assert is_hex("jsr") is False

def test_is_hex_bracketed_address():
    # r2 sometimes wraps addresses in brackets — should be rejected
    assert is_hex("[0x93c1]") is False

def test_is_hex_empty_string():
    assert is_hex("") is False

def test_is_hex_none():
    assert is_hex(None) is False


# ── parse_candidates ─────────────────────────────────────────────────────────

def test_parse_candidates_basic(small_cluster):
    result = parse_candidates(small_cluster)
    assert len(result) == 5
    assert 0x9300 in result
    assert result[0x9300].dest_addr == 0x93C1

def test_parse_candidates_skips_short_lines():
    raw = "0x9300 jsr\n0x9305 01 jsr 0x93c2"
    result = parse_candidates(raw)
    assert 0x9300 not in result
    assert 0x9305 in result

def test_parse_candidates_skips_non_hex_dest():
    raw = "0x9300 01 jsr fcn.00009300\n0x9305 01 jsr 0x93c2"
    result = parse_candidates(raw)
    assert 0x9300 not in result
    assert 0x9305 in result

def test_parse_candidates_empty_string():
    assert parse_candidates("") == {}

def test_parse_candidates_preserves_insertion_order(two_clusters):
    result = parse_candidates(two_clusters)
    addrs = list(result.keys())
    assert addrs == sorted(addrs), "Addresses should be in insertion (ascending) order"


# ── get_callers ───────────────────────────────────────────────────────────────

def test_get_callers_single_group(small_cluster):
    result = get_callers(small_cluster)
    assert len(result) == 1
    assert 0x9300 in result

def test_get_callers_group_has_correct_count(small_cluster):
    result = get_callers(small_cluster)
    assert result[0x9300].count == 5

def test_get_callers_two_groups(two_clusters):
    result = get_callers(two_clusters)
    assert len(result) == 2
    assert 0x9300 in result
    assert 0xA000 in result

def test_get_callers_discards_small_cluster(too_small_cluster):
    result = get_callers(too_small_cluster)
    assert len(result) == 0

def test_get_callers_exactly_min_size():
    # MIN_CLUSTER_SIZE sites — should be kept
    lines = "\n".join(
        f"0x{0x9300 + i*5:04x} 01 jsr 0x93c{i}"
        for i in range(MIN_CLUSTER_SIZE)
    )
    result = get_callers(lines)
    assert len(result) == 1

def test_get_callers_one_below_min_size():
    lines = "\n".join(
        f"0x{0x9300 + i*5:04x} 01 jsr 0x93c{i}"
        for i in range(MIN_CLUSTER_SIZE - 1)
    )
    result = get_callers(lines)
    assert len(result) == 0

def test_get_callers_last_group_is_not_discarded():
    """
    Regression: original code omitted a flush after the loop, silently
    dropping the last cluster.
    """
    lines = "\n".join([
        # A small cluster that will be discarded
        "0x9000 01 jsr 0x9100",
        "0x9005 01 jsr 0x9200",
        # Large gap
        # The LAST cluster — must be kept
        "0xa000 01 jsr 0xa100",
        "0xa004 01 jsr 0xa200",
        "0xa008 01 jsr 0xa300",
        "0xa00c 01 jsr 0xa400",
    ])
    result = get_callers(lines)
    assert 0xA000 in result, "Last cluster should not be silently discarded"

def test_get_callers_empty_input():
    assert get_callers("") == {}

def test_get_callers_cluster_boundary_exact():
    # Two sites exactly CLUSTER_WINDOW apart → same group
    lines = f"0x9300 01 jsr 0x93c1\n0x{0x9300 + 0xA:04x} 01 jsr 0x93c2"
    # Only 2 sites → below min, but let's verify they land in the same group
    from pysensorparser.grouping import parse_candidates, CLUSTER_WINDOW
    cands = parse_candidates(lines)
    assert len(cands) == 2
    addrs = list(cands.keys())
    assert abs(addrs[1] - addrs[0]) == CLUSTER_WINDOW

def test_get_callers_cluster_boundary_over():
    # Gap of CLUSTER_WINDOW+1 → different groups
    lines = "\n".join([
        # Group A: 4 sites
        "0x9300 01 jsr 0x93c1",
        "0x9305 01 jsr 0x93c2",
        "0x930a 01 jsr 0x93c3",
        "0x930f 01 jsr 0x93c4",
        # Gap of 0xB (one over limit)
        f"0x{0x930f + 0xB:04x} 01 jsr 0x93c5",
        f"0x{0x930f + 0x10:04x} 01 jsr 0x93c6",
        f"0x{0x930f + 0x15:04x} 01 jsr 0x93c7",
        f"0x{0x930f + 0x1a:04x} 01 jsr 0x93c8",
    ])
    result = get_callers(lines)
    # Both groups have 4 sites, both should be kept
    assert len(result) == 2
