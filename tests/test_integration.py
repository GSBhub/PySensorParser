"""
Integration tests — require radare2 with the r2-m7700 plugin installed.

Run with:  pytest -m integration
Skip with: pytest -m "not integration"
"""
import os
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def rom_path():
    repo_root = os.path.dirname(os.path.dirname(__file__))
    path = os.path.join(repo_root, "742521-1994-USDM-SVX-EG33.bin")
    if not os.path.exists(path):
        pytest.skip(f"Test ROM not found: {path}")
    return path


def test_parse_rom_returns_dict(rom_path):
    from pysensorparser import parse_rom
    result = parse_rom(rom_path)
    assert isinstance(result, dict)


def test_parse_rom_caller_keys_are_ints(rom_path):
    from pysensorparser import parse_rom
    result = parse_rom(rom_path)
    for key in result:
        assert isinstance(key, int), f"Expected int key, got {type(key)}: {key!r}"


def test_parse_rom_callers_have_min_site_count(rom_path):
    from pysensorparser import parse_rom
    from pysensorparser.grouping import MIN_CLUSTER_SIZE
    result = parse_rom(rom_path)
    for addr, caller in result.items():
        assert caller.count >= MIN_CLUSTER_SIZE, (
            f"Caller at 0x{addr:04x} has {caller.count} sites, "
            f"expected >= {MIN_CLUSTER_SIZE}"
        )


def test_parse_rom_finds_at_least_one_hub(rom_path):
    from pysensorparser import parse_rom
    result = parse_rom(rom_path)
    assert len(result) >= 1, (
        "Expected at least one call-hub function in the test ROM"
    )
