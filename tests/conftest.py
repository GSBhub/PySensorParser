"""
Fixtures shared across the test suite.

The mock /A call output uses the format the original code expected:
  <source_addr>  <bytes>  <mnemonic>  <dest_addr>
"""
import os
import pytest


@pytest.fixture
def small_cluster() -> str:
    """Five JSR sites within 0xA of each other → one caller group."""
    return "\n".join([
        "0x9300 01 jsr 0x93c1",
        "0x9305 01 jsr 0x93c2",
        "0x930a 01 jsr 0x93c3",
        "0x930f 01 jsr 0x93c4",
        "0x9314 01 jsr 0x93c5",
    ])


@pytest.fixture
def two_clusters() -> str:
    """
    Cluster A (5 sites at 0x9300..0x9314) and cluster B (4 sites at 0xa000..0xa00c),
    separated by a large gap so they are distinct groups.
    """
    lines = [
        # Cluster A
        "0x9300 01 jsr 0x93c1",
        "0x9305 01 jsr 0x93c2",
        "0x930a 01 jsr 0x93c3",
        "0x930f 01 jsr 0x93c4",
        "0x9314 01 jsr 0x93c5",
        # Cluster B (starts far away)
        "0xa000 01 jsr 0xa100",
        "0xa004 01 jsr 0xa200",
        "0xa008 01 jsr 0xa300",
        "0xa00c 01 jsr 0xa400",
    ]
    return "\n".join(lines)


@pytest.fixture
def too_small_cluster() -> str:
    """Three JSR sites — below the MIN_CLUSTER_SIZE of 4, should be discarded."""
    return "\n".join([
        "0x9300 01 jsr 0x93c1",
        "0x9305 01 jsr 0x93c2",
        "0x930a 01 jsr 0x93c3",
    ])


@pytest.fixture
def binary_path() -> str:
    repo_root = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(repo_root, "742521-1994-USDM-SVX-EG33.bin")
