"""
Pure-Python grouping logic: parse the raw `/A call` output from radare2
and cluster JSR sites into caller groups.

No r2pipe dependency — fully unit-testable.
"""
from __future__ import annotations

import logging
from collections import OrderedDict

from .models import Callee, Caller

log = logging.getLogger(__name__)

# Maximum byte distance between two JSR sites to be considered part of the
# same caller function.
CLUSTER_WINDOW = 0xA

# Minimum number of unique call sites required to keep a cluster.
MIN_CLUSTER_SIZE = 4


def is_hex(s: str) -> bool:
    """Return True if *s* can be parsed as a hexadecimal integer."""
    try:
        int(s, 16)
        return True
    except (ValueError, TypeError):
        return False


def parse_candidates(candidates_str: str) -> OrderedDict[int, Callee]:
    """
    Parse the whitespace-delimited output of radare2's ``/A call`` command
    into an address-ordered dict of Callee objects.

    Expected line format (at least 4 whitespace-separated tokens):
        <source_addr>  <bytes/info>  <mnemonic>  <dest_addr>

    Lines that don't have 4 tokens or whose 4th token isn't hex are skipped.
    """
    result: OrderedDict[int, Callee] = OrderedDict()
    for line in candidates_str.splitlines():
        tokens = line.split()
        if len(tokens) < 4:
            continue
        if not is_hex(tokens[3]):
            log.debug("Skipping line (field 3 not hex): %r", line)
            continue
        try:
            src = int(tokens[0], 16)
            dst = int(tokens[3], 16)
        except ValueError:
            log.debug("Could not parse addresses on line: %r", line)
            continue
        result[src] = Callee(src, dst)
    log.info("Found %d potential call sites.", len(result))
    return result


def get_callers(candidates_str: str) -> dict[int, Caller]:
    """
    Group spatially-close JSR sites into Caller clusters.

    A cluster is kept only if it has at least MIN_CLUSTER_SIZE unique sites.
    Sites are considered neighbours if they lie within CLUSTER_WINDOW bytes of
    the previous site.

    Fixes two bugs from the Python 2 original:
    - IndexError on short lines (guarded in parse_candidates)
    - Last cluster was silently discarded (now explicitly flushed after loop)
    """
    cand_list = parse_candidates(candidates_str)

    callers: dict[int, Caller] = {}
    current_addr: int = 0
    active: Caller | None = None

    for address, callee in cand_list.items():
        if active is None:
            active = Caller(address, callee)
            current_addr = address
        elif abs(address - current_addr) <= CLUSTER_WINDOW:
            active.push(address, callee)
            current_addr = address
        else:
            if active.count >= MIN_CLUSTER_SIZE:
                callers[active.base_addr] = active
            active = Caller(address, callee)
            current_addr = address

    # Flush the last active cluster (the original code omitted this).
    if active is not None and active.count >= MIN_CLUSTER_SIZE:
        callers[active.base_addr] = active

    log.info("Found %d caller groups.", len(callers))
    return callers
