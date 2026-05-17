"""
Pure-Python grouping logic: parse the raw ``/at call`` output from radare2
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


def _normalize_addr(s: str) -> str | None:
    """
    Return *s* as a canonical '0x…' hex string, or None if unparseable.

    Handles both '0xNNNN' (r2 JSR output) and '$NNNNNN' (r2 JSL output).
    """
    if s.startswith("$"):
        s = "0x" + s[1:]
    if is_hex(s):
        return s
    return None


def parse_candidates(candidates_str: str) -> OrderedDict[int, Callee]:
    """
    Parse whitespace-delimited ``/at call`` (r2 6.x) or legacy ``/A call``
    output into an address-ordered dict of Callee objects.

    r2 6.x format (5+ tokens):
        <src_addr>  call  <size>  <MNEMONIC>  <dest_addr>  [extra…]
    Legacy format (4 tokens):
        <src_addr>  <bytes>  <mnemonic>  <dest_addr>

    Lines that cannot yield valid hex source and destination addresses are
    skipped silently.
    """
    result: OrderedDict[int, Callee] = OrderedDict()
    for line in candidates_str.splitlines():
        tokens = line.split()
        if len(tokens) < 4:
            continue

        src_str = tokens[0]
        # Detect format: new format has a non-hex token at index 3 (the mnemonic)
        # and the destination at index 4; legacy format has dest at index 3.
        if len(tokens) >= 5 and not is_hex(tokens[3]):
            dest_str = _normalize_addr(tokens[4])
        else:
            dest_str = _normalize_addr(tokens[3])

        if dest_str is None:
            log.debug("Skipping line (dest not hex): %r", line)
            continue
        try:
            src = int(src_str, 16)
            dst = int(dest_str, 16)
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
