"""
Radare2-backed parser: open an M7700 binary, run full analysis, and return
the call-hub groups found by the grouping module.
"""
from __future__ import annotations

import logging

import r2pipe

from .grouping import get_callers
from .models import Caller

log = logging.getLogger(__name__)


def get_rst(r2) -> int:
    """Read the M7700 reset vector from 0xFFFE (little-endian 16-bit)."""
    r2.cmd("s 0xfffe")
    raw = str(r2.cmd("px0"))
    if raw and len(raw) >= 4:
        return int(f"{raw[2:4]}{raw[:2]}", 16)
    return 0


def parse_rom(infile: str) -> dict[int, Caller]:
    """
    Full pipeline: open binary in r2, analyse, find call-hub functions.

    Returns a dict mapping caller base_addr (int) → Caller object.
    An empty dict is returned (not an exception) if the binary has no
    identifiable hub functions.
    """
    print(f"Loading '{infile}' into R2...")
    r2 = r2pipe.open(infile)
    r2.cmd("e asm.arch=m7700")
    log.info("R2 arch: %s", r2.cmd("e asm.arch"))

    rst = get_rst(r2)
    log.info("Reset vector: 0x%04x", rst)
    r2.cmd(f"s 0x{rst:04x}")
    log.info("R2 seeked to: %s", r2.cmd("s"))

    r2.cmd("aaa")
    candidates = r2.cmd("/A call")
    log.debug("'/A call' output:\n%s", candidates)

    callers = get_callers(candidates)
    print(f"Found {len(callers)} caller group(s).")

    r2.quit()
    return callers
