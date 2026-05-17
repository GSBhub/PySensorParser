"""
Data structures for the call-hub detection pass.

A Callee is a single JSR target site (source_addr → dest_addr).
A Caller is a group of spatially-close JSR sites — a function that calls
many other functions within a narrow address range.
"""
from __future__ import annotations


class Callee:
    def __init__(self, source_addr: int, dest_addr: int) -> None:
        self.source_addr = source_addr
        self.dest_addr = dest_addr

    def __repr__(self) -> str:
        return f"Callee(0x{self.source_addr:04x} -> 0x{self.dest_addr:04x})"


class Caller:
    """
    A cluster of closely-spaced JSR sites that together form a hub function.

    count  - number of unique call sites in this cluster
    callees - map of site_addr → Callee
    """

    def __init__(self, base_addr: int, first_callee: Callee) -> None:
        self.base_addr = base_addr
        self.count = 1
        self.callees: dict[int, Callee] = {base_addr: first_callee}

    def push(self, addr: int, callee: Callee) -> None:
        if addr not in self.callees:
            self.count += 1
            self.callees[addr] = callee

    def __repr__(self) -> str:
        return f"Caller(0x{self.base_addr:04x}, {self.count} sites)"
