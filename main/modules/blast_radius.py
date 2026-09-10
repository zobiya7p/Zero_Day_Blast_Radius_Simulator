"""
Zero-day compromise simulation.

Given a graph where an edge A -> B means "A depends on B", compromising B
propagates upstream to every component that depends on B, directly or
transitively. That set is exactly `networkx.ancestors(graph, B)`.

This module treats the selected component as compromised unconditionally --
it does not require a known CVE match, matching the "assume zero-day"
requirement.
"""
from __future__ import annotations

import networkx as nx


def simulate_compromise(graph: nx.DiGraph, compromised_id: str) -> set[str]:
    """Return the full blast-radius set (including the compromised node itself)."""
    if compromised_id not in graph:
        raise ValueError(f"Component '{compromised_id}' is not in the dependency graph.")
    affected = nx.ancestors(graph, compromised_id)
    affected.add(compromised_id)
    return affected
