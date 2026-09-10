"""
Builds the component dependency graph and renders it with PyVis.

Edge direction convention: an edge A -> B means "A depends on B". This makes
`networkx.ancestors(graph, B)` return every component that (directly or
transitively) depends on B -- exactly the "downstream blast radius" needed
when B is compromised. See modules/blast_radius.py.
"""
from __future__ import annotations

import networkx as nx

STATUS_COLORS = {
    "vulnerable": "#d9534f",   # red
    "restricted": "#d9534f",   # red
    "unknown": "#9e9e9e",      # gray
    "clean": "#5cb85c",        # green
}

BLAST_RADIUS_COLOR = "#d9534f"   # red overlay for simulated compromise
UNAFFECTED_DIM_COLOR = "#5cb85c"  # green for confirmed-unaffected during simulation


def build_graph(components: list) -> nx.DiGraph:
    graph = nx.DiGraph()
    for comp in components:
        graph.add_node(comp.id, label=comp.name)
    for comp in components:
        for dep_id in comp.dependencies:
            if dep_id in graph:  # ignore dangling refs to components not in the BOM
                graph.add_edge(comp.id, dep_id)
    return graph


def dependent_counts(graph: nx.DiGraph) -> dict[str, int]:
    """Number of components that (transitively) depend on each node."""
    total_others = max(len(graph.nodes) - 1, 1)
    return {node: len(nx.ancestors(graph, node)) for node in graph.nodes}, total_others


def render_graph_html(
    graph: nx.DiGraph,
    component_status: dict[str, str],
    component_labels: dict[str, str],
    highlighted: set[str] | None = None,
    height_px: int = 600,
) -> str:
    """
    Render the graph to standalone HTML.

    `component_status` maps component id -> "vulnerable" | "restricted" | "unknown" | "clean".
    `highlighted` (if given) is the blast-radius set from an active simulation;
    highlighted nodes are colored red and everything else is dimmed green/gray
    per the "green = unaffected, red = compromised, gray = unknown" convention.
    """
    from pyvis.network import Network  # imported lazily so build_graph/dependent_counts
                                        # work in environments without pyvis installed

    net = Network(height="450px", width="100%", directed=True, bgcolor="#0e1117", font_color="white")
    #net = Network(height=f"{height_px}px", width="100%", directed=True, notebook=False, bgcolor="#ffffff")
    net.barnes_hut(gravity=-3000, central_gravity =0.3,spring_length=120)

    for node in graph.nodes:
        label = component_labels.get(node, node)
        status = component_status.get(node, "unknown")

        if highlighted is not None:
            if node in highlighted:
                color = BLAST_RADIUS_COLOR
                title = f"{label}\nBLAST RADIUS: potentially compromised"
            elif status == "unknown":
                color = STATUS_COLORS["unknown"]
                title = f"{label}\nStatus: unknown/unverified"
            else:
                color = UNAFFECTED_DIM_COLOR
                title = f"{label}\nUnaffected by this simulation"
        else:
            color = STATUS_COLORS.get(status, STATUS_COLORS["unknown"])
            title = f"{label}\nStatus: {status}"
        
        net.add_node(
            node,
            label=label,
            color=color,
            title=title,
            font={"color": "white", "size": 16}
        )
            

        #net.add_node(node, label=label, color=color, title=title)

    for src, dst in graph.edges:
        net.add_edge(src, dst, arrows="to")

    return net.generate_html(notebook=False)
