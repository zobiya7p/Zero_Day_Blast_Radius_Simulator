"""

Workflow: Upload BOM -> Parse & Normalize -> Risk Analysis -> Findings ->
Dependency Graph -> Simulate Zero-Day Compromise -> Blast Radius ->
Financial Impact -> Executive Recommendation.
"""
from __future__ import annotations

import os

import streamlit as st
import streamlit.components.v1 as components

from modules import bom_parser, cve_matcher, vendor_checker, component_health
from modules import dependency_graph, risk_engine, blast_radius, financial_calculator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_data")

st.set_page_config(page_title="Zero-Day Blast Radius Simulator", layout="wide")

@st.cache_data
def _load_reference_data():
    return {
        "cve": cve_matcher.load_cve_dataset(os.path.join(DATA_DIR, "cve.json")),
        "vendors": vendor_checker.load_vendor_policy(os.path.join(DATA_DIR, "vendors.json")),
        "health": component_health.load_health_data(os.path.join(DATA_DIR, "component_health.json")),
        "assets": financial_calculator.load_business_assets(os.path.join(DATA_DIR, "business_assets.json")),
    }


REFERENCE = _load_reference_data()


# --------------------------------------------------------------------------
# Analysis pipeline (pure function of parsed components -> everything downstream)
# --------------------------------------------------------------------------

def run_analysis(components_list):
    graph = dependency_graph.build_graph(components_list)
    dep_counts, total_other_nodes = dependency_graph.dependent_counts(graph)

    risks = []
    for comp in components_list:
        cve_matches = cve_matcher.match_component(comp, REFERENCE["cve"])
        vendor_finding = vendor_checker.check_vendor(comp, REFERENCE["vendors"])
        health_finding = component_health.check_health(comp, REFERENCE["health"])
        risks.append(
            risk_engine.score_component(
                comp, cve_matches, vendor_finding, health_finding,
                dep_counts.get(comp.id, 0), total_other_nodes,
            )
        )

    bom_summary = risk_engine.score_bom(risks)
    return graph, risks, bom_summary


def _load_bytes(uploaded_file) -> bytes:
    uploaded_file.seek(0)
    return uploaded_file.read()


# --------------------------------------------------------------------------
# Sidebar: BOM upload
# --------------------------------------------------------------------------

st.sidebar.title("Upload BOM")
st.sidebar.caption("CycloneDX JSON, SPDX JSON, or CSV")

uploaded_bom = st.sidebar.file_uploader("BOM file", type=["json", "csv"])
uploaded_deps_csv = None
if uploaded_bom is not None and uploaded_bom.name.lower().endswith(".csv"):
    uploaded_deps_csv = st.sidebar.file_uploader(
        "Optional: dependencies.csv (component_id, depends_on_id) -- only needed if your BOM CSV has no 'dependencies' column",
        type=["csv"],
    )

st.sidebar.markdown("---")
st.sidebar.caption("Or try the demo instantly:")
load_demo = st.sidebar.button("Load Demo: Government AI BOM", use_container_width=True)

parse_error = None
if load_demo:
    with open(os.path.join(SAMPLE_DIR, "government_ai_bom.json"), "rb") as f:
        raw = f.read()
    try:
        st.session_state["components"] = bom_parser.parse_bom("government_ai_bom.json", raw)
        st.session_state["bom_name"] = "government_ai_bom.json (demo)"
    except bom_parser.BOMParseError as exc:
        parse_error = str(exc)

elif uploaded_bom is not None:
    raw = _load_bytes(uploaded_bom)
    deps_raw = _load_bytes(uploaded_deps_csv) if uploaded_deps_csv is not None else None
    try:
        st.session_state["components"] = bom_parser.parse_bom(uploaded_bom.name, raw, deps_raw)
        st.session_state["bom_name"] = uploaded_bom.name
    except bom_parser.BOMParseError as exc:
        parse_error = str(exc)

if parse_error:
    st.sidebar.error(parse_error)

st.title("Zero-Day Blast Radius Simulator")
st.caption("Supply Chain Risk Scoring Tool (Software-Only Version)")

if "components" not in st.session_state:
    st.info("Upload a BOM or click **Load Demo: Government AI BOM** in the sidebar to begin.")
    st.stop()

components_list = st.session_state["components"]
st.success(f"Loaded **{st.session_state['bom_name']}** -- {len(components_list)} components parsed and normalized.")

graph, risks, bom_summary = run_analysis(components_list)
risks_by_id = {r.component_id: r for r in risks}

tabs = st.tabs([
    "Risk Analysis", "Findings", "Dependency Graph",
    "Zero-Day Simulation", "Financial Impact & Recommendation",
])

with tabs[0]:
    st.subheader("Overall BOM Risk Score")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall BOM Score", f"{bom_summary['overall_score']} / 100")
    c2.metric("Vulnerable Components", bom_summary["vulnerable_count"])
    c3.metric("Restricted Vendor Components", bom_summary["restricted_count"])
    c4.metric("Unknown / Unverified", bom_summary["unknown_count"])

    st.subheader("Per-Component Scores")
    st.caption("Weighting: Vulnerability 50% | Vendor/Policy 20% | Component Health 15% | Dependency Criticality 15%")

    rows = []
    for r in sorted(risks, key=lambda x: -x.overall_score):
        rows.append({
            "Component": r.name,
            "Vendor": r.vendor,
            "Version": r.version,
            "Status": r.status.upper(),
            "Score": r.overall_score,
            "Vulnerability": r.breakdown["vulnerability"],
            "Vendor/Policy": r.breakdown["vendor"],
            "Health": r.breakdown["health"],
            "Dependency": r.breakdown["dependency"],
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

with tabs[1]:
    st.subheader("Highest-Risk Findings")
    top_findings = sorted(risks, key=lambda x: -x.overall_score)[:8]

    for r in top_findings:
        status_emoji = {"vulnerable": "\U0001F534", "restricted": "\U0001F534", "unknown": "\u26AA", "clean": "\U0001F7E2"}
        with st.expander(f"{status_emoji.get(r.status, '')} {r.name}  --  score {r.overall_score}/100  ({r.status.upper()})"):
            st.markdown("**Why this is risky:**")
            for reason in r.reasons:
                st.markdown(f"- {reason}")
            if r.evidence:
                st.markdown("**Evidence:**")
                for ev in r.evidence:
                    st.code(ev, language=None)
            st.markdown(f"**Suggested mitigation:** {r.mitigation}")

with tabs[2]:
    st.subheader("Dependency Graph")
    st.caption("\U0001F7E2 Green = unaffected/clean   \U0001F534 Red = vulnerable/restricted   \u26AA Gray = unknown/unverified")

    status_map = {r.component_id: r.status for r in risks}
    label_map = {c.id: c.name for c in components_list}
    html = dependency_graph.render_graph_html(graph, status_map, label_map)
    components.html(html, height=620, scrolling=True)

with tabs[3]:
    st.subheader("Simulate a Zero-Day Compromise")
    st.caption("Selecting a component treats it as compromised *regardless* of whether it has a known CVE, and traces every downstream dependent.")

    options = {c.id: f"{c.name} ({c.vendor or 'unlisted vendor'})" for c in components_list}
    selected_id = st.selectbox(
        "Component to compromise", options=list(options.keys()), format_func=lambda cid: options[cid],
    )

    if st.button("\U0001F4A5 SIMULATE ZERO-DAY COMPROMISE", type="primary"):
        st.session_state["blast_radius"] = blast_radius.simulate_compromise(graph, selected_id)
        st.session_state["compromised_id"] = selected_id

    if st.session_state.get("compromised_id") and st.session_state["compromised_id"] in graph:
        affected = st.session_state["blast_radius"]
        compromised_name = label_map[st.session_state["compromised_id"]]

        st.warning(f"**{len(affected)} component(s)** are within the blast radius of a compromised **{compromised_name}**.")
        status_map = {r.component_id: r.status for r in risks}
        html = dependency_graph.render_graph_html(graph, status_map, label_map, highlighted=affected)
        components.html(html, height=620, scrolling=True)

        with st.expander("Affected components"):
            for cid in sorted(affected, key=lambda x: label_map.get(x, x)):
                st.markdown(f"- {label_map.get(cid, cid)}")
    else:
        st.info("Select a component above and click **SIMULATE ZERO-DAY COMPROMISE** to trace its blast radius.")

with tabs[4]:
    st.subheader("Estimated Financial Impact / Exposure")

    if not st.session_state.get("compromised_id"):
        st.info("Run a zero-day simulation in the previous tab first.")
    else:
        downtime_hours = st.slider("Assumed downtime (hours)", min_value=1, max_value=24,
                                    value=financial_calculator.DEFAULT_ASSUMED_DOWNTIME_HOURS)

        affected = st.session_state["blast_radius"]
        impact = financial_calculator.calculate_impact(affected, REFERENCE["assets"], downtime_hours)
        compromised_name = label_map[st.session_state["compromised_id"]]

        c1, c2, c3 = st.columns(3)
        c1.metric("Asset Exposure", f"${impact.asset_exposure:,.0f}")
        c2.metric(f"Downtime Cost ({downtime_hours}h assumed)", f"${impact.downtime_cost:,.0f}")
        c3.metric("Estimated Financial Impact/Exposure", f"${impact.total_estimated_impact:,.0f}")
        st.caption("This is an estimated exposure figure based on stated assumptions -- not a guaranteed loss prediction.")

        if impact.affected_assets:
            st.markdown("**Affected business assets:**")
            st.dataframe(
                [{"Asset": a["name"], "Type": a["type"], "Asset Value": f"${a['asset_value']:,.0f}",
                  "Hourly Downtime Cost": f"${a['hourly_downtime_cost']:,.0f}"} for a in impact.affected_assets],
                use_container_width=True, hide_index=True,
            )

        st.subheader("Executive Recommendation")
        compromised_risk = risks_by_id.get(st.session_state["compromised_id"])
        should_remediate = (
            (compromised_risk and compromised_risk.status in ("vulnerable", "restricted"))
            or impact.total_estimated_impact >= 1_000_000
        )
        recommendation = "remediate before deployment." if should_remediate else "monitor and reassess before production rollout."

        statement = (
            f"A compromise of **{compromised_name}** could affect **{impact.critical_service_count} critical "
            f"service(s)** and **{impact.ai_pipeline_count} AI pipeline(s)**, representing an estimated "
            f"**${impact.total_estimated_impact:,.0f}** in asset exposure and downtime costs. "
            f"**Recommendation: {recommendation}**"
        )
        st.markdown(f"> {statement}")

        st.markdown("---")
        st.caption(
            "Traceability: BOM -> Finding -> Risk Score -> Dependency Graph -> Blast Radius -> "
            "Affected Business Assets -> Financial Impact -> Recommendation."
        )
