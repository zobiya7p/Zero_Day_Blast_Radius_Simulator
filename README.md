# Zero-Day Blast Radius Simulator
### Supply Chain Risk Scoring Tool 

A Supply Chain Risk Scoring Tool that converts technical BOM (Bill of Materials) vulnerabilities into operational and financial impact, for CISOs and government procurement
teams.

# Tech Stack

* **Language & Runtime:** Python 3.10+
* **User Interface & Dashboard:** Streamlit
* **Graph Network & Algorithms:** NetworkX (Directed Graphs & BFS Traversal)
* **Graph Visualization:** PyVis (Interactive HTML network topology)
* **Data Processing & Analytics:** Pandas
* **BOM Standards Supported:** CycloneDX JSON, SPDX JSON, Structured CSV
## Workflow

```
Upload BOM -> Parse & Normalize -> Risk Analysis -> Findings ->
Dependency Graph -> Simulate Zero-Day Compromise -> Blast Radius ->
Financial Impact -> Executive Recommendation
```

Every result is traceable end to end:
`BOM -> Finding -> Risk -> Dependency -> Affected Service -> Financial Impact -> Recommendation`.

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Demo

1. In the sidebar, click **Load Demo: Government AI BOM** (or upload your own
   CycloneDX JSON / SPDX JSON / CSV BOM).
2. **Risk Analysis** tab -- see the overall BOM score and per-component
   breakdown (vulnerability / vendor-policy / health / dependency criticality).
3. **Findings** tab -- see the highest-risk components, why they're risky,
   evidence, and suggested mitigation.
4. **Dependency Graph** tab -- the full component graph, color-coded green
   (unaffected/clean) / red (vulnerable or restricted-vendor) / gray
   (unknown/unverified).
5. **Zero-Day Simulation** tab -- pick a component (try **BMC Firmware**) and
   click **SIMULATE ZERO-DAY COMPROMISE**. The tool traces every downstream
   dependent via graph traversal and highlights the blast radius.
6. **Financial Impact & Recommendation** tab -- see Asset Exposure, Downtime
   Cost (at an adjustable assumed downtime), the combined Estimated Financial
   Impact/Exposure, and an auto-generated executive recommendation.

The bundled demo BOM (`sample_data/government_ai_bom.json`) intentionally
contains:
- 2 vulnerable firmware components (BMC Firmware, Network Switch OS)
- 1 restricted-vendor component (Edge AI Chipset)
- 3 unknown/unverified components (no listed vendor)
- 2 AI pipelines (Inference Service, Training Pipeline)
- 4 critical services (Auth, Logging, API Gateway, Web Portal)

Simulating a BMC Firmware compromise cascades through the shared server
hardware platform to nearly every downstream service producing a compelling, realistic exposure figure.
<img width="488" height="327" alt="Screenshot 2026-09-11 171918" src="https://github.com/user-attachments/assets/9a01c8d3-607a-4e17-aff7-436f4287e115" />

## BOM Input Formats

- **CycloneDX JSON** -- `components[]` + `dependencies[]` (`ref`/`dependsOn`).
- **SPDX JSON** -- `packages[]` + `relationships[]` (`DEPENDS_ON`).
- **CSV** -- columns `id,name,vendor,version,origin,type,dependencies`, where
  `dependencies` is a `|`-separated list of component ids. If your CSV has no
  `dependencies` column, upload a second edge-list CSV
  (`component_id,depends_on_id`) alongside it -- see `sample_data/dependencies.csv`.

## Data Files (`data/`)

- `cve.json` -- curated local CVE dataset (vendor, product, affected version
  range, CVSS, severity, fixed version). Matching is version-range aware.
- `vendors.json` -- restricted vendors, restricted countries, and trusted
  vendors for procurement policy checks.
- `component_health.json` -- EOL status, single-source flags, and maintenance
  status keyed by `vendor|product`.
- `business_assets.json` -- business assets/services, their asset value,
  hourly downtime cost, and which component id(s) they depend on.

## Risk Scoring

Deterministic, transparent, and fully rule-based (no ML/LLM scoring):

| Factor                  | Weight |
|--------------------------|--------|
| Vulnerability             | 50% |
| Vendor / Policy           | 20% |
| Component Health          | 15% |
| Dependency Criticality    | 15% |

Components with no CVE dataset match and no recognized vendor are always
flagged **UNKNOWN / UNVERIFIED** -- never scored as safe.

## Project Structure

```
zero-day-blast-radius/
├── app.py
├── requirements.txt
├── README.md
├── modules/
│   ├── bom_parser.py          BOM ingestion & normalization (CycloneDX/SPDX/CSV)
│   ├── cve_matcher.py         Vendor/product/version CVE matching
│   ├── vendor_checker.py      Restricted-vendor/country policy checks
│   ├── component_health.py    EOL / single-source / maintenance lookups
│   ├── risk_engine.py         Deterministic 0-100 risk scoring
│   ├── dependency_graph.py    NetworkX graph build + PyVis rendering
│   ├── blast_radius.py        Zero-day compromise propagation (graph traversal)
│   └── financial_calculator.py Asset exposure + downtime cost calculation
├── data/
│   ├── cve.json
│   ├── vendors.json
│   ├── component_health.json
│   └── business_assets.json
└── sample_data/
    ├── government_ai_bom.json
    ├── government_ai_bom.csv
    └── dependencies.csv
```
