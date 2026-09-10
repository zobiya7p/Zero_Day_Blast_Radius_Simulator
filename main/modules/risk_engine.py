"""
Deterministic 0-100 risk scoring, per component and for the overall BOM.

Weighting (transparent and fixed, no ML/black-box scoring):
    Vulnerability      50%
    Vendor / policy    20%
    Component health   15%
    Dependency risk    15%

Every sub-score is computed from an explicit rule so a reviewer can trace
"why" a component scored the way it did.
"""
from __future__ import annotations

from dataclasses import dataclass, field

WEIGHTS = {"vulnerability": 0.50, "vendor": 0.20, "health": 0.15, "dependency": 0.15}

# Vulnerability score baselines for components with no CVE dataset match.
UNKNOWN_VENDOR_BASELINE = 60   # unrecognized/unlisted vendor: cannot verify -> flagged UNKNOWN
TRUSTED_NO_CVE_BASELINE = 15   # known/vetted vendor, no CVE found in local dataset

# Component health score contributions (summed, capped at 100).
HEALTH_EOL_POINTS = 50
HEALTH_SINGLE_SOURCE_POINTS = 30
HEALTH_UNSUPPORTED_POINTS = 20
HEALTH_UNKNOWN_BASELINE = 40  # no lifecycle data available: cannot verify -> moderate risk

VENDOR_SCORE = {"restricted": 100, "unknown": 50, "trusted": 10}


@dataclass
class ComponentRisk:
    component_id: str
    name: str
    vendor: str
    version: str
    overall_score: int
    breakdown: dict[str, int]
    status: str  # "vulnerable" | "restricted" | "unknown" | "clean"
    cve_matches: list = field(default_factory=list)
    vendor_finding: object = None
    health_finding: object = None
    dependents_count: int = 0
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    mitigation: str = ""


def _vulnerability_score(component, cve_matches, vendor_finding) -> tuple[int, str]:
    if cve_matches:
        worst = max(cve_matches, key=lambda m: m.cvss)
        return round(worst.cvss * 10), "matched"
    if vendor_finding.status == "trusted":
        return TRUSTED_NO_CVE_BASELINE, "no_cve_trusted_vendor"
    return UNKNOWN_VENDOR_BASELINE, "unverified"


def _health_score(health_finding) -> int:
    if not health_finding.known:
        return HEALTH_UNKNOWN_BASELINE
    score = 0
    if health_finding.eol:
        score += HEALTH_EOL_POINTS
    if health_finding.single_source:
        score += HEALTH_SINGLE_SOURCE_POINTS
    if health_finding.maintenance_status == "unsupported":
        score += HEALTH_UNSUPPORTED_POINTS
    return min(score, 100)


def _dependency_score(dependents_count: int, total_other_nodes: int) -> int:
    if total_other_nodes <= 0:
        return 0
    return min(100, round((dependents_count / total_other_nodes) * 100))


def _overall_status(vendor_finding, cve_matches, vuln_reason: str) -> str:
    if vendor_finding.status == "restricted":
        return "restricted"
    if cve_matches:
        return "vulnerable"
    if vuln_reason == "unverified":
        return "unknown"
    return "clean"


def score_component(component, cve_matches, vendor_finding, health_finding, dependents_count, total_other_nodes) -> ComponentRisk:
    vuln_score, vuln_reason = _vulnerability_score(component, cve_matches, vendor_finding)
    vendor_score = VENDOR_SCORE[vendor_finding.status]
    health_score = _health_score(health_finding)
    dependency_score = _dependency_score(dependents_count, total_other_nodes)

    overall = round(
        vuln_score * WEIGHTS["vulnerability"]
        + vendor_score * WEIGHTS["vendor"]
        + health_score * WEIGHTS["health"]
        + dependency_score * WEIGHTS["dependency"]
    )
    overall = max(0, min(100, overall))
    status = _overall_status(vendor_finding, cve_matches, vuln_reason)

    reasons, evidence = [], []
    if cve_matches:
        worst = max(cve_matches, key=lambda m: m.cvss)
        reasons.append(f"Matched {len(cve_matches)} known CVE(s); worst is {worst.cve_id} (CVSS {worst.cvss}, {worst.severity}).")
        evidence.append(f"{worst.cve_id}: {worst.description}")
    elif vuln_reason == "unverified":
        reasons.append("No vendor/product match in the local CVE dataset -- flagged UNKNOWN/UNVERIFIED, not assumed safe.")
    else:
        reasons.append("No known CVEs found for this trusted, recognized vendor/product.")

    if vendor_finding.status == "restricted":
        reasons.append(vendor_finding.reason)
        evidence.append(vendor_finding.reason)
    elif vendor_finding.status == "unknown":
        reasons.append(vendor_finding.reason)

    if health_finding.known:
        if health_finding.eol:
            reasons.append(f"End-of-life since {health_finding.eol_date or 'unknown date'}.")
            evidence.append(f"EOL date: {health_finding.eol_date}")
        if health_finding.single_source:
            reasons.append("Single-source dependency with no vetted alternative on file.")
        if health_finding.maintenance_status == "unsupported":
            reasons.append("Vendor maintenance status: unsupported.")
    else:
        reasons.append("No lifecycle/health data on file -- EOL and support status cannot be verified.")

    if dependents_count > 0:
        reasons.append(f"{dependents_count} other component(s) depend on this one, directly or transitively.")

    mitigation = _suggest_mitigation(status, cve_matches, vendor_finding, health_finding)

    return ComponentRisk(
        component_id=component.id,
        name=component.name,
        vendor=component.vendor or "(unlisted)",
        version=component.version,
        overall_score=overall,
        breakdown={
            "vulnerability": vuln_score,
            "vendor": vendor_score,
            "health": health_score,
            "dependency": dependency_score,
        },
        status=status,
        cve_matches=cve_matches,
        vendor_finding=vendor_finding,
        health_finding=health_finding,
        dependents_count=dependents_count,
        reasons=reasons,
        evidence=evidence,
        mitigation=mitigation,
    )


def _suggest_mitigation(status, cve_matches, vendor_finding, health_finding) -> str:
    if cve_matches:
        worst = max(cve_matches, key=lambda m: m.cvss)
        return f"Upgrade to version {worst.fixed_version} or later to remediate {worst.cve_id}."
    if vendor_finding.status == "restricted":
        return "Replace with a component from an approved, non-restricted vendor before deployment."
    if status == "unknown":
        return "Request an SBOM/attestation from the supplier or substitute a vetted, trusted-vendor alternative."
    if health_finding.known and health_finding.eol:
        return "Plan replacement -- vendor has ended support; no further security patches expected."
    return "No action required; continue routine monitoring."


def score_bom(component_risks: list[ComponentRisk]) -> dict:
    if not component_risks:
        return {"overall_score": 0, "highest_risk": None}
    overall_score = round(sum(cr.overall_score for cr in component_risks) / len(component_risks))
    highest = max(component_risks, key=lambda cr: cr.overall_score)
    return {
        "overall_score": overall_score,
        "highest_risk": highest,
        "vulnerable_count": sum(1 for cr in component_risks if cr.status == "vulnerable"),
        "restricted_count": sum(1 for cr in component_risks if cr.status == "restricted"),
        "unknown_count": sum(1 for cr in component_risks if cr.status == "unknown"),
    }
