"""
Matches BOM components against the curated local CVE dataset (data/cve.json)
by vendor + product name, then checks whether the component's version falls
inside the CVE's affected range.

Never infers vulnerability status for components that simply aren't in the
dataset -- that absence is handled by risk_engine as UNKNOWN/UNVERIFIED, not
as "safe".
"""
from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


@dataclass
class CVEMatch:
    cve_id: str
    cvss: float
    severity: str
    fixed_version: str
    description: str


def _normalize(text: str) -> str:
    return (text or "").strip().lower()


def _parse_version(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _version_in_range(component_version: str, introduced: str, fixed: str) -> bool:
    """
    Returns True if component_version falls within [introduced, fixed).
    Falls back to a lenient numeric-tuple comparison if the version string
    isn't PEP 440-parseable (common with vendor firmware versions).
    """
    cv, lo, hi = _parse_version(component_version), _parse_version(introduced), _parse_version(fixed)
    if cv is not None and lo is not None and hi is not None:
        return lo <= cv < hi

    def tuple_of(v: str) -> tuple[int, ...]:
        parts = []
        for chunk in v.replace("-", ".").split("."):
            digits = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts) or (0,)

    return tuple_of(introduced) <= tuple_of(component_version) < tuple_of(fixed)


def load_cve_dataset(path: str) -> list[dict]:
    import json

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def match_component(component, cve_dataset: list[dict]) -> list[CVEMatch]:
    """Return every CVE in the dataset that applies to this component's vendor/product/version."""
    matches: list[CVEMatch] = []
    comp_vendor, comp_name = _normalize(component.vendor), _normalize(component.name)
    if not comp_vendor or not comp_name:
        return matches

    for entry in cve_dataset:
        if _normalize(entry["vendor"]) != comp_vendor or _normalize(entry["product"]) != comp_name:
            continue
        rng = entry["affected_range"]
        if _version_in_range(component.version, rng["introduced"], rng["fixed"]):
            matches.append(
                CVEMatch(
                    cve_id=entry["cve_id"],
                    cvss=float(entry["cvss"]),
                    severity=entry["severity"],
                    fixed_version=entry["fixed_version"],
                    description=entry["description"],
                )
            )
    return matches
