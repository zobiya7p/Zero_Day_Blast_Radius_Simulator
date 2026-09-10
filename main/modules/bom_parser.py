"""
BOM ingestion and normalization.

Supports CycloneDX JSON, SPDX JSON, and CSV. All formats are normalized into
a single internal structure so every downstream module only ever deals with
one shape of data:

    {
        "id": str,
        "name": str,
        "vendor": str,          # empty string if unknown
        "version": str,
        "origin": str,          # country/origin, "Unknown" if not provided
        "type": str,            # e.g. firmware, library, application, hardware
        "dependencies": [str],  # ids of components this component depends on
    }

A component with an empty/blank vendor is intentionally normalized to an
empty string (never guessed) so risk_engine can flag it as UNKNOWN/UNVERIFIED.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Component:
    id: str
    name: str
    vendor: str
    version: str
    origin: str
    type: str
    dependencies: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "vendor": self.vendor,
            "version": self.version,
            "origin": self.origin,
            "type": self.type,
            "dependencies": self.dependencies,
        }


class BOMParseError(ValueError):
    """Raised when a BOM file cannot be parsed or normalized."""


def parse_bom(filename: str, raw_bytes: bytes, dependencies_csv_bytes: bytes | None = None) -> list[Component]:
    """
    Detect the BOM format from filename/content and return a normalized
    list of Component objects.

    `dependencies_csv_bytes` is an optional second file used only for the
    CSV workflow when dependency edges are supplied as a separate
    (component_id, depends_on_id) edge list rather than an inline column.
    """
    lower_name = filename.lower()
    text = raw_bytes.decode("utf-8-sig", errors="replace")

    if lower_name.endswith(".csv"):
        components = _parse_csv(text)
        if dependencies_csv_bytes:
            _merge_csv_dependency_edges(components, dependencies_csv_bytes.decode("utf-8-sig", errors="replace"))
        return components

    if lower_name.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BOMParseError(f"Invalid JSON in {filename}: {exc}") from exc

        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            return _parse_cyclonedx(data)
        if isinstance(data, dict) and "spdxVersion" in data:
            return _parse_spdx(data)
        raise BOMParseError(
            "Unrecognized JSON BOM format. Expected a CycloneDX document "
            "(bomFormat: CycloneDX) or an SPDX document (spdxVersion present)."
        )

    raise BOMParseError(f"Unsupported file type for '{filename}'. Use .json (CycloneDX/SPDX) or .csv.")


# --------------------------------------------------------------------------
# CycloneDX
# --------------------------------------------------------------------------

def _parse_cyclonedx(data: dict[str, Any]) -> list[Component]:
    components: dict[str, Component] = {}

    for raw in data.get("components", []):
        comp_id = raw.get("bom-ref") or raw.get("purl") or raw.get("name")
        if not comp_id:
            continue
        supplier = raw.get("supplier") or {}
        vendor = (supplier.get("name") or raw.get("group") or "").strip()
        components[comp_id] = Component(
            id=comp_id,
            name=(raw.get("name") or comp_id).strip(),
            vendor=vendor,
            version=(raw.get("version") or "0.0.0").strip(),
            origin=(raw.get("origin") or "Unknown").strip() or "Unknown",
            type=(raw.get("type") or "unknown").strip(),
        )

    for dep in data.get("dependencies", []):
        ref = dep.get("ref")
        depends_on = dep.get("dependsOn", [])
        if ref in components:
            components[ref].dependencies = list(depends_on)

    if not components:
        raise BOMParseError("CycloneDX BOM contained no usable 'components' entries.")
    return list(components.values())


# --------------------------------------------------------------------------
# SPDX
# --------------------------------------------------------------------------

def _parse_spdx(data: dict[str, Any]) -> list[Component]:
    components: dict[str, Component] = {}

    for pkg in data.get("packages", []):
        comp_id = pkg.get("SPDXID")
        if not comp_id:
            continue
        origin = "Unknown"
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "cpe23Type":
                origin = ref.get("referenceLocator", origin)
        components[comp_id] = Component(
            id=comp_id,
            name=(pkg.get("name") or comp_id).strip(),
            vendor=(pkg.get("supplier") or pkg.get("originator") or "").replace("Organization: ", "").strip(),
            version=(pkg.get("versionInfo") or "0.0.0").strip(),
            origin=origin,
            type="package",
        )

    for rel in data.get("relationships", []):
        if rel.get("relationshipType") != "DEPENDS_ON":
            continue
        src, dst = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        if src in components and dst:
            components[src].dependencies.append(dst)

    if not components:
        raise BOMParseError("SPDX BOM contained no usable 'packages' entries.")
    return list(components.values())


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

_REQUIRED_CSV_COLUMNS = {"id", "name", "vendor", "version", "origin", "type"}


def _parse_csv(text: str) -> list[Component]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or not _REQUIRED_CSV_COLUMNS.issubset(set(reader.fieldnames)):
        missing = _REQUIRED_CSV_COLUMNS - set(reader.fieldnames or [])
        raise BOMParseError(f"CSV BOM missing required column(s): {', '.join(sorted(missing))}")

    components = []
    for row in reader:
        deps_field = (row.get("dependencies") or "").strip()
        dependencies = [d.strip() for d in deps_field.split("|") if d.strip()]
        components.append(
            Component(
                id=row["id"].strip(),
                name=row["name"].strip(),
                vendor=(row.get("vendor") or "").strip(),
                version=(row.get("version") or "0.0.0").strip(),
                origin=(row.get("origin") or "Unknown").strip() or "Unknown",
                type=(row.get("type") or "unknown").strip(),
                dependencies=dependencies,
            )
        )
    if not components:
        raise BOMParseError("CSV BOM contained no data rows.")
    return components


def _merge_csv_dependency_edges(components: list[Component], edges_text: str) -> None:
    """Merge a (component_id, depends_on_id) edge-list CSV into components in place."""
    by_id = {c.id: c for c in components}
    reader = csv.DictReader(io.StringIO(edges_text))
    if reader.fieldnames is None or not {"component_id", "depends_on_id"}.issubset(set(reader.fieldnames)):
        raise BOMParseError("Dependencies CSV must have 'component_id' and 'depends_on_id' columns.")
    for row in reader:
        src, dst = row["component_id"].strip(), row["depends_on_id"].strip()
        comp = by_id.get(src)
        if comp and dst not in comp.dependencies:
            comp.dependencies.append(dst)
