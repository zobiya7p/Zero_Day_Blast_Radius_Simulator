"""Component lifecycle/health lookups (EOL, single-source, maintenance status)."""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class HealthFinding:
    known: bool
    eol: bool
    single_source: bool
    maintenance_status: str
    eol_date: str | None = None


def load_health_data(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_health(component, health_data: dict) -> HealthFinding:
    key = f"{(component.vendor or '').strip().lower()}|{component.name.strip().lower()}"
    entry = health_data.get(key)
    if entry is None:
        # No lifecycle data available. This is NOT the same as "healthy" --
        # it is unverifiable and risk_engine treats it as such.
        return HealthFinding(known=False, eol=False, single_source=False, maintenance_status="unknown")
    return HealthFinding(
        known=True,
        eol=bool(entry.get("eol", False)),
        single_source=bool(entry.get("single_source", False)),
        maintenance_status=entry.get("maintenance_status", "unknown"),
        eol_date=entry.get("eol_date"),
    )
