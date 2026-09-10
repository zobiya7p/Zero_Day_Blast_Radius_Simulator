"""
Financial impact estimation.

    Asset Exposure = sum(asset_value for every affected business asset)
    Downtime Cost   = sum(hourly_downtime_cost for every affected asset) x assumed_downtime_hours
    Estimated Financial Impact/Exposure = Asset Exposure + Downtime Cost

This is explicitly an *estimate of exposure*, not a guaranteed loss
prediction -- callers should always surface the assumed downtime hours
alongside the number.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

DEFAULT_ASSUMED_DOWNTIME_HOURS = 4


@dataclass
class FinancialImpact:
    asset_exposure: float
    downtime_cost: float
    total_estimated_impact: float
    assumed_downtime_hours: float
    affected_assets: list[dict] = field(default_factory=list)
    ai_pipeline_count: int = 0
    critical_service_count: int = 0


def load_business_assets(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def calculate_impact(
    affected_component_ids: set[str],
    business_assets: list[dict],
    assumed_downtime_hours: float = DEFAULT_ASSUMED_DOWNTIME_HOURS,
) -> FinancialImpact:
    affected_assets = [
        asset for asset in business_assets
        if affected_component_ids.intersection(asset.get("supported_by", []))
    ]

    asset_exposure = sum(a["asset_value"] for a in affected_assets)
    hourly_total = sum(a["hourly_downtime_cost"] for a in affected_assets)
    downtime_cost = hourly_total * assumed_downtime_hours
    total = asset_exposure + downtime_cost

    return FinancialImpact(
        asset_exposure=asset_exposure,
        downtime_cost=downtime_cost,
        total_estimated_impact=total,
        assumed_downtime_hours=assumed_downtime_hours,
        affected_assets=affected_assets,
        ai_pipeline_count=sum(1 for a in affected_assets if a["type"] == "ai_pipeline"),
        critical_service_count=sum(1 for a in affected_assets if a["type"] == "critical_service"),
    )
