"""Restricted-vendor / restricted-country procurement policy checks."""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class VendorFinding:
    status: str  # "restricted" | "trusted" | "unknown"
    reason: str


def load_vendor_policy(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_vendor(component, policy: dict) -> VendorFinding:
    vendor = (component.vendor or "").strip()
    origin = (component.origin or "").strip()

    restricted_vendors = {v.lower() for v in policy.get("restricted_vendors", [])}
    restricted_countries = {c.lower() for c in policy.get("restricted_countries", [])}
    trusted_vendors = {v.lower() for v in policy.get("trusted_vendors", [])}

    if vendor.lower() in restricted_vendors:
        return VendorFinding("restricted", f"'{vendor}' is on the restricted vendor list.")
    if origin.lower() in restricted_countries:
        return VendorFinding("restricted", f"Component origin '{origin}' is a restricted country/jurisdiction.")
    if vendor.lower() in trusted_vendors:
        return VendorFinding("trusted", f"'{vendor}' is a known, vetted vendor.")
    if not vendor:
        return VendorFinding("unknown", "No vendor/supplier listed on this component.")
    return VendorFinding("unknown", f"'{vendor}' is not on the trusted or restricted vendor lists.")
