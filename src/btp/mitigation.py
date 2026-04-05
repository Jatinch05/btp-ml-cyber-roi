from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ControlSpec:
    vulnerability: str
    control: str
    tools: str
    cost_min: float
    cost_max: float
    cost_unit: str
    cost_scaling_type: str
    effectiveness_min: float
    effectiveness_max: float
    real_world_factor: float
    mitigatable_fraction: float
    control_type: str
    scope: str
    max_effect_cap: float
    effort: str


ROOT = Path(__file__).resolve().parents[2]
MITIGATION_CSV_PATH = ROOT / "data" / "reference" / "mitigation_controls.csv"

_MITIGATION_CACHE: Dict[str, Any] = {
    "mtime": None,
    "specs": None,
}


def _load_control_specs(csv_path: Path) -> List[ControlSpec]:
    if not csv_path.exists():
        raise FileNotFoundError(f"Mitigation controls CSV not found: {csv_path}")

    specs: List[ControlSpec] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {
            "vulnerability", "control", "tool_examples", "cost_min", "cost_max", "cost_unit",
            "effectiveness_min", "effectiveness_max", "control_type", "effort",
        }
        headers = set(reader.fieldnames or [])
        missing = required - headers
        if missing:
            raise ValueError(f"Mitigation CSV missing required columns: {sorted(missing)}")

        for row in reader:
            specs.append(
                ControlSpec(
                    vulnerability=str(row["vulnerability"]).strip(),
                    control=str(row["control"]).strip(),
                    tools=str(row["tool_examples"]).strip(),
                    cost_min=float(row["cost_min"]),
                    cost_max=float(row["cost_max"]),
                    cost_unit=str(row["cost_unit"]).strip(),
                    cost_scaling_type=str(row.get("cost_scaling_type", "flat")).strip() or "flat",
                    effectiveness_min=float(row["effectiveness_min"]),
                    effectiveness_max=float(row["effectiveness_max"]),
                    real_world_factor=float(row.get("real_world_factor", 1.0)),
                    mitigatable_fraction=float(row.get("mitigatable_fraction", 0.5)),
                    control_type=str(row["control_type"]).strip(),
                    scope=str(row.get("scope", "general")).strip() or "general",
                    max_effect_cap=float(row.get("max_effect_cap", 0.95)),
                    effort=str(row["effort"]).strip(),
                )
            )

    if not specs:
        raise ValueError(f"Mitigation CSV has no rows: {csv_path}")

    return specs


def get_mitigation_specs() -> List[ControlSpec]:
    mtime = MITIGATION_CSV_PATH.stat().st_mtime if MITIGATION_CSV_PATH.exists() else None
    cached_mtime = _MITIGATION_CACHE.get("mtime")
    cached_specs = _MITIGATION_CACHE.get("specs")

    if cached_specs is not None and cached_mtime == mtime:
        return cached_specs

    specs = _load_control_specs(MITIGATION_CSV_PATH)
    _MITIGATION_CACHE["mtime"] = mtime
    _MITIGATION_CACHE["specs"] = specs
    return specs


TYPE_MULTIPLIER = {
    "preventive": 1.0,
    "detective": 0.7,
    "recovery": 0.8,
    "human": 0.6,
}

MITIGATABLE_FRACTION_BY_TYPE = {
    "preventive": 0.6,
    "detective": 0.4,
    "recovery": 0.5,
    "human": 0.3,
}

REALISM_FACTOR = 0.7
OVERLAP_PENALTY = 0.85
MAX_REDUCTION = 0.85
SCENARIO_SHIFT = 0.1
MIN_REALISTIC_COST = 1.0

PRIORITY_WEIGHT = {
    "low": 1.0,
    "medium": 0.9,
    "high": 0.8,
}


ATTACK_PROBABILITY = {
    "API Abuse": 0.08,
    "Account Takeover": 0.12,
    "App Vulnerability": 0.08,
    "DDoS": 0.05,
    "Data Breach": 0.08,
    "Data Exposure": 0.07,
    "Email Compromise": 0.14,
    "Industrial Espionage": 0.03,
    "Insider Threat": 0.08,
    "IoT Breach": 0.05,
    "Malware": 0.08,
    "MITM": 0.04,
    "Network Breach": 0.06,
    "OT Attack": 0.03,
    "POS Malware": 0.05,
    "Phishing": 0.15,
    "Ransomware": 0.08,
    "SQL Injection": 0.06,
    "Supply Chain": 0.05,
    "Other": 0.07,
}

MIN_COST_BY_SIZE = {
    "small": 10000.0,
    "medium": 25000.0,
    "large": 75000.0,
}

MITIGATABLE_FRACTION_RANGE_BY_TYPE = {
    "preventive": (0.4, 0.7),
    "detective": (0.3, 0.5),
    "recovery": (0.4, 0.6),
    "human": (0.2, 0.4),
}


ATTACK_ALIAS = {
    "api abuse": "API Abuse",
    "account takeover": "Account Takeover",
    "app vulnerability": "App Vulnerability",
    "claims fraud": "Other",
    "connected car": "Other",
    "content piracy": "Other",
    "ddos": "DDoS",
    "data breach": "Data Breach",
    "data exposure": "Data Exposure",
    "email compromise": "Email Compromise",
    "gaming hack": "Other",
    "industrial espionage": "Industrial Espionage",
    "insider threat": "Insider Threat",
    "iot breach": "IoT Breach",
    "malware": "Malware",
    "man in the middle": "MITM",
    "mitm": "MITM",
    "network breach": "Network Breach",
    "ot attack": "OT Attack",
    "pos malware": "POS Malware",
    "passenger data": "Other",
    "payment fraud": "Other",
    "phishing": "Phishing",
    "precision ag": "Other",
    "property fraud": "Other",
    "ransomware": "Ransomware",
    "research theft": "Other",
    "sql injection": "SQL Injection",
    "supply chain": "Supply Chain",
    "wallet hack": "Other",
    "other": "Other",
}


INDUSTRY_MATURITY = {
    "finance": 0.95,
    "healthcare": 0.9,
    "technology": 0.9,
    "public": 0.78,
    "retail": 0.82,
    "industrial": 0.84,
    "education": 0.8,
}


DEFAULT_EMPLOYEE_BY_SIZE = {
    "small": 100,
    "medium": 500,
    "large": 2000,
}


def _norm_key(value: str) -> str:
    s = str(value).strip().lower()
    s = re.sub(r"[_+,\-]", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def canonical_vulnerability(attack_type: str) -> str:
    key = _norm_key(attack_type)
    return ATTACK_ALIAS.get(key, "Other")


def estimate_company_size(employee_count: Optional[float], explicit: Optional[str] = None) -> str:
    if explicit:
        e = explicit.strip().lower()
        if e in {"small", "medium", "large"}:
            return e
    if employee_count is None or employee_count <= 0:
        return "medium"
    if employee_count < 200:
        return "small"
    if employee_count > 1500:
        return "large"
    return "medium"


def get_coverage(company_size: str) -> float:
    size = company_size.lower()
    if size == "small":
        return 0.6
    if size == "large":
        return 0.85
    return 0.75


def _scope_key(spec: ControlSpec) -> str:
    return _norm_key(spec.scope or spec.control_type or spec.control)


def get_maturity_score(industry: str) -> float:
    return INDUSTRY_MATURITY.get(industry.strip().lower(), 0.85)


def _scenario_bounds(value: float, lo: float, hi: float) -> tuple[float, float, float]:
    expected = min(max(value, lo), hi)
    low = max(lo, expected - SCENARIO_SHIFT)
    high = min(hi, expected + SCENARIO_SHIFT)
    return low, expected, high


def _annual_cost(spec: ControlSpec, company_size: str, employee_count: Optional[float], device_count: Optional[float]) -> float:
    midpoint = (spec.cost_min + spec.cost_max) / 2.0

    users = max(float(employee_count or 0), 0.0)
    if users <= 0:
        users = float(DEFAULT_EMPLOYEE_BY_SIZE.get(company_size, 500))

    devices = max(float(device_count or 0), 0.0)
    if devices <= 0:
        devices = users

    cost_unit = _norm_key(spec.cost_unit)
    scaling_type = _norm_key(spec.cost_scaling_type)

    if cost_unit == "monthly":
        annual = midpoint * 12.0
    elif cost_unit == "per_user_month":
        annual = midpoint * users * 12.0
    elif cost_unit == "per_user_year":
        annual = midpoint * users
    elif cost_unit == "per_device_month":
        annual = midpoint * devices * 12.0
    elif cost_unit == "per_device_year":
        annual = midpoint * devices
    else:
        annual = midpoint * 12.0

    # Apply the richer scaling hints from the CSV.
    # If the cost unit already encodes per-user or per-device pricing, do not multiply twice.
    if scaling_type == "per_user" and cost_unit in {"monthly", "flat"}:
        annual *= max(users, 1.0)
    elif scaling_type == "per_device" and cost_unit in {"monthly", "flat"}:
        annual *= max(devices, 1.0)
    elif scaling_type == "per_traffic":
        annual *= {"small": 2.0, "medium": 5.0, "large": 10.0}.get(company_size, 5.0)
    elif scaling_type == "per_log_volume":
        annual *= 10.0
    elif scaling_type == "per_network":
        annual *= {"small": 1.2, "medium": 2.0, "large": 4.0}.get(company_size, 2.0)
    elif scaling_type == "per_site":
        annual *= {"small": 1.0, "medium": 1.5, "large": 3.0}.get(company_size, 1.5)

    # Cost scaling by company size.
    if company_size == "small":
        annual *= 0.5
    elif company_size == "large":
        annual *= 2.0

    return max(annual, 0.0)


def _effective_reduction(spec: ControlSpec, coverage: float, implementation_quality: float) -> float:
    effectiveness = (spec.effectiveness_min + spec.effectiveness_max) / 2.0
    effectiveness *= max(0.1, min(spec.real_world_factor, 1.0))
    if effectiveness > 0.95:
        effectiveness = 0.95
    control_mult = TYPE_MULTIPLIER.get(spec.control_type.strip().lower(), 1.0)
    er = effectiveness * coverage * implementation_quality * control_mult * REALISM_FACTOR
    return min(max(er, 0.0), min(0.95, max(0.05, spec.max_effect_cap)))


def _effective_reduction_band(spec: ControlSpec, coverage: float, implementation_quality: float) -> tuple[float, float, float]:
    control_mult = TYPE_MULTIPLIER.get(spec.control_type.strip().lower(), 1.0)
    eff_low = max(0.0, min(spec.effectiveness_min * spec.real_world_factor, 0.95))
    eff_expected = min(max((spec.effectiveness_min + spec.effectiveness_max) / 2.0 * spec.real_world_factor, 0.0), 0.95)
    eff_high = max(eff_expected, min(spec.effectiveness_max * spec.real_world_factor, 0.95))

    cov_low, cov_expected, cov_high = _scenario_bounds(coverage, 0.5, 1.0)
    impl_low, impl_expected, impl_high = _scenario_bounds(implementation_quality, 0.7, 1.0)

    low = eff_low * cov_low * impl_low * control_mult * REALISM_FACTOR
    expected = eff_expected * cov_expected * impl_expected * control_mult * REALISM_FACTOR
    high = eff_high * cov_high * impl_high * control_mult * REALISM_FACTOR

    return (
        min(max(low, 0.0), min(0.95, max(0.05, spec.max_effect_cap))),
        min(max(expected, 0.0), min(0.95, max(0.05, spec.max_effect_cap))),
        min(max(high, 0.0), min(0.95, max(0.05, spec.max_effect_cap))),
    )


def _priority_from_rank(rank_score: float) -> str:
    if rank_score >= 1.0:
        return "High"
    if rank_score >= 0.25:
        return "Medium"
    return "Low"


def _rosi(loss_before: float, loss_after: float, control_cost: float) -> Optional[float]:
    if control_cost <= 0:
        return None
    return (loss_before - loss_after - control_cost) / control_cost


def _bundle_metrics(
    loss_before: float,
    reductions: List[float],
    mitigatable_fractions: List[float],
    costs: List[float],
) -> Dict[str, float]:
    if not reductions:
        return {
            "combined_effectiveness": 0.0,
            "loss_after": loss_before,
            "control_cost": 0.0,
            "rosi": 0.0,
            "mitigatable_fraction": 0.0,
        }

    prod = 1.0
    for reduction in reductions:
        prod *= (1.0 - reduction)
    combined_effectiveness = 1.0 - prod
    combined_effectiveness *= OVERLAP_PENALTY
    combined_effectiveness = min(max(combined_effectiveness, 0.0), MAX_REDUCTION)

    mitigatable_fraction = sum(mitigatable_fractions) / len(mitigatable_fractions)
    control_cost = sum(costs)
    loss_after = loss_before - (loss_before * mitigatable_fraction * combined_effectiveness)
    rosi = _rosi(loss_before, loss_after, control_cost) or 0.0
    return {
        "combined_effectiveness": combined_effectiveness,
        "loss_after": loss_after,
        "control_cost": control_cost,
        "rosi": rosi,
        "mitigatable_fraction": mitigatable_fraction,
    }


def recommend_controls(
    attack_type: str,
    loss_before: float,
    industry: str,
    company_size: Optional[str] = None,
    employee_count: Optional[float] = None,
    device_count: Optional[float] = None,
    coverage: Optional[float] = None,
    implementation_quality: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Strict implementation of the requested ROI model.
    loss_before is expected in USD (not millions).
    """
    if loss_before < 0:
        raise ValueError("loss_before must be >= 0")

    size = estimate_company_size(employee_count, explicit=company_size)
    cov = coverage if coverage is not None else get_coverage(size)
    impl = implementation_quality if implementation_quality is not None else get_maturity_score(industry)

    cov = min(max(float(cov), 0.6), 1.0)
    impl = min(max(float(impl), 0.7), 1.0)

    vulnerability = canonical_vulnerability(attack_type)
    attack_probability = ATTACK_PROBABILITY.get(vulnerability, ATTACK_PROBABILITY["Other"])
    expected_loss_before = loss_before * attack_probability
    specs = get_mitigation_specs()
    controls = [s for s in specs if s.vulnerability == vulnerability]
    if not controls:
        controls = [s for s in specs if s.vulnerability == "Other"]
        vulnerability = "Other"

    recommendations: List[Dict[str, Any]] = []
    reductions_low: List[float] = []
    reductions_expected: List[float] = []
    reductions_high: List[float] = []
    mitigatable_fractions_low: List[float] = []
    mitigatable_fractions_expected: List[float] = []
    mitigatable_fractions_high: List[float] = []
    costs_low: List[float] = []
    costs_expected: List[float] = []
    costs_high: List[float] = []

    for spec in controls:
        reduction_low, reduction_expected, reduction_high = _effective_reduction_band(spec, cov, impl)
        reductions_low.append(reduction_low)
        reductions_expected.append(reduction_expected)
        reductions_high.append(reduction_high)

        frac_lo, frac_hi = MITIGATABLE_FRACTION_RANGE_BY_TYPE.get(
            spec.control_type.strip().lower(), (0.2, 0.7)
        )
        mitigatable_fraction_expected = min(max(spec.mitigatable_fraction, frac_lo), frac_hi)
        mitigatable_fraction_expected = min(max(mitigatable_fraction_expected, 0.2), 0.7)
        mitigatable_fraction_low = max(frac_lo, mitigatable_fraction_expected - 0.08)
        mitigatable_fraction_high = min(frac_hi, mitigatable_fraction_expected + 0.08)
        mitigatable_fractions_low.append(mitigatable_fraction_low)
        mitigatable_fractions_expected.append(mitigatable_fraction_expected)
        mitigatable_fractions_high.append(mitigatable_fraction_high)

        cost_low = _annual_cost(
            ControlSpec(
                vulnerability=spec.vulnerability,
                control=spec.control,
                tools=spec.tools,
                cost_min=spec.cost_min,
                cost_max=spec.cost_min,
                cost_unit=spec.cost_unit,
                cost_scaling_type=spec.cost_scaling_type,
                effectiveness_min=spec.effectiveness_min,
                effectiveness_max=spec.effectiveness_max,
                real_world_factor=spec.real_world_factor,
                mitigatable_fraction=spec.mitigatable_fraction,
                control_type=spec.control_type,
                scope=spec.scope,
                max_effect_cap=spec.max_effect_cap,
                effort=spec.effort,
            ),
            size,
            employee_count,
            device_count,
        )
        annual_cost = _annual_cost(spec, size, employee_count, device_count)
        cost_high = _annual_cost(
            ControlSpec(
                vulnerability=spec.vulnerability,
                control=spec.control,
                tools=spec.tools,
                cost_min=spec.cost_max,
                cost_max=spec.cost_max,
                cost_unit=spec.cost_unit,
                cost_scaling_type=spec.cost_scaling_type,
                effectiveness_min=spec.effectiveness_min,
                effectiveness_max=spec.effectiveness_max,
                real_world_factor=spec.real_world_factor,
                mitigatable_fraction=spec.mitigatable_fraction,
                control_type=spec.control_type,
                scope=spec.scope,
                max_effect_cap=spec.max_effect_cap,
                effort=spec.effort,
            ),
            size,
            employee_count,
            device_count,
        )
        # Avoid zero-cost optimistic bands, which make ROSI explode or become undefined.
        min_floor = max(MIN_REALISTIC_COST, annual_cost * 0.5)
        cost_low = max(cost_low, min_floor)
        cost_high = max(cost_high, annual_cost)
        costs_low.append(cost_low)
        costs_expected.append(annual_cost)
        costs_high.append(cost_high)

        loss_after_low = expected_loss_before - (expected_loss_before * mitigatable_fraction_low * reduction_low)
        loss_after_expected = expected_loss_before - (expected_loss_before * mitigatable_fraction_expected * reduction_expected)
        loss_after_high = expected_loss_before - (expected_loss_before * mitigatable_fraction_high * reduction_high)

        loss_after_low = max(loss_after_low, 0.0)
        loss_after_expected = max(loss_after_expected, 0.0)
        loss_after_high = max(loss_after_high, 0.0)

        rosi_low = _rosi(expected_loss_before, loss_after_low, cost_high)
        rosi_expected = _rosi(expected_loss_before, loss_after_expected, annual_cost)
        rosi_high = _rosi(expected_loss_before, loss_after_high, cost_low)
        pr_weight = PRIORITY_WEIGHT.get(spec.effort.strip().lower(), 0.9)
        rank_score = (rosi_expected if rosi_expected is not None else 3.0) * pr_weight

        recommendations.append(
            {
                "vulnerability": vulnerability,
                "control": spec.control,
                "tool_examples": spec.tools,
                "cost": round(annual_cost, 2),
                "cost_low": round(cost_low, 2),
                "cost_high": round(cost_high, 2),
                "cost_basis": "annual_usd",
            "cost_scaling_type": spec.cost_scaling_type,
            "scope": spec.scope,
                "risk_reduction": round(reduction_expected, 4),
                "risk_reduction_low": round(reduction_low, 4),
                "risk_reduction_high": round(reduction_high, 4),
                "mitigatable_fraction": round(mitigatable_fraction_expected, 4),
                "mitigatable_fraction_low": round(mitigatable_fraction_low, 4),
                "mitigatable_fraction_high": round(mitigatable_fraction_high, 4),
                "loss_after": round(loss_after_expected, 2),
                "loss_after_low": round(loss_after_low, 2),
                "loss_after_high": round(loss_after_high, 2),
                "rosi": None if rosi_expected is None else round(rosi_expected, 4),
                "rosi_low": None if rosi_low is None else round(rosi_low, 4),
                "rosi_high": None if rosi_high is None else round(rosi_high, 4),
                "priority": _priority_from_rank(rank_score),
                "rank_score": round(rank_score, 4),
                "control_type": spec.control_type,
                "effort": spec.effort,
            }
        )

    # Scope-aware adjustment: combine reductions within the same scope first to avoid double counting.
    def _scope_combined(reductions: List[float], scopes: List[str]) -> List[float]:
        grouped: Dict[str, List[float]] = {}
        for reduction, scope in zip(reductions, scopes):
            grouped.setdefault(scope, []).append(reduction)
        combined: List[float] = []
        for scope, items in grouped.items():
            prod = 1.0
            for reduction in items:
                prod *= (1.0 - reduction)
            combined_scope = 1.0 - prod
            combined.append(min(max(combined_scope, 0.0), MAX_REDUCTION))
        return combined

    scopes = [spec.scope for spec in controls]
    bundle_low = _bundle_metrics(expected_loss_before, _scope_combined(reductions_low, scopes), mitigatable_fractions_low, costs_high)
    bundle_expected = _bundle_metrics(expected_loss_before, _scope_combined(reductions_expected, scopes), mitigatable_fractions_expected, costs_expected)
    bundle_high = _bundle_metrics(expected_loss_before, _scope_combined(reductions_high, scopes), mitigatable_fractions_high, costs_low)

    # Convert raw loss to expected annual loss via attack probability.
    for bundle in (bundle_low, bundle_expected, bundle_high):
        bundle["raw_loss_before"] = loss_before
        bundle["attack_probability"] = attack_probability
        bundle["expected_loss_before"] = expected_loss_before
        # Portfolio cost floor by size keeps the business case from becoming unrealistically tiny.
        size_floor = MIN_COST_BY_SIZE.get(size, MIN_COST_BY_SIZE["medium"])
        bundle["control_cost"] = max(bundle["control_cost"], size_floor)
        bundle["rosi"] = _rosi(expected_loss_before, bundle["loss_after"], bundle["control_cost"]) or 0.0

    recommendations = sorted(recommendations, key=lambda r: r["rank_score"], reverse=True)

    return {
        "attack_type_input": attack_type,
        "mapped_vulnerability": vulnerability,
        "raw_loss_before": round(loss_before, 2),
        "attack_probability": round(attack_probability, 4),
        "loss_before": round(expected_loss_before, 2),
        "expected_loss_before": round(expected_loss_before, 2),
        "coverage": round(cov, 4),
        "implementation_quality": round(impl, 4),
        "company_size": size,
        "mitigatable_fraction": round(bundle_expected["mitigatable_fraction"], 4),
        "combined_effectiveness": round(bundle_expected["combined_effectiveness"], 4),
        "combined_effectiveness_low": round(bundle_low["combined_effectiveness"], 4),
        "combined_effectiveness_high": round(bundle_high["combined_effectiveness"], 4),
        "loss_after": round(bundle_expected["loss_after"], 2),
        "loss_after_low": round(bundle_low["loss_after"], 2),
        "loss_after_high": round(bundle_high["loss_after"], 2),
        "control_cost": round(bundle_expected["control_cost"], 2),
        "control_cost_low": round(bundle_low["control_cost"], 2),
        "control_cost_high": round(bundle_high["control_cost"], 2),
        "rosi": None if bundle_expected["rosi"] is None else round(bundle_expected["rosi"], 4),
        "rosi_low": None if bundle_low["rosi"] is None else round(bundle_low["rosi"], 4),
        "rosi_high": None if bundle_high["rosi"] is None else round(bundle_high["rosi"], 4),
        "recommendations": recommendations,
        "scope_count": len(set(scopes)),
    }
