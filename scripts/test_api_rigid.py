from __future__ import annotations

import argparse
import itertools
import json
import math
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
import requests


ACRONYM_MAP = {
    "api": "API",
    "ddos": "DDoS",
    "iot": "IoT",
    "ot": "OT",
    "pii": "PII",
    "phi": "PHI",
    "ip": "IP",
    "gps": "GPS",
    "scada": "SCADA",
    "pos": "POS",
}


def normalize_token(text: str) -> str:
    t = text.strip().replace("_", " ").replace("-", " ")
    parts = [p for p in t.split() if p]
    normalized: list[str] = []
    for p in parts:
        normalized.append(ACRONYM_MAP.get(p.lower(), p.capitalize()))
    return " ".join(normalized)


def normalize_label(value: str) -> str:
    s = str(value).strip()
    if not s:
        return s
    if "," in s:
        return ", ".join(normalize_token(p) for p in s.split(",") if p.strip())
    return normalize_token(s)


def chunked(items: Iterable[dict], size: int) -> Iterable[List[dict]]:
    batch: List[dict] = []
    for it in items:
        batch.append(it)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


@dataclass
class Failure:
    test: str
    mode: str
    key: str
    reason: str


def approx_equal(a: float, b: float, tol: float = 1e-3) -> bool:
    return abs(a - b) <= tol * max(1.0, abs(a), abs(b))


def validate_predict_item(item: Any) -> Optional[str]:
    if not isinstance(item, dict):
        return "predict item is not an object"
    v = item.get("prediction_musd")
    if v is None or not isinstance(v, (int, float)):
        return f"prediction_musd missing/invalid: {v}"
    fv = float(v)
    if not math.isfinite(fv) or fv < 0:
        return f"prediction_musd not finite/non-negative: {v}"
    ff = item.get("fields_filled")
    if ff is not None and not isinstance(ff, list):
        return f"fields_filled should be list or null: {type(ff).__name__}"
    return None


def validate_recommendation_response(resp: Any) -> Optional[str]:
    if not isinstance(resp, dict):
        return "recommendation response is not an object"

    for fld in ["mapped_vulnerability", "loss_before", "combined_effectiveness", "loss_after", "control_cost", "recommendations"]:
        if fld not in resp:
            return f"missing field: {fld}"

    loss_before = float(resp.get("loss_before", -1))
    combined_eff = float(resp.get("combined_effectiveness", -1))
    loss_after = float(resp.get("loss_after", -1))
    control_cost = float(resp.get("control_cost", -1))

    if loss_before < 0:
        return "loss_before < 0"
    if not (0.0 <= combined_eff <= 1.0):
        return f"combined_effectiveness out of range: {combined_eff}"
    if loss_after < 0 or loss_after > loss_before + 1e-6:
        return f"loss_after invalid relative to loss_before: {loss_after} > {loss_before}"
    if control_cost < 0:
        return "control_cost < 0"

    # Check combined effectiveness math relation.
    expected_loss_after = loss_before * (1.0 - combined_eff)
    if not approx_equal(loss_after, expected_loss_after, tol=5e-3):
        return f"loss_after mismatch with combined_effectiveness: expected {expected_loss_after}, got {loss_after}"

    recs = resp.get("recommendations")
    if not isinstance(recs, list) or not recs:
        return "recommendations missing/empty"

    # Per-control sanity.
    for i, r in enumerate(recs):
        if not isinstance(r, dict):
            return f"recommendation[{i}] not object"
        for f in ["control", "cost", "risk_reduction", "loss_after", "priority"]:
            if f not in r:
                return f"recommendation[{i}] missing field {f}"
        rr = float(r.get("risk_reduction", -1))
        c = float(r.get("cost", -1))
        la = float(r.get("loss_after", -1))
        if rr < 0 or rr > 0.95 + 1e-6:
            return f"recommendation[{i}] risk_reduction out of range: {rr}"
        if c < 0:
            return f"recommendation[{i}] cost < 0"
        if la < 0 or la > loss_before + 1e-6:
            return f"recommendation[{i}] loss_after invalid"
        pr = str(r.get("priority", ""))
        if pr not in {"High", "Medium", "Low"}:
            return f"recommendation[{i}] priority invalid: {pr}"

        rosi = r.get("rosi")
        if c > 0 and rosi is not None:
            expected_rosi = (loss_before - la - c) / c
            if not approx_equal(float(rosi), expected_rosi, tol=8e-3):
                return f"recommendation[{i}] rosi mismatch"

    rosi_top = resp.get("rosi")
    if control_cost > 0 and rosi_top is not None:
        expected = (loss_before - loss_after - control_cost) / control_cost
        if not approx_equal(float(rosi_top), expected, tol=8e-3):
            return "portfolio rosi mismatch"

    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Rigid API test across exhaustive combinations with sanity checks")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--data", default="data/model_ready/combined_clean.csv")
    ap.add_argument("--batch-size", type=int, default=400)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--max-combos", type=int, default=0, help="0 means full Cartesian")
    ap.add_argument("--run-predict", action="store_true")
    ap.add_argument("--run-recommend", action="store_true")
    ap.add_argument("--run-predict-recommend", action="store_true")
    ap.add_argument("--mode", choices=["raw", "readable", "both"], default="both")
    ap.add_argument("--out", default="data/processed/api_rigid_test_report.json")
    args = ap.parse_args()

    if not (args.run_predict or args.run_recommend or args.run_predict_recommend):
        # default: run all
        args.run_predict = True
        args.run_recommend = True
        args.run_predict_recommend = True

    p = Path(args.data)
    if not p.exists():
        raise FileNotFoundError(f"dataset not found: {p}")
    df = pd.read_csv(p)

    industries = sorted(df["Industry"].dropna().astype(str).str.strip().unique().tolist())
    attacks_raw = sorted(df["Attack_Type"].dropna().astype(str).str.strip().unique().tolist())
    dtypes_raw = sorted(df["Data_Type"].dropna().astype(str).str.strip().unique().tolist())

    year = int(pd.to_numeric(df["Year"], errors="coerce").dropna().max())
    records = float(pd.to_numeric(df["Records_Compromised"], errors="coerce").dropna().median())
    country_s = df["Country"].dropna().astype(str).str.strip()
    country = country_s.mode().iloc[0] if not country_s.empty else "US"

    modes = [args.mode] if args.mode in {"raw", "readable"} else ["raw", "readable"]

    session = requests.Session()
    failures: List[Failure] = []
    summary: Dict[str, Any] = {
        "base_url": args.base_url,
        "dataset": str(p),
        "mode": args.mode,
        "totals": {},
        "passes": {},
        "failures": 0,
        "elapsed_sec": None,
    }

    start = time.time()

    # --- /predict exhaustive ---
    if args.run_predict:
        endpoint = f"{args.base_url}/predict"
        for mode in modes:
            attacks = attacks_raw if mode == "raw" else [normalize_label(v) for v in attacks_raw]
            dtypes = dtypes_raw if mode == "raw" else [normalize_label(v) for v in dtypes_raw]

            combos = itertools.product(industries, attacks, dtypes)
            total = len(industries) * len(attacks) * len(dtypes)
            if args.max_combos > 0:
                total = min(total, args.max_combos)
                combos = itertools.islice(combos, args.max_combos)

            key = f"predict::{mode}"
            summary["totals"][key] = total
            summary["passes"][key] = 0

            def payload_iter() -> Iterable[dict]:
                for ind, atk, dt in combos:
                    yield {
                        "Industry": ind,
                        "Year": year,
                        "Attack_Type": atk,
                        "Data_Type": dt,
                        "Records_Compromised": records,
                        "Country": country,
                    }

            processed = 0
            for bi, batch in enumerate(chunked(payload_iter(), args.batch_size), start=1):
                try:
                    resp = session.post(endpoint, json=batch, timeout=args.timeout)
                    if resp.status_code != 200:
                        raise RuntimeError(f"http_{resp.status_code}: {resp.text[:200]}")
                    data = resp.json()
                    if not isinstance(data, list) or len(data) != len(batch):
                        raise RuntimeError("response length mismatch")
                    for item_in, item_out in zip(batch, data):
                        err = validate_predict_item(item_out)
                        if err:
                            failures.append(Failure("predict", mode, json.dumps(item_in, ensure_ascii=False), err))
                        else:
                            summary["passes"][key] += 1
                except Exception as e:
                    for item_in in batch:
                        failures.append(Failure("predict", mode, json.dumps(item_in, ensure_ascii=False), f"request_error: {e}"))
                processed += len(batch)
                if bi % 10 == 0 or processed == total:
                    print(f"[{key}] processed {processed}/{total}")

    # --- /recommend-controls exhaustive ---
    if args.run_recommend:
        endpoint = f"{args.base_url}/recommend-controls"
        company_sizes = ["small", "medium", "large"]
        cov_grid: List[Optional[float]] = [None, 0.6, 1.0]
        impl_grid: List[Optional[float]] = [None, 0.7, 1.0]

        for mode in modes:
            attacks = attacks_raw if mode == "raw" else [normalize_label(v) for v in attacks_raw]
            combos = itertools.product(industries, attacks, company_sizes, cov_grid, impl_grid)
            total = len(industries) * len(attacks) * len(company_sizes) * len(cov_grid) * len(impl_grid)
            if args.max_combos > 0:
                total = min(total, args.max_combos)
                combos = itertools.islice(combos, args.max_combos)

            key = f"recommend::{mode}"
            summary["totals"][key] = total
            summary["passes"][key] = 0

            for i, (ind, atk, size, cov, impl) in enumerate(combos, start=1):
                payload = {
                    "attack_type": atk,
                    "predicted_loss_usd": 4_500_000.0,
                    "industry": ind,
                    "company_size": size,
                    "employee_count": 500.0 if size == "medium" else (120.0 if size == "small" else 2500.0),
                    "device_count": 500.0 if size == "medium" else (120.0 if size == "small" else 2500.0),
                    "coverage": cov,
                    "implementation_quality": impl,
                }
                try:
                    resp = session.post(endpoint, json=payload, timeout=args.timeout)
                    if resp.status_code != 200:
                        raise RuntimeError(f"http_{resp.status_code}: {resp.text[:200]}")
                    data = resp.json()
                    err = validate_recommendation_response(data)
                    if err:
                        failures.append(Failure("recommend", mode, json.dumps(payload, ensure_ascii=False), err))
                    else:
                        summary["passes"][key] += 1
                except Exception as e:
                    failures.append(Failure("recommend", mode, json.dumps(payload, ensure_ascii=False), f"request_error: {e}"))

                if i % 1000 == 0 or i == total:
                    print(f"[{key}] processed {i}/{total}")

    # --- /predict-and-recommend exhaustive ---
    if args.run_predict_recommend:
        endpoint = f"{args.base_url}/predict-and-recommend"
        for mode in modes:
            attacks = attacks_raw if mode == "raw" else [normalize_label(v) for v in attacks_raw]
            dtypes = dtypes_raw if mode == "raw" else [normalize_label(v) for v in dtypes_raw]
            combos = itertools.product(industries, attacks, dtypes)
            total = len(industries) * len(attacks) * len(dtypes)
            if args.max_combos > 0:
                total = min(total, args.max_combos)
                combos = itertools.islice(combos, args.max_combos)

            key = f"predict_recommend::{mode}"
            summary["totals"][key] = total
            summary["passes"][key] = 0

            def payload_iter() -> Iterable[dict]:
                for ind, atk, dt in combos:
                    yield {
                        "Industry": ind,
                        "Year": year,
                        "Attack_Type": atk,
                        "Data_Type": dt,
                        "Records_Compromised": records,
                        "Country": country,
                        "Employee_Count": 500,
                    }

            processed = 0
            for bi, batch in enumerate(chunked(payload_iter(), args.batch_size), start=1):
                try:
                    resp = session.post(endpoint, json=batch, timeout=args.timeout)
                    if resp.status_code != 200:
                        raise RuntimeError(f"http_{resp.status_code}: {resp.text[:200]}")
                    data = resp.json()
                    if not isinstance(data, list) or len(data) != len(batch):
                        raise RuntimeError("response length mismatch")

                    for item_in, item_out in zip(batch, data):
                        if not isinstance(item_out, dict):
                            failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), "item is not object"))
                            continue
                        pm = item_out.get("prediction_musd")
                        pu = item_out.get("prediction_usd")
                        rec = item_out.get("recommendation")
                        if not isinstance(pm, (int, float)) or not isinstance(pu, (int, float)):
                            failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), "missing prediction values"))
                            continue
                        if float(pm) < 0 or float(pu) < 0:
                            failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), "negative prediction"))
                            continue
                        if not approx_equal(float(pu), float(pm) * 1_000_000.0, tol=1e-6):
                            failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), "prediction_usd mismatch"))
                            continue
                        err = validate_recommendation_response(rec)
                        if err:
                            failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), err))
                            continue
                        if not approx_equal(float(rec.get("loss_before", -1)), float(pu), tol=1e-6):
                            failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), "recommend.loss_before != prediction_usd"))
                            continue
                        summary["passes"][key] += 1

                except Exception as e:
                    for item_in in batch:
                        failures.append(Failure("predict_recommend", mode, json.dumps(item_in, ensure_ascii=False), f"request_error: {e}"))

                processed += len(batch)
                if bi % 10 == 0 or processed == total:
                    print(f"[{key}] processed {processed}/{total}")

    elapsed = time.time() - start
    summary["elapsed_sec"] = round(elapsed, 2)
    summary["failures"] = len(failures)

    out = {
        "summary": summary,
        "failure_samples": [asdict(f) for f in failures[:2000]],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print("\n=== Rigid API Test Summary ===")
    print(json.dumps(summary, indent=2))
    print(f"report: {out_path}")

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
