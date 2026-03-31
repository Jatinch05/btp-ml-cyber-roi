from __future__ import annotations

import argparse
import itertools
import json
import math
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

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
        return " + ".join(normalize_token(p) for p in s.split(",") if p.strip())
    return normalize_token(s)


@dataclass
class Failure:
    mode: str
    industry: str
    attack_type: str
    data_type: str
    reason: str


def chunked(items: Iterable[dict], size: int) -> Iterable[list[dict]]:
    batch: list[dict] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def main() -> int:
    parser = argparse.ArgumentParser(description="Test API /predict for all category combinations.")
    parser.add_argument("--endpoint", default="http://127.0.0.1:8000/predict")
    parser.add_argument("--data", default="data/model_ready/combined_clean.csv")
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--mode", choices=["raw", "readable", "both"], default="both")
    parser.add_argument("--max-combos", type=int, default=0, help="Limit combinations per mode; 0 means all.")
    parser.add_argument("--out", default="data/processed/api_combo_test_report.json")
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    df = pd.read_csv(data_path)
    required_cols = ["Industry", "Attack_Type", "Data_Type", "Year", "Records_Compromised", "Country"]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in dataset: {missing}")

    industries = sorted(df["Industry"].dropna().astype(str).str.strip().unique().tolist())
    attacks_raw = sorted(df["Attack_Type"].dropna().astype(str).str.strip().unique().tolist())
    data_types_raw = sorted(df["Data_Type"].dropna().astype(str).str.strip().unique().tolist())

    if not industries or not attacks_raw or not data_types_raw:
        raise ValueError("One or more category vocabularies are empty.")

    year = int(pd.to_numeric(df["Year"], errors="coerce").dropna().max())
    records = float(pd.to_numeric(df["Records_Compromised"], errors="coerce").dropna().median())
    country_series = df["Country"].dropna().astype(str).str.strip()
    country = country_series.mode().iloc[0] if not country_series.empty else "US"

    modes = [args.mode] if args.mode in {"raw", "readable"} else ["raw", "readable"]

    failures: list[Failure] = []
    totals: dict[str, int] = {}
    successes: dict[str, int] = {}

    session = requests.Session()
    started = time.time()

    for mode in modes:
        if mode == "raw":
            attacks = attacks_raw
            data_types = data_types_raw
        else:
            attacks = [normalize_label(v) for v in attacks_raw]
            data_types = [normalize_label(v) for v in data_types_raw]

        combos = itertools.product(industries, attacks, data_types)
        total_mode = len(industries) * len(attacks) * len(data_types)
        if args.max_combos > 0:
            total_mode = min(total_mode, args.max_combos)
            combos = itertools.islice(combos, args.max_combos)

        totals[mode] = total_mode
        successes[mode] = 0

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
        for batch_idx, batch in enumerate(chunked(payload_iter(), args.batch_size), start=1):
            try:
                resp = session.post(args.endpoint, json=batch, timeout=args.timeout)
            except Exception as e:
                reason = f"request_error: {e}"
                for item in batch:
                    failures.append(
                        Failure(mode, item["Industry"], item["Attack_Type"], item["Data_Type"], reason)
                    )
                processed += len(batch)
                continue

            if resp.status_code != 200:
                reason = f"http_{resp.status_code}: {resp.text[:400]}"
                for item in batch:
                    failures.append(
                        Failure(mode, item["Industry"], item["Attack_Type"], item["Data_Type"], reason)
                    )
                processed += len(batch)
                continue

            try:
                preds = resp.json()
            except Exception as e:
                reason = f"json_decode_error: {e}"
                for item in batch:
                    failures.append(
                        Failure(mode, item["Industry"], item["Attack_Type"], item["Data_Type"], reason)
                    )
                processed += len(batch)
                continue

            if not isinstance(preds, list) or len(preds) != len(batch):
                reason = f"response_length_mismatch: got={len(preds) if isinstance(preds, list) else 'non-list'} expected={len(batch)}"
                for item in batch:
                    failures.append(
                        Failure(mode, item["Industry"], item["Attack_Type"], item["Data_Type"], reason)
                    )
                processed += len(batch)
                continue

            for item, pred in zip(batch, preds):
                value = pred.get("prediction_musd") if isinstance(pred, dict) else None
                if value is None or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or float(value) < 0:
                    failures.append(
                        Failure(mode, item["Industry"], item["Attack_Type"], item["Data_Type"], f"bad_prediction_value: {value}")
                    )
                else:
                    successes[mode] += 1

            processed += len(batch)
            if batch_idx % 10 == 0 or processed == total_mode:
                print(f"[{mode}] processed {processed}/{total_mode}")

    elapsed = time.time() - started
    report = {
        "endpoint": args.endpoint,
        "dataset": str(data_path),
        "mode": args.mode,
        "totals": totals,
        "successes": successes,
        "failures_count": len(failures),
        "elapsed_sec": round(elapsed, 2),
        "failures": [asdict(f) for f in failures[:5000]],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n=== API Combination Test Summary ===")
    print(f"Endpoint: {args.endpoint}")
    print(f"Modes: {', '.join(modes)}")
    print(f"Totals: {totals}")
    print(f"Successes: {successes}")
    print(f"Failures: {len(failures)}")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Report: {out_path}")

    return 0 if len(failures) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
