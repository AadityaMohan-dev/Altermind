#!/usr/bin/env python3
import argparse
import csv
import json
import statistics
import sys
from datetime import datetime, timedelta
from pathlib import Path


CONDITIONS = {"baseline", "assistant"}
FIELDS = {
    "run_id",
    "scenario_id",
    "condition",
    "incident_start_utc",
    "detected_utc",
    "resolved_utc",
}


def parse_timestamp(value: str, field: str, run_id: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{run_id}: invalid {field} timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{run_id}: {field} must include a UTC offset")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{run_id}: {field} must be normalized to UTC")
    return parsed


def load_measurements(path: Path) -> dict:
    groups = {condition: [] for condition in CONDITIONS}
    scenario_ids = {condition: set() for condition in CONDITIONS}
    seen_run_ids = set()

    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not FIELDS.issubset(reader.fieldnames):
            raise ValueError(f"CSV must include columns: {', '.join(sorted(FIELDS))}")

        for line_number, row in enumerate(reader, start=2):
            run_id = (row.get("run_id") or "").strip()
            scenario_id = (row.get("scenario_id") or "").strip()
            condition = (row.get("condition") or "").strip().lower()
            if not run_id or not scenario_id:
                raise ValueError(f"Line {line_number}: run_id and scenario_id are required")
            if run_id in seen_run_ids:
                raise ValueError(f"Line {line_number}: duplicate run_id {run_id!r}")
            if condition not in CONDITIONS:
                raise ValueError(
                    f"Line {line_number}: condition must be baseline or assistant"
                )
            seen_run_ids.add(run_id)

            started = parse_timestamp(row["incident_start_utc"], "incident_start_utc", run_id)
            detected = parse_timestamp(row["detected_utc"], "detected_utc", run_id)
            resolved = parse_timestamp(row["resolved_utc"], "resolved_utc", run_id)
            if detected < started:
                raise ValueError(f"{run_id}: detection precedes incident start")
            if resolved < detected:
                raise ValueError(f"{run_id}: resolution precedes detection")

            groups[condition].append({
                "mttd_minutes": (detected - started).total_seconds() / 60,
                "mttr_minutes": (resolved - detected).total_seconds() / 60,
            })
            scenario_ids[condition].add(scenario_id)

    for condition, runs in groups.items():
        if not runs:
            raise ValueError(f"No measurements provided for {condition}")
    if scenario_ids["baseline"] != scenario_ids["assistant"]:
        raise ValueError(
            "Baseline and assistant runs must cover the same scenario_id values"
        )

    results = {}
    for condition, runs in groups.items():
        mttd = [run["mttd_minutes"] for run in runs]
        mttr = [run["mttr_minutes"] for run in runs]
        results[condition] = {
            "run_count": len(runs),
            "mean_mttd_minutes": round(statistics.fmean(mttd), 2),
            "median_mttd_minutes": round(statistics.median(mttd), 2),
            "mean_mttr_minutes": round(statistics.fmean(mttr), 2),
            "median_mttr_minutes": round(statistics.median(mttr), 2),
        }

    def reduction_percent(baseline: float, assisted: float):
        if baseline == 0:
            return None
        return round((baseline - assisted) / baseline * 100, 2)

    return {
        "definitions": {
            "mttd": "detected_utc minus incident_start_utc",
            "mttr": "resolved_utc minus detected_utc",
            "reduction_percent": "positive means lower mean duration with assistant",
        },
        "results": results,
        "mean_duration_reduction_percent": {
            "mttd": reduction_percent(
                results["baseline"]["mean_mttd_minutes"],
                results["assistant"]["mean_mttd_minutes"],
            ),
            "mttr": reduction_percent(
                results["baseline"]["mean_mttr_minutes"],
                results["assistant"]["mean_mttr_minutes"],
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calculate paired baseline-versus-assistant MTTD/MTTR."
    )
    parser.add_argument("csv_path", type=Path, help="Completed measurement CSV")
    args = parser.parse_args()
    try:
        result = load_measurements(args.csv_path)
    except (OSError, ValueError) as exc:
        print(f"Measurement error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
