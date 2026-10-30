import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "measure_impact.py"


def test_impact_calculator_reports_paired_metric_changes(tmp_path):
    measurements = tmp_path / "measurements.csv"
    measurements.write_text(
        "run_id,scenario_id,condition,incident_start_utc,detected_utc,resolved_utc\n"
        "b1,scenario-a,baseline,2026-10-30T10:00:00+00:00,"
        "2026-10-30T10:05:00+00:00,2026-10-30T10:25:00+00:00\n"
        "a1,scenario-a,assistant,2026-10-30T10:00:00+00:00,"
        "2026-10-30T10:04:00+00:00,2026-10-30T10:14:00+00:00\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(measurements)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["results"]["baseline"]["mean_mttd_minutes"] == 5
    assert result["results"]["assistant"]["mean_mttr_minutes"] == 10
    assert result["mean_duration_reduction_percent"] == {"mttd": 20, "mttr": 50}


def test_impact_calculator_rejects_unpaired_scenarios(tmp_path):
    measurements = tmp_path / "measurements.csv"
    measurements.write_text(
        "run_id,scenario_id,condition,incident_start_utc,detected_utc,resolved_utc\n"
        "b1,scenario-a,baseline,2026-10-30T10:00:00+00:00,"
        "2026-10-30T10:05:00+00:00,2026-10-30T10:25:00+00:00\n"
        "a1,scenario-b,assistant,2026-10-30T10:00:00+00:00,"
        "2026-10-30T10:04:00+00:00,2026-10-30T10:14:00+00:00\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(measurements)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "same scenario_id" in completed.stderr
