#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

import requests


def forward_alert(alert_path: Path, api_url: str, token: str) -> int:
    try:
        with alert_path.open(encoding="utf-8") as file:
            alert = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read one Wazuh alert JSON object: {exc}") from exc
    if not isinstance(alert, dict):
        raise ValueError("Wazuh alert file must contain one JSON object")

    response = requests.post(
        f"{api_url.rstrip('/')}/integrations/wazuh/alerts",
        json=alert,
        headers={"X-Wazuh-Token": token},
        timeout=15,
    )
    if not response.ok:
        raise RuntimeError(
            f"AlertMind returned HTTP {response.status_code}; check endpoint, "
            "token, and alert schema."
        )
    result = response.json()
    print(
        f"Accepted event {result['event']['id']}; "
        f"duplicate={result['duplicate']}; alerts_created={result['alerts_created']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Forward one Wazuh JSON alert to the AlertMind lab API."
    )
    parser.add_argument("alert_json", type=Path, help="File containing one JSON alert object")
    parser.add_argument(
        "--api-url",
        default=os.getenv("ALERTMIND_API", "http://127.0.0.1:8000"),
        help="AlertMind API base URL (default: ALERTMIND_API or localhost)",
    )
    args = parser.parse_args()
    token = os.getenv("WAZUH_INGEST_TOKEN")
    if not token:
        print("WAZUH_INGEST_TOKEN must be set in the environment.", file=sys.stderr)
        return 2
    try:
        return forward_alert(args.alert_json, args.api_url, token)
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"Wazuh forwarding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
