#!/usr/bin/env python3
"""
PagerDuty L1 vs L2 Incident Acknowledgment Analysis

Analyzes PagerDuty incidents for a given service and determines how often
an incident is first acknowledged by an L2 responder instead of L1.
L1/L2 is determined by the service's escalation policy levels.

Usage:
    export PAGERDUTY_API_KEY="u+your-api-key"
    python analyze_pagerduty.py --service-id PABC123
    python analyze_pagerduty.py --service-id PABC123 --days 180 --csv-output report.csv
"""

import argparse
import csv
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import requests

PAGERDUTY_BASE_URL = "https://api.pagerduty.com"
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze PagerDuty incidents: L1 vs L2 acknowledgment rates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --service-id PABC123\n"
            "  %(prog)s --service-id PABC123 --days 180\n"
            "  %(prog)s --service-id PABC123 --csv-output my_report.csv\n"
        ),
    )
    parser.add_argument(
        "--service-id",
        required=True,
        help="PagerDuty Service ID (e.g. PABC123)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="Number of days to look back (default: 90)",
    )
    parser.add_argument(
        "--csv-output",
        default="pagerduty_l1_l2_analysis.csv",
        help="CSV output filename (default: pagerduty_l1_l2_analysis.csv)",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# PagerDuty API Client
# ─────────────────────────────────────────────────────────────────────────────

class PagerDutyClient:
    """Thin wrapper around the PagerDuty REST API v2."""

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token token={api_key}",
                "Accept": "application/vnd.pagerduty+json;version=2",
                "Content-Type": "application/json",
            }
        )

    # ── helpers ──────────────────────────────────────────────────────────

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        """Execute an HTTP request with retry on transient errors and rate limits."""
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.request(method, url, **kwargs)
            except requests.ConnectionError as exc:
                if attempt == MAX_RETRIES:
                    raise
                wait = RETRY_BACKOFF_BASE ** attempt
                print(f"\n  ⚠ Connection error, retrying in {wait}s… ({exc})")
                time.sleep(wait)
                continue

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 30))
                print(f"\n  ⚠ Rate limited, waiting {wait}s…")
                time.sleep(wait)
                continue

            if resp.status_code >= 500 and attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_BASE ** attempt
                print(f"\n  ⚠ Server error {resp.status_code}, retrying in {wait}s…")
                time.sleep(wait)
                continue

            return resp

        # Should not reach here, but just in case
        return resp  # type: ignore[possibly-undefined]

    def _paginated_get(self, url: str, params: dict, resource_key: str) -> list:
        """Handle PagerDuty's offset-based pagination."""
        all_items: list = []
        params = {**params, "limit": 100, "offset": 0}
        while True:
            resp = self._request_with_retry("GET", url, params=params)
            resp.raise_for_status()
            data = resp.json()
            all_items.extend(data.get(resource_key, []))
            if not data.get("more", False):
                break
            params["offset"] += params["limit"]
        return all_items

    # ── API methods ──────────────────────────────────────────────────────

    def get_service(self, service_id: str) -> dict:
        """Get service details including its escalation policy reference."""
        resp = self._request_with_retry(
            "GET",
            f"{PAGERDUTY_BASE_URL}/services/{service_id}",
            params={"include[]": "escalation_policies"},
        )
        if resp.status_code == 404:
            print(
                f"\n✖ Service '{service_id}' not found.\n"
                "  Check the ID in your PagerDuty URL: "
                "https://<org>.pagerduty.com/services/<SERVICE_ID>"
            )
            sys.exit(1)
        resp.raise_for_status()
        return resp.json()["service"]

    def list_incidents(
        self, service_id: str, since: str, until: str
    ) -> list:
        """List all acknowledged/resolved incidents for a service in a date range."""
        return self._paginated_get(
            f"{PAGERDUTY_BASE_URL}/incidents",
            params={
                "service_ids[]": service_id,
                "since": since,
                "until": until,
                "statuses[]": ["acknowledged", "resolved"],
                "sort_by": "created_at:asc",
            },
            resource_key="incidents",
        )

    def get_incident_log_entries(self, incident_id: str) -> list:
        """Get all log entries for an incident."""
        return self._paginated_get(
            f"{PAGERDUTY_BASE_URL}/incidents/{incident_id}/log_entries",
            params={"is_overview": "false"},
            resource_key="log_entries",
        )

    def get_oncalls(
        self, escalation_policy_id: str, since: str, until: str
    ) -> list:
        """Get who was on-call for a given escalation policy at a specific time."""
        return self._paginated_get(
            f"{PAGERDUTY_BASE_URL}/oncalls",
            params={
                "escalation_policy_ids[]": escalation_policy_id,
                "since": since,
                "until": until,
            },
            resource_key="oncalls",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_incidents(
    client: PagerDutyClient, service_id: str, since: str, until: str
) -> tuple[list[dict], str, str]:
    """
    Analyze all incidents for a service and classify each acknowledgment
    as L1, L2, other, or not_acknowledged.

    Returns (results, service_name, escalation_policy_name).
    """
    # Step 1: Get the service and its escalation policy
    print("  Fetching service details…")
    service = client.get_service(service_id)
    escalation_policy_id = service["escalation_policy"]["id"]
    ep_name = service["escalation_policy"]["summary"]
    service_name = service["name"]

    # Step 2: Fetch all incidents in the date range
    print("  Fetching incidents…")
    incidents = client.list_incidents(service_id, since, until)
    total = len(incidents)
    print(f"  Found {total} incidents.\n")

    if total == 0:
        return [], service_name, ep_name

    # On-call cache keyed by date string (YYYY-MM-DD) to avoid redundant calls
    oncall_cache: dict[str, dict[int, list[dict]]] = {}
    results: list[dict] = []

    for i, incident in enumerate(incidents, 1):
        print(f"\r  Processing incident {i}/{total}…", end="", flush=True)

        # Step 3: Find the first acknowledgment log entry
        log_entries = client.get_incident_log_entries(incident["id"])
        first_ack = next(
            (e for e in log_entries if e["type"] == "acknowledge_log_entry"),
            None,
        )

        # Step 4: Determine L1/L2 on-call at incident creation time
        incident_created = incident["created_at"]
        date_key = incident_created[:10]  # YYYY-MM-DD for caching

        if date_key not in oncall_cache:
            oncalls = client.get_oncalls(
                escalation_policy_id, incident_created, incident_created
            )
            level_map: dict[int, list[dict]] = defaultdict(list)
            for oc in oncalls:
                level_map[oc["escalation_level"]].append(
                    {
                        "id": oc["user"]["id"],
                        "name": oc["user"]["summary"],
                    }
                )
            oncall_cache[date_key] = dict(level_map)

        level_map = oncall_cache[date_key]
        l1_users = level_map.get(1, [])
        l2_users = level_map.get(2, [])
        l1_user_ids = {u["id"] for u in l1_users}
        l2_user_ids = {u["id"] for u in l2_users}
        l1_names = ", ".join(u["name"] for u in l1_users) or "—"
        l2_names = ", ".join(u["name"] for u in l2_users) or "—"

        if not first_ack:
            results.append(
                {
                    "incident_number": incident["incident_number"],
                    "title": incident["title"],
                    "created_at": incident_created,
                    "urgency": incident.get("urgency", ""),
                    "ack_user_name": "—",
                    "ack_time": "—",
                    "classification": "not_acknowledged",
                    "l1_oncall": l1_names,
                    "l2_oncall": l2_names,
                }
            )
            continue

        ack_user_id = first_ack["agent"]["id"]
        ack_user_name = first_ack["agent"]["summary"]
        ack_time = first_ack["created_at"]

        # Step 5: Classify
        if ack_user_id in l1_user_ids:
            classification = "L1"
        elif ack_user_id in l2_user_ids:
            classification = "L2"
        else:
            classification = "other"

        results.append(
            {
                "incident_number": incident["incident_number"],
                "title": incident["title"],
                "created_at": incident_created,
                "urgency": incident.get("urgency", ""),
                "ack_user_name": ack_user_name,
                "ack_time": ack_time,
                "classification": classification,
                "l1_oncall": l1_names,
                "l2_oncall": l2_names,
            }
        )

    print()  # clear the progress line
    return results, service_name, ep_name


# ─────────────────────────────────────────────────────────────────────────────
# Output: Terminal Summary
# ─────────────────────────────────────────────────────────────────────────────

def _pct(count: int, total: int) -> str:
    """Format a percentage string."""
    if total == 0:
        return " 0.0%"
    return f"{count / total * 100:5.1f}%"


def print_summary(
    results: list[dict],
    service_name: str,
    ep_name: str,
    since_str: str,
    until_str: str,
) -> None:
    """Print a formatted terminal summary of the analysis."""
    total = len(results)

    # ── header ───────────────────────────────────────────────────────────
    w = 65
    print()
    print("═" * w)
    print("  PagerDuty L1 vs L2 Acknowledgment Analysis")
    print("═" * w)
    print(f"  Service:            {service_name}")
    print(f"  Escalation Policy:  {ep_name}")
    print(f"  Date Range:         {since_str[:10]} → {until_str[:10]}")
    print(f"  Total Incidents:    {total}")
    print("═" * w)

    if total == 0:
        print("\n  No incidents found in this time range.\n")
        return

    # ── breakdown ────────────────────────────────────────────────────────
    counts: dict[str, int] = defaultdict(int)
    for r in results:
        counts[r["classification"]] += 1

    l1 = counts.get("L1", 0)
    l2 = counts.get("L2", 0)
    other = counts.get("other", 0)
    no_ack = counts.get("not_acknowledged", 0)

    print()
    print("  ACKNOWLEDGMENT BREAKDOWN")
    print("  " + "─" * (w - 2))
    print(f"  Acknowledged by L1:     {l1:5d}  ({_pct(l1, total)})")
    print(f"  Acknowledged by L2:     {l2:5d}  ({_pct(l2, total)})")
    print(f"  Acknowledged by Other:  {other:5d}  ({_pct(other, total)})")
    print(f"  Not Acknowledged:       {no_ack:5d}  ({_pct(no_ack, total)})")

    # ── L2 acknowledged incidents (with L1 on-call info) ─────────────────
    l2_incidents = [r for r in results if r["classification"] == "L2"]
    if l2_incidents:
        print()
        print("  INCIDENTS ACKNOWLEDGED BY L2 (showing who was L1 at the time)")
        print("  " + "─" * (w - 2))
        for r in l2_incidents:
            ts = r["created_at"][:16].replace("T", " ")
            title = r["title"]
            if len(title) > 45:
                title = title[:42] + "…"
            print(f'  #{r["incident_number"]:<6}  {ts}  "{title}"')
            print(
                f'         Acked by: {r["ack_user_name"]} (L2)  │  '
                f'L1 on-call: {r["l1_oncall"]}'
            )

    # ── top acknowledgers ────────────────────────────────────────────────
    user_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"L1": 0, "L2": 0, "other": 0, "total": 0}
    )
    for r in results:
        if r["classification"] == "not_acknowledged":
            continue
        name = r["ack_user_name"]
        user_stats[name][r["classification"]] += 1
        user_stats[name]["total"] += 1

    if user_stats:
        sorted_users = sorted(
            user_stats.items(), key=lambda x: x[1]["total"], reverse=True
        )
        print()
        print("  TOP ACKNOWLEDGERS")
        print("  " + "─" * (w - 2))
        print(f"  {'User Name':<26} {'Count':>5}  {'as L1':>5}  {'as L2':>5}  {'as Other':>8}")
        print("  " + "─" * (w - 2))
        for name, stats in sorted_users[:15]:
            print(
                f"  {name:<26} {stats['total']:>5}  "
                f"{stats['L1']:>5}  {stats['L2']:>5}  {stats['other']:>8}"
            )

    # ── monthly trend ────────────────────────────────────────────────────
    monthly: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "L1": 0, "L2": 0, "other": 0, "not_acknowledged": 0}
    )
    for r in results:
        month = r["created_at"][:7]  # YYYY-MM
        monthly[month]["total"] += 1
        monthly[month][r["classification"]] += 1

    if monthly:
        print()
        print("  MONTHLY TREND")
        print("  " + "─" * (w - 2))
        print(
            f"  {'Month':<12} {'Total':>5}  {'L1 Ack':>6}  "
            f"{'L2 Ack':>6}  {'Other':>5}  {'No Ack':>6}"
        )
        print("  " + "─" * (w - 2))
        for month in sorted(monthly.keys()):
            m = monthly[month]
            print(
                f"  {month:<12} {m['total']:>5}  {m['L1']:>6}  "
                f"{m['L2']:>6}  {m['other']:>5}  {m['not_acknowledged']:>6}"
            )

    print()


# ─────────────────────────────────────────────────────────────────────────────
# Output: CSV Export
# ─────────────────────────────────────────────────────────────────────────────

CSV_COLUMNS = [
    "incident_number",
    "title",
    "created_at",
    "urgency",
    "ack_user_name",
    "ack_time",
    "classification",
    "l1_oncall",
    "l2_oncall",
]


def write_csv(results: list[dict], output_path: str) -> None:
    """Write analysis results to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    print(f"  ✔ CSV written to {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # Validate API key
    api_key = os.environ.get("PAGERDUTY_API_KEY", "").strip()
    if not api_key:
        print(
            "✖ PAGERDUTY_API_KEY environment variable is not set.\n\n"
            "  Create an API key at:\n"
            "    https://<your-org>.pagerduty.com/api_keys\n\n"
            "  Then run:\n"
            '    export PAGERDUTY_API_KEY="u+your-api-key"\n'
            f"    python {sys.argv[0]} --service-id {args.service_id}\n"
        )
        sys.exit(1)

    # Compute date range
    now = datetime.now(timezone.utc)
    since_dt = now - timedelta(days=args.days)
    since_str = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    print()
    print(f"  Analyzing service {args.service_id}")
    print(f"  Date range: {since_str[:10]} → {until_str[:10]} ({args.days} days)")
    print()

    client = PagerDutyClient(api_key)

    results, service_name, ep_name = analyze_incidents(
        client, args.service_id, since_str, until_str
    )

    print_summary(results, service_name, ep_name, since_str, until_str)
    write_csv(results, args.csv_output)
    print()


if __name__ == "__main__":
    main()
