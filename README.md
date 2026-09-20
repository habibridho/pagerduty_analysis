# PagerDuty L1 vs L2 Acknowledgment Analysis

Analyzes PagerDuty incidents for a service and determines how often an incident is first acknowledged by L2 instead of L1.

**L1/L2** is determined by the service's **escalation policy levels**: Level 1 = L1, Level 2 = L2.

## Prerequisites

- Python 3.10+
- A PagerDuty REST API key (read-only is sufficient)
- Your PagerDuty Service ID

### Getting Your API Key

1. Go to your PagerDuty "My Profile" page
2. Under the "User Settings" tab, click **Create API User Key**
3. Give it a description (e.g., "L1/L2 Analysis") and create it
4. Copy the key — it starts with `u+`

### Finding Your Service ID

1. Open your service in the PagerDuty web UI
2. The URL will look like: `https://<your-org>.pagerduty.com/services/PABC123`
3. `PABC123` is your Service ID

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Set your API key
export PAGERDUTY_API_KEY="u+your-api-key-here"

# Run analysis (default: last 90 days)
python analyze_pagerduty.py --service-id PABC123

# Custom date range (last 180 days)
python analyze_pagerduty.py --service-id PABC123 --days 180

# Custom CSV output filename
python analyze_pagerduty.py --service-id PABC123 --csv-output my_report.csv
```

## Output

### Terminal Summary

The script prints a formatted summary including:

- **Acknowledgment Breakdown**: Counts and percentages for L1, L2, other, and unacknowledged
- **Incidents Acknowledged by L2**: Lists each L2-acked incident with who the L1 on-call was at the time
- **Top Acknowledgers**: Who acknowledged the most incidents, broken down by L1/L2/other
- **Monthly Trend**: Month-by-month breakdown of acknowledgment patterns

### CSV Export

A CSV file (default: `pagerduty_l1_l2_analysis.csv`) with one row per incident:

| Column | Description |
|---|---|
| `incident_number` | PagerDuty incident number |
| `title` | Incident title |
| `created_at` | When the incident was created |
| `urgency` | high / low |
| `ack_user_name` | Who acknowledged (or `—` if nobody) |
| `ack_time` | When it was acknowledged |
| `classification` | `L1`, `L2`, `other`, or `not_acknowledged` |
| `l1_oncall` | Who was L1 on-call when the incident was created |
| `l2_oncall` | Who was L2 on-call when the incident was created |

## API Rate Limits

PagerDuty allows 960 API requests per minute. The script caches on-call lookups by date and handles rate limiting (HTTP 429) automatically with retries.

For services with many incidents, the script may take a few minutes to process all data.
