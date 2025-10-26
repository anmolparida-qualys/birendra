#!/usr/bin/env python3
import os
import requests
import json
import shutil
import time
import logging
import urllib3
import sys
import argparse
import csv
from datetime import datetime, timedelta, timezone, date

# === Disable SSL warnings ===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
TOKEN = ""
BASE_URL = ""
LIMIT = 250
TEMP_DIR = "temp_reports"
FINAL_JSON_DIR = "weekly_reports"
FINAL_CSV_DIR = "weekly_csv_reports"

# === Hardcoded CSV Columns (one row per vulnerability QID) ===
CSV_COLUMNS = [
    # Container identity & status
    "containerId","uuid","name","state","ipv4","ipv6",
    "created","updated","stateChanged","riskScore","qdsSeverity","maxQdsScore",
    "imageId","imageSha","imageUuid","customerUuid","privileged","isRoot",
    "isVulnPropagated","source","sensorUuid",
    # Host / cluster info
    "host.sensorUuid","host.hostname","host.ipAddress",
    "cluster.name","cluster.uid","cluster.version",
    "cluster.k8s.pod.name","cluster.k8s.pod.namespace","cluster.k8s.pod.uuid",
    "cluster.k8s.pod.controller[0].name","cluster.k8s.pod.controller[0].type",
    "hostArchitecture",
    # Runtime context
    "environment","command","arguments",
    # Vulnerability fields (one row per QID)
    "vuln_qid","vuln_firstFound","vuln_lastFound","vuln_typeDetected","vuln_scanTypes",
    # From vulnerability.software[] (joined if multiple)
    "vuln_software_names","vuln_software_versions","vuln_software_fixVersions","vuln_software_packagePaths"
]

# === CLI Arguments ===
parser = argparse.ArgumentParser(description="Fetch weekly container data from Qualys API.")
parser.add_argument("BASE_URL", nargs="?", help="Qualys Gateway URL (e.g. https://gateway.qg2.apps.qualys.com)")
parser.add_argument("--optional_filter", help="Optional additional filter to combine with created filter", default="")
parser.add_argument("--start_date", help="Start date (YYYY-MM-DD). Optional.", default="")
parser.add_argument("--end_date", help="End date (YYYY-MM-DD). Optional.", default="")
parser.add_argument("--csv_columns", help="Optional comma-separated list of CSV columns to override defaults.", default="")
args = parser.parse_args()

# === Validate and Construct Full API URL ===
BASE_URL = args.BASE_URL.strip() if args.BASE_URL else ""
if not BASE_URL:
    print("[ERROR] BASE_URL is required. Example:")
    print("  python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com")
    sys.exit(1)

# Ensure API endpoint suffix
if not BASE_URL.endswith("/csapi/v1.3/containers/list"):
    BASE_URL = BASE_URL.rstrip("/") + "/csapi/v1.3/containers/list"

optional_filter = args.optional_filter.strip()
start_date_arg = args.start_date.strip()
end_date_arg = args.end_date.strip()

TOKEN = os.getenv("QUALYS_TOKEN", TOKEN)

# Check token presence
if not TOKEN:
    print("[ERROR] Missing QUALYS_TOKEN. Please export it first:")
    print("  export QUALYS_TOKEN='<your_api_token_here>'")
    sys.exit(1)

if args.csv_columns.strip():
    CSV_COLUMNS = [c.strip() for c in args.csv_columns.split(",") if c.strip()]

# === Logging ===
os.makedirs("logs", exist_ok=True)
log_file = os.path.join("logs", f"weekly_report_{datetime.now().strftime('%Y%m%d_%H%M')}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[logging.FileHandler(log_file, mode='a'), logging.StreamHandler()]
)
logger = logging.getLogger()
print = lambda *a, **k: logger.info(" ".join(map(str, a)))  # Log + console output

# === Headers ===
HEADERS = {
    "accept": "application/json",
    "Authorization": f"Bearer {TOKEN}"
}

# === Helper Functions ===
def parse_date_ymd(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def daterange(start_date, end_date, step_days=7):
    current = start_date
    while current < end_date:
        next_date = min(current + timedelta(days=step_days), end_date)
        yield current, next_date
        current = next_date

def fetch_paginated_data(filter_query):
    url = BASE_URL
    params = {"filter": filter_query, "limit": LIMIT}
    all_data = []
    page = 1

    while url:
        print(f"[+] Fetching PAGE {page} for filter {filter_query}")
        response = requests.get(url, headers=HEADERS, params=params if page == 1 else None, verify=False)
        time.sleep(0.2)  # safer pacing for API calls

        if response.status_code == 401:
            print(f"[ERROR] Unauthorized (401). Token may be invalid or expired. Exiting script.")
            sys.exit(1)

        if response.status_code != 200:
            print(f"[ERROR] {response.status_code}: {response.text}")
            break

        json_data = response.json()
        data = json_data.get("data", [])
        all_data.extend(data)
        print(f"Page {page}: {len(data)} records")

        link_header = response.headers.get("Link")
        if link_header and "rel=next" in link_header:
            start = link_header.find("<") + 1
            end = link_header.find(">")
            url = link_header[start:end]
            page += 1
        else:
            url = None

    return all_data

def parse_week_filename(filename):
    try:
        name = os.path.splitext(filename)[0]
        start_str, end_str = name.split("-")
        year = datetime.now().year
        start_date = datetime.strptime(f"{start_str}{year}", "%b%d%Y").date()
        end_date = datetime.strptime(f"{end_str}{year}", "%b%d%Y").date()
        return start_date, end_date
    except Exception:
        return None, None

def get_existing_week_files():
    if not os.path.exists(FINAL_JSON_DIR):
        os.makedirs(FINAL_JSON_DIR)
    files = os.listdir(FINAL_JSON_DIR)
    week_files = {}
    for f in files:
        start, end = parse_week_filename(f)
        if start and end:
            week_files[f] = (start, end)
    return week_files

def generate_all_week_ranges(start_date, end_date):
    if start_date >= end_date:
        print("[ERROR] No valid date range selected.")
        sys.exit(1)
    weeks = []
    for week_start, week_end in daterange(start_date, end_date):
        filename = f"{week_start.strftime('%b%d')}-{week_end.strftime('%b%d')}.json"
        weeks.append((week_start, week_end, filename))
    return weeks

def get_nested_value(obj, path):
    """Safely get a nested value using dotted or indexed notation."""
    try:
        parts = path.replace("]", "").split(".")
        for part in parts:
            if "[" in part:
                key, idx = part.split("[")
                obj = obj.get(key, [])
                if isinstance(obj, list) and len(obj) > int(idx):
                    obj = obj[int(idx)]
                else:
                    return ""
            else:
                obj = obj.get(part) if isinstance(obj, dict) else ""
            if obj in [None, "null"]:
                return ""
        if isinstance(obj, (list, dict)):
            return json.dumps(obj, ensure_ascii=False)
        return str(obj)
    except Exception:
        return ""

def sanitize_cell(v):
    if v is None or v in ["None", "null", [], {}, ""]:
        return ""
    return str(v).replace("\n", " ").replace("\r", " ").strip()

BASE_CONTAINER_COLUMNS = [c for c in CSV_COLUMNS if not c.startswith("vuln_")]

def build_container_base(container):
    base = {}
    for col in BASE_CONTAINER_COLUMNS:
        base[col] = sanitize_cell(get_nested_value(container, col))
    return base

def flatten_vuln(v):
    """Extract per-QID fields and join software info lists nicely."""
    qid = sanitize_cell(v.get("qid"))
    firstFound = sanitize_cell(v.get("firstFound"))
    lastFound  = sanitize_cell(v.get("lastFound"))
    typeDetected = sanitize_cell(v.get("typeDetected"))
    scan_types = v.get("scanType", [])
    if isinstance(scan_types, list):
        scan_types = ", ".join([sanitize_cell(x) for x in scan_types if sanitize_cell(x)])
    else:
        scan_types = sanitize_cell(scan_types)
    sw_list = v.get("software", [])
    names, versions, fixes, paths = [], [], [], []
    if isinstance(sw_list, list):
        for sw in sw_list:
            disp_name = sw.get("name") or sw.get("software")
            names.append(sanitize_cell(disp_name))
            versions.append(sanitize_cell(sw.get("version")))
            fixes.append(sanitize_cell(sw.get("fixVersion")))
            paths.append(sanitize_cell(sw.get("packagePath")))
    return {
        "vuln_qid": qid,
        "vuln_firstFound": firstFound,
        "vuln_lastFound": lastFound,
        "vuln_typeDetected": typeDetected,
        "vuln_scanTypes": scan_types,
        "vuln_software_names": ", ".join(names),
        "vuln_software_versions": ", ".join(versions),
        "vuln_software_fixVersions": ", ".join(fixes),
        "vuln_software_packagePaths": ", ".join(paths),
    }

def expand_container_to_rows(container):
    rows = []
    base = build_container_base(container)
    vulns = container.get("vulnerabilities")
    if isinstance(vulns, list) and len(vulns) > 0:
        for v in vulns:
            row = dict(base)
            row.update(flatten_vuln(v))
            for col in CSV_COLUMNS:
                if col not in row:
                    row[col] = ""
            rows.append(row)
    else:
        row = dict(base)
        for col in CSV_COLUMNS:
            if col not in row:
                row[col] = ""
        rows.append(row)
    for r in rows:
        for k in r:
            r[k] = sanitize_cell(r[k])
    return rows

def write_weekly_csv(week_data, csv_path):
    """Write weekly container data to CSV file with one row per QID."""
    if not week_data:
        print(f"[i] No data for this week — skipping CSV: {os.path.basename(csv_path)}")
        return
    total_rows = 0
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for item in week_data:
            for row in expand_container_to_rows(item):
                filtered_row = {col: row.get(col, "") for col in CSV_COLUMNS}
                writer.writerow(filtered_row)
                total_rows += 1
    print(f"[+] CSV report generated: {csv_path}  (rows written: {total_rows})")

# === Main ===
if __name__ == "__main__":
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(FINAL_JSON_DIR, exist_ok=True)
    os.makedirs(FINAL_CSV_DIR, exist_ok=True)

    today = datetime.now(timezone.utc).date()
    existing_files = get_existing_week_files()

    # Determine date range:
    if start_date_arg and end_date_arg:
        try:
            start_date = parse_date_ymd(start_date_arg)
            end_date = parse_date_ymd(end_date_arg)
            if end_date <= start_date:
                print(f"[ERROR] end_date ({end_date_arg}) must be after start_date ({start_date_arg}).")
                sys.exit(1)
            print(f"[*] Using provided date range: {start_date} → {end_date}")
        except Exception as e:
            print(f"[ERROR] Failed to parse provided dates. Use YYYY-MM-DD. Details: {e}")
            sys.exit(1)
    else:
        if existing_files:
            oldest_start = min(v[0] for v in existing_files.values())
            newest_end = max(v[1] for v in existing_files.values())
            start_date = min(oldest_start, today - timedelta(weeks=52))
        else:
            start_date = today - timedelta(weeks=52)
        end_date = today
        print(f"[*] Using default workflow (last ~52 weeks): {start_date} → {end_date}")

    if optional_filter:
        print(f"Using optional filter: {optional_filter}")

    all_weeks = generate_all_week_ranges(start_date, end_date)
    total_containers = 0
    current_year = datetime.now().year  # used for CSV filenames

    for week_start, week_end, filename in all_weeks:
        final_json_path = os.path.join(FINAL_JSON_DIR, filename)
        temp_json_path = os.path.join(TEMP_DIR, filename)
        csv_filename = filename.replace(".json", f"_{current_year}.csv")
        csv_path = os.path.join(FINAL_CSV_DIR, csv_filename)

        # Skip JSON files that already exist (same as before)
        if filename in existing_files:
            print(f"Skipping existing report {filename}")
            continue

        # === Epoch-based filtering ===
        epoch_start = int(datetime.combine(week_start, datetime.min.time()).timestamp() * 1000) + (10 * 60 * 60 * 1000)
        epoch_end   = int(datetime.combine(week_end, datetime.min.time()).timestamp() * 1000) + (18 * 60 * 60 * 1000)

        if optional_filter:
            filter_query = f"created:[{epoch_start} ... {epoch_end}] and {optional_filter}"
        else:
            filter_query = f"created:[{epoch_start} ... {epoch_end}]"

        print(f"[+] Fetching data for {filename} — Filter: {filter_query} ({week_start} → {week_end})")
        week_data = fetch_paginated_data(filter_query)

        # === Write JSON file (original behavior) ===
        with open(temp_json_path, "w") as f:
            json.dump(week_data, f, indent=2)
        shutil.move(temp_json_path, final_json_path)
        print(f"Moved JSON to final directory: {final_json_path}")

        # === Write corresponding CSV file (one row per QID) only if data is present ===
        write_weekly_csv(week_data, csv_path)

        records_count = len(week_data)
        total_containers += records_count
        print(f"Week {filename} — {records_count} containers processed.\n")

    print(f"Total number of containers found in this run: {total_containers}")
    print("Weekly JSON and CSV reports updated successfully.")
    print(f"Logs written to {log_file}")