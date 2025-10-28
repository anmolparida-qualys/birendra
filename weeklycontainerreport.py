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
import tzlocal   # pip install tzlocal

# === Disable SSL warnings ===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
TOKEN = ""
BASE_URL = ""
LIMIT = 250
TEMP_DIR = "temp_reports"
FINAL_JSON_DIR = "weekly_reports"
FINAL_CSV_DIR = "weekly_csv_reports"

# === Hardcoded CSV Columns ===
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
    # Vulnerability fields
    "vuln_qid","vuln_firstFound","vuln_lastFound","vuln_typeDetected","vuln_scanTypes",
    "vuln_software_names","vuln_software_versions",
    "vuln_software_fixVersions","vuln_software_packagePaths"
]

# === CLI Arguments ===
parser = argparse.ArgumentParser(description="Fetch weekly container data from Qualys API.")
parser.add_argument("BASE_URL", nargs="?", help="Qualys Gateway URL (e.g. https://gateway.qg2.apps.qualys.com)")
parser.add_argument("--optional_filter", help="Additional filter expression", default="")
parser.add_argument("--start_date", help="Start date (YYYY-MM-DD)", default="")
parser.add_argument("--end_date", help="End date (YYYY-MM-DD)", default="")
parser.add_argument("--csv_columns", help="Comma-separated list of CSV columns to override defaults.", default="")
args = parser.parse_args()

# === URL & Token Validation ===
BASE_URL = args.BASE_URL.strip() if args.BASE_URL else ""
if not BASE_URL:
    print("[ERROR] BASE_URL required. Example: python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com")
    sys.exit(1)
if not BASE_URL.endswith("/csapi/v1.3/containers/list"):
    BASE_URL = BASE_URL.rstrip("/") + "/csapi/v1.3/containers/list"

TOKEN = os.getenv("QUALYS_TOKEN", TOKEN)
if not TOKEN:
    print("[ERROR] Missing QUALYS_TOKEN. Run: export QUALYS_TOKEN='<your_api_token_here>'")
    sys.exit(1)

optional_filter = args.optional_filter.strip()
start_date_arg = args.start_date.strip()
end_date_arg = args.end_date.strip()
if args.csv_columns.strip():
    CSV_COLUMNS = [c.strip() for c in args.csv_columns.split(",") if c.strip()]

# === Logging ===
os.makedirs("logs", exist_ok=True)
log_file = os.path.join("logs", f"weekly_report_{datetime.now().strftime('%Y%m%d_%H%M')}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[logging.FileHandler(log_file, mode="a"), logging.StreamHandler()]
)
logger = logging.getLogger()
print = lambda *a, **k: logger.info(" ".join(map(str, a)))

# === Headers ===
HEADERS = {"accept": "application/json", "Authorization": f"Bearer {TOKEN}"}

# === Helper functions ===
def parse_date_ymd(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def daterange(start_date, end_date, step_days=7):
    current = start_date
    while current < end_date:
        next_date = min(current + timedelta(days=step_days), end_date)
        yield current, next_date
        current = next_date  # continuous

def fetch_paginated_data(filter_query):
    url = BASE_URL
    params = {"filter": filter_query, "limit": LIMIT}
    all_data, page = [], 1
    while url:
        print(f"[+] Fetching PAGE {page} for filter {filter_query}")
        r = requests.get(url, headers=HEADERS, params=params if page == 1 else None, verify=False)
        time.sleep(0.2)
        if r.status_code == 401:
            print("[ERROR] Unauthorized (401) – token may be invalid. Exiting.")
            sys.exit(1)
        if r.status_code != 200:
            print(f"[ERROR] {r.status_code}: {r.text}")
            break
        j = r.json()
        data = j.get("data", [])
        all_data.extend(data)
        print(f"Page {page}: {len(data)} records")
        link_header = r.headers.get("Link")
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
        start = datetime.strptime(f"{start_str}{year}", "%b%d%Y").date()
        end = datetime.strptime(f"{end_str}{year}", "%b%d%Y").date()
        return start, end
    except Exception:
        return None, None

def get_existing_week_files():
    os.makedirs(FINAL_JSON_DIR, exist_ok=True)
    week_files = {}
    for f in os.listdir(FINAL_JSON_DIR):
        start, end = parse_week_filename(f)
        if start and end:
            week_files[f] = (start, end)
    return week_files

def get_nested_value(obj, path):
    try:
        parts = path.replace("]", "").split(".")
        for part in parts:
            if "[" in part:
                key, idx = part.split("[")
                obj = obj.get(key, [])
                obj = obj[int(idx)] if isinstance(obj, list) and len(obj) > int(idx) else ""
            else:
                obj = obj.get(part) if isinstance(obj, dict) else ""
            if obj in [None, "null"]:
                return ""
        return json.dumps(obj, ensure_ascii=False) if isinstance(obj, (list, dict)) else str(obj)
    except Exception:
        return ""

def sanitize_cell(v):
    return "" if v in [None, "None", "null", [], {}, ""] else str(v).replace("\n", " ").replace("\r", " ").strip()

BASE_CONTAINER_COLUMNS = [c for c in CSV_COLUMNS if not c.startswith("vuln_")]

def build_container_base(c):
    return {col: sanitize_cell(get_nested_value(c, col)) for col in BASE_CONTAINER_COLUMNS}

def flatten_vuln(v):
    qid = sanitize_cell(v.get("qid"))
    scan_types = v.get("scanType", [])
    if isinstance(scan_types, list):
        scan_types = ", ".join([sanitize_cell(x) for x in scan_types if x])
    sw_list = v.get("software", [])
    names, versions, fixes, paths = [], [], [], []
    for sw in sw_list or []:
        names.append(sanitize_cell(sw.get("name") or sw.get("software")))
        versions.append(sanitize_cell(sw.get("version")))
        fixes.append(sanitize_cell(sw.get("fixVersion")))
        paths.append(sanitize_cell(sw.get("packagePath")))
    return {
        "vuln_qid": qid,
        "vuln_firstFound": sanitize_cell(v.get("firstFound")),
        "vuln_lastFound": sanitize_cell(v.get("lastFound")),
        "vuln_typeDetected": sanitize_cell(v.get("typeDetected")),
        "vuln_scanTypes": scan_types,
        "vuln_software_names": ", ".join(names),
        "vuln_software_versions": ", ".join(versions),
        "vuln_software_fixVersions": ", ".join(fixes),
        "vuln_software_packagePaths": ", ".join(paths),
    }

def expand_container_to_rows(c):
    base = build_container_base(c)
    vulns = c.get("vulnerabilities", [])
    rows = []
    if vulns:
        for v in vulns:
            row = dict(base)
            row.update(flatten_vuln(v))
            rows.append({col: row.get(col, "") for col in CSV_COLUMNS})
    else:
        rows.append({col: base.get(col, "") for col in CSV_COLUMNS})
    return rows

def write_weekly_csv(data, path):
    if not data:
        print(f"[i] No data for this week — skipping CSV: {os.path.basename(path)}")
        return
    total = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL)
        w.writeheader()
        for c in data:
            for row in expand_container_to_rows(c):
                w.writerow(row)
                total += 1
    print(f"[+] CSV report generated: {path}  (rows written: {total})")

# === Main ===
if __name__ == "__main__":
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(FINAL_JSON_DIR, exist_ok=True)
    os.makedirs(FINAL_CSV_DIR, exist_ok=True)

    today = datetime.now(timezone.utc).date()
    existing = get_existing_week_files()

    # Determine date range
    if start_date_arg and end_date_arg:
        try:
            start_date = parse_date_ymd(start_date_arg)
            end_date = parse_date_ymd(end_date_arg)
            if end_date <= start_date:
                print("[ERROR] end_date must be after start_date.")
                sys.exit(1)
            print(f"[*] Using provided range: {start_date} → {end_date}")
        except Exception as e:
            print(f"[ERROR] Invalid date input: {e}")
            sys.exit(1)
    else:
        start_date = today - timedelta(weeks=52)
        end_date = today
        print(f"[*] Default range (last 52 weeks): {start_date} → {end_date}")

    LOCAL_TZ = tzlocal.get_localzone()
    UTC = timezone.utc
    all_weeks = list(daterange(start_date, end_date))
    total_containers = 0
    current_year = datetime.now().year

    for ws, we in all_weeks:
        fname = f"{ws:%b%d}-{we:%b%d}.json"
        final_json = os.path.join(FINAL_JSON_DIR, fname)
        temp_json = os.path.join(TEMP_DIR, fname)
        csv_file = os.path.join(FINAL_CSV_DIR, fname.replace(".json", f"_{current_year}.csv"))

        if fname in existing:
            print(f"Skipping existing report {fname}")
            continue

        # === Timezone-aware weekly epoch range ===
        local_start = datetime.combine(ws, datetime.min.time(), tzinfo=LOCAL_TZ)
        local_end   = datetime.combine(we, datetime.min.time(), tzinfo=LOCAL_TZ)
        epoch_start = int(local_start.astimezone(UTC).timestamp() * 1000)
        epoch_end   = int(local_end.astimezone(UTC).timestamp() * 1000) + 2000  # 2s overlap buffer

        print(f"[✓] Date window → {local_start:%Y-%m-%d %H:%M:%S %Z} → {local_end:%Y-%m-%d %H:%M:%S %Z} "
              f"(UTC {datetime.utcfromtimestamp(epoch_start/1000):%Y-%m-%d %H:%M:%S}Z → "
              f"{datetime.utcfromtimestamp(epoch_end/1000):%Y-%m-%d %H:%M:%S}Z)")

        # === Build filter query ===
        filter_query = f"created:[{epoch_start} ... {epoch_end}]"
        if optional_filter:
            filter_query += f" and {optional_filter}"

        print(f"[+] Fetching data for {fname} — Filter: {filter_query}")
        week_data = fetch_paginated_data(filter_query)

        with open(temp_json, "w") as f:
            json.dump(week_data, f, indent=2)
        shutil.move(temp_json, final_json)
        print(f"Moved JSON to final directory: {final_json}")

        write_weekly_csv(week_data, csv_file)

        total_containers += len(week_data)
        print(f"Week {fname} — {len(week_data)} containers processed.\n")

    print(f"Total containers found in this run: {total_containers}")
    print("Weekly JSON and CSV reports updated successfully.")
    print(f"Logs written to {log_file}")