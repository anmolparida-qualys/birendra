# Weekly Container Report — Qualys API Integration

## Description
This Python script retrieves container inventory data from a **Qualys subscription account** using the Qualys Container Security API.  
It automatically organizes and exports container data in **JSON** and **CSV** formats, grouped by weekly date ranges.

- Fetches container data from Qualys `/csapi/v1.3/containers/list`
- Exports data to two directories:
  - `weekly_reports/` → JSON (includes empty weeks)
  - `weekly_csv_reports/` → CSV (only weeks with data)
- Automatically skips previously fetched weeks
- Supports date ranges, filters, and custom CSV columns
- Includes automatic token retry and detailed logging

---

## Directory Overview

| Directory | Purpose |
|------------|----------|
| **`weekly_reports/`** | Stores all weekly JSON files (even empty ones). |
| **`weekly_csv_reports/`** | Stores weekly CSVs only when data exists. |
| **`temp_reports/`** | Temporary storage for JSON files before moving to final directory. |
| **`logs/`** | Contains runtime logs for each script execution. |

---

## 🔐 Authentication

Before running the script, export your **Qualys Access Token**:

```bash
export QUALYS_TOKEN="your_qualys_access_token_here"
```

You can find it in **Qualys UI → Configurations → Access Token**.  
If both an environment token and in-script token exist:
- The **environment token** is used first.  
- If it fails (401 / JWT error), the **in-script token** is tried automatically.  
- If both fail, the script exits cleanly.

---

## Usage

### 1️⃣ Default Run (Last 52 Weeks)
```bash
python3 weeklycontainerreport.py
```

Fetches container data for the past year using default columns and date ranges.

---

### 2️⃣ Specify Date Range
```bash
python3 weeklycontainerreport.py --start_date 2025-09-27 --end_date 2025-10-04
```

---

### 3️⃣ Apply Optional Filter
```bash
python3 weeklycontainerreport.py \
  --start_date 2025-09-27 \
  --end_date 2025-10-04 \
  --optional_filter "state:RUNNING and imageId:d1a50f311f32"
```

---

### 4️⃣ Custom CSV Columns
```bash
python3 weeklycontainerreport.py \
  --csv_columns "containerId,uuid,name,state,vuln_qid,vuln_software_names"
```

---

### 5️⃣ Combine All Options
```bash
python3 weeklycontainerreport.py \
  --start_date 2025-10-22 \
  --end_date 2025-10-25 \
  --optional_filter "state:RUNNING and imageId:d1a50f311f32" \
  --csv_columns "containerId,uuid,name,state,vuln_qid,vuln_software_names"
```

---

## ⚠️ Error Handling

| Error Type | Script Behavior |
|-------------|----------------|
| 401 / 403 Unauthorized | Retries with fallback token, exits if both fail |
| JWT Parsing Failed | Treated as token error, triggers retry |
| Empty Data Week | JSON created, CSV skipped |
| Invalid Dates | Graceful error message and exit |
| Duplicate Week | Skipped automatically |

---

## 🧩 Requirements

- Python **3.8+**
- Internet access to Qualys API
- Module: `requests`

Install dependencies:
```bash
pip install requests
```

---

## Summary

| Feature | Description |
|----------|-------------|
| **API** | `/csapi/v1.3/containers/list` |
| **Formats** | JSON + CSV |
| **Token Retry** | Automatic fallback |
| **Date Range** | Weekly batching |
| **Custom Columns** |  |
| **Filters** |  |
| **Logging** |  Detailed logs in `logs/` |

---

## 🪶 Author Notes
This script provides a reliable, incremental way to extract and analyze Qualys container security data, ensuring that weekly history is preserved and redundant downloads are avoided.
