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

> ⚙️ **Note:** The first argument is always the **Qualys Gateway URL** for your platform (see table below).  
> Example gateway: `https://gateway.qg2.apps.qualys.com`

---

### 1️⃣ Default Run (Last 52 Weeks)
```bash
python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com
```

Fetches container data for the past year using default columns and date ranges.

---

### 2️⃣ Specify Date Range
```bash
python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com   --start_date 2025-09-27 --end_date 2025-10-04
```

---

### 3️⃣ Apply Optional Filter
```bash
python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com   --start_date 2025-09-27   --end_date 2025-10-04   --optional_filter "state:RUNNING and imageId:d1a50f311f32"
```

---

### 4️⃣ Custom CSV Columns
```bash
python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com   --csv_columns "containerId,uuid,name,state,vuln_qid,vuln_software_names"
```

---

### 5️⃣ Combine All Options
```bash
python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com   --start_date 2025-10-22   --end_date 2025-10-25   --optional_filter "state:RUNNING and imageId:d1a50f311f32"   --csv_columns "containerId,uuid,name,state,vuln_qid,vuln_software_names"
```

---

### 📄 Supported CSV Column Names
When using the `--csv_columns` flag, only the following column names are supported.  
Custom column sets **must** be chosen from this list (you can specify any subset, comma-separated):

```text
# Container identity & status
containerId, uuid, name, state, ipv4, ipv6,
created, updated, stateChanged, riskScore, qdsSeverity, maxQdsScore,
imageId, imageSha, imageUuid, customerUuid, privileged, isRoot,
isVulnPropagated, source, sensorUuid,

# Host / cluster info
host.sensorUuid, host.hostname, host.ipAddress,
cluster.name, cluster.uid, cluster.version,
cluster.k8s.pod.name, cluster.k8s.pod.namespace, cluster.k8s.pod.uuid,
cluster.k8s.pod.controller[0].name, cluster.k8s.pod.controller[0].type,
hostArchitecture,

# Runtime context
environment, command, arguments,

# Vulnerability fields (one row per QID)
vuln_qid, vuln_firstFound, vuln_lastFound, vuln_typeDetected, vuln_scanTypes,

# From vulnerability.software[] (joined if multiple)
vuln_software_names, vuln_software_versions, vuln_software_fixVersions, vuln_software_packagePaths
```

**Example:**
```bash
python3 weeklycontainerreport.py https://gateway.qg2.apps.qualys.com   --csv_columns "containerId,name,state,vuln_qid,vuln_software_names"
```

If a column outside this list is provided, it will appear as blank in the CSV output.

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
| **Custom Columns** | Supported |
| **Filters** | Supported |
| **Logging** | Detailed logs in `logs/` |

---

## 🌐 Platform Gateway URLs
Below is a list of **Qualys API Gateway URLs** by platform.  
You must pass the correct gateway URL for your Qualys subscription region as the **first argument** to the script.

| Platform              | API Gateway URL                                                                  |
| --------------------- | -------------------------------------------------------------------------------- |
| **US1**               | [https://gateway.qg1.apps.qualys.com](https://gateway.qg1.apps.qualys.com)       |
| **US2**               | [https://gateway.qg2.apps.qualys.com](https://gateway.qg2.apps.qualys.com)       |
| **US3**               | [https://gateway.qg3.apps.qualys.com](https://gateway.qg3.apps.qualys.com)       |
| **US4**               | [https://gateway.qg4.apps.qualys.com](https://gateway.qg4.apps.qualys.com)       |
| **GOV1**              | [https://gateway.gov1.qualys.us](https://gateway.gov1.qualys.us)                 |
| **EU1**               | [https://gateway.qg1.apps.qualys.eu](https://gateway.qg1.apps.qualys.eu)         |
| **EU2**               | [https://gateway.qg2.apps.qualys.eu](https://gateway.qg2.apps.qualys.eu)         |
| **EU3**               | [https://gateway.qg3.apps.qualys.it](https://gateway.qg3.apps.qualys.it)         |
| **IN1**               | [https://gateway.qg1.apps.qualys.in](https://gateway.qg1.apps.qualys.in)         |
| **CA1**               | [https://gateway.qg1.apps.qualys.ca](https://gateway.qg1.apps.qualys.ca)         |
| **AE1**               | [https://gateway.qg1.apps.qualys.ae](https://gateway.qg1.apps.qualys.ae)         |
| **UK1**               | [https://gateway.qg1.apps.qualys.co.uk](https://gateway.qg1.apps.qualys.co.uk)   |
| **AU1**               | [https://gateway.qg1.apps.qualys.com.au](https://gateway.qg1.apps.qualys.com.au) |
| **KSA1**              | [https://gateway.qg1.apps.qualysksa.com](https://gateway.qg1.apps.qualysksa.com) |
| **Private Platforms** | [https://qualysgateway.<customer_base_url>](https://qualysgateway.<customer_base_url>) |

---

## 🪶 Author Notes
This script provides a reliable, incremental way to extract and analyze Qualys container security data, ensuring that weekly history is preserved and redundant downloads are avoided.
