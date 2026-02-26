# Hybrid Analysis Service for Assemblyline 4
![Python](https://img.shields.io/badge/Python-3-blue) ![Assemblyline 4](https://img.shields.io/badge/Assemblyline-4-green)

## Description
The Hybrid Analysis service is an Assemblyline 4 Dynamic Analysis integration that automatically submits unknown files to [Hybrid Analysis](https://hybrid-analysis.com/) for deep behavioral sandboxing. It parses the resulting JSON reports, mapping detailed threat scores, MITRE ATT&CK techniques, process activity, and network communications directly into Assemblyline 4's native result ontologies.

## Prerequisites & Installation
To run this service in your Assemblyline 4 environment, follow these steps:

1. **Pull the Image**: 
   Ensure your AL4 appliance can pull the Docker image:
   ```bash
   docker pull ghcr.io/boredchilada/al4-hybridanalysis:4.7.0.3
   ```
2. **Register the Service**:
   Copy the `service_manifest.yml` into your AL4 service directory or register it via the Assemblyline 4 Administration UI.
3. **Configure the API Key**:
   Navigate to the Service Management page in the AL4 UI. Under the **HybridAnalysis** service configuration, paste your Hybrid Analysis API Key into the `api_key` field.

## Quick Start / Usage
Once the service is active, any file submitted to Assemblyline 4 will automatically be queried against the Hybrid Analysis dataset via its SHA256 hash.

If you want the service to *upload* unknown files to Hybrid Analysis (instead of just checking for existing reports), you must explicitly enable submission during your AL4 upload:
1. In the AL4 Submission UI, open **Submission Parameters**.
2. Under **Service Selection**, locate **HybridAnalysis**.
3. Check the **allow_submission** box.
4. (Optional) Check **force_resubmit** to re-sandbox a file that already has a completed report.

## Tech Stack
Based on the service configuration and dependencies, this project utilizes:
- **Language:** Python 3
- **Framework:** Assemblyline v4 Service Base (`assemblyline-v4-service`)
- **API Communication:** `requests`, `urllib3`
- **Data Parsing:** `python-dateutil`
- **Containerization:** Docker (`ghcr.io/boredchilada/al4-hybridanalysis`)

---

## Features
- Automated file submission to Hybrid Analysis
- Comprehensive analysis results including:
  - Overall verdict and threat scoring
  - Behavioral analysis with MITRE ATT&CK mapping
  - Process activity monitoring
  - Network communications analysis
  - AV Detection rates
  - CrowdStrike Memory Analysis
  - Malware family attribution
- Integration with Assemblyline's ontology mapping (Sandbox, Network, Process)
- Integration with Assemblyline's heuristics system

## Submission Parameters
The service supports the following user submission parameters:

- **force_resubmit** (bool, default: false)
  - Force resubmission even if previous analysis exists
- **allow_submission** (bool, default: false)
  - Allow the service to upload unknown files to Hybrid Analysis. If false, it only queries existing hashes.
- **environment_id** (list, default: "160")
  - Analysis environment selection (e.g., "160" for Windows 10 64 bit, "310" for Linux 64 bit, "200" for macOS 10).
- **experimental_anti_evasion** (bool, default: false)
  - Enable experimental anti-evasion techniques.
- **network_settings** (list, default: "default")
  - Network configuration for analysis (Options: `default`, `tor`, `simulated`).

## Service Configuration
The service requires the following configuration via AL4:

```yaml
api_key:
  type: str
  value: null  # Required: Your Hybrid Analysis API key
  description: API key for Hybrid Analysis

base_url:
  type: str
  value: "https://hybrid-analysis.com/api/v2"  # Default API endpoint
  description: Base URL for Hybrid Analysis API

enable_debug_logging:
  type: bool
  value: false
  description: Enable detailed debug logging to file and stdout
```

## Logging & Error Handling
- Dual logging output (File logs in the system's temp directory and console logging to stdout).
- Structured log format: `timestamp - log_level - message`.
- Logs track service lifecycle, API interactions, polling updates, and error tracking.
- Exponential polling fallback is implemented for `IN_PROGRESS` analyses to prevent rate-limiting.

## Heuristics
The service implements 11 heuristic rules mapping to threat scores, AV detections, and CrowdStrike AI memory analysis. Each heuristic is mapped to MITRE ATT&CK where applicable.

| ID | Name | Description | Score | MITRE ATT&CK |
|----|------|-------------|-------|--------------|
| **1** | Critical Threat Score | Sample received a critical threat score (>=85) | 1000 | T1204 |
| **2** | High Threat Score | Sample received a high threat score (70-84) | 750 | T1204 |
| **3** | High AV Detection Rate | Detected as malicious by multiple antivirus engines (>30) | 1000 | T1204 |
| **4** | Malicious Memory Analysis | CrowdStrike AI detected malicious behavior in process memory | 1000 | T1055 |
| **5** | Suspicious Memory Analysis | CrowdStrike AI detected suspicious behavior in process memory | 500 | T1055 |
| **6** | Multiple ATT&CK Techniques | Triggered multiple MITRE techniques with malicious indicators | 750 | T1204 |
| **7** | High Signature Count | Triggered a large number of behavioral signatures (>100) | 500 | T1204 |
| **8** | Known Malware Family | Identified as belonging to a known malware family | 1000 | T1204 |
| **9** | Malicious Verdict | Received a malicious verdict from Hybrid Analysis | 1000 | T1204 |
| **10** | Malicious Behavior | Exhibited malicious behavior based on behavioral signatures | 1000 | T1204 |
| **11** | Suspicious Behavior | Exhibited suspicious behavior based on behavioral signatures | 500 | T1204 |
