# Hybrid Analysis Service for Assemblyline 4

```
docker pull ghcr.io/boredchilada/al4-hybridanalysis:4.5.0.33
```

## Description
This service integrates with Hybrid Analysis to provide additional threat intelligence and malware analysis capabilities for Assemblyline 4. It submits files to Hybrid Analysis for dynamic analysis and retrieves detailed behavioral analysis results.

## Features
- Automated file submission to Hybrid Analysis
- Comprehensive analysis results including:
  - Overall verdict and threat scoring
  - Behavioral analysis with MITRE ATT&CK mapping (WIP)
  - Process activity monitoring (WIP)
  - Network communications analysis (WIP)
  - File system activity tracking (WIP)
  - Registry modifications monitoring (WIP)
- Detailed logging for troubleshooting
- Integration with Assemblyline's heuristics system

## Logging System
The service implements a comprehensive logging system with the following features:

### Log Configuration (INFO Only!)
- Dual logging output:
  - File logging: Detailed logs stored in the system's temp directory (`hybrid_analysis.log`)
  - Console logging: Real-time output to stdout for monitoring
- Debug level logging for maximum visibility *(removed, WIP)*
- Structured log format: `timestamp - log_level - message`

### Logged Information
- Service lifecycle events (start/stop)
- API interactions and responses
- File submission details and progress
- Analysis status and polling updates
- Result processing and section creation
- Error tracking and troubleshooting data

### Debug Logging
The debug log captures detailed information about:
- API request/response content
- File processing steps
- Analysis verdicts and threat scores
- Section creation and tag addition
- Error states and exception details

### Log Format Example
```
2024-02-13 14:53:13 - INFO - ==========================================
2024-02-13 14:53:13 - INFO - Logging initialized. Log file: /tmp/hybrid_analysis.log
2024-02-13 14:53:13 - INFO - ==========================================
2024-02-13 14:53:13 - INFO - Starting Hybrid Analysis Service
2024-02-13 14:53:13 - INFO - Configuration loaded - Base URL: https://www.hybrid-analysis.com/api/v2
```

## Service Configuration
The service requires the following configuration:

```yaml
api_key:
  type: str
  value: null  # Required: Your Hybrid Analysis API key
  description: API key for Hybrid Analysis

base_url:
  type: str
  value: "https://www.hybrid-analysis.com/api/v2"  # Default API endpoint
  description: Base URL for Hybrid Analysis API
```

## Heuristics (WIP)
The service implements three heuristics:

1. High Threat Score (1000)
   - Triggers when sample receives a high threat score
   - MITRE ATT&CK: T1204 (User Execution)

2. Malicious Behavior Detected (1000)
   - Triggers when malicious behavior is observed
   - MITRE ATT&CK: T1204 (User Execution)

3. Suspicious Behavior Detected (500)
   - Triggers when suspicious behavior is observed
   - MITRE ATT&CK: T1204 (User Execution)

## Docker Configuration
```yaml
allow_internet_access: true
cpu_cores: 1
ram_mb: 1024
```

## Installation

1. Copy service_manifest.yml into AL4


## Results (SHOULD SHOW)
The service provides results in several sections:
- Analysis Summary (verdict, threat score, malware family)
- Behavioral Analysis (suspicious/malicious behaviors with MITRE ATT&CK mapping) (WIP)
- Process Activity (executed processes and command lines)
- Network Activity (connections, domains, IPs) (WIP)
- File Activity (file system modifications) (WIP)
- Registry Activity (registry modifications) 

## Dependencies
- Python 3
- Assemblyline 4
- Requests library
- Internet access for API communication

## Error Handling
- Comprehensive logging to troubleshoot issues
- Detailed error reporting in service results
- API connection validation on service start
