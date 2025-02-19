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
  - Behavioral analysis with MITRE ATT&CK mapping
  - Process activity monitoring
  - Network communications analysis
  - File system activity tracking
  - Registry modifications monitoring
- Detailed logging for troubleshooting
- Integration with Assemblyline's heuristics system

## Submission Parameters
The service supports the following submission parameters:

- **force_resubmit** (bool, default: false)
  - Force resubmission even if previous analysis exists

- **environment_id** (list, default: "160")
  - Analysis environment selection
  - Available options:
    - "160": Windows 10 64 bit
    - "140": Windows 7 64 bit
    - "120": Windows 7 32 bit
    - "110": Windows XP 32 bit
    - "100": Windows 7 Smart Mode
    - "400": Android Static Analysis
    - "310": Linux 64 bit
    - "200": macOS 10

- **experimental_anti_evasion** (bool, default: false)
  - Enable experimental anti-evasion techniques

- **network_settings** (list, default: "default")
  - Network configuration for analysis
  - Available options:
    - "default": Standard network access
    - "tor": Route traffic through TOR
    - "simulated": Simulate network services

## Logging System
The service implements a comprehensive logging system with the following features:

### Log Configuration
- Dual logging output:
  - File logging: Detailed logs stored in the system's temp directory (`hybrid_analysis.log`)
  - Console logging: Real-time output to stdout for monitoring
- Structured log format: `timestamp - log_level - message`

### Logged Information
- Service lifecycle events (start/stop)
- API interactions and responses
- File submission details and progress
- Analysis status and polling updates
- Result processing and section creation
- Error tracking and troubleshooting data

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

enable_debug_logging:
  type: bool
  value: false
  description: Enable detailed debug logging to file and stdout
```

## Heuristics
The service implements eight heuristics:

1. Critical Threat Score (1000)
   - Triggers when sample receives a critical threat score (>=85)
   - MITRE ATT&CK: T1204 (User Execution)

2. High Threat Score (750)
   - Triggers when sample receives a high threat score (70-84)
   - MITRE ATT&CK: T1204 (User Execution)

3. High AV Detection Rate (1000)
   - Triggers when sample is detected by multiple AV engines (>30)
   - MITRE ATT&CK: T1204 (User Execution)

4. Malicious Memory Analysis (1000)
   - Triggers when CrowdStrike AI detects malicious behavior in process memory
   - MITRE ATT&CK: T1055 (Process Injection)

5. Suspicious Memory Analysis (500)
   - Triggers when CrowdStrike AI detects suspicious behavior in process memory
   - MITRE ATT&CK: T1055 (Process Injection)

6. Multiple MITRE ATT&CK Techniques (750)
   - Triggers when multiple MITRE ATT&CK techniques with malicious indicators are detected
   - MITRE ATT&CK: T1204 (User Execution)

7. High Signature Count (500)
   - Triggers when sample has a large number of behavioral signatures (>100)
   - MITRE ATT&CK: T1204 (User Execution)

8. Known Malware Family (1000)
   - Triggers when sample is identified as belonging to a known malware family
   - MITRE ATT&CK: T1204 (User Execution)

## Docker Configuration
```yaml
allow_internet_access: true
cpu_cores: 1
ram_mb: 1024
```

## Installation

1. Copy service_manifest.yml into AL4

## Results
The service provides results in several sections:
- Analysis Summary (verdict, threat score, malware family)
- Submission History
- File Information
- Scanner Results
- MITRE ATT&CK Techniques
- Signature Statistics
- Behavioral Analysis
- CrowdStrike Memory Analysis
- Process Activity
- Network Activity

## Dependencies
- Python 3
- Assemblyline 4
- Requests library
- Internet access for API communication

## Error Handling
- Comprehensive logging to troubleshoot issues
- Detailed error reporting in service results
- API connection validation on service start
