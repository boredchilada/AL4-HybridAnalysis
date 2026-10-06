# Assemblyline service: HybridAnalysis

Shows [Hybrid Analysis](https://www.hybrid-analysis.com) results for files in Assemblyline 4.

The service looks up each file's SHA-256. When successful analyses exist, it reports the most
severe one (malicious, then suspicious, then others; the newest within each) and links to it.
A lookup sends only the hash. Files Hybrid Analysis has never seen, or has only failed
analyses for, produce an empty result.

The result shows:

- the verdict, threat score, AV detection rate, malware family (tagged as
  `attribution.family`), classification tags, and how the sample was run;
- links to the report and to the file's reports in other environments;
- CrowdStrike machine learning and MetaDefender verdicts;
- behaviour signatures by threat level, each with what it observed, its category, ATT&CK ID
  and Hybrid Analysis identifier;
- Suricata alerts, tagged as `network.signature.signature_id` and `network.signature.message`;
- CrowdStrike memory analysis verdicts;
- the process tree with command lines;
- dropped and extracted files, most dangerous first;
- contacted domains and hosts, and ATT&CK techniques;
- other names the file was submitted under, and its submission history.

Processes, domains and IPs are tagged (`dynamic.process.*`, `network.dynamic.*`). The analysis
is recorded as a `Sandbox` part of the result ontology.

## Which files are looked up

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `lookup_depth` | `6` | Maximum extraction depth. `0` is the submitted file only, `1` adds files extracted from it, and `6` covers Assemblyline's default depth. |
| `extracted_types` | `.*` | Regular expression matched from the start of an extracted file's type, for example `executable/.*\|document/.*\|code/.*`. The submitted file is always looked up. |

A lookup normally uses up to 3 API calls (hash search, report summary, file overview) against
Hybrid Analysis's limit of 2,000 calls per hour. Skipped files cost nothing, and their empty
results are not cached, so a later submission with a wider scope looks them up.

## Uploading files

Both parameters default to `false`.

| Parameter | Uploads the file when |
|-----------|-----------------------|
| `allow_submission` | Hybrid Analysis has no successful or running analysis of it |
| `force_resubmit` | always |

Extracted files are uploaded only when `upload_extracted` is also `true`, within the lookup
scope above. `environment_id`, `experimental_anti_evasion` and `network_settings` choose how an
uploaded file is analysed. Uploaded files and their reports are public, and uploads count
against the account's allowance.

- A refused upload or a failed analysis shows Hybrid Analysis's message.
- An analysis that does not finish within `submission_timeout` is retried by Assemblyline. The
  retry finds the analysis by hash and does not upload again. With `force_resubmit`, the result
  reports the job instead of retrying.

## Heuristics

Scores follow Hybrid Analysis's overall verdict. Hybrid Analysis also rates generic traits of
benign files as malicious-level signatures (a statically linked binary, a document linking to an
executable), so signatures alone cannot make a file malicious.

| ID | Name | Score | Raised when |
|----|------|-------|-------------|
| 9 | Malicious Verdict | 1000 | Hybrid Analysis's verdict is malicious |
| 12 | Suspicious Verdict | 300 | Hybrid Analysis's verdict is suspicious |
| 13 | Malicious-level Behaviour Signatures | 100 each, at most 500 | Signatures Hybrid Analysis rates malicious |
| 14 | Suspicious-level Behaviour Signatures | 0 | Signatures Hybrid Analysis rates suspicious |
| 4 | Malicious Memory Analysis | 1000 | CrowdStrike finds malicious process memory |
| 5 | Suspicious Memory Analysis | 500 | CrowdStrike finds suspicious process memory |

Heuristics 13 and 14 carry each signature's Hybrid Analysis identifier (for example
`network-12`) and ATT&CK IDs, so single signatures can be searched or safelisted. Informative
signatures are listed without a heuristic. Heuristics 1 to 3, 6 to 8, 10 and 11 are retired and
score 0.

## Installation and configuration

In Assemblyline, open Administration → Services → Add service, paste `service_manifest.yml`,
then set `api_key` in the service settings.

| Key | Default | Meaning |
|-----|---------|---------|
| `api_key` | (empty) | Hybrid Analysis API key. Required. |
| `base_url` | `https://hybrid-analysis.com/api/v2` | API endpoint. |
| `submission_timeout` | `600` | Seconds to wait for an uploaded file's analysis. |
| `poll_interval` | `15` | Seconds between status checks while waiting. |

A missing or rejected key fails each file with an error naming the problem. Rate limits and
outages are retried.

## Tests

```bash
bash scripts/build-image.sh al4-hybridanalysis:test 4.7.0.dev0 podman
bash scripts/ci-gate.sh al4-hybridanalysis:test podman
```

The gate runs Ruff, Pyright and pytest inside the image, offline, against recorded responses in
`tests/fixtures/ha/`.

## Layout

```
hybridanalysis/
  analysis.py     lookup scope, report selection, verdicts, signatures, process tree
  client.py       Hybrid Analysis API v2 client
  results.py      result sections, tags and the Sandbox ontology part
  service.py      class HybridAnalysis(ServiceBase)
tests/            tests, fake client, recorded responses, samples/ and results/
scripts/          build-image.sh, ci-gate.sh, gentests.py
```
