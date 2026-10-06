"""Unit tests for the pure report helpers (no AssemblyLine runtime, no network)."""

import pytest

from hybridanalysis.analysis import (
    MAX_DETAIL,
    InvalidScope,
    analysis_conditions,
    av_text,
    classify_reports,
    detail,
    dropped_files,
    in_lookup_scope,
    may_upload,
    notable_techniques,
    other_names,
    platform,
    process_tree,
    report_time,
    scanner_rows,
    split_signatures,
    suricata_alerts,
    verdict_heuristic,
)


@pytest.mark.parametrize(
    "depth,file_type,depth_param,types_param,expected",
    [
        (6, "archive/zip", 6, ".*", True),
        (7, "archive/zip", 6, ".*", False),
        (2, "archive/zip", 2, ".*", True),
        (3, "archive/zip", 2, ".*", False),
        (0, "archive/zip", 0, "executable/.*", True),
        (0, "archive/zip", 0, "[", True),
        (1, "executable/windows/pe32", 6, "executable/.*", True),
        (1, "archive/zip", 6, "executable/.*", False),
        (1, "executable/windows/pe32", 6, "windows", False),
        (6, "archive/zip", None, ".*", True),
        (7, "archive/zip", None, ".*", False),
        (6, "archive/zip", "abc", ".*", True),
        (7, "archive/zip", "abc", ".*", False),
        (0, "archive/zip", -1, ".*", True),
        (1, "archive/zip", -1, ".*", False),
        (1, "archive/zip", 6, "", True),
        (1, "archive/zip", 6, None, True),
        (1, "archive/zip", 6, 42, True),
        (2, "archive/zip", "2", ".*", True),
        (3, "archive/zip", "2", ".*", False),
        (1, "", 6, ".*", True),
        (7, "archive/zip", 6, "[", False),
    ],
)
def test_lookup_scope(depth, file_type, depth_param, types_param, expected):
    assert in_lookup_scope(depth, file_type, depth_param, types_param) is expected


@pytest.mark.parametrize("pattern", ["[", "("])
def test_lookup_scope_rejects_invalid_extracted_types(pattern):
    with pytest.raises(InvalidScope, match="extracted_types"):
        in_lookup_scope(1, "executable/windows/pe32", 6, pattern)


@pytest.mark.parametrize(
    "depth,upload_extracted,expected",
    [
        (0, True, True),
        (0, False, True),
        (0, None, True),
        (0, "true", True),
        (1, True, True),
        (1, False, False),
        (1, None, False),
        (1, "true", False),
    ],
)
def test_may_upload(depth, upload_extracted, expected):
    assert may_upload(depth, upload_extracted) is expected


def test_classify_reports_ranks_by_verdict_then_newest_and_finds_running():
    lookup = classify_reports([
        {"id": "e", "state": "ERROR"},
        {"id": "6a1f00000000000000000001", "state": "SUCCESS", "verdict": "no specific threat"},
        {"id": "6a0000000000000000000002", "state": "SUCCESS", "verdict": "malicious"},
        {"id": "q", "state": "IN_QUEUE"},
        {"id": "6a1e00000000000000000003", "state": "SUCCESS", "verdict": "malicious"},
        {"id": "6a1d00000000000000000004", "state": "SUCCESS", "verdict": "suspicious"},
        {"id": "6a1c00000000000000000005", "state": "SUCCESS", "verdict": None},
        {"id": "r", "state": "IN_PROGRESS"}, {"state": "SUCCESS"},
    ])
    assert [r["id"][-1] for r in lookup.successful] == ["3", "2", "4", "1", "5"]
    assert lookup.running == "q"


@pytest.mark.parametrize(
    "report_id,expected",
    [("6a8437f3335921c00b0a2667", "2026-08-18T10:46:11Z"), ("not-an-objectid", ""), (None, ""),
     ("6a8437f3335921c00b0a26", "")],
)
def test_report_time_reads_the_objectid_timestamp(report_id, expected):
    assert report_time(report_id) == expected


@pytest.mark.parametrize(
    "verdict,heur",
    [("malicious", 9), ("Malicious", 9), ("suspicious", 12), ("no specific threat", None), ("whitelisted", None),
     (None, None)],
)
def test_verdict_heuristic(verdict, heur):
    assert verdict_heuristic(verdict) == heur


@pytest.mark.parametrize(
    "environment,expected",
    [("Windows 10 64 bit", "Windows"), ("Linux (Ubuntu 24.04, 64 bit)", "Linux"), ("macOS Tahoe (ARM64)", "MacOS"),
     ("Android Static Analysis", "Android"), ("", None), (None, None)],
)
def test_platform(environment, expected):
    assert platform(environment) == expected


def test_split_signatures_by_threat_level_most_relevant_first():
    raw: list = [  # API data may contain non-dict entries
        {"name": "m-low", "threat_level": 2, "relevance": 3}, {"name": "m-high", "threat_level": 2, "relevance": 10},
        {"name": "m3", "threat_level": 3}, {"name": "s", "threat_level": 1}, {"name": "i", "threat_level": 0},
        {"name": "n", "threat_level": None}, {"_truncated_info_": "x"}, "junk",
    ]
    malicious, suspicious, informative = split_signatures(raw)
    assert [s["name"] for s in malicious] == ["m-high", "m-low", "m3"]
    assert [s["name"] for s in suspicious] == ["s"]
    assert [s["name"] for s in informative] == ["i", "n"]


def test_detail_joins_lines_drops_placeholder_and_shortens():
    assert detail('"a.exe" wrote data\n "b.exe" wrote data\n') == '"a.exe" wrote data | "b.exe" wrote data'
    assert detail("No specific details available") == ""
    long = detail("x" * (MAX_DETAIL * 2))
    assert len(long) == MAX_DETAIL and long.endswith("…")


def test_notable_techniques_skip_informative_only_and_sort_by_weight():
    techniques = [
        {"attck_id": "T1", "malicious_identifiers_count": 0, "suspicious_identifiers_count": 0},
        {"attck_id": "T2", "malicious_identifiers_count": 0, "suspicious_identifiers_count": 4},
        {"attck_id": "T3", "malicious_identifiers_count": 2, "suspicious_identifiers_count": None},
        {"_truncated_info_": "x"},
    ]
    notable, informative_only = notable_techniques(techniques)
    assert [t["attck_id"] for t in notable] == ["T3", "T2"]
    assert informative_only == 1


def test_process_tree_orders_parents_before_children():
    procs = [
        {"uid": "c", "parentuid": "b", "name": "child"},
        {"uid": "a", "parentuid": None, "name": "root"},
        {"uid": "b", "parentuid": "a", "name": "middle"},
        {"uid": "x", "parentuid": "gone", "name": "orphan"},
    ]
    assert [(depth, p["name"]) for depth, p in process_tree(procs)] == [(0, "root"), (1, "middle"), (2, "child"),
                                                                        (0, "orphan")]


def test_process_tree_survives_parent_loops():
    procs = [{"uid": "a", "parentuid": "b", "name": "a"}, {"uid": "b", "parentuid": "a", "name": "b"},
             {"uid": "s", "parentuid": "s", "name": "self"}]
    assert sorted(p["name"] for _, p in process_tree(procs)) == ["a", "b", "self"]


@pytest.mark.parametrize(
    "label,matched,total,expected",
    [("Worm.X", 18, 24, "Worm.X (18/24)"), (None, 2, 20, "detected (2/20)"), ("Worm.X", None, None, "Worm.X"),
     (None, None, None, ""), (None, 0, 20, "")],
)
def test_av_text(label, matched, total, expected):
    assert av_text(label, matched, total) == expected


def test_dropped_files_most_dangerous_first():
    files = [{"name": "clean", "threat_level": 0}, {"name": "few", "threat_level": 2, "av_matched": 1},
             {"name": "many", "threat_level": 2, "av_matched": 13}, {"name": "sus", "threat_level": 1}]
    assert [f["name"] for f in dropped_files(files)] == ["many", "few", "sus", "clean"]


def test_suricata_alerts_parsed_and_deduplicated():
    sigs = [
        {"identifier": "suricata-2", "threat_level_human": "malicious",
         "description": 'Detected alert "ET MALWARE Mozi Botnet DHT Config Sent" (SID: 2030919, Rev: 1, Severity: 1) '
                        'categorized as "Malware Command and Control Activity Detected"\n '
                        'Detected alert "ET P2P BitTorrent DHT ping request" (SID: 2008581, Rev: 3, Severity: 1)'},
        {"identifier": "suricata-1", "threat_level_human": "suspicious",
         "description": 'Detected alert "ET MALWARE Mozi Botnet DHT Config Sent" (SID: 2030919, Rev: 1, Severity: 1)'},
        {"identifier": "network-12", "description": 'Detected alert "not suricata" (SID: 1, Rev: 1, Severity: 1)'},
    ]
    alerts = suricata_alerts(sigs)
    assert [(a["sid"], a["message"], a["category"], a["level"]) for a in alerts] == [
        ("2030919", "ET MALWARE Mozi Botnet DHT Config Sent", "Malware Command and Control Activity Detected",
         "malicious"),
        ("2008581", "ET P2P BitTorrent DHT ping request", "", "malicious"),
    ]


def test_scanner_rows_keep_scanners_with_a_result():
    overview = {"scanners": [
        {"name": "Metadefender", "status": "malicious", "positives": 19, "total": 27},
        {"name": "CrowdStrike Falcon Static Analysis (ML)", "status": "malicious", "positives": None, "total": None},
        {"name": "VirusTotal", "status": "no-result"}, {"name": "Other", "status": None}, {"status": "clean"},
    ]}
    assert scanner_rows(overview) == [
        {"scanner": "Metadefender", "verdict": "malicious", "detections": "19/27"},
        {"scanner": "CrowdStrike Falcon Static Analysis (ML)", "verdict": "malicious", "detections": ""},
    ]
    assert scanner_rows({}) == [] and scanner_rows(None) == []


def test_other_names_skip_the_current_name_and_duplicates():
    overview = {"last_file_name": "AV.scr", "other_file_name": ["Av.scr", "Photo.scr", "photo.scr", None, ""]}
    assert other_names(overview, "av.scr") == ["Photo.scr"]


def test_analysis_conditions():
    summary = {"network_mode": "tor", "detonation_parameters": {"experimental_anti_evasion": False},
               "warnings": ["Some low-level data is hidden, as this is only a slim report"]}
    assert analysis_conditions(summary) == {"Network Mode": "tor", "Anti-evasion": "off",
                                            "Report Detail": "slim report: Hybrid Analysis hid some low-level data"}
    assert analysis_conditions({}) == {}
