"""Turns Hybrid Analysis report summaries into AssemblyLine result sections, tags and ontology.

Scoring follows Hybrid Analysis's own verdict (heuristics 9 and 12). Behaviour signatures are
evidence: they are attached by identifier with their ATT&CK IDs (heuristics 13 and 14) and carry
little or no score, because Hybrid Analysis rates generic traits of benign files as malicious.
"""

from logging import Logger
from typing import Any

from assemblyline.odm.models.ontology.results.sandbox import Sandbox
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.result import (
    Heuristic,
    ResultKeyValueSection,
    ResultMultiSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
    URLSectionBody,
)

from hybridanalysis.analysis import (
    MAX_ROWS,
    analysis_conditions,
    av_text,
    detail,
    dropped_files,
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

REPORT_URL = "https://www.hybrid-analysis.com/sample/{sha256}/{report_id}"
SAMPLE_URL = "https://www.hybrid-analysis.com/sample/{sha256}"
# Tables longer than this start collapsed.
COLLAPSE_ROWS = 50
# Other submission names shown; popular samples have hundreds.
MAX_NAMES = 20


def build_main_section(summary: dict, others: list[dict], overview: dict, uploaded: bool, ontology: OntologyHelper,
                       log: Logger) -> ResultSection:
    """``others`` are the file's other successful /search/hash reports; ``overview`` is /overview or {}."""
    main = ResultSection("Hybrid Analysis Results")
    _summary(summary, overview, main)
    _link(summary, main)
    if uploaded:
        notice = ResultTextSection("File uploaded to Hybrid Analysis")
        notice.add_line("This file was uploaded because the submission enabled allow_submission or force_resubmit. "
                        "Files uploaded to Hybrid Analysis and their reports are public.")
        main.add_subsection(notice)
    _scanners(overview, main)
    _other_analyses(summary, others, main)
    _behaviour(summary, main)
    _suricata(summary, main)
    _crowdstrike(summary, main)
    _processes(summary, main)
    _dropped(summary, main)
    _network(summary, main)
    _mitre(summary, main)
    _file_info(summary, overview, main)
    _submission_history(summary, main)
    _ontology(summary, ontology, log)
    return main


def _report_url(summary: dict) -> str | None:
    sha256, report_id = summary.get("sha256"), summary.get("job_id")
    if sha256 and report_id:
        return REPORT_URL.format(sha256=sha256, report_id=report_id)
    return SAMPLE_URL.format(sha256=sha256) if sha256 else None


def _summary(summary: dict, overview: dict, main: ResultSection) -> None:
    section = ResultKeyValueSection("Analysis Summary")
    verdict = summary.get("verdict") or "unknown"
    section.set_item("Verdict", verdict)
    score = summary.get("threat_score")
    if isinstance(score, (int, float)):
        section.set_item("Threat Score", f"{int(score)}/100")
    av_detect = summary.get("av_detect")
    if isinstance(av_detect, (int, float)):
        section.set_item("AV Detection", f"{int(av_detect)}%")
    if summary.get("vx_family"):
        section.set_item("Malware Family", summary["vx_family"])
        section.add_tag("attribution.family", summary["vx_family"])
    tags = [t for t in summary.get("classification_tags") or [] if isinstance(t, str)]
    if tags:
        section.set_item("Classification Tags", ", ".join(tags))
    if summary.get("environment_description"):
        section.set_item("Analysis Environment", summary["environment_description"])
    if summary.get("analysis_start_time"):
        section.set_item("Analysed At", summary["analysis_start_time"])
    if summary.get("job_id"):
        section.set_item("Report ID", summary["job_id"])
    for label, value in analysis_conditions(summary).items():
        section.set_item(label, value)
    if overview.get("whitelisted") is True:
        section.set_item("Known-good", "Hybrid Analysis lists this file as whitelisted")
    heur = verdict_heuristic(verdict)
    if heur:
        section.set_heuristic(heur)
    main.add_subsection(section)


def _link(summary: dict, main: ResultSection) -> None:
    url = _report_url(summary)
    if not url:
        return
    link = ResultMultiSection("Hybrid Analysis Report Link")
    body = URLSectionBody()
    body.add_url(url, name="Open this Falcon Sandbox report on Hybrid Analysis")
    link.add_section_part(body)
    main.add_subsection(link)


def _scanners(overview: dict, main: ResultSection) -> None:
    rows = scanner_rows(overview)
    if not rows:
        return
    section = ResultTableSection("Scanner Results")
    section.set_column_order(["scanner", "verdict", "detections"])
    for row in rows:
        section.add_row(TableRow(row))
    main.add_subsection(section)


def _other_analyses(summary: dict, others: list[dict], main: ResultSection) -> None:
    sha256 = summary.get("sha256")
    if not others or not sha256:
        return
    section = ResultTableSection("Other Hybrid Analysis reports for this file", auto_collapse=True)
    section.set_column_order(["environment", "verdict", "created", "report"])
    for other in others[:MAX_ROWS]:
        section.add_row(TableRow({"environment": other.get("environment_description") or "",
                                  "verdict": other.get("verdict") or "",
                                  "created": report_time(other.get("id")),
                                  "report": REPORT_URL.format(sha256=sha256, report_id=other.get("id"))}))
    main.add_subsection(section)


def _suricata(summary: dict, main: ResultSection) -> None:
    alerts = suricata_alerts(summary.get("signatures"))
    if not alerts:
        return
    section = ResultTableSection("Suricata Alerts")
    section.set_column_order(["alert", "sid", "severity", "category", "level"])
    for alert in alerts:
        section.add_row(TableRow({"alert": alert["message"], "sid": alert["sid"], "severity": alert["severity"],
                                  "category": alert["category"], "level": alert["level"]}))
        section.add_tag("network.signature.signature_id", alert["sid"])
        section.add_tag("network.signature.message", alert["message"])
    main.add_subsection(section)


def _signature_table(title: str, sigs: list[dict], heur_id: int | None, collapsed: bool) -> ResultTableSection:
    section = ResultTableSection(title, auto_collapse=collapsed)
    section.set_column_order(["signature", "details", "category", "attack_id", "identifier"])
    heuristic = Heuristic(heur_id) if heur_id else None
    for sig in sigs:
        identifier = str(sig.get("identifier") or "").lower()
        section.add_row(TableRow({"signature": sig.get("name") or "", "details": detail(sig.get("description")),
                                  "category": sig.get("category") or "", "attack_id": sig.get("attck_id") or "",
                                  "identifier": identifier}))
        if heuristic is not None:
            if identifier:
                heuristic.add_signature_id(identifier)
            if sig.get("attck_id"):
                heuristic.add_attack_id(sig["attck_id"])
    if heuristic is not None:
        section.set_heuristic(heuristic)
    return section


def _behaviour(summary: dict, main: ResultSection) -> None:
    malicious, suspicious, informative = split_signatures(summary.get("signatures"))
    if malicious:
        main.add_subsection(_signature_table("Malicious-level behaviour signatures", malicious, 13, False))
    if suspicious:
        main.add_subsection(_signature_table("Suspicious-level behaviour signatures", suspicious, 14, False))
    if informative:
        main.add_subsection(_signature_table("Informative behaviour signatures", informative, None, True))


def _crowdstrike(summary: dict, main: ResultSection) -> None:
    analyses = [a for a in ((summary.get("crowdstrike_ai") or {}).get("executable_process_memory_analysis") or [])
                if isinstance(a, dict) and "_truncated_info_" not in a]
    if not analyses:
        return
    section = ResultTableSection("CrowdStrike Memory Analysis")
    section.set_column_order(["process", "pid", "verdict", "path"])
    verdicts = set()
    for a in analyses[:MAX_ROWS]:
        verdict = str(a.get("verdict") or "").lower()
        verdicts.add(verdict)
        section.add_row(TableRow({"process": a.get("file_process") or "", "pid": a.get("file_process_pid") or "",
                                  "verdict": verdict, "path": a.get("file_process_disc_pathway") or ""}))
        if a.get("file_process"):
            section.add_tag("dynamic.process.file_name", a["file_process"])
    if "malicious" in verdicts:
        section.set_heuristic(4)
    elif "suspicious" in verdicts:
        section.set_heuristic(5)
    main.add_subsection(section)


def _processes(summary: dict, main: ResultSection) -> None:
    tree = process_tree(summary.get("processes"))
    if not tree:
        return
    section = ResultTableSection("Process Tree", auto_collapse=len(tree) > COLLAPSE_ROWS)
    section.set_column_order(["process", "command_line", "av_detection", "pid"])
    for depth, p in tree:
        name = p.get("name") or ""
        section.add_row(TableRow({
            "process": ("  " * depth + "└ " if depth else "") + name,
            "command_line": p.get("command_line") or "",
            "av_detection": av_text(p.get("av_label"), p.get("av_matched"), p.get("av_total")),
            "pid": "" if p.get("pid") is None else str(p["pid"]),
        }))
        if name:
            section.add_tag("dynamic.process.file_name", name)
        if p.get("command_line"):
            section.add_tag("dynamic.process.command_line", p["command_line"])
    main.add_subsection(section)


def _dropped(summary: dict, main: ResultSection) -> None:
    files = dropped_files(summary.get("extracted_files"))
    if not files:
        return
    flagged = any(f.get("threat_level") for f in files)
    section = ResultTableSection("Files dropped or extracted during the analysis",
                                 auto_collapse=not flagged or len(files) > COLLAPSE_ROWS)
    section.set_column_order(["name", "path", "verdict", "av_detection", "type", "sha256"])
    for f in files:
        section.add_row(TableRow({
            "name": f.get("name") or "", "path": f.get("file_path") or "",
            "verdict": f.get("threat_level_readable") or "",
            "av_detection": av_text(f.get("av_label"), f.get("av_matched"), f.get("av_total")),
            "type": ", ".join(t for t in f.get("type_tags") or [] if isinstance(t, str)),
            "sha256": f.get("sha256") or "",
        }))
    main.add_subsection(section)


def _network(summary: dict, main: ResultSection) -> None:
    rows: list[tuple[str, str]] = []
    rows += [("domain", d) for d in summary.get("domains") or [] if isinstance(d, str) and d]
    rows += [("host", h) for h in summary.get("hosts") or [] if isinstance(h, str) and h]
    rows += [("compromised host", h) for h in summary.get("compromised_hosts") or [] if isinstance(h, str) and h]
    if not rows:
        return
    shown = rows[:MAX_ROWS]
    title = "Network Activity" if len(rows) == len(shown) else f"Network Activity (first {len(shown)} of {len(rows)})"
    section = ResultTableSection(title, auto_collapse=len(shown) > COLLAPSE_ROWS)
    section.set_column_order(["type", "value"])
    for kind, value in shown:
        section.add_row(TableRow({"type": kind, "value": value}))
        section.add_tag("network.dynamic.domain" if kind == "domain" else "network.dynamic.ip", value)
    main.add_subsection(section)


def _mitre(summary: dict, main: ResultSection) -> None:
    techniques, informative_only = notable_techniques(summary.get("mitre_attcks"))
    if not techniques:
        return
    title = "MITRE ATT&CK techniques with malicious or suspicious indicators"
    if informative_only:
        title += f" ({informative_only} more with informative indicators only)"
    section = ResultTableSection(title, auto_collapse=len(techniques) > COLLAPSE_ROWS)
    section.set_column_order(["tactic", "technique", "id", "malicious", "suspicious", "informative"])
    for t in techniques:
        section.add_row(TableRow({"tactic": t.get("tactic") or "", "technique": t.get("technique") or "",
                                  "id": t.get("attck_id") or "", "malicious": t.get("malicious_identifiers_count") or 0,
                                  "suspicious": t.get("suspicious_identifiers_count") or 0,
                                  "informative": t.get("informative_identifiers_count") or 0}))
    main.add_subsection(section)


def _file_info(summary: dict, overview: dict, main: ResultSection) -> None:
    info = ResultKeyValueSection("File Information", auto_collapse=True)
    fields = (("File Type", "type"), ("File Size (bytes)", "size"), ("MD5", "md5"), ("SHA1", "sha1"),
              ("SHA256", "sha256"), ("SHA512", "sha512"), ("SSDEEP", "ssdeep"))
    for label, key in fields:
        if summary.get(key):
            info.set_item(label, summary[key])
    names = other_names(overview, summary.get("submit_name"))
    if names:
        shown = ", ".join(names[:MAX_NAMES])
        if len(names) > MAX_NAMES:
            shown += f" ({len(names) - MAX_NAMES} more)"
        info.set_item("Also Submitted As", shown)
    if "peexe" in (summary.get("type_short") or []):
        pe = ResultKeyValueSection("PE Information")
        pe_fields = (("Import Hash", "imphash"), ("Entry Point", "entrypoint"), ("Image Base", "image_base"),
                     ("Subsystem", "subsystem"))
        for label, key in pe_fields:
            if summary.get(key) and summary[key] != "Unknown":
                pe.set_item(label, summary[key])
        if pe.body:
            info.add_subsection(pe)
    if info.body:
        main.add_subsection(info)


def _submission_history(summary: dict, main: ResultSection) -> None:
    # Source URLs are where submitters got the file, not content of the file, so they are not tagged.
    submissions = [s for s in summary.get("submissions") or [] if isinstance(s, dict)]
    if not submissions:
        return
    section = ResultTableSection("Submission History", auto_collapse=True)
    section.set_column_order(["filename", "submitted_at", "source_url", "submission_id"])
    for sub in submissions[:MAX_ROWS]:
        section.add_row(TableRow({
            "filename": sub.get("filename") or "", "submitted_at": sub.get("created_at") or "",
            "source_url": sub.get("url") or "", "submission_id": sub.get("submission_id") or "",
        }))
    main.add_subsection(section)


def _ontology(summary: dict, ontology: OntologyHelper, log: Logger) -> None:
    """Sandbox part only: Hybrid Analysis gives no per-process start times or connection details,
    so processes and traffic stay as tags rather than invented ontology records."""
    start = summary.get("analysis_start_time")
    if not start:
        return
    data: dict[str, Any] = {
        "objectid": {"tag": f"hybridanalysis_{summary.get('job_id') or summary.get('sha256')}"},
        "analysis_metadata": {"task_id": summary.get("job_id"), "start_time": start,
                              "machine_metadata": {"platform": platform(summary.get("environment_description")),
                                                   "version": summary.get("environment_description")}},
        "sandbox_name": "Hybrid Analysis",
    }
    # add_result_part takes the model class; its type hint says instance.
    if ontology.add_result_part(Sandbox, data) is None:  # type: ignore[arg-type]
        log.warning("Hybrid Analysis Sandbox ontology part was rejected by the model")
