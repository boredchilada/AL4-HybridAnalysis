"""Pure helpers for Hybrid Analysis lookups and reports. No AssemblyLine imports."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime

DEFAULT_LOOKUP_DEPTH = 6

RUNNING_STATES = {"IN_QUEUE", "IN_PROGRESS", "SUBMITTED"}
# Summaries tried, best report first, when one comes back empty.
MAX_SUMMARIES = 5
# Hostile or very large reports must not produce unbounded tables.
MAX_ROWS = 500
# Longest signature description shown; Hybrid Analysis descriptions can run to many kilobytes.
MAX_DETAIL = 500

# Hybrid Analysis verdict -> manifest heuristic id. Other verdicts ("no specific threat",
# "whitelisted") raise none.
VERDICT_HEURISTIC = {"malicious": 9, "suspicious": 12}
# Report preference by verdict; unknown verdicts rank lowest.
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "no specific threat": 1}

PLATFORMS = (("windows", "Windows"), ("linux", "Linux"), ("macos", "MacOS"), ("android", "Android"))

# One Suricata alert line in a "suricata-*" signature description, e.g.
# Detected alert "ET MALWARE Mozi Botnet DHT Config Sent" (SID: 2030919, Rev: 1, Severity: 1)
# categorized as "Malware Command and Control Activity Detected"
SURICATA_ALERT = re.compile(
    r'Detected alert "(?P<message>[^"]+)" \(SID: (?P<sid>\d+), Rev: (?P<rev>\d+), Severity: (?P<severity>\d+)\)'
    r'(?: categorized as "(?P<category>[^"]*)")?'
)


class InvalidScope(ValueError):
    """extracted_types is not a valid regular expression."""


def in_lookup_scope(depth: int, file_type: str, depth_param: object, types_param: object) -> bool:
    """Whether a file is looked up: within lookup_depth and, for extracted files, matching extracted_types."""
    try:
        limit = max(0, int(str(depth_param)))
    except ValueError:
        limit = DEFAULT_LOOKUP_DEPTH
    if depth > limit:
        return False
    if depth == 0:
        return True
    pattern = types_param if isinstance(types_param, str) and types_param else ".*"
    try:
        return re.match(pattern, file_type or "") is not None
    except re.error as exc:
        raise InvalidScope(f"Submission parameter extracted_types is not a valid regular expression: {exc}") from None


def may_upload(depth: int, upload_extracted: object) -> bool:
    """Uploads apply to the submitted file; to extracted files only when upload_extracted is true."""
    return depth == 0 or upload_extracted is True


@dataclass
class Lookup:
    successful: list[dict]  # /search/hash reports with state SUCCESS, best first
    running: str | None  # first report still queued or running


def report_time(report_id: object) -> str:
    """Creation time encoded in a Hybrid Analysis report ID (a MongoDB ObjectId), or ''.

    The first 8 hex digits are the creation time in Unix seconds; the search results carry no
    other date, so this is what orders reports and dates the "other reports" table.
    """
    text = str(report_id or "")
    if not re.fullmatch(r"[0-9a-fA-F]{24}", text):
        return ""
    return datetime.fromtimestamp(int(text[:8], 16), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_reports(reports: list[dict]) -> Lookup:
    """Successful reports, best first (malicious, suspicious, others; newest first within each),
    and the first running one. Failed reports are ignored."""
    successful = [r for r in reports if isinstance(r, dict) and r.get("state") == "SUCCESS" and r.get("id")]
    successful.sort(key=lambda r: (VERDICT_RANK.get(str(r.get("verdict") or "").lower(), 0), report_time(r["id"])),
                    reverse=True)
    running = next((str(r["id"]) for r in reports
                    if isinstance(r, dict) and r.get("state") in RUNNING_STATES and r.get("id")), None)
    return Lookup(successful=successful, running=running)


def verdict_heuristic(verdict: object) -> int | None:
    return VERDICT_HEURISTIC.get(str(verdict or "").strip().lower())


def platform(environment: object) -> str | None:
    """AssemblyLine platform name for a Hybrid Analysis environment description."""
    text = str(environment or "").lower()
    return next((name for key, name in PLATFORMS if key in text), None)


def _real(items: object) -> list[dict]:
    """List entries that are objects, without Hybrid Analysis's truncation markers."""
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict) and "_truncated_info_" not in i]


def _level(item: dict) -> int:
    level = item.get("threat_level")
    return level if isinstance(level, int) else 0


def split_signatures(signatures: object) -> tuple[list[dict], list[dict], list[dict]]:
    """Signatures by threat level (malicious 2+, suspicious 1, informative 0), most relevant first."""
    def relevance(sig: dict) -> int:
        value = sig.get("relevance")
        return value if isinstance(value, int) else 0

    def ordered(sigs: list[dict]) -> list[dict]:
        return sorted(sigs, key=lambda s: -relevance(s))[:MAX_ROWS]

    sigs = _real(signatures)
    return (ordered([s for s in sigs if _level(s) >= 2]), ordered([s for s in sigs if _level(s) == 1]),
            ordered([s for s in sigs if _level(s) <= 0]))


def detail(text: object) -> str:
    """A signature description on one line, shortened to MAX_DETAIL characters."""
    line = " | ".join(part.strip() for part in str(text or "").splitlines() if part.strip())
    if line == "No specific details available":
        return ""
    return line if len(line) <= MAX_DETAIL else line[:MAX_DETAIL - 1] + "…"


def notable_techniques(techniques: object) -> tuple[list[dict], int]:
    """ATT&CK techniques with malicious or suspicious indicators (most first) and the count of the rest."""
    real = _real(techniques)

    def count(t: dict, key: str) -> int:
        value = t.get(key)
        return value if isinstance(value, int) else 0

    notable = [t for t in real if count(t, "malicious_identifiers_count") or count(t, "suspicious_identifiers_count")]
    notable.sort(key=lambda t: (-count(t, "malicious_identifiers_count"), -count(t, "suspicious_identifiers_count")))
    return notable[:MAX_ROWS], len(real) - len(notable)


def process_tree(processes: object) -> list[tuple[int, dict]]:
    """Processes as (depth, process) in tree order, parents before their children.

    Processes whose parent is missing are treated as roots; a loop in the parent links cannot
    cause endless recursion because every process is placed once.
    """
    procs = _real(processes)
    by_uid = {p.get("uid"): p for p in procs if p.get("uid")}
    children: dict[object, list[dict]] = {}
    roots = []
    for p in procs:
        parent = p.get("parentuid")
        (children.setdefault(parent, []) if parent in by_uid and parent != p.get("uid") else roots).append(p)
    ordered: list[tuple[int, dict]] = []
    placed: set[int] = set()

    def visit(p: dict, depth: int) -> None:
        if id(p) in placed or len(ordered) >= MAX_ROWS:
            return
        placed.add(id(p))
        ordered.append((depth, p))
        for child in children.get(p.get("uid"), []):
            visit(child, depth + 1)

    for root in roots:
        visit(root, 0)
    for p in procs:  # anything only reachable through a loop
        visit(p, 0)
    return ordered


def av_text(label: object, matched: object, total: object) -> str:
    """'Worm.Bflient (18/24)'; empty when nothing was detected."""
    if not label and not matched:
        return ""
    counts = f" ({matched}/{total})" if isinstance(matched, int) and isinstance(total, int) else ""
    return f"{label or 'detected'}{counts}"


def dropped_files(files: object) -> list[dict]:
    """Extracted and dropped files, most dangerous first: threat level, then AV detections."""
    def matched(f: dict) -> int:
        value = f.get("av_matched")
        return value if isinstance(value, int) else 0

    return sorted(_real(files), key=lambda f: (-_level(f), -matched(f)))[:MAX_ROWS]


def suricata_alerts(signatures: object) -> list[dict]:
    """Distinct Suricata alerts from "suricata-*" signatures, with the signature's threat level.

    Hybrid Analysis reports Suricata only inside signature descriptions, one alert per line.
    """
    alerts: dict[str, dict] = {}
    for sig in _real(signatures):
        if not str(sig.get("identifier") or "").lower().startswith("suricata-"):
            continue
        for match in SURICATA_ALERT.finditer(str(sig.get("description") or "")):
            alerts.setdefault(match["sid"], {
                "message": match["message"], "sid": match["sid"], "severity": int(match["severity"]),
                "category": match["category"] or "", "level": sig.get("threat_level_human") or "",
            })
            if len(alerts) >= MAX_ROWS:
                return list(alerts.values())
    return list(alerts.values())


def scanner_rows(overview: object) -> list[dict]:
    """Independent scanner verdicts from /overview: scanners that returned a result."""
    if not isinstance(overview, dict):
        return []
    rows = []
    for scanner in _real(overview.get("scanners")):
        status = str(scanner.get("status") or "").lower()
        if not scanner.get("name") or status in ("", "no-result", "in-queue", "error"):
            continue
        positives, total = scanner.get("positives"), scanner.get("total")
        detections = f"{positives}/{total}" if isinstance(positives, int) and isinstance(total, int) else ""
        rows.append({"scanner": scanner["name"], "verdict": status, "detections": detections})
    return rows[:MAX_ROWS]


def other_names(overview: object, current: object) -> list[str]:
    """File names the sample was also submitted under, without the current name."""
    if not isinstance(overview, dict):
        return []
    seen = {str(current or "").lower()}
    names = []
    for name in [overview.get("last_file_name"), *(overview.get("other_file_name") or [])]:
        if isinstance(name, str) and name and name.lower() not in seen:
            seen.add(name.lower())
            names.append(name)
    return names[:MAX_ROWS]


def analysis_conditions(summary: dict) -> dict[str, str]:
    """How the sample was run, as label -> value; only what affects reading the results."""
    raw = summary.get("detonation_parameters")
    params: dict = raw if isinstance(raw, dict) else {}
    conditions = {}
    network = summary.get("network_mode") or params.get("network_mode")
    if network:
        conditions["Network Mode"] = str(network)
    if isinstance(params.get("experimental_anti_evasion"), bool):
        conditions["Anti-evasion"] = "on" if params["experimental_anti_evasion"] else "off"
    warnings = [w for w in summary.get("warnings") or [] if isinstance(w, str)]
    if any("slim report" in w.lower() for w in warnings):
        conditions["Report Detail"] = "slim report: Hybrid Analysis hid some low-level data"
    return conditions
