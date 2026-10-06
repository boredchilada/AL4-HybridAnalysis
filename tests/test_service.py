"""Service behaviour: lookup-only by default, opt-in uploads, retries and error handling."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml
from assemblyline.common.exceptions import NonRecoverableError, RecoverableError

from hybridanalysis import service as svc
from hybridanalysis.client import AuthError, HybridAnalysisError, TransientError

FIXTURE = json.loads(next((Path(__file__).resolve().parent / "fixtures" / "ha").glob("*.json")).read_text())
RICH = FIXTURE["summaries"]["6a0000000000000000000a02"]


class Client:
    """Scriptable client: one file per test, uploads recorded."""

    def __init__(self, reports: list[dict], submit_error: Exception | None = None, states: list[str] | None = None,
                 search_error: Exception | None = None) -> None:
        self.reports, self.submit_error, self.search_error = reports, submit_error, search_error
        self.states = states or ["SUCCESS"]
        self.uploads: list[dict] = []
        self.summaries_fetched: list[str] = []
        self.overview_error: Exception | None = None
        self.calls: list[str] = []

    def search_hash(self, sha256: str) -> list[dict]:
        self.calls.append("search_hash")
        if self.search_error:
            raise self.search_error
        return self.reports

    def summary(self, report_id: str) -> dict:
        self.calls.append("summary")
        self.summaries_fetched.append(report_id)
        return dict(RICH, job_id=report_id)

    def overview(self, sha256: str) -> dict:
        self.calls.append("overview")
        if self.overview_error:
            raise self.overview_error
        return FIXTURE["overview"]

    def submit(self, path: str, file_name: str, params: dict) -> dict:
        self.calls.append("submit")
        self.uploads.append(params)
        if self.submit_error:
            raise self.submit_error
        return {"job_id": "JOB1", "sha256": "0" * 64}

    def state(self, report_id: str) -> dict:
        self.calls.append("state")
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"state": state, "error_type": "FILE_TYPE_BAD_ERROR" if state == "ERROR" else None}


SUCCESS = [{"id": "R1", "state": "SUCCESS"}]


@pytest.fixture
def instance(monkeypatch):
    service = svc.HybridAnalysis({"api_key": "offline-test-key", "submission_timeout": 0, "poll_interval": 0})
    service.start()
    monkeypatch.setattr(svc.time, "sleep", lambda _: None)
    return service


def run(service: Any, client: Client, tmp_path: Path, *, depth: int = 0,
        file_type: str = "executable/windows/pe32", partial: Any = None, **params: Any) -> Any:
    service.make_client = lambda: client
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    scope_params = {"lookup_depth": 6, "extracted_types": ".*"}
    scope_params.update(params)
    request = SimpleNamespace(file_path=str(sample), file_name="sample.bin", sha256="0" * 64, result=None,
                              task=SimpleNamespace(depth=depth), file_type=file_type,
                              partial=partial or Mock(), get_param=lambda name: scope_params.get(name))
    service.execute(request)
    return request.result


def titles(result: Any) -> list[str]:
    return [s.title_text for s in result.sections[0].subsections] if result.sections else []


def test_uploads_are_off_by_default_in_the_manifest():
    manifest = yaml.safe_load(Path(os.environ["SERVICE_MANIFEST_PATH"]).read_text())
    params = {p["name"]: p for p in manifest["submission_params"]}
    for name in ("allow_submission", "force_resubmit", "upload_extracted"):
        assert params[name]["default"] is False and params[name]["value"] is False


def test_default_manifest_scope_covers_all_default_extractions():
    manifest = yaml.safe_load(Path(os.environ["SERVICE_MANIFEST_PATH"]).read_text())
    params = {p["name"]: p for p in manifest["submission_params"]}
    for field in ("default", "value"):
        depth = params["lookup_depth"][field]
        types = params["extracted_types"][field]
        assert svc.in_lookup_scope(6, "archive/zip", depth, types)
        assert svc.in_lookup_scope(6, "executable/windows/pe32", depth, types)
        assert not svc.in_lookup_scope(7, "archive/zip", depth, types)


@pytest.mark.parametrize(
    "depth,file_type,params",
    [
        (1, "executable/windows/pe32", {"lookup_depth": 0}),
        (7, "executable/windows/pe32", {}),
        (1, "archive/zip", {"extracted_types": "executable/.*"}),
        (1, "executable/windows/pe32", {"extracted_types": "windows"}),
    ],
)
@pytest.mark.parametrize("upload_params", [
    {}, {"allow_submission": True}, {"force_resubmit": True},
    {"allow_submission": True, "force_resubmit": True, "upload_extracted": True},
])
def test_out_of_scope_files_are_partial_without_api_calls(instance, tmp_path, depth, file_type, params, upload_params):
    client = Client(reports=SUCCESS)
    partial = Mock()
    result = run(instance, client, tmp_path, depth=depth, file_type=file_type, partial=partial,
                 **params, **upload_params)
    assert result.sections == []
    assert client.calls == []
    partial.assert_called_once_with()


def test_scope_is_checked_before_the_api_key(instance, tmp_path):
    instance.api_key = ""
    client = Client(reports=SUCCESS)
    partial = Mock()
    result = run(instance, client, tmp_path, depth=1, lookup_depth=0, partial=partial)
    assert result.sections == []
    assert client.calls == []
    partial.assert_called_once_with()


def test_invalid_extracted_types_is_not_recoverable(instance, tmp_path):
    client = Client(reports=SUCCESS)
    partial = Mock()
    with pytest.raises(NonRecoverableError, match="extracted_types"):
        run(instance, client, tmp_path, depth=1, extracted_types="[", partial=partial)
    assert client.calls == []
    partial.assert_not_called()


@pytest.mark.parametrize("depth,pattern", [(0, "["), (0, "archive/.*"), (1, "executable/.*"), (6, ".*")])
def test_in_scope_files_are_looked_up(instance, tmp_path, depth, pattern):
    client = Client(reports=SUCCESS)
    partial = Mock()
    result = run(instance, client, tmp_path, depth=depth, extracted_types=pattern, partial=partial)
    assert titles(result)[0] == "Analysis Summary"
    assert client.calls == ["search_hash", "summary", "overview"]
    partial.assert_not_called()


@pytest.mark.parametrize("parameter", ["allow_submission", "force_resubmit"])
@pytest.mark.parametrize("upload_extracted", [False, None, "true"])
@pytest.mark.parametrize("reports", [[], SUCCESS])
def test_extracted_files_only_looked_up_without_upload_permission(
        instance, tmp_path, parameter, upload_extracted, reports):
    client = Client(reports=reports)
    result = run(instance, client, tmp_path, depth=1, upload_extracted=upload_extracted,
                 allow_submission=parameter == "allow_submission", force_resubmit=parameter == "force_resubmit")
    assert client.uploads == []
    if reports:
        assert client.calls == ["search_hash", "summary", "overview"]
        assert titles(result)[0] == "Analysis Summary"
    else:
        assert client.calls == ["search_hash"]
        assert result.sections == []


@pytest.mark.parametrize("parameter", ["allow_submission", "force_resubmit"])
@pytest.mark.parametrize("depth,upload_extracted", [(0, False), (1, True)])
def test_upload_permission_preserves_upload_settings(instance, tmp_path, parameter, depth, upload_extracted):
    client = Client(reports=SUCCESS if parameter == "force_resubmit" else [])
    result = run(instance, client, tmp_path, depth=depth, extracted_types="executable/.*",
                 upload_extracted=upload_extracted, environment_id="140", experimental_anti_evasion=True,
                 network_settings="tor", allow_submission=parameter == "allow_submission",
                 force_resubmit=parameter == "force_resubmit")
    assert client.uploads == [{
        "environment_id": 140,
        "experimental_anti_evasion": True,
        "network_settings": "tor",
        "allow_community_access": True,
        "no_share_third_party": True,
    }]
    expected_calls = ["submit", "state", "summary", "overview"]
    if parameter == "allow_submission":
        expected_calls.insert(0, "search_hash")
    assert client.calls == expected_calls
    assert "File uploaded to Hybrid Analysis" in titles(result)


@pytest.mark.parametrize("depth", [0, 1])
def test_upload_extracted_alone_does_not_enable_uploads(instance, tmp_path, depth):
    client = Client(reports=[])
    result = run(instance, client, tmp_path, depth=depth, upload_extracted=True,
                 allow_submission=False, force_resubmit=False)
    assert client.calls == ["search_hash"]
    assert client.uploads == []
    assert result.sections == []


def test_unknown_file_is_not_uploaded_by_default(instance, tmp_path):
    client = Client(reports=[])
    assert run(instance, client, tmp_path).sections == []
    assert client.uploads == []


def test_known_file_is_not_uploaded_with_allow_submission(instance, tmp_path):
    client = Client(reports=SUCCESS)
    result = run(instance, client, tmp_path, allow_submission=True)
    assert client.uploads == []
    assert titles(result)[0] == "Analysis Summary"
    assert [type(p).__name__ for p in instance.ontology._result_parts.values()] == ["Sandbox"]


def test_only_failed_reports_count_as_unknown(instance, tmp_path):
    client = Client(reports=[{"id": "E", "state": "ERROR"}])
    assert run(instance, client, tmp_path).sections == []


def test_running_report_is_retried_not_uploaded(instance, tmp_path):
    client = Client(reports=[{"id": "R9", "state": "IN_PROGRESS"}])
    with pytest.raises(RecoverableError, match="R9"):
        run(instance, client, tmp_path, allow_submission=True)
    assert client.uploads == []


def test_allow_submission_uploads_unknown_file_and_says_it_is_public(instance, tmp_path):
    client = Client(reports=[], states=["IN_QUEUE", "SUCCESS"])
    instance.submission_timeout = 60
    result = run(instance, client, tmp_path, allow_submission=True, environment_id="140")
    assert client.uploads[0]["environment_id"] == 140
    assert "File uploaded to Hybrid Analysis" in titles(result)


def test_force_resubmit_uploads_even_when_a_report_exists(instance, tmp_path):
    client = Client(reports=SUCCESS)
    run(instance, client, tmp_path, force_resubmit=True)
    assert len(client.uploads) == 1


def test_refused_upload_is_reported_not_retried(instance, tmp_path):
    client = Client(reports=[], submit_error=HybridAnalysisError("HTTP 400: Unsupported file type", 400))
    result = run(instance, client, tmp_path, allow_submission=True)
    assert [s.title_text for s in result.sections] == ["Hybrid Analysis did not accept the upload"]


def test_failed_analysis_is_reported(instance, tmp_path):
    client = Client(reports=[], states=["ERROR"])
    result = run(instance, client, tmp_path, allow_submission=True)
    assert [s.title_text for s in result.sections] == ["Hybrid Analysis could not analyse the uploaded file"]
    assert "FILE_TYPE_BAD_ERROR" in result.sections[0].body


def test_unfinished_upload_is_retried(instance, tmp_path):
    client = Client(reports=[], states=["IN_PROGRESS"])
    with pytest.raises(RecoverableError, match="JOB1"):
        run(instance, client, tmp_path, allow_submission=True)


def test_unfinished_forced_upload_is_reported_because_a_retry_would_upload_again(instance, tmp_path):
    client = Client(reports=SUCCESS, states=["IN_PROGRESS"])
    result = run(instance, client, tmp_path, force_resubmit=True)
    assert [s.title_text for s in result.sections] == ["Hybrid Analysis analysis not finished"]
    assert len(client.uploads) == 1


def test_rejected_key_is_not_retried(instance, tmp_path):
    with pytest.raises(NonRecoverableError, match="rejected the API key"):
        run(instance, Client(reports=[], search_error=AuthError("HTTP 401: Invalid", 401)), tmp_path)


def test_rate_limit_is_retried(instance, tmp_path):
    with pytest.raises(RecoverableError, match="temporarily unavailable"):
        run(instance, Client(reports=[], search_error=TransientError("HTTP 429: Slow down", 429)), tmp_path)


def test_missing_key_fails_clearly(tmp_path):
    service = svc.HybridAnalysis({"api_key": ""})
    service.start()
    with pytest.raises(NonRecoverableError, match="API key"):
        run(service, Client(reports=[]), tmp_path)


def _score(result: Any) -> int:
    def walk(sections: list) -> Any:
        for section in sections:
            yield section
            yield from walk(section.subsections)

    return sum(s.heuristic.score for s in walk(result.sections) if s.heuristic)


def _summary_with(verdict: str, malicious_signatures: int) -> dict:
    sigs = [{"identifier": f"test-{i}", "name": f"sig {i}", "threat_level": 2, "attck_id": "T1027"}
            for i in range(malicious_signatures)]
    return {"job_id": "J", "sha256": "0" * 64, "verdict": verdict, "signatures": sigs,
            "total_signatures": malicious_signatures}


@pytest.mark.parametrize(
    "verdict,signatures,score",
    [
        # Hybrid Analysis rates generic traits of benign files as malicious-level signatures;
        # however many there are, they must not make a file malicious (1000) on their own.
        ("no specific threat", 12, 500),
        ("no specific threat", 1, 100),
        ("suspicious", 12, 800),
        ("malicious", 0, 1000),
        ("malicious", 3, 1300),
    ],
)
def test_scoring_follows_the_verdict(instance, tmp_path, verdict, signatures, score):
    client = Client(reports=SUCCESS)
    client.summary = lambda report_id: _summary_with(verdict, signatures)  # type: ignore[method-assign]
    assert _score(run(instance, client, tmp_path)) == score


def test_signatures_are_attached_by_identifier_with_attack_ids(instance, tmp_path):
    result = run(instance, Client(reports=SUCCESS), tmp_path)
    section = next(s for s in result.sections[0].subsections if s.heuristic and s.heuristic.heur_id == 13)
    assert set(section.heuristic.signatures) == {"suricata-2", "test-injects", "test-contacts"}  # from the fixture
    assert set(section.heuristic.attack_ids) == {"T1055", "T1071"}


def test_other_reports_are_listed_with_links(instance, tmp_path):
    client = Client(reports=[{"id": "R1", "state": "SUCCESS"}, {"id": "R2", "state": "SUCCESS"}])
    result = run(instance, client, tmp_path)
    other = next(s for s in result.sections[0].subsections if s.title_text.startswith("Other Hybrid Analysis reports"))
    rows = json.loads(other.body)
    assert [r["report"].rsplit("/", 1)[1] for r in rows] == ["R2"]  # R1 is the main report; equal rank keeps the first


def test_lookup_fetches_one_summary_for_the_best_report(instance, tmp_path):
    client = Client(reports=[{"id": "6a1f00000000000000000001", "state": "SUCCESS", "verdict": "no specific threat"},
                             {"id": "6a0000000000000000000002", "state": "SUCCESS", "verdict": "malicious"},
                             {"id": "6a1e00000000000000000003", "state": "SUCCESS", "verdict": "malicious"}])
    run(instance, client, tmp_path)
    # Three API calls per file: search, this one summary, overview.
    assert client.summaries_fetched == ["6a1e00000000000000000003"]  # malicious beats newer, newest malicious wins


def test_empty_summary_falls_back_to_the_next_report(instance, tmp_path):
    client = Client(reports=[{"id": "6a1e00000000000000000003", "state": "SUCCESS", "verdict": "malicious"},
                             {"id": "6a0000000000000000000002", "state": "SUCCESS", "verdict": "malicious"}])
    full = client.summary
    client.summary = lambda report_id: {} if report_id.endswith("3") else full(report_id)  # type: ignore[method-assign]
    result = run(instance, client, tmp_path)
    assert result.sections[0].subsections[0].body  # the second report is shown


def test_unavailable_overview_still_gives_the_report(instance, tmp_path):
    client = Client(reports=SUCCESS)
    client.overview_error = TransientError("HTTP 502: Bad Gateway", 502)
    assert "Scanner Results" not in titles(run(instance, client, tmp_path))
    assert titles(run(instance, client, tmp_path))[0] == "Analysis Summary"


def test_settings_from_the_2026_github_version_still_work():
    # That version stored each setting as {"type", "value", "description"}.
    service = svc.HybridAnalysis({"api_key": {"type": "str", "value": "legacy-key"},
                                  "base_url": {"type": "str", "value": "https://ha.example/api/v2"}})
    service.start()
    assert (service.api_key, service.base_url) == ("legacy-key", "https://ha.example/api/v2")
