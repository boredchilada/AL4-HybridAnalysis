"""AssemblyLine 4 service that shows Hybrid Analysis results for a file.

By default the service looks up the file's SHA-256 on Hybrid Analysis and reports the most
informative successful analysis; the file never leaves AssemblyLine. Uploading is opt-in per
submission: ``allow_submission`` uploads when no analysis exists or is running, and
``force_resubmit`` uploads even when one exists. Uploaded files and their reports are public.
"""

import time
from typing import Any, cast

from assemblyline.common.exceptions import NonRecoverableError, RecoverableError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection

from hybridanalysis.analysis import MAX_SUMMARIES, InvalidScope, classify_reports, in_lookup_scope, may_upload
from hybridanalysis.client import AuthError, HybridAnalysisClient, HybridAnalysisError, TransientError
from hybridanalysis.results import build_main_section

DEFAULT_BASE_URL = "https://hybrid-analysis.com/api/v2"


class HybridAnalysis(ServiceBase):
    def _setting(self, name: str, default: Any) -> Any:
        # Installations of the 2026 GitHub version store settings as {"type", "value", "description"}.
        value = (self.config or {}).get(name, default)
        return value.get("value", default) if isinstance(value, dict) else value

    def start(self) -> None:
        self.api_key = str(self._setting("api_key", "") or "")
        self.base_url = str(self._setting("base_url", DEFAULT_BASE_URL) or DEFAULT_BASE_URL)
        self.submission_timeout = int(self._setting("submission_timeout", 600))
        self.poll_interval = int(self._setting("poll_interval", 15))
        if not self.api_key:
            self.log.error("No Hybrid Analysis API key: set api_key in the service configuration")

    def make_client(self) -> HybridAnalysisClient:
        return HybridAnalysisClient(self.api_key, self.base_url)

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result
        try:
            in_scope = in_lookup_scope(cast(int, request.task.depth), request.file_type,
                                       request.get_param("lookup_depth"), request.get_param("extracted_types"))
        except InvalidScope as exc:
            raise NonRecoverableError(str(exc)) from None
        if not in_scope:
            # Partial: AssemblyLine must not reuse this empty result for a submission that looks deeper or wider.
            request.partial()
            return
        uploads_allowed = may_upload(cast(int, request.task.depth), request.get_param("upload_extracted"))
        if not self.api_key:
            raise NonRecoverableError("No Hybrid Analysis API key configured (service setting api_key)")
        client = self.make_client()
        force = uploads_allowed and bool(request.get_param("force_resubmit"))

        try:
            if not force:
                lookup = classify_reports(client.search_hash(request.sha256))
                # The best report first; the next one only if Hybrid Analysis returns an empty summary.
                for report in lookup.successful[:MAX_SUMMARIES]:
                    summary = client.summary(str(report["id"]))
                    if summary:
                        others = [r for r in lookup.successful if r is not report]
                        overview = self._overview(client, request.sha256)
                        result.add_section(build_main_section(summary, others, overview, False, self.ontology,
                                                              self.log))
                        return
                if lookup.running:
                    # Not cached by AL: the retry fetches the finished report instead of uploading again.
                    raise RecoverableError(f"Hybrid Analysis report {lookup.running} for this file is still running")
                if not uploads_allowed or not request.get_param("allow_submission"):
                    return  # nothing usable known about this file; uploading is off

            summary = self._submit_and_wait(client, request, result, force)
            if summary:
                overview = self._overview(client, request.sha256)
                result.add_section(build_main_section(summary, [], overview, True, self.ontology, self.log))
        except AuthError as exc:
            raise NonRecoverableError(f"Hybrid Analysis rejected the API key: {exc}") from exc
        except TransientError as exc:
            raise RecoverableError(f"Hybrid Analysis temporarily unavailable: {exc}") from exc

    def _overview(self, client: HybridAnalysisClient, sha256: str) -> dict:
        """Scanner results are extra context: without them the report is still complete."""
        try:
            return client.overview(sha256)
        except AuthError:
            raise
        except HybridAnalysisError as exc:
            self.log.warning(f"Hybrid Analysis overview for {sha256} unavailable: {exc}")
            return {}

    def _submit_and_wait(self, client: HybridAnalysisClient, request: ServiceRequest, result: Result,
                         force: bool) -> dict | None:
        """Upload the file and wait for its report. Returns the summary, or None after reporting why not."""
        params = {
            "environment_id": int(request.get_param("environment_id") or 160),
            "experimental_anti_evasion": bool(request.get_param("experimental_anti_evasion")),
            "network_settings": request.get_param("network_settings") or "default",
            "allow_community_access": True,
            "no_share_third_party": True,
        }
        try:
            submission = client.submit(request.file_path, request.file_name or request.sha256, params)
        except (AuthError, TransientError):
            raise
        except HybridAnalysisError as exc:
            # Unsupported file type, invalid environment, account limits: Hybrid Analysis says which.
            section = ResultTextSection("Hybrid Analysis did not accept the upload")
            section.add_line(str(exc))
            result.add_section(section)
            return None

        job_id = str(submission.get("job_id") or "")
        deadline = time.monotonic() + self.submission_timeout
        while True:  # check at least once, then until the deadline
            try:
                state = client.state(job_id)
            except TransientError as exc:
                self.log.warning(f"Hybrid Analysis job {job_id} state check failed: {exc}")
                state = {}
            if state.get("state") == "SUCCESS":
                return client.summary(job_id)
            if state.get("state") == "ERROR":
                section = ResultTextSection("Hybrid Analysis could not analyse the uploaded file")
                detail = f"{state.get('error_type') or 'error'} {state.get('error') or ''}".strip()
                section.add_line(f"Job {job_id}: {detail}")
                result.add_section(section)
                return None
            if time.monotonic() >= deadline:
                break
            time.sleep(self.poll_interval)

        message = (f"Uploaded to Hybrid Analysis as job {job_id}; the analysis did not finish within "
                   f"{self.submission_timeout} s.")
        if force:
            # A retry would upload again (force_resubmit skips the lookup), so report instead of retrying.
            section = ResultTextSection("Hybrid Analysis analysis not finished")
            section.add_line(message + " Submit the file again without force_resubmit to fetch the report.")
            result.add_section(section)
            return None
        raise RecoverableError(message + " AL retries and fetches it by hash without uploading again.")
