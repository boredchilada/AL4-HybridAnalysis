"""Minimal Hybrid Analysis API v2 client. Errors are typed so the service can decide what to retry."""

from typing import Any

import requests


class HybridAnalysisError(Exception):
    """The API refused a request; ``message`` is Hybrid Analysis's own explanation."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AuthError(HybridAnalysisError):
    """The API key is missing, invalid or lacks permission (HTTP 401/403)."""


class TransientError(HybridAnalysisError):
    """Rate limit, server error or network failure; the same request may succeed later."""


class HybridAnalysisClient:
    def __init__(self, api_key: str, base_url: str, timeout: int = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"api-key": api_key, "User-Agent": "Falcon Sandbox", "accept": "application/json"})

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self.session.request(method, f"{self.base_url}{path}", timeout=self.timeout, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise TransientError(f"Hybrid Analysis unreachable: {exc}") from exc
        if response.ok:
            return response.json()
        try:
            message = response.json().get("message") or response.text
        except ValueError:
            message = response.text
        message = f"HTTP {response.status_code}: {str(message)[:300]}"
        if response.status_code in (401, 403):
            raise AuthError(message, response.status_code)
        if response.status_code == 429 or response.status_code >= 500:
            raise TransientError(message, response.status_code)
        raise HybridAnalysisError(message, response.status_code)

    def search_hash(self, sha256: str) -> list[dict]:
        """Reports for a file: ``[{"id", "state", "verdict", "environment_id", ...}]``; empty if unknown."""
        try:
            return (self._request("GET", "/search/hash", params={"hash": sha256}) or {}).get("reports") or []
        except HybridAnalysisError as exc:
            if exc.status == 404:  # "Requested hash not found"
                return []
            raise

    def overview(self, sha256: str) -> dict:
        """Scanner verdicts and submission names for a file; empty if Hybrid Analysis has none."""
        try:
            return self._request("GET", f"/overview/{sha256}") or {}
        except HybridAnalysisError as exc:
            if exc.status == 404:
                return {}
            raise

    def summary(self, report_id: str) -> dict:
        return self._request("GET", f"/report/{report_id}/summary") or {}

    def state(self, report_id: str) -> dict:
        return self._request("GET", f"/report/{report_id}/state") or {}

    def submit(self, path: str, file_name: str, params: dict) -> dict:
        with open(path, "rb") as handle:
            return self._request("POST", "/submit/file", files={"file": (file_name, handle)}, data=params) or {}
