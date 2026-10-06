"""How the API client maps Hybrid Analysis responses to results and typed errors."""

import pytest
import requests

from hybridanalysis.client import AuthError, HybridAnalysisClient, HybridAnalysisError, TransientError


class Response:
    def __init__(self, status: int, body: object) -> None:
        self.status_code, self._body = status, body
        self.ok = 200 <= status < 300
        self.text = str(body)

    def json(self) -> object:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def client_returning(monkeypatch, response: object) -> HybridAnalysisClient:
    client = HybridAnalysisClient("key", "https://ha.example/api/v2/")

    def request(*_: object, **__: object) -> object:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(client.session, "request", request)
    return client


def test_unknown_hash_is_an_empty_result(monkeypatch):
    client = client_returning(monkeypatch, Response(404, {"message": "Requested hash not found"}))
    assert client.search_hash("0" * 64) == []


def test_search_returns_reports(monkeypatch):
    body = {"sha256s": ["x"], "reports": [{"id": "r", "state": "SUCCESS"}]}
    client = client_returning(monkeypatch, Response(200, body))
    assert client.search_hash("x") == [{"id": "r", "state": "SUCCESS"}]


@pytest.mark.parametrize(
    "response,error",
    [
        (Response(401, {"message": "Invalid API key"}), AuthError),
        (Response(403, {"message": "Restricted"}), AuthError),
        (Response(429, {"message": "Slow down"}), TransientError),
        (Response(502, ValueError("not json")), TransientError),
        (requests.ConnectionError("refused"), TransientError),
        (requests.Timeout("slow"), TransientError),
        (Response(400, {"message": "Unsupported file type"}), HybridAnalysisError),
    ],
)
def test_errors_are_typed(monkeypatch, response, error):
    client = client_returning(monkeypatch, response)
    with pytest.raises(error) as raised:
        client.summary("r")
    assert type(raised.value) is error


def test_error_message_comes_from_hybrid_analysis(monkeypatch):
    client = client_returning(monkeypatch, Response(400, {"message": "Unsupported file type"}))
    with pytest.raises(HybridAnalysisError, match="HTTP 400: Unsupported file type"):
        client.summary("r")
