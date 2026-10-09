import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
import requests

from nvd_exporter.client import API_URL, NvdClient, NvdError, date_windows


def response(payload=None, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode()
    result._content_consumed = True
    result.headers.update(headers or {})
    return result


def client(monkeypatch, responses, **kwargs):
    session = Mock(headers={})
    session.get.side_effect = responses
    sleep = Mock()
    monkeypatch.setattr("nvd_exporter.client.time.sleep", sleep)
    return NvdClient(session=session, **kwargs), session, sleep


def test_pagination_and_header(monkeypatch, cve):
    first = {"startIndex": 0, "totalResults": 2, "vulnerabilities": [{"cve": cve}]}
    second = {**first, "startIndex": 1}
    api, session, sleep = client(monkeypatch, [response(first), response(second)], api_key="secret")
    assert list(api.iter_cves({"keywordSearch": "test"})) == [cve, cve]
    assert session.headers["apiKey"] == "secret"
    assert session.get.call_args_list[1].kwargs["params"]["startIndex"] == 1
    assert session.get.call_args_list[0].args == (API_URL,)
    assert "apiKey" not in session.get.call_args.kwargs["params"]
    assert "verify" not in session.get.call_args.kwargs
    assert sleep.called
    api.close()
    session.close.assert_called_once()


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_retry_after(monkeypatch, status):
    api, session, sleep = client(
        monkeypatch,
        [
            response(status=status, headers={"Retry-After": "12"}),
            response({"startIndex": 0, "totalResults": 0, "vulnerabilities": []}),
        ],
    )
    assert list(api.iter_cves()) == []
    assert session.get.call_count == 2
    assert any(call.args == (12.0,) for call in sleep.call_args_list)


def test_retry_network_and_exhaustion(monkeypatch):
    api, session, _ = client(monkeypatch, [requests.Timeout()] * 3, retries=2)
    with pytest.raises(NvdError, match="Unable to reach NVD"):
        list(api.iter_cves())
    assert session.get.call_count == 3


@pytest.mark.parametrize("status", [400, 403, 404])
def test_non_retryable(monkeypatch, status):
    api, session, _ = client(monkeypatch, [response(status=status)])
    with pytest.raises(NvdError, match=f"HTTP {status}"):
        list(api.iter_cves())
    assert session.get.call_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"startIndex": 0, "totalResults": 1, "vulnerabilities": []},
        {"startIndex": 4, "totalResults": 1, "vulnerabilities": [{}]},
        {"startIndex": 0, "totalResults": 1, "vulnerabilities": [{}]},
    ],
)
def test_bad_responses(monkeypatch, payload):
    api, _, _ = client(monkeypatch, [response(payload)])
    with pytest.raises(NvdError):
        list(api.iter_cves())


def test_date_windows():
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2025, 1, 1, tzinfo=timezone.utc)
    windows = list(date_windows(start, end))
    assert len(windows) == 4
    assert windows[0][0] == start
    assert windows[-1][1] == end
    for i, (begin, stop) in enumerate(windows):
        assert stop - begin < timedelta(days=120)
        if i:
            assert begin - windows[i - 1][1] == timedelta(milliseconds=1)
    assert list(date_windows(start, start)) == [(start, start)]
    with pytest.raises(ValueError):
        list(date_windows(end, start))
