"""Paginated NVD API 2.0 client with bounded retries and rate limiting."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LOG = logging.getLogger(__name__)


class NvdError(RuntimeError):
    """An NVD request failed or returned unusable data."""


def date_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    """Split inclusive, millisecond-precision ranges without overlapping endpoints."""
    if start > end:
        raise ValueError("Start date must be on or before end date")
    while start <= end:
        stop = min(start + timedelta(days=120) - timedelta(milliseconds=1), end)
        yield start, stop
        start = stop + timedelta(milliseconds=1)


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        page_size: int = 2000,
        timeout: float = 60,
        retries: int = 5,
        session: requests.Session | None = None,
    ):
        if not 1 <= page_size <= 2000:
            raise ValueError("Page size must be between 1 and 2000")
        self.session = session if session is not None else requests.Session()
        self.session.headers.update(
            {"User-Agent": "nvd-export/2.0.0", "Accept": "application/json"}
        )
        if api_key:
            self.session.headers["apiKey"] = api_key
        self.page_size = page_size
        self.timeout = timeout
        self.retries = retries
        self.interval = 0.65 if api_key else 6.1
        self._last_request: float | None = None

    def close(self) -> None:
        self.session.close()

    def _request(self, params: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(self.retries + 1):
            if self._last_request is not None:
                time.sleep(max(0, self.interval - (time.monotonic() - self._last_request)))
            self._last_request = time.monotonic()
            delay = min(60, 2**attempt)
            try:
                response = self.session.get(API_URL, params=params, timeout=self.timeout)
            except requests.RequestException:
                if attempt == self.retries:
                    raise NvdError(
                        "Unable to reach NVD after retries; check network/TLS access"
                    ) from None
            else:
                with response:
                    if response.status_code == 200:
                        try:
                            payload = response.json()
                        except ValueError:
                            raise NvdError("NVD returned invalid JSON") from None
                        if not isinstance(payload, dict):
                            raise NvdError("NVD returned an unexpected response")
                        return payload
                    if response.status_code != 429 and not 500 <= response.status_code < 600:
                        raise NvdError(
                            f"NVD returned HTTP {response.status_code}; check API key and filters"
                        )
                    if attempt == self.retries:
                        raise NvdError(f"NVD returned HTTP {response.status_code} after retries")
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        try:
                            retry_date = parsedate_to_datetime(retry_after)
                            delay = max(
                                delay, (retry_date - datetime.now(timezone.utc)).total_seconds()
                            )
                        except (TypeError, ValueError, OverflowError):
                            pass
            LOG.warning("NVD request failed; retrying (%d/%d)", attempt + 1, self.retries)
            time.sleep(delay)
        raise NvdError("NVD request failed")

    def iter_cves(self, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        start = 0
        while True:
            payload = self._request(
                {**(params or {}), "startIndex": start, "resultsPerPage": self.page_size}
            )
            items = payload.get("vulnerabilities")
            total = payload.get("totalResults")
            if (
                not isinstance(items, list)
                or not isinstance(total, int)
                or total < 0
                or payload.get("startIndex") != start
            ):
                raise NvdError("NVD returned invalid pagination metadata")
            if not items and start < total:
                raise NvdError("NVD returned an empty page before all results were downloaded")
            LOG.info("Downloaded %d/%d CVEs for current query", start + len(items), total)
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                    raise NvdError("NVD returned an invalid CVE record")
                yield item["cve"]
            start += len(items)
            if start >= total:
                return
