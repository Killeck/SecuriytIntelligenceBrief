# Copyright © 2026 John-Helge Gantz. All rights reserved.
#
# Proprietary and confidential.
# Unauthorised use, copying, modification or distribution is prohibited.
# See the LICENSE file at the repository root for complete terms.

"""Thread-local HTTP client with bounded retries and connection reuse.

A separate session is created per worker thread because ``requests.Session`` is
not documented as thread-safe. Connection pooling and retry handling are still
shared within each worker's sequence of requests.
"""

from __future__ import annotations

import threading
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


_thread_local = threading.local()


def _new_session() -> requests.Session:
    """Create a session configured for transient read and server failures."""

    retry = Retry(
        total=2,
        connect=2,
        read=2,
        status=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=8,
        pool_maxsize=8,
    )
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def session() -> requests.Session:
    """Return the current worker thread's reusable HTTP session."""

    current = getattr(_thread_local, "session", None)
    if current is None:
        current = _new_session()
        _thread_local.session = current
    return current


def get(
    url: str,
    *,
    timeout: float = 45,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Perform a GET through the thread-local session."""

    return session().get(
        url,
        timeout=timeout,
        headers=headers,
        **kwargs,
    )
