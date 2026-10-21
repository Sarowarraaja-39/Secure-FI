"""Bounded loopback HTTP clients for opt-in local integrations."""

import json
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import URLError


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def local_url(value):
    try:
        parts = urlsplit(value)
        port = parts.port
    except (ValueError, TypeError):
        raise ValueError(
            "Integration URL must be an HTTP IPv4 loopback address"
        ) from None
    if (
        parts.scheme != "http"
        or parts.hostname != "127.0.0.1"
        or not port
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
    ):
        raise ValueError("Use http://127.0.0.1:PORT for local integrations")
    return f"http://127.0.0.1:{port}"


def post_json(url, payload, timeout=10, limit=131072):
    body = json.dumps(payload, allow_nan=False).encode()
    request = Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    # Never forward local evidence through proxy environment variables or redirects.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Integration response exceeded its size limit")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("Integration response must be an object")
        return result
    except (URLError, TimeoutError, OSError, UnicodeError, ValueError, RecursionError):
        raise ValueError(
            "Local integration unavailable or returned an invalid response"
        ) from None
