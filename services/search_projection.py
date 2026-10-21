"""Optional tenant-scoped OpenSearch projection. SQL is the source of truth."""

import base64
import hashlib
import json
import os
import ssl
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler
from securefi.local_http import NoRedirects
from urllib.parse import urlsplit
from securefi.platform.auth import initialise
from securefi.platform.store import Store


def project():
    endpoint = os.environ["SECUREFI_SEARCH_URL"].rstrip("/")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Search requires a TLS endpoint without embedded credentials")
    tenant = os.environ.get("SECUREFI_WORKER_TENANT", "fintech-lab")
    index = "securefi-events-" + hashlib.sha256(tenant.encode()).hexdigest()[:12]
    store = Store(os.environ.get("SECUREFI_DB", "data/platform.db"))
    context = ssl.create_default_context(cafile=os.environ.get("SECUREFI_SEARCH_CA"))
    opener = build_opener(
        ProxyHandler({}), HTTPSHandler(context=context), NoRedirects()
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic "
        + base64.b64encode(
            (
                os.environ["SECUREFI_SEARCH_USER"]
                + ":"
                + os.environ["SECUREFI_SEARCH_PASSWORD"]
            ).encode()
        ).decode(),
    }
    for event in store.list(tenant, "event"):
        request = Request(
            endpoint
            + "/"
            + index
            + "/_doc/"
            + hashlib.sha256(event["event_id"].encode()).hexdigest(),
            data=json.dumps(event).encode(),
            headers=headers,
            method="PUT",
        )
        with opener.open(request, timeout=10) as response:
            if response.status not in (200, 201):
                raise ValueError("Search projection failed")
    return {"index": index, "events": len(store.list(tenant, "event"))}


if __name__ == "__main__":
    print(json.dumps(project()))
