"""Run in the optional-platform virtual environment after installing httpx."""

from pathlib import Path
import importlib, json, os, sys, tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unittest.mock import patch
from fastapi.testclient import TestClient
from securefi.platform.auth import initialise
from securefi.platform.synthetic import scenarios

with tempfile.TemporaryDirectory() as temp:
    auth = str(Path(temp) / "access.json")
    config, tokens = initialise(auth)
    with patch.dict(
        os.environ,
        {
            "SECUREFI_AUTH_FILE": auth,
            "SECUREFI_DB": str(Path(temp) / "test.db"),
            "SECUREFI_ALLOWED_HOSTS": "testserver",
        },
    ):
        module = importlib.import_module("services.asgi")
        with TestClient(module.app) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/api/state").status_code == 403
            header = {"Authorization": "Bearer " + tokens["analyst"]}
            result = client.post(
                "/api/events", headers=header, json={"events": scenarios()}
            )
            assert result.status_code == 200, result.text
            assert result.json()["alerts"] == 49
            result = client.get("/api/state", headers=header)
            assert result.json()["metrics"]["events"] == len(scenarios())
            executive = client.get(
                "/api/state", headers={"Authorization": "Bearer " + tokens["executive"]}
            ).json()
            assert "alerts" not in executive
            assert (
                client.post(
                    "/api/evidence",
                    headers={"Authorization": "Bearer " + tokens["ingestor"]},
                    json={},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/events",
                    headers=header,
                    json={"tenant": "other", "events": []},
                ).status_code
                == 403
            )
            assert (
                client.get(
                    "/api/state", headers={**header, "Origin": "https://evil.invalid"}
                ).status_code
                == 403
            )
    print(
        "PASS: ASGI ingestion, 49 detections, token/role/tenant/origin boundaries and executive privacy"
    )
