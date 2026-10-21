"""ASGI transport for sandbox deployments; domain rules stay in platform.route."""

import json
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from starlette.concurrency import run_in_threadpool
from securefi.platform.auth import initialise, authenticate
from securefi.platform.product import Product as Platform
from securefi.platform.store import Store
from securefi.platform.server import route

config_path = os.environ.get("SECUREFI_AUTH_FILE", "data/access.json")
if not Path(config_path).exists():
    raise RuntimeError(
        "Initialise access.json using the CLI and mount it read-only; no container bootstrap tokens are generated"
    )
config, _ = initialise(config_path)
platform = Platform(
    Store(os.environ.get("SECUREFI_DB", "data/platform.db")), config["pseudonym_key"]
)
app = FastAPI(
    title="SecureFI API",
    version="2.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
static = Path(__file__).resolve().parents[1] / "securefi/platform/static"


@app.get("/healthz")
def health():
    return {"status": "ok", "profile": "synthetic-sandbox"}


@app.get("/")
def index():
    return FileResponse(static / "index.html")


@app.get("/app.js")
def javascript():
    return FileResponse(static / "app.js", media_type="text/javascript")


@app.get("/style.css")
def css():
    return FileResponse(static / "style.css", media_type="text/css")


@app.middleware("http")
async def headers(request, call_next):
    allowed = os.environ.get(
        "SECUREFI_ALLOWED_HOSTS", "127.0.0.1,localhost,securefi.local"
    ).split(",")
    host = request.headers.get("host", "").split(":", 1)[0]
    if request.url.path != "/healthz" and host not in allowed:
        return JSONResponse({"error": "Host rejected"}, 403)
    origin = request.headers.get("origin")
    if origin and origin != str(request.base_url).rstrip("/"):
        return JSONResponse({"error": "Origin rejected"}, 403)
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.api_route("/api/{path:path}", methods=["GET", "POST"])
async def api(path: str, request: Request):
    try:
        actor = authenticate(config, request.headers.get("authorization"))
        body = await request.body()
        if len(body) > 2 * 1024 * 1024:
            return JSONResponse({"error": "Body exceeds limit"}, 413)
        data = json.loads(body) if body else {}
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        result = await run_in_threadpool(
            route, platform, actor, request.method, "/api/" + path, data
        )
        return JSONResponse(result)
    except PermissionError as error:
        return JSONResponse({"error": str(error)}, 403)
    except (ValueError, KeyError, TypeError) as error:
        return JSONResponse({"error": str(error)}, 400)
