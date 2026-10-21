"""Opaque-token authentication for the sandbox; tokens bind role and tenant."""

import hashlib
import json
import os
import secrets
from pathlib import Path
from .app import ROLES


def initialise(path):
    path = Path(path)
    if path.exists():
        return json.loads(path.read_text()), {}
    path.parent.mkdir(parents=True, exist_ok=True)
    config = {"pseudonym_key": secrets.token_urlsafe(32), "principals": {}}
    display = {}
    for role in sorted(ROLES):
        token = secrets.token_urlsafe(32)
        config["principals"][hashlib.sha256(token.encode()).hexdigest()] = {
            "id": "lab-" + role,
            "role": role,
            "tenant": "fintech-lab",
        }
        display[role] = token
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)
    return config, display


def authenticate(config, header):
    if not isinstance(header, str) or not header.startswith("Bearer "):
        raise PermissionError("Bearer token required")
    supplied = hashlib.sha256(header[7:].encode()).hexdigest()
    actor = config["principals"].get(supplied)
    if actor is None:
        raise PermissionError("Invalid access token")
    return actor.copy()


def issue(path, role, tenant, identity):
    if role not in ROLES or not tenant or not identity:
        raise ValueError("Valid role, tenant and identity required")
    config, _ = initialise(path)
    token = secrets.token_urlsafe(32)
    config["principals"][hashlib.sha256(token.encode()).hexdigest()] = {
        "id": identity,
        "role": role,
        "tenant": tenant,
    }
    temp = Path(str(path) + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)
    os.replace(temp, path)
    return token
