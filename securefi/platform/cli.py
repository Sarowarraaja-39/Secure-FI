"""Platform command-line entry point: python -m securefi lab ..."""

import argparse
import json
import os
import sys
from pathlib import Path
from .auth import initialise, issue
from .store import Store
from .product import Product as Platform
from .synthetic import scenarios, ml_dataset
from .ml import train
from .server import make_server


def main(argv=None):
    p = argparse.ArgumentParser(description="SecureFI security operations application")
    p.add_argument("--db", default="data/platform.db")
    p.add_argument("--auth", default="data/access.json")
    sub = p.add_subparsers(dest="command", required=True)
    for cmd in ["init", "demo", "evaluate", "train", "verify-audit", "worker"]:
        sub.add_parser(cmd)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8765)
    report = sub.add_parser("report")
    report.add_argument("--output", default="artifacts/compliance-report.json")
    imp = sub.add_parser("ingest")
    imp.add_argument("file")
    imp.add_argument("--queued", action="store_true")
    token = sub.add_parser("token")
    token.add_argument("--role", required=True)
    token.add_argument("--tenant", default="fintech-lab")
    token.add_argument("--identity", required=True)
    args = p.parse_args(argv)
    try:
        config, tokens = initialise(args.auth)
        if tokens:
            print(
                "Save these workspace tokens; they are displayed only at initialisation:\n"
                + json.dumps(tokens, indent=2),
                flush=True,
            )
        app = Platform(Store(args.db), config["pseudonym_key"])
        actor = {"id": "cli-operator", "role": "admin", "tenant": "fintech-lab"}
        if args.command == "token":
            print(issue(args.auth, args.role, args.tenant, args.identity))
            return 0
        if args.command == "init":
            result = {"status": "ready"}
        elif args.command == "demo":
            result = app.ingest(actor, scenarios())
        elif args.command == "ingest":
            path = Path(args.file)
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("Input exceeds 2 MiB")
            result = app.ingest(actor, json.loads(path.read_text()), args.queued)
        elif args.command == "worker":
            result = app.work(actor, 500)
        elif args.command == "train":
            result = train(app, actor, ml_dataset())
        elif args.command == "verify-audit":
            result = app.store.verify_audit(actor["tenant"])
        elif args.command == "evaluate":
            from .evaluate import evaluate

            result = evaluate()
        elif args.command == "report":
            result = app.report(actor)
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("x") as f:
                json.dump(result, f, indent=2)
            result = {"path": str(out), "sha256": result["digest"]}
        else:
            server = make_server(app, config, args.port)
            print(f"SecureFI: http://127.0.0.1:{server.server_port}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, PermissionError) as error:
        print("SecureFI: " + str(error), file=sys.stderr)
        return 1
