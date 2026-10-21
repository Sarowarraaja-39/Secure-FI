"""Run with python -m securefi. No third-party runtime dependencies."""

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from .db import Database
from .integrations import Integrations
from .service import Service
from .demo import seed
from .server import make_server, MAX_BODY


def main(argv=None):
    incoming = sys.argv[1:] if argv is None else argv
    if incoming and incoming[0] in ("lab", "app"):
        from .platform.cli import main as platform_main

        return platform_main(incoming[1:])
    parser = argparse.ArgumentParser(description="SecureFI local security workbench")
    parser.add_argument(
        "--db",
        default="data/securefi.db",
        help="SQLite path (default: data/securefi.db)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialise an empty database")
    commands.add_parser("demo", help="Load synthetic data into an empty database")
    serve = commands.add_parser("serve", help="Start the loopback dashboard")
    serve.add_argument("--port", type=int, default=8765)
    create = commands.add_parser("asset", help="Register an asset")
    create.add_argument("name")
    create.add_argument("--owner", required=True)
    create.add_argument("--criticality", type=int, choices=range(1, 6), default=3)
    create.add_argument("--exposed", action="store_true")
    create.add_argument(
        "--environment", choices=("production", "staging", "test"), default="test"
    )
    ingest = commands.add_parser("import", help="Import a scanner report")
    ingest.add_argument(
        "format", choices=("normalized", "sarif", "cyclonedx", "cloud", "events")
    )
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--asset", type=int, required=True)
    export = commands.add_parser("export", help="Export a JSON evidence snapshot")
    export.add_argument("file", type=Path)
    gate = commands.add_parser("gate", help="Exit 2 if active risk meets the threshold")
    gate.add_argument("--threshold", type=int, default=80)
    ai_cmd = commands.add_parser("ai", help="Generate an investigation draft")
    ai_cmd.add_argument("--finding", type=int, required=True)
    ledger = commands.add_parser("ledger", help="Local evidence registry")
    ledger.add_argument(
        "action", choices=("snapshot", "deploy", "anchor", "verify", "export", "reset")
    )
    ledger.add_argument("--id", type=int)
    ledger.add_argument("--file", type=Path)
    ledger.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        service = Service(Database(args.db))
        if args.command == "serve":
            server, token = make_server(
                service, args.port, os.environ.get("SECUREFI_TOKEN")
            )
            print(
                f"SecureFI: http://127.0.0.1:{server.server_port}\nAccess token: {token}\nLocal single-user mode. Press Ctrl+C to stop.",
                flush=True,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\nServer stopped.")
            finally:
                server.server_close()
            return 0
        if args.command == "ai":
            result = Integrations(service).generate(args.finding)
        elif args.command == "ledger":
            integration = Integrations(service)
            if args.action == "snapshot":
                result = integration.freeze()
            elif args.action == "deploy":
                result = integration.deploy()
            elif args.action == "anchor":
                result = integration.anchor(args.id)
            elif args.action == "verify":
                if args.file and args.file.stat().st_size > MAX_BODY:
                    raise ValueError("Verification files must not exceed 2 MiB")
                document = json.loads(args.file.read_text()) if args.file else None
                result = integration.verify(args.id, document)
                print(json.dumps(result, indent=2))
                return 0 if result["verified"] else 2
            elif args.action == "export":
                if not args.file:
                    raise ValueError("ledger export requires --file")
                row = integration.get_snapshot(args.id)
                with args.file.open("x", encoding="utf-8") as output:
                    output.write(row["content"])
                result = {"exported": str(args.file), "digest": row["digest"]}
            else:
                result = integration.reset_registry(args.confirm)
        elif args.command == "init":
            result = {"database": args.db, "status": "ready"}
        elif args.command == "demo":
            result = seed(service)
        elif args.command == "asset":
            result = service.create_asset(
                dict(
                    name=args.name,
                    owner=args.owner,
                    criticality=args.criticality,
                    internet_exposed=args.exposed,
                    environment=args.environment,
                ),
                "CLI analyst",
            )
        elif args.command == "import":
            if args.file.stat().st_size > MAX_BODY:
                raise ValueError("Import files must not exceed 2 MiB")
            report = json.loads(args.file.read_text(encoding="utf-8"))
            result = service.ingest(args.asset, args.format, report, "CLI analyst")
        elif args.command == "export":
            # Exclusive create avoids silently overwriting an existing export.
            with args.file.open("x", encoding="utf-8") as output:
                json.dump(service.snapshot(), output, indent=2)
            result = {"exported": str(args.file)}
        elif args.command == "gate":
            result = service.gate(args.threshold)
            print(json.dumps(result, indent=2))
            return 0 if result["passed"] else 2
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, sqlite3.Error, RecursionError) as exc:
        print(f"SecureFI: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
