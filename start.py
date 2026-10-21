"""Start SecureFI locally with one command: python start.py [--demo]."""

import argparse
from securefi.platform.auth import initialise
from securefi.platform.store import Store
from securefi.platform.product import Product
from securefi.platform.server import make_server
from securefi.platform.synthetic import scenarios


def main():
    parser = argparse.ArgumentParser(description="Start SecureFI security operations")
    parser.add_argument(
        "--demo", action="store_true", help="Load the included sample telemetry"
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    config, tokens = initialise("data/access.json")
    app = Product(Store("data/platform.db"), config["pseudonym_key"])
    if tokens:
        print("Save these access tokens; they are displayed only once:", flush=True)
        for role, token in tokens.items():
            print(f"{role}: {token}", flush=True)
    if args.demo:
        result = app.ingest(
            {"id": "sample-loader", "role": "admin", "tenant": "fintech-lab"},
            scenarios(),
        )
        print(
            f"Sample telemetry: {result['accepted']} accepted, {result['duplicates']} duplicates.",
            flush=True,
        )
    server = make_server(app, config, args.port)
    print(f"SecureFI is running at http://127.0.0.1:{server.server_port}", flush=True)
    print(
        "Use the analyst token to investigate, or admin for workspace administration.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSecureFI stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
