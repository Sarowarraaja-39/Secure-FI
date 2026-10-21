"""Real local EVM smoke test. Requires `npm ci --prefix blockchain`; not a mock."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from securefi.db import Database
from securefi.service import Service
from securefi.demo import seed
from securefi.integrations import Integrations
from securefi.blockchain import LedgerClient


def main():
    cli = ROOT / "blockchain/node_modules/hardhat/dist/src/cli.js"
    if not cli.is_file():
        raise SystemExit("Run npm ci --prefix blockchain first")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        log = open(Path(temp) / "chain.log", "w+")
        process = subprocess.Popen(
            ["node", str(cli), "node", "--hostname", "127.0.0.1", "--port", str(port)],
            cwd=ROOT / "blockchain",
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            with patch.dict(
                os.environ,
                {
                    "SECUREFI_CHAIN_ENABLED": "1",
                    "SECUREFI_CHAIN_RPC": f"http://127.0.0.1:{port}",
                },
            ):
                client = LedgerClient()
                ready = False
                for _ in range(100):
                    try:
                        client.check_chain()
                        ready = True
                        break
                    except ValueError:
                        if process.poll() is not None:
                            break
                        time.sleep(0.1)
                if not ready:
                    log.seek(0)
                    raise RuntimeError(log.read())
                service = Service(Database(Path(temp) / "test.db"))
                seed(service)
                app = Integrations(service)
                checkpoint = client.rpc("evm_snapshot")
                registry = app.deploy()
                assert app.deploy()["reused"]
                frozen = app.freeze()
                document = json.loads(app.get_snapshot(frozen["id"])["content"])
                assert not app.verify(frozen["id"])["verified"]
                anchored = app.anchor(frozen["id"])
                assert anchored["tx_hash"].startswith("0x")
                assert app.verify(frozen["id"], document)["verified"]
                assert app.anchor(frozen["id"])["already_recorded"]
                document["snapshot"]["findings"][0]["title"] = "Tampered"
                assert not app.verify(frozen["id"], document)["verified"]
                # The current application shares the same verified local-chain adapter.
                from securefi.platform.product import Product
                from securefi.platform.store import Store
                from securefi.platform.synthetic import scenarios
                from securefi.platform import evidence_ledger

                product = Product(
                    Store(Path(temp) / "product.db"),
                    "synthetic-evm-product-key-32characters",
                )
                analyst = {
                    "id": "analyst-one",
                    "role": "analyst",
                    "tenant": "local-chain",
                }
                approver = {
                    "id": "approver-two",
                    "role": "approver",
                    "tenant": "local-chain",
                }
                product.ingest(analyst, scenarios())
                product_registry = evidence_ledger.deploy(product, approver)
                assert evidence_ledger.deploy(product, approver)["reused"]
                report = product.report(analyst)
                assert not evidence_ledger.verify(product, analyst, report["id"])[
                    "verified"
                ]
                evidence_ledger.anchor(product, analyst, report["id"])
                assert evidence_ledger.verify(product, analyst, report["id"])[
                    "verified"
                ]
                assert evidence_ledger.anchor(product, analyst, report["id"])["tx_hash"]
                modified = json.loads(json.dumps(report["document"]))
                modified["scope"] = "Tampered export"
                assert not evidence_ledger.verify(
                    product, analyst, report["id"], modified
                )["verified"]
                assert product.store.verify_audit("local-chain")["valid"]
                # Direct EVM rejection checks, bypassing application guards.
                accounts = client.rpc("eth_accounts")
                selector = client.artifact["methods"]["anchor(bytes32)"]
                for account, digest in (
                    (accounts[1], "1" * 64),
                    (accounts[0], "0" * 64),
                    (accounts[0], frozen["digest"]),
                ):
                    rejected = False
                    try:
                        tx = client.rpc(
                            "eth_sendTransaction",
                            [
                                {
                                    "from": account,
                                    "to": registry["contract_address"],
                                    "data": "0x" + selector + digest,
                                    "gas": "0x30d40",
                                }
                            ],
                        )
                        client.receipt(tx)
                    except ValueError:
                        rejected = True
                    assert rejected, "Contract did not reject an invalid anchor"
                unknown = client.lookup(registry["contract_address"], "2" * 64)
                assert not unknown["recorded"]
                # A chain reset must not produce a false successful verification.
                client.rpc("evm_revert", [checkpoint])
                try:
                    app.verify(frozen["id"])
                except ValueError:
                    pass
                else:
                    raise AssertionError("Reset chain was not detected")
                print(
                    "PASS: application evidence workflow and real EVM deployment, recording, lookup, duplicate handling, tamper detection, owner restriction, zero-hash rejection and chain-reset detection."
                )
        finally:
            process.terminate()
            process.wait(timeout=10)
            log.close()


if __name__ == "__main__":
    main()
