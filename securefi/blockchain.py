"""Minimal Ethereum JSON-RPC client for the local evidence registry only."""

import json
import os
import re
import time
from pathlib import Path
from .local_http import local_url, post_json

ARTIFACT = Path(__file__).with_name("EvidenceRegistry.json")


def canonical(document):
    if not isinstance(document, dict):
        raise ValueError("Snapshot must be a JSON object")
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def digest_hex(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Expected a lowercase SHA-256 digest")
    return value


def address(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise ValueError("Invalid contract address")
    return value.lower()


class LedgerClient:
    def __init__(self, url=None, enabled=None):
        if enabled is None:
            enabled = os.environ.get("SECUREFI_CHAIN_ENABLED") == "1"
        if not enabled:
            raise ValueError(
                "Blockchain disabled. Start the local chain and set SECUREFI_CHAIN_ENABLED=1."
            )
        self.url = local_url(
            url or os.environ.get("SECUREFI_CHAIN_RPC", "http://127.0.0.1:8545")
        )
        self.artifact = json.loads(ARTIFACT.read_text())

    def rpc(self, method, params=None):
        result = post_json(
            self.url,
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []},
        )
        if (
            result.get("jsonrpc") != "2.0"
            or result.get("id") != 1
            or result.get("error")
            or "result" not in result
        ):
            raise ValueError(
                f"Local blockchain rejected {method}; check the node and transaction state"
            )
        return result["result"]

    def check_chain(self):
        raw = self.rpc("eth_chainId")
        if not isinstance(raw, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", raw):
            raise ValueError("Invalid chain ID response")
        value = int(raw, 16)
        if value != 31337:
            raise ValueError(
                "Only the disposable development chain ID 31337 is supported"
            )
        return value

    def receipt(self, tx):
        for _ in range(40):
            result = self.rpc("eth_getTransactionReceipt", [tx])
            if result:
                if not isinstance(result, dict):
                    raise ValueError("Invalid transaction receipt")
                if result.get("status") != "0x1":
                    raise ValueError("Blockchain transaction reverted")
                return result
            time.sleep(0.1)
        raise ValueError("Transaction confirmation timed out; verify before retrying")

    def account(self):
        self.check_chain()
        accounts = self.rpc("eth_accounts")
        if not isinstance(accounts, list) or not accounts:
            raise ValueError("No development account is available")
        return address(accounts[0])

    def check_contract(self, contract):
        self.check_chain()
        contract = address(contract)
        code = self.rpc("eth_getCode", [contract, "latest"])
        if (
            not isinstance(code, str)
            or code.lower() != self.artifact["deployedBytecode"].lower()
        ):
            raise ValueError(
                "Registry code is missing or different; the development chain may have restarted"
            )
        return contract

    def deploy(self):
        account = self.account()
        tx = self.rpc(
            "eth_sendTransaction",
            [{"from": account, "data": self.artifact["bytecode"], "gas": "0x1e8480"}],
        )
        result = self.receipt(tx)
        contract = self.check_contract(result.get("contractAddress"))
        return {
            "chain_id": 31337,
            "contract_address": contract,
            "tx_hash": tx,
            "owner": account,
        }

    def lookup(self, contract, digest):
        contract = self.check_contract(contract)
        data = "0x" + self.artifact["methods"]["verify(bytes32)"] + digest_hex(digest)
        raw = self.rpc("eth_call", [{"to": contract, "data": data}, "latest"])
        if not isinstance(raw, str) or not re.fullmatch(r"0x[0-9a-fA-F]{192}", raw):
            raise ValueError("Invalid registry response")
        words = [raw[2 + i : 2 + i + 64] for i in range(0, 192, 64)]
        return {
            "recorded": int(words[1], 16) > 0,
            "block_number": int(words[0], 16),
            "recorded_at": int(words[1], 16),
            "recorder": "0x" + words[2][-40:],
        }

    def anchor(self, contract, digest):
        contract = self.check_contract(contract)
        existing = self.lookup(contract, digest)
        if existing["recorded"]:
            return {**existing, "tx_hash": None, "already_recorded": True}
        data = "0x" + self.artifact["methods"]["anchor(bytes32)"] + digest_hex(digest)
        tx = self.rpc(
            "eth_sendTransaction",
            [{"from": self.account(), "to": contract, "data": data, "gas": "0x30d40"}],
        )
        self.receipt(tx)
        result = self.lookup(contract, digest)
        if not result["recorded"]:
            raise ValueError("Transaction completed without a readable evidence record")
        return {**result, "tx_hash": tx, "already_recorded": False}
