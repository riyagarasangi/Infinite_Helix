"""
Module 3: HTTP vs HTTPS Credential Sniffing.

Reads the static logs from data/http_logs.json and also demonstrates how
a password would look on the wire vs. how it is stored server-side
(as a salted SHA-256 hash).
"""

import os
import json
import hashlib
import secrets

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "http_logs.json")


def _load_logs() -> dict:
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def hash_password(password: str, salt: str | None = None) -> dict:
    """Return a salted SHA-256 hash for the given password."""
    if salt is None:
        salt = secrets.token_hex(8)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return {"salt": salt, "hash": digest, "algo": "sha256(salt + password)"}


def build_comparison(username: str = "cashier", password: str = "cash@123") -> dict:
    """Build the side-by-side comparison shown in the UI."""
    logs = _load_logs()

    http = logs["http_request"].copy()
    https = logs["https_request"].copy()

    # override sample credentials with whatever the user typed in the UI
    http["body_raw"] = f"username={username}&password={password}"
    https["server_stored_hash_demo"] = hash_password(password)

    return {
        "http": http,
        "https": https,
        "summary": [
            "HTTP sends the password in PLAIN TEXT over the network.",
            "HTTPS encrypts the entire HTTP body with TLS; sniffers see only ciphertext.",
            "A secure server never stores the password itself, only a salted hash.",
            "Even if the database is stolen, reversing a salted hash is computationally hard.",
        ],
    }
