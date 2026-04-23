"""
Module 4: MQTT-based IoT Inventory Sensor Security Analysis.

We simulate sensors (fridge, shelf weight, entry door) publishing to an
MQTT broker. To keep the demo dependency-free we DO NOT require a real
broker running. Instead we generate representative messages in-memory.

If you do want to use a real broker, install Mosquitto and flip
USE_REAL_BROKER = True.
"""

import time
import random
import hmac
import hashlib

USE_REAL_BROKER = False  # flip to True if a local broker is running on 1883

SECRET_KEY = b"retail-store-shared-key-2026"  # shared HMAC secret (demo only)


# ---------- simulation helpers -------------------------------------------------

def _new_message(topic: str, payload: str) -> dict:
    return {
        "timestamp": time.strftime("%H:%M:%S"),
        "topic": topic,
        "payload": payload,
    }


def _sign(payload: str) -> str:
    return hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()[:16]


def insecure_feed(n: int = 6) -> list[dict]:
    """Plain MQTT: no auth, no TLS, no signature. Anyone can publish/read."""
    sensors = ["store/sensor/fridge", "store/sensor/shelf", "store/sensor/door"]
    out = []
    for _ in range(n):
        topic = random.choice(sensors)
        if "fridge" in topic:
            payload = f"temp={round(random.uniform(2, 8), 1)}C"
        elif "shelf" in topic:
            payload = f"weight={round(random.uniform(0, 20), 2)}kg"
        else:
            payload = random.choice(["LOCKED", "UNLOCKED", "UNLOCK_CMD"])
        out.append(_new_message(topic, payload))
    # sprinkle an obviously malicious message
    out.append(_new_message("store/sensor/door", "UNLOCK (spoofed by attacker)"))
    return out


def secure_feed(n: int = 6) -> list[dict]:
    """
    Secure MQTT demo:
      - Username/password auth (shown in metadata)
      - TLS (shown in metadata)
      - Each payload is HMAC-signed so the receiver can detect tampering.
    """
    base = insecure_feed(n)
    secured = []
    for m in base:
        # reject the spoofed attacker message in the secure feed
        if "spoofed" in m["payload"]:
            continue
        sig = _sign(m["payload"])
        secured.append({
            **m,
            "signature": sig,
            "tls": "TLSv1.3",
            "auth": "user=store-iot password=****",
        })
    return secured


def build_view() -> dict:
    return {
        "insecure": {
            "config": {
                "broker": "mqtt://192.168.1.40:1883",
                "auth": "NONE",
                "tls": "NONE",
            },
            "messages": insecure_feed(),
            "issues": [
                "No authentication - any device can publish/subscribe.",
                "No TLS - payloads travel in plain text and can be sniffed.",
                "No message signing - attacker can spoof an UNLOCK command.",
                "Default port 1883 exposed on the LAN.",
            ],
        },
        "secure": {
            "config": {
                "broker": "mqtts://192.168.1.40:8883",
                "auth": "username + password",
                "tls": "TLSv1.3",
                "integrity": "HMAC-SHA256 on every payload",
            },
            "messages": secure_feed(),
            "protections": [
                "Username/password restricts who may connect.",
                "TLS encrypts all traffic on the wire.",
                "HMAC signature proves the message came from a trusted sensor.",
                "ACLs (topic-level) limit which topics each device may publish to.",
            ],
        },
    }
