"""
Module 1: Wireshark Traffic Capture Simulation.

Loads a pre-recorded set of "packets" from data/sample_packets.json and
returns them with a small security analysis summary.

In a real project you would use pyshark / scapy on a live PCAP file.
For an academic demo we ship a JSON file so the project runs on any
machine without Wireshark / npcap installed.
"""

import os
import json
from collections import Counter

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "sample_packets.json")


def load_packets() -> list[dict]:
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze(packets: list[dict] | None = None) -> dict:
    if packets is None:
        packets = load_packets()

    proto_count = Counter(p["protocol"] for p in packets)
    risk_count = Counter(p["risk"] for p in packets)
    cred_packets = [p for p in packets if p.get("credentials")]

    findings = []
    if proto_count.get("HTTP", 0) > 0:
        findings.append(
            "Plain HTTP traffic detected. Credentials and cookies are visible in clear text."
        )
    if cred_packets:
        findings.append(
            f"{len(cred_packets)} packet(s) leaked credentials or session tokens."
        )
    if any("OR '1'='1" in p["info"] for p in packets):
        findings.append("SQL-injection style payload observed in HTTP request.")
    if any("port scan" in p["info"].lower() for p in packets):
        findings.append("Port scanning behaviour detected from an external IP.")
    if any("malware" in p["info"].lower() for p in packets):
        findings.append("DNS query to suspicious domain (possible C2 / malware).")
    if proto_count.get("MQTT", 0) > 0 and any("UNLOCK" in p["info"] for p in packets):
        findings.append("Unauthenticated MQTT command attempting to unlock a door.")

    return {
        "packets": packets,
        "protocol_counts": dict(proto_count),
        "risk_counts": dict(risk_count),
        "credential_leaks": cred_packets,
        "findings": findings,
    }
