"""
Generate a synthetic network-traffic dataset for anomaly detection.

Columns:
    packet_size   - bytes per packet (normal: small-medium, attack: very large / tiny)
    req_per_sec   - requests per second from a single source
    failed_logins - failed login attempts in a 10s window
    unusual_port  - 0/1 flag: is the destination port unusual?
    label         - 0 = normal, 1 = attack (kept only for evaluation / UI)

Run:
    python ml/generate_dataset.py
"""

import os
import csv
import random

random.seed(42)

OUT = os.path.join(os.path.dirname(__file__), "dataset.csv")


def gen_normal(n=400):
    rows = []
    for _ in range(n):
        rows.append([
            random.randint(60, 1200),       # packet_size
            round(random.uniform(0.5, 8), 2),  # req_per_sec
            random.randint(0, 2),           # failed_logins
            0,                              # unusual_port
            0,
        ])
    return rows


def gen_attack(n=80):
    rows = []
    for _ in range(n):
        # mix of DDoS-like, brute force, and port-scan patterns
        pattern = random.choice(["ddos", "bruteforce", "portscan"])
        if pattern == "ddos":
            rows.append([
                random.randint(1400, 9000),
                round(random.uniform(40, 200), 2),
                random.randint(0, 1),
                random.choice([0, 1]),
                1,
            ])
        elif pattern == "bruteforce":
            rows.append([
                random.randint(80, 300),
                round(random.uniform(5, 25), 2),
                random.randint(15, 60),
                0,
                1,
            ])
        else:  # portscan
            rows.append([
                random.randint(40, 90),
                round(random.uniform(20, 90), 2),
                0,
                1,
                1,
            ])
    return rows


def main():
    rows = gen_normal() + gen_attack()
    random.shuffle(rows)
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["packet_size", "req_per_sec", "failed_logins", "unusual_port", "label"])
        w.writerows(rows)
    print(f"[OK] Wrote {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()
