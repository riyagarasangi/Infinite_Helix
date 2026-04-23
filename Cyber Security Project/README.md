# Smart Retail Store Security Audit

A beginner-friendly, full-stack **academic cybersecurity project** that audits
a fictional smart retail store across six angles:

| # | Module                                      | What it shows                                                         |
|---|---------------------------------------------|-----------------------------------------------------------------------|
| 1 | Wireshark Traffic Capture Simulation        | Parse packet logs, find leaked credentials & attack patterns.          |
| 2 | SQL Injection on Billing Login System        | Vulnerable login vs. parameterized (prepared-statement) login.         |
| 3 | HTTP Credential Sniffing vs HTTPS Protection | Plain-text HTTP vs TLS-encrypted HTTPS, with salted hash on the server. |
| 4 | MQTT-based IoT Inventory Sensor Security     | Insecure MQTT vs. TLS + username/password + HMAC-signed payloads.      |
| 5 | Machine-Learning Anomaly Detection            | Isolation Forest trained on synthetic traffic, with charts & live predict. |
| 6 | Cloud IAM Security Review                    | Insecure (full-access) vs. least-privilege AWS IAM policies, with risk score. |

Everything is wrapped in a single **Flask** web app with a clean dashboard UI.

---

## Folder structure

```
Smart Retail Store Security Audit/
├── app.py                    # Flask entry point (routes for all 6 modules)
├── requirements.txt
├── README.md
│
├── database/
│   ├── init_db.py            # Creates SQLite DB and seeds users
│   └── store.db              # Generated after running init_db.py
│
├── modules/                  # One Python file per security module
│   ├── billing_login.py      # Module 2  - vulnerable & secure login
│   ├── http_vs_https.py      # Module 3  - HTTP vs HTTPS sniffing
│   ├── wireshark_sim.py      # Module 1  - packet analysis
│   ├── mqtt_iot.py           # Module 4  - MQTT IoT security
│   ├── ml_anomaly.py         # Module 5  - ML inference
│   └── cloud_iam.py          # Module 6  - IAM policy compare
│
├── ml/
│   ├── generate_dataset.py   # Produces ml/dataset.csv
│   ├── train_model.py        # Trains Isolation Forest -> ml/model.pkl
│   ├── dataset.csv           # Generated
│   └── model.pkl             # Generated
│
├── data/                     # Sample inputs loaded by the modules
│   ├── sample_packets.json
│   ├── http_logs.json
│   ├── iam_insecure.json
│   └── iam_secure.json
│
├── static/
│   ├── css/style.css
│   └── js/
│       ├── main.js
│       └── charts.js         # Chart.js graphs for the ML page
│
└── templates/                # Jinja2 HTML templates
    ├── base.html
    ├── dashboard.html
    ├── wireshark.html
    ├── billing.html
    ├── http_https.html
    ├── mqtt.html
    ├── anomaly.html
    ├── iam.html
    └── error.html
```

---

## Setup

You need **Python 3.10+** installed.

### 1. Create a virtual environment (recommended)

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialize the SQLite database

```bash
python database/init_db.py
```

This seeds three users:

| username | password  | role    |
|----------|-----------|---------|
| admin    | admin123  | admin   |
| cashier  | cash@123  | cashier |
| manager  | mgr2024   | manager |

### 4. Build the ML dataset and train the model

```bash
python ml/generate_dataset.py
python ml/train_model.py
```

This creates `ml/dataset.csv` and `ml/model.pkl`.

### 5. Run the web app

```bash
python app.py
```

Open <http://127.0.0.1:5000> in your browser. Pick any module from the sidebar.

---

## How each module works (simple explanation)

### 1. Wireshark Traffic Capture Simulation
`data/sample_packets.json` contains 10 pre-recorded "packets" with fields you
would see in Wireshark (source IP, destination IP, protocol, length, info).
`modules/wireshark_sim.py` counts protocols, spots HTTP credential leaks, port
scans, a SQL-injection-style URL, and a suspicious DNS query. The UI renders
the table and highlights high-risk rows in red.

### 2. SQL Injection on Billing Login System
Two functions live in `modules/billing_login.py`:

- `vulnerable_login()` builds SQL by **string concatenation** - type
  `admin' OR '1'='1 --` as the username and anything as the password to
  **bypass authentication** entirely.
- `secure_login()` uses `cur.execute(sql, (username, password))` - a
  **parameterized / prepared statement**. The same payload is now treated
  as a literal string and login fails.

The UI shows the exact SQL that ran, and the rows returned - so you can see
the injection bypass happening live.

### 3. HTTP vs HTTPS Credential Sniffing
`modules/http_vs_https.py` shows, side by side:

- An HTTP POST body with `username=...&password=...` in plain text.
- An HTTPS POST where the on-wire body is encrypted TLS ciphertext.
- A salted SHA-256 hash - the only thing a secure server should store.

### 4. MQTT IoT Inventory Security
`modules/mqtt_iot.py` simulates three sensors (fridge, shelf, door) publishing
messages. The insecure panel shows a broker with **no auth / no TLS** and
includes a spoofed `UNLOCK` command. The secure panel adds:

- `username + password` auth.
- `TLSv1.3` transport.
- An `HMAC-SHA256` signature on every payload so tampering is detected.

A **Refresh sensor feed** button calls `/api/mqtt/refresh` and re-renders the
messages.

> The project does not require a running MQTT broker. It uses an in-process
> simulation. If you do want to try a real broker, install
> [Mosquitto](https://mosquitto.org/) and flip `USE_REAL_BROKER = True`
> in `modules/mqtt_iot.py`.

### 5. Machine-Learning Anomaly Detection
Features: `packet_size`, `req_per_sec`, `failed_logins`, `unusual_port`.
`ml/generate_dataset.py` creates a synthetic dataset with ~400 normal records
and ~80 attack-like records (DDoS / brute force / port-scan patterns).
`ml/train_model.py` fits an `IsolationForest` inside a `StandardScaler`
pipeline and saves it. The page shows:

- Total / anomaly / TP / FP stats.
- Distribution of anomaly scores (bar chart).
- Normal vs. anomaly doughnut chart.
- A form to predict **your own** record.
- A sample table with each row coloured by prediction.

### 6. Cloud IAM Security Review
`data/iam_insecure.json` = `Effect: Allow, Action: *, Resource: *, Principal: *`.
`data/iam_secure.json` = scoped actions on one S3 bucket, a VPC condition,
and an explicit `Deny` on destructive actions. `modules/cloud_iam.py` scores
each policy and shows the two JSON files side by side with reasons.

---

## Notes

- This repository is for **education only**. Do not use any of the
  intentionally-vulnerable code in production.
- Passwords are stored in plain text in SQLite **on purpose**, so the SQL
  injection demo is clear. A real system must use a salted hash
  (`bcrypt`, `argon2`, etc.).
- `debug=True` is fine for class demos but never in production.

## Troubleshooting

| Problem | Fix |
|--------|-----|
| `Model not trained yet` on the Anomaly page | Run `python ml/generate_dataset.py` then `python ml/train_model.py`. |
| `no such table: users` on the Billing page | Run `python database/init_db.py`. |
| Charts don't show | Check your browser can reach `cdn.jsdelivr.net` (Chart.js). |
| Port 5000 already in use | Change `app.run(..., port=5000)` in `app.py`. |

Happy auditing!
