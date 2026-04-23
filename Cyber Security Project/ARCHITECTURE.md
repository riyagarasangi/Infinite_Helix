# Architecture – Smart Retail Store Security Audit

This document describes how the 6 modules fit together, and where the
**message queue** (MQTT) sits in the system.

---

## 1. High-level system architecture

```mermaid
flowchart LR
    subgraph Client["Client (Browser)"]
        UI["Dashboard UI<br/>HTML + CSS + JS<br/>Chart.js"]
    end

    subgraph Server["Flask Web Server (app.py @ 127.0.0.1:5000)"]
        R1["/wireshark"]
        R2["/billing"]
        R3["/http-vs-https"]
        R4["/mqtt  +  /api/mqtt/refresh"]
        R5["/anomaly"]
        R6["/iam"]
    end

    subgraph Modules["Python modules/"]
        M1["wireshark_sim.py"]
        M2["billing_login.py"]
        M3["http_vs_https.py"]
        M4["mqtt_iot.py"]
        M5["ml_anomaly.py"]
        M6["cloud_iam.py"]
    end

    subgraph Storage["Data & Artifacts"]
        P1[("sample_packets.json")]
        P2[("store.db<br/>SQLite")]
        P3[("http_logs.json")]
        P4["IoT Sensor<br/>Simulation<br/>(in-memory)"]
        P5[("dataset.csv<br/>model.pkl")]
        P6[("iam_insecure.json<br/>iam_secure.json")]
    end

    UI -- HTTP GET/POST --> R1 & R2 & R3 & R4 & R5 & R6

    R1 --> M1 --> P1
    R2 --> M2 --> P2
    R3 --> M3 --> P3
    R4 --> M4 --> P4
    R5 --> M5 --> P5
    R6 --> M6 --> P6

    M5 -. loads .- T[train_model.py]
    T -. reads .- P5
```

---

## 2. Request / response flow (what happens on one click)

Example: user opens **/anomaly** and submits the "Predict" form.

```mermaid
sequenceDiagram
    participant Browser
    participant Flask as Flask (app.py)
    participant ML as modules/ml_anomaly.py
    participant Model as ml/model.pkl
    participant Chart as Chart.js (in browser)

    Browser->>Flask: POST /anomaly (packet_size, req_per_sec, ...)
    Flask->>ML: predict_one(record)
    ML->>Model: joblib.load()
    Model-->>ML: IsolationForest pipeline
    ML-->>Flask: {label: "anomaly", score: -0.14}
    Flask-->>Browser: Rendered anomaly.html + JSON for charts
    Browser->>Chart: render bar + doughnut charts
```

The flow for the other modules is identical, just with a different
Python module on the server side.

---

## 3. MQTT queue architecture (Module 4)

This is where the **queue** (publish/subscribe message broker) lives in
the project.

```mermaid
flowchart TB
    subgraph Sensors["IoT Sensors (simulated)"]
        S1["Fridge<br/>temp sensor"]
        S2["Shelf<br/>weight sensor"]
        S3["Entry door<br/>lock sensor"]
        A["Attacker device<br/>(spoofed UNLOCK)"]
    end

    subgraph Broker["MQTT Broker (queue)"]
        T1(["topic: store/sensor/fridge"])
        T2(["topic: store/sensor/shelf"])
        T3(["topic: store/sensor/door"])
    end

    subgraph Subs["Subscribers"]
        C1["Store<br/>controller"]
        C2["Dashboard UI<br/>/mqtt page"]
    end

    S1 -- PUBLISH --> T1
    S2 -- PUBLISH --> T2
    S3 -- PUBLISH --> T3
    A  -. spoofs .-> T3

    T1 -- SUBSCRIBE --> C1
    T2 -- SUBSCRIBE --> C1
    T3 -- SUBSCRIBE --> C1
    C1 -- render --> C2

    classDef bad fill:#ef4444,stroke:#991b1b,color:#fff;
    class A bad
```

### Insecure vs. secure queue

```mermaid
flowchart LR
    subgraph Insecure["Insecure MQTT (port 1883)"]
        I1["No auth"] --> I2["Plain TCP<br/>(sniffable)"] --> I3["Attacker can<br/>publish UNLOCK"]
    end

    subgraph Secure["Secure MQTT (port 8883)"]
        S1["user + password"] --> S2["TLS 1.3<br/>(encrypted)"] --> S3["HMAC-SHA256<br/>signature on every<br/>message"]
    end
```

---

## 4. One-page file layout

```
Browser (port 5000)
        │
        ▼
┌────────────────────────┐
│   Flask app.py         │
│   (routes + templates) │
└─────┬──────────────────┘
      │
      ├── modules/wireshark_sim.py ──► data/sample_packets.json
      ├── modules/billing_login.py ──► database/store.db  (SQLite)
      ├── modules/http_vs_https.py ──► data/http_logs.json + hashlib
      ├── modules/mqtt_iot.py      ──► in-memory pub/sub simulation
      ├── modules/ml_anomaly.py    ──► ml/model.pkl  ◄── train_model.py
      └── modules/cloud_iam.py     ──► data/iam_insecure.json
                                      data/iam_secure.json
```
