"""
Smart Retail Store Security Audit - main Flask app.

Run:
    1) pip install -r requirements.txt
    2) python database/init_db.py
    3) python ml/generate_dataset.py
    4) python ml/train_model.py
    5) python app.py
    6) open http://127.0.0.1:5000

Routes:
    /                -> Dashboard
    /wireshark       -> Module 1 : Traffic capture simulation
    /billing         -> Module 2 : SQL Injection demo
    /http-vs-https   -> Module 3 : HTTP vs HTTPS sniffing
    /mqtt            -> Module 4 : IoT / MQTT security
    /anomaly         -> Module 5 : ML anomaly detection
    /iam             -> Module 6 : Cloud IAM review
"""

from flask import Flask, render_template, request, jsonify

from modules import (
    billing_login,
    http_vs_https,
    wireshark_sim,
    mqtt_iot,
    ml_anomaly,
    cloud_iam,
)

app = Flask(__name__)

MODULES = [
    {"id": "wireshark",     "title": "1. Wireshark Traffic Simulation",
     "desc": "Analyze captured packets and find leaks.", "icon": "W",
     "url": "/wireshark"},
    {"id": "billing",       "title": "2. SQL Injection on Billing Login",
     "desc": "Compare vulnerable vs. parameterized SQL login.", "icon": "S",
     "url": "/billing"},
    {"id": "http_vs_https", "title": "3. HTTP vs HTTPS Sniffing",
     "desc": "See why plain HTTP leaks passwords.", "icon": "H",
     "url": "/http-vs-https"},
    {"id": "mqtt",          "title": "4. MQTT IoT Inventory Security",
     "desc": "Insecure vs. TLS+HMAC MQTT for store sensors.", "icon": "M",
     "url": "/mqtt"},
    {"id": "anomaly",       "title": "5. ML Anomaly Detection",
     "desc": "Isolation Forest flags attack-like traffic.", "icon": "A",
     "url": "/anomaly"},
    {"id": "iam",           "title": "6. Cloud IAM Review",
     "desc": "Compare full-access vs least-privilege IAM policies.", "icon": "I",
     "url": "/iam"},
]


# ----------------------------------------------------------------------------- 
# Dashboard
# -----------------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html", modules=MODULES)


# -----------------------------------------------------------------------------
# Module 1 : Wireshark
# -----------------------------------------------------------------------------
@app.route("/wireshark")
def wireshark():
    data = wireshark_sim.analyze()
    return render_template("wireshark.html", data=data, modules=MODULES, active="wireshark")


# -----------------------------------------------------------------------------
# Module 2 : SQL Injection demo
# -----------------------------------------------------------------------------
@app.route("/billing", methods=["GET", "POST"])
def billing():
    result = None
    username = password = ""
    mode = "vulnerable"
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        mode = request.form.get("mode", "vulnerable")
        if mode == "secure":
            result = billing_login.secure_login(username, password)
        else:
            result = billing_login.vulnerable_login(username, password)
    return render_template(
        "billing.html",
        result=result,
        username=username,
        password=password,
        mode=mode,
        modules=MODULES,
        active="billing",
    )


# -----------------------------------------------------------------------------
# Module 3 : HTTP vs HTTPS
# -----------------------------------------------------------------------------
@app.route("/http-vs-https", methods=["GET", "POST"])
def http_vs_https_view():
    username = request.values.get("username", "cashier")
    password = request.values.get("password", "cash@123")
    data = http_vs_https.build_comparison(username, password)
    return render_template(
        "http_https.html",
        data=data,
        username=username,
        password=password,
        modules=MODULES,
        active="http_vs_https",
    )


# -----------------------------------------------------------------------------
# Module 4 : MQTT
# -----------------------------------------------------------------------------
@app.route("/mqtt")
def mqtt_view():
    data = mqtt_iot.build_view()
    return render_template("mqtt.html", data=data, modules=MODULES, active="mqtt")


@app.route("/api/mqtt/refresh")
def mqtt_refresh():
    return jsonify(mqtt_iot.build_view())


# -----------------------------------------------------------------------------
# Module 5 : ML anomaly detection
# -----------------------------------------------------------------------------
@app.route("/anomaly", methods=["GET", "POST"])
def anomaly_view():
    try:
        dataset_view = ml_anomaly.evaluate_dataset()
    except FileNotFoundError as e:
        return render_template(
            "error.html", message=str(e), modules=MODULES, active="anomaly"
        )

    one_result = None
    if request.method == "POST":
        record = {
            "packet_size":   request.form.get("packet_size", 0),
            "req_per_sec":   request.form.get("req_per_sec", 0),
            "failed_logins": request.form.get("failed_logins", 0),
            "unusual_port":  request.form.get("unusual_port", 0),
        }
        one_result = ml_anomaly.predict_one(record)

    return render_template(
        "anomaly.html",
        data=dataset_view,
        one_result=one_result,
        modules=MODULES,
        active="anomaly",
    )


# -----------------------------------------------------------------------------
# Module 6 : IAM
# -----------------------------------------------------------------------------
@app.route("/iam")
def iam_view():
    data = cloud_iam.compare()
    return render_template("iam.html", data=data, modules=MODULES, active="iam")


if __name__ == "__main__":
    # debug=True is fine for a class demo; turn off in production.
    app.run(host="127.0.0.1", port=5000, debug=True)
