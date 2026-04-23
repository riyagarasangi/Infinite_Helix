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

from flask import Flask, render_template, request, jsonify, redirect, url_for
import time
import random

from modules import (
    billing_login,
    http_vs_https,
    wireshark_sim,
    mqtt_iot,
    ml_anomaly,
    cloud_iam,
    logger
)

app = Flask(__name__)

# Global System State
SECURITY_MODE = "vulnerable"  # "vulnerable" or "secure"
PEAK_RISK = 0

MODULES = [
    {"id": "wireshark",     "title": "1. Wireshark Traffic Simulation",
     "desc": "Analyze captured packets and find leaks.", "icon": "🔍",
     "url": "/wireshark"},
    {"id": "billing",       "title": "2. SQL Injection & Login",
     "desc": "Compare vulnerable vs. parameterized SQL login.", "icon": "🔑",
     "url": "/billing"},
    {"id": "http_vs_https", "title": "3. HTTP vs HTTPS Sniffing",
     "desc": "See why plain HTTP leaks passwords.", "icon": "🌐",
     "url": "/http-vs-https"},
    {"id": "mqtt",          "title": "4. MQTT IoT Security",
     "desc": "Insecure vs. TLS+HMAC MQTT for store sensors.", "icon": "📡",
     "url": "/mqtt"},
    {"id": "anomaly",       "title": "5. ML Anomaly Detection",
     "desc": "Isolation Forest flags attack-like traffic.", "icon": "🤖",
     "url": "/anomaly"},
    {"id": "iam",           "title": "6. Cloud IAM Review",
     "desc": "Compare full-access vs least-privilege IAM policies.", "icon": "☁️",
     "url": "/iam"},
]

# ----------------------------------------------------------------------------- 
# Core Logic & API
# -----------------------------------------------------------------------------

@app.context_processor
def inject_global_vars():
    return {
        "security_mode": SECURITY_MODE,
        "risk_score": calculate_risk_score(),
        "modules": MODULES
    }

def calculate_risk_score():
    global PEAK_RISK
    score = 0
    breakdown = []

    # 1. Base Security Mode
    if SECURITY_MODE == "vulnerable":
        score += 40
        breakdown.append({"factor": "System in Vulnerable Mode", "points": 40})
    else:
        breakdown.append({"factor": "System Protected (WAF Active)", "points": 0})
    
    # 2. Recent Anomalies
    recent_logs = logger.logger.get_logs()[:20]
    anomalies = [l for l in recent_logs if l['severity'] in ['warning', 'danger']]
    if anomalies:
        points = min(len(anomalies) * 5, 40)
        score += points
        breakdown.append({"factor": f"Detected Threats ({len(anomalies)})", "points": points})
    
    # 3. Weak IAM Policies (Simulated check)
    if SECURITY_MODE == "vulnerable":
        score += 20
        breakdown.append({"factor": "Weak Cloud IAM Policies", "points": 20})
    
    final_score = min(score, 100)
    if final_score > PEAK_RISK:
        PEAK_RISK = final_score
        
    return {
        "score": final_score,
        "peak": PEAK_RISK,
        "breakdown": breakdown,
        "level": "LOW" if final_score < 30 else "MEDIUM" if final_score < 70 else "HIGH",
        "health": "HEALTHY" if final_score < 25 else "AT RISK" if final_score < 60 else "CRITICAL"
    }

@app.route("/api/toggle-security")
def toggle_security():
    global SECURITY_MODE
    SECURITY_MODE = "secure" if SECURITY_MODE == "vulnerable" else "vulnerable"
    logger.logger.log("SYSTEM", f"Security mode changed to {SECURITY_MODE.upper()}", "info")
    return jsonify({"status": "success", "mode": SECURITY_MODE})

@app.route("/api/logs")
def get_logs():
    return jsonify(logger.logger.get_logs())

@app.route("/api/risk-score")
def get_risk_score():
    return jsonify(calculate_risk_score())

@app.route("/api/timeline")
def get_timeline():
    # Return only major security events
    major_types = ['ATTACK', 'DEFENSE', 'EXPLOIT', 'ML_ALERT']
    logs = logger.logger.get_logs()
    timeline = [l for l in logs if l['type'] in major_types or l['severity'] == 'danger']
    return jsonify(timeline[:15])

@app.route("/api/simulate-attack", methods=["POST"])
def simulate_attack():
    attack_type = request.json.get("type")
    
    if attack_type == "sql_injection":
        payload = request.json.get("custom_payload", "' OR '1'='1")
        logger.logger.log("ATTACK", f"SQL Injection attempt: {payload}", "danger", "sql", "attack")
        
        if SECURITY_MODE == "vulnerable":
            logger.logger.log("EXPLOIT", "Bypass Successful: Unauthorized DB Access", "danger", "sql", "blocked")
            return jsonify({"status": "vulnerable", "message": "Bypass Successful! Admin logged in.", "severity": "CRITICAL", "action": "MONITOR"})
        else:
            logger.logger.log("DEFENSE", "SQL Injection blocked by Parameterized Query", "success", "sql", "blocked")
            return jsonify({"status": "secure", "message": "Attack Blocked by WAF/Secure Coding.", "severity": "LOW", "action": "BLOCK"})
            
    elif attack_type == "brute_force":
        logger.logger.log("ATTACK", "Brute force burst detected from 192.168.1.50", "warning", "system", "detection")
        if SECURITY_MODE == "vulnerable":
            logger.logger.log("EXPLOIT", "Account 'admin' compromised after 50 attempts", "danger", "system", "attack")
            return jsonify({"status": "vulnerable", "message": "Account compromised due to no rate limiting.", "severity": "HIGH", "action": "ALERT"})
        else:
            logger.logger.log("DEFENSE", "Brute force blocked: IP 192.168.1.50 blacklisted.", "success", "system", "defense")
            return jsonify({"status": "secure", "message": "Attack Blocked: Rate limiting active.", "severity": "LOW", "action": "BLOCK"})

    elif attack_type == "mqtt_malicious":
        logger.logger.log("ATTACK", "Unauthorized MQTT Command: 'UNLOCK DOOR'", "danger", "iot", "attack")
        if SECURITY_MODE == "vulnerable":
            logger.logger.log("EXPLOIT", "Security Breach: Door Unlocked!", "danger", "iot", "attack")
            return jsonify({"status": "vulnerable", "message": "Door Unlocked! No HMAC verification.", "severity": "CRITICAL", "action": "MONITOR"})
        else:
            logger.logger.log("DEFENSE", "MQTT Command Rejected: Invalid HMAC Signature.", "success", "iot", "blocked")
            return jsonify({"status": "secure", "message": "Attack Blocked: Secure MQTT active.", "severity": "LOW", "action": "BLOCK"})

    return jsonify({"status": "unknown"})

@app.route("/api/reset")
def reset_system():
    global SECURITY_MODE, PEAK_RISK
    SECURITY_MODE = "vulnerable"
    PEAK_RISK = 0
    logger.logger.clear()
    logger.logger.log("SYSTEM", "System reset to default state.", "info")
    return jsonify({"status": "success"})

# ----------------------------------------------------------------------------- 
# Pages
# -----------------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard")

@app.route("/live-logs")
def live_logs_view():
    return render_template("live_logs.html", active="live_logs")

@app.route("/wireshark")
def wireshark():
    data = wireshark_sim.analyze()
    return render_template("wireshark.html", data=data, active="wireshark")

@app.route("/billing", methods=["GET", "POST"])
def billing():
    result = None
    username = password = ""
    mode = SECURITY_MODE # Default to global mode
    
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Use provided mode or fall back to global
        mode = request.form.get("mode", SECURITY_MODE)
        
        if mode == "secure":
            result = billing_login.secure_login(username, password)
            if result and result.get("success"):
                logger.logger.log("LOGIN", f"Secure login success for user: {username}", "success")
            else:
                logger.logger.log("LOGIN", f"Secure login failed for user: {username}", "info")
        else:
            result = billing_login.vulnerable_login(username, password)
            if result and result.get("success"):
                if "' OR" in username or "' OR" in password:
                    logger.logger.log("EXPLOIT", f"SQL Injection bypass success for user: {username}", "danger")
                else:
                    logger.logger.log("LOGIN", f"Vulnerable login success for user: {username}", "info")
            else:
                logger.logger.log("LOGIN", f"Vulnerable login failed for user: {username}", "info")
                
    return render_template(
        "billing.html",
        result=result,
        username=username,
        password=password,
        mode=mode,
        active="billing",
    )

@app.route("/http-vs-https", methods=["GET", "POST"])
def http_vs_https_view():
    username = request.values.get("username", "cashier")
    password = request.values.get("password", "cash@123")
    data = http_vs_https.build_comparison(username, password)
    
    if request.method == "POST":
        logger.logger.log("TRAFFIC", f"Login attempt over {'HTTPS' if SECURITY_MODE == 'secure' else 'HTTP'}", "warning" if SECURITY_MODE == 'vulnerable' else 'info')
        
    return render_template(
        "http_https.html",
        data=data,
        username=username,
        password=password,
        active="http_vs_https",
    )

@app.route("/mqtt")
def mqtt_view():
    data = mqtt_iot.build_view()
    return render_template("mqtt.html", data=data, active="mqtt")

@app.route("/api/mqtt/refresh")
def mqtt_refresh():
    return jsonify(mqtt_iot.build_view())

@app.route("/anomaly", methods=["GET", "POST"])
def anomaly_view():
    try:
        dataset_view = ml_anomaly.evaluate_dataset()
    except FileNotFoundError:
        return render_template("error.html", message="ML model or dataset not found. Please run training scripts.", active="anomaly")

    one_result = None
    if request.method == "POST":
        record = {
            "packet_size":   float(request.form.get("packet_size", 0)),
            "req_per_sec":   float(request.form.get("req_per_sec", 0)),
            "failed_logins": float(request.form.get("failed_logins", 0)),
            "unusual_port":  float(request.form.get("unusual_port", 0)),
        }
        one_result = ml_anomaly.predict_one(record)
        if one_result["is_anomaly"]:
            logger.logger.log("ML_ALERT", f"Anomaly detected! Score: {one_result['score']}", "danger")
        else:
            logger.logger.log("ML_INFO", "Traffic pattern analyzed: Normal", "success")

    return render_template(
        "anomaly.html",
        data=dataset_view,
        one_result=one_result,
        active="anomaly",
    )

@app.route("/iam")
def iam_view():
    data = cloud_iam.compare()
    return render_template("iam.html", data=data, active="iam")

if __name__ == "__main__":
    logger.logger.log("SYSTEM", "Smart Retail Security Audit System Started", "info")
    app.run(host="127.0.0.1", port=5000, debug=True)

