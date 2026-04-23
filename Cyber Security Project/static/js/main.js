/* Helper used by mqtt.html to re-render tables after /api/mqtt/refresh */
function renderMqttTables(json) {
  const ins = document.querySelector("table.mqtt-insecure tbody");
  const sec = document.querySelector("table.mqtt-secure tbody");
  if (ins) {
    ins.innerHTML = json.insecure.messages
      .map(m => `<tr><td>${m.timestamp}</td><td>${m.topic}</td><td class="mono">${escapeHtml(m.payload)}</td></tr>`)
      .join("");
  }
  if (sec) {
    sec.innerHTML = json.secure.messages
      .map(m => `<tr><td>${m.timestamp}</td><td>${m.topic}</td><td class="mono">${escapeHtml(m.payload)}</td><td class="mono">${m.signature}</td></tr>`)
      .join("");
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// --- SOC Dashboard Logic ---

function showToast(message, type = "info") {
    let bgColor = "#3b82f6"; // info
    if (type === "success") bgColor = "#10b981";
    if (type === "warning") bgColor = "#f59e0b";
    if (type === "danger") bgColor = "#ef4444";

    Toastify({
        text: message,
        duration: 4000,
        gravity: "top",
        position: "right",
        backgroundColor: bgColor,
        stopOnFocus: true,
    }).showToast();
}

async function toggleSecurity() {
    const response = await fetch('/api/toggle-security');
    const data = await response.json();
    
    if (data.status === "success") {
        document.body.className = `mode-${data.mode}`;
        showToast(`Security Mode: ${data.mode.toUpperCase()}`, data.mode === "secure" ? "success" : "warning");
        
        // Update labels
        document.querySelectorAll('.toggle-label').forEach(el => {
            el.classList.toggle('active', el.innerText.toLowerCase() === data.mode);
        });

        // Trigger UI refresh if needed
        setTimeout(() => window.location.reload(), 1000);
    }
}

async function simulateAttack(type) {
    showToast(`Initiating Simulation: ${type.replace('_', ' ').toUpperCase()}`, "info");
    
    const response = await fetch('/api/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: type })
    });
    
    const data = await response.json();
    
    setTimeout(() => {
        showToast(data.message, data.status === "vulnerable" ? "danger" : "success");
        updateRiskScore();
    }, 800);
}

async function updateRiskScore() {
    const response = await fetch('/api/risk-score');
    const data = await response.json();
    
    const scoreEl = document.getElementById('global-risk-score');
    const barEl = document.getElementById('risk-bar-fill');
    
    if (scoreEl && barEl) {
        scoreEl.innerText = data.score;
        barEl.style.width = `${data.score}%`;
        
        // Update colors
        let statusClass = 'low';
        if (data.score >= 30) statusClass = 'medium';
        if (data.score >= 70) statusClass = 'high';
        
        scoreEl.className = `risk-${statusClass}`;
        barEl.className = `risk-bar-fill risk-${statusClass}`;
    }
}

async function resetSystem() {
    if (confirm("Reset system state and logs?")) {
        await fetch('/api/reset');
        showToast("System Reset Complete", "success");
        setTimeout(() => window.location.href = "/", 1000);
    }
}

// Manual Test for SQL Injection
async function testPayload() {
    const payload = document.getElementById('test-payload').value;
    if (!payload) return showToast("Please enter a payload", "warning");

    showToast("Testing payload...", "info");
    
    // We can just submit the billing form programmatically or simulate via API
    // For this demo, let's use the simulation logic
    const response = await fetch('/api/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'sql_injection', custom_payload: payload })
    });
    const data = await response.json();
    showToast(data.message, data.status === "vulnerable" ? "danger" : "success");
}

// Update risk score periodically
setInterval(updateRiskScore, 5000);
updateRiskScore();

