/**
 * SOC ENGINE - Advanced Security Logic
 * Handles real-time pipeline, timeline, and full scenario simulations.
 */

const PIPELINE_STEPS = {
    1: "Attack Initiated",
    2: "Suspicious Pattern Detected",
    3: "Analyzing Attack Vector...",
    4: "Deploying Countermeasures",
    5: "Threat Mitigated & Blocked"
};

async function runAttackPipeline(attackType, customPayload = null) {
    const overlay = document.getElementById('pipeline-overlay');
    const statusText = document.getElementById('pipeline-status');
    
    // Reset steps
    document.querySelectorAll('.p-step').forEach(s => s.classList.remove('active', 'completed'));
    overlay.classList.remove('hidden');
    
    for (let step = 1; step <= 5; step++) {
        const stepEl = document.getElementById(`p-step-${step}`);
        stepEl.classList.add('active');
        statusText.innerText = PIPELINE_STEPS[step];
        
        // Wait for effect
        await new Promise(r => setTimeout(r, 800 + Math.random() * 500));
        
        if (step < 5) {
            stepEl.classList.remove('active');
            stepEl.classList.add('completed');
        }

        // Mid-way: actual backend call
        if (step === 3) {
            const response = await fetch('/api/simulate-attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: attackType, custom_payload: customPayload })
            });
            const data = await response.json();
            
            // Adjust step 5 text based on result
            if (data.status === "vulnerable") {
                PIPELINE_STEPS[5] = "ATTACK SUCCESSFUL (System Vulnerable)";
                document.getElementById('p-step-5').querySelector('.p-icon').innerText = "💀";
            } else {
                PIPELINE_STEPS[5] = "THREAT BLOCKED (Defense Active)";
                document.getElementById('p-step-5').querySelector('.p-icon').innerText = "🛑";
            }
        }
    }
    
    updateTimeline();
    updateRiskScore();
    
    setTimeout(() => {
        // overlay.classList.add('hidden'); // Optional: keep open for review
    }, 2000);
}

function closePipeline() {
    document.getElementById('pipeline-overlay').classList.add('hidden');
}

async function updateTimeline() {
    const timelineContainer = document.getElementById('attack-timeline');
    if (!timelineContainer) return;

    const response = await fetch('/api/timeline');
    const events = await response.json();
    
    timelineContainer.innerHTML = '';
    events.forEach(ev => {
        const item = document.createElement('div');
        item.className = `timeline-item stage-${ev.stage}`;
        item.innerHTML = `
            <div class="t-time">${ev.timestamp}</div>
            <div class="t-content">
                <div class="t-title">${ev.type} - ${ev.module.toUpperCase()}</div>
                <div class="t-msg">${ev.message}</div>
            </div>
        `;
        timelineContainer.appendChild(item);
    });
}

async function runFullScenario() {
    showToast("Initiating Full System Stress Test...", "warning");
    
    const attacks = ['sql_injection', 'brute_force', 'mqtt_malicious'];
    for (const a of attacks) {
        await runAttackPipeline(a);
        await new Promise(r => setTimeout(r, 2000));
    }
    
    showToast("Full Scenario Simulation Complete", "success");
}

// Global update for Risk Score with breakdown
async function updateRiskScore() {
    const response = await fetch('/api/risk-score');
    const data = await response.json();
    
    const scoreEl = document.getElementById('global-risk-score');
    const barEl = document.getElementById('risk-bar-fill');
    const healthEl = document.getElementById('health-indicator');
    const breakdownEl = document.getElementById('risk-breakdown');
    
    if (scoreEl) {
        scoreEl.innerText = data.score;
        scoreEl.className = `risk-${data.level.toLowerCase()}`;
    }
    if (barEl) {
        barEl.style.width = `${data.score}%`;
        barEl.className = `risk-bar-fill risk-${data.level.toLowerCase()}`;
    }
    if (healthEl) {
        healthEl.className = `health-indicator health-${data.health.toLowerCase().replace(' ', '-')}`;
        healthEl.querySelector('.health-text').innerText = `SYSTEM ${data.health}`;
    }
    if (breakdownEl) {
        breakdownEl.innerHTML = data.breakdown.map(item => `
            <div class="breakdown-item"><span>${item.factor}</span><b>+${item.points}</b></div>
        `).join('');
    }
}

// Initial update
document.addEventListener('DOMContentLoaded', () => {
    updateTimeline();
    setInterval(updateTimeline, 5000);
});
