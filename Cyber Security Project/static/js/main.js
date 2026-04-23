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
