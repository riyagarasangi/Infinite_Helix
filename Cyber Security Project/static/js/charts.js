/* Chart.js renderings for the anomaly detection page. */

(function () {
  const barCtx = document.getElementById("scoreChart");
  const pieCtx = document.getElementById("pieChart");
  if (!barCtx || typeof SCORE_BINS === "undefined") return;

  new Chart(barCtx, {
    type: "bar",
    data: {
      labels: SCORE_BINS.map(b => b.range),
      datasets: [{
        label: "# records",
        data: SCORE_BINS.map(b => b.count),
        backgroundColor: "rgba(59,130,246,0.6)",
        borderColor: "rgba(59,130,246,1)",
        borderWidth: 1,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: "#e2e8f0" } } },
      scales: {
        x: { ticks: { color: "#94a3b8", maxRotation: 60, minRotation: 45 }, grid: { color: "#1f2937" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1f2937" } },
      },
    },
  });

  new Chart(pieCtx, {
    type: "doughnut",
    data: {
      labels: ["Normal", "Anomaly"],
      datasets: [{
        data: [NORMAL, ANOM],
        backgroundColor: ["rgba(16,185,129,0.7)", "rgba(239,68,68,0.75)"],
        borderColor: ["rgba(16,185,129,1)", "rgba(239,68,68,1)"],
        borderWidth: 1,
      }],
    },
    options: {
      plugins: { legend: { labels: { color: "#e2e8f0" } } },
    },
  });
})();
