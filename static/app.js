/**
 * SentinX Frontend Application Logic
 * Real-time polling, Chart.js telemetry waveforms, attack triggering,
 * interactive firewall quarantine, and cryptographic audit.
 */

let telemetryChart = null;
let currentSimulationMode = "NORMAL";

// Initialize Chart.js
function initTelemetryChart() {
  const ctx = document.getElementById('telemetryChart').getContext('2d');
  
  telemetryChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array(20).fill(''),
      datasets: [
        {
          label: 'Packet Rate (pps)',
          data: Array(20).fill(60),
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56, 189, 248, 0.08)',
          fill: true,
          tension: 0.35,
          yAxisID: 'y'
        },
        {
          label: 'Shannon Entropy (bits/byte)',
          data: Array(20).fill(4.2),
          borderColor: '#8b5cf6',
          borderDash: [5, 5],
          tension: 0.35,
          yAxisID: 'y1'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { display: false }
        },
        y: {
          type: 'linear',
          position: 'left',
          title: { display: true, text: 'Packets / Sec', color: '#94a3b8' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#cbd5e1' },
          min: 0,
          suggestedMax: 450
        },
        y1: {
          type: 'linear',
          position: 'right',
          title: { display: true, text: 'Shannon Entropy', color: '#a78bfa' },
          grid: { drawOnChartArea: false },
          ticks: { color: '#c084fc' },
          min: 0,
          max: 8.0
        }
      },
      plugins: {
        legend: {
          labels: { color: '#f8fafc', font: { family: "'Outfit', sans-serif" } }
        }
      }
    }
  });
}

// Fetch real-time telemetry from FastAPI backend
async function fetchTelemetry() {
  try {
    const res = await fetch('/api/telemetry');
    if (!res.ok) return;
    const data = await res.json();
    
    updateKPIs(data.summary);
    updatePacketsTable(data.recent_packets);
    updateAlertsList(data.recent_alerts);
    updateWaveform(data.telemetry_stream);
  } catch (err) {
    console.error("Telemetry sync error:", err);
  }
}

function updateKPIs(summary) {
  document.getElementById('kpi-packets').textContent = summary.total_packets.toLocaleString();
  document.getElementById('kpi-anomalies').textContent = summary.total_anomalies.toLocaleString();
  document.getElementById('kpi-firewall').textContent = summary.blocked_ip_count;

  const severityElem = document.getElementById('kpi-severity');
  const descElem = document.getElementById('kpi-threat-desc');
  const statusBadge = document.getElementById('system-status-badge');
  const statusText = document.getElementById('system-status-text');

  severityElem.textContent = summary.current_severity;
  descElem.textContent = summary.current_threat;

  if (summary.current_severity === "CRITICAL") {
    severityElem.style.color = "var(--accent-rose)";
    statusBadge.style.borderColor = "var(--accent-rose)";
    statusBadge.style.background = "rgba(244, 63, 94, 0.15)";
    statusBadge.style.color = "var(--accent-rose)";
    statusText.textContent = "ATTACK IN PROGRESS - THREAT LEVEL CRITICAL";
  } else if (summary.current_severity === "HIGH") {
    severityElem.style.color = "var(--accent-amber)";
    statusBadge.style.borderColor = "var(--accent-amber)";
    statusBadge.style.background = "rgba(245, 158, 11, 0.15)";
    statusBadge.style.color = "var(--accent-amber)";
    statusText.textContent = "SUSPICIOUS ACTIVITY FLAGGED";
  } else {
    severityElem.style.color = "var(--accent-emerald)";
    statusBadge.style.borderColor = "rgba(16, 185, 129, 0.3)";
    statusBadge.style.background = "rgba(16, 185, 129, 0.1)";
    statusBadge.style.color = "var(--accent-emerald)";
    statusText.textContent = "SHIELD ACTIVE (MONITORING)";
  }
}

function updateWaveform(telemetryStream) {
  if (!telemetryChart || !telemetryStream || telemetryStream.length === 0) return;

  const pRates = telemetryStream.map(t => Math.round(t.packet_rate));
  const entropies = telemetryStream.map(t => Number(t.entropy.toFixed(2)));

  telemetryChart.data.labels = telemetryStream.map((_, i) => `T-${telemetryStream.length - i}`);
  telemetryChart.data.datasets[0].data = pRates;
  telemetryChart.data.datasets[1].data = entropies;
  telemetryChart.update();
}

function updatePacketsTable(packets) {
  const tbody = document.getElementById('packet-tbody');
  tbody.innerHTML = '';

  packets.forEach(pkt => {
    const tr = document.createElement('tr');
    
    // Proto badge style
    let pClass = 'badge-tcp';
    if (pkt.protocol.includes('TLS')) pClass = 'badge-tls';
    else if (pkt.protocol === 'UDP') pClass = 'badge-udp';
    else if (pkt.protocol === 'DNS') pClass = 'badge-dns';

    const shortSha = pkt.sha256 ? `${pkt.sha256.substring(0, 10)}...` : 'n/a';
    const firewallBadge = pkt.is_blocked 
      ? `<span class="badge badge-critical">DROPPED</span>`
      : `<button class="btn btn-cyan" style="padding: 2px 8px; font-size: 0.7rem;" onclick="blockIp('${pkt.src_ip}')">Quarantine</button>`;

    tr.innerHTML = `
      <td>#${pkt.id}</td>
      <td style="font-weight: 600; color: #fff;">${pkt.src_ip}:${pkt.src_port}</td>
      <td>${pkt.dst_ip}:${pkt.dst_port}</td>
      <td><span class="badge ${pClass}">${pkt.protocol}</span></td>
      <td>${pkt.flags}</td>
      <td style="color: ${pkt.crypto_entropy > 7.2 ? '#f43f5e' : '#38bdf8'}">${pkt.crypto_entropy}</td>
      <td title="${pkt.sha256}">${shortSha}</td>
      <td>${firewallBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

function updateAlertsList(alerts) {
  const container = document.getElementById('alerts-container');
  if (alerts.length === 0) {
    container.innerHTML = `<div style="color: var(--text-dim); text-align: center; padding: 2rem;">No active security anomalies detected. System baseline secure.</div>`;
    return;
  }

  container.innerHTML = '';
  alerts.forEach(alt => {
    const card = document.createElement('div');
    card.className = 'alert-card';
    
    let borderCol = 'var(--accent-rose)';
    if (alt.severity === 'HIGH') borderCol = 'var(--accent-amber)';
    if (alt.severity === 'MEDIUM') borderCol = 'var(--accent-purple)';
    card.style.borderLeftColor = borderCol;

    const timeAgo = `${Math.max(1, Math.round(Date.now() / 1000 - alt.timestamp))}s ago`;

    card.innerHTML = `
      <div class="alert-top">
        <span class="alert-title">${alt.threat_type}</span>
        <span class="alert-time">${timeAgo}</span>
      </div>
      <div class="alert-desc">${alt.details}</div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.3rem;">
        <span style="font-size: 0.75rem; color: var(--accent-cyan); font-family: var(--font-mono);">Src: ${alt.suspect_ip} -> ${alt.target_service}</span>
        <span class="badge ${alt.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">Score: ${alt.risk_score}%</span>
      </div>
    `;
    container.appendChild(card);
  });
}

// Attack Simulation switch
async function setSimulationMode(mode) {
  currentSimulationMode = mode;
  
  // Highlight active button
  document.querySelectorAll('.attack-buttons .btn').forEach(btn => btn.classList.remove('active'));
  const btnMap = {
    'NORMAL': 'sim-btn-normal',
    'SYN_FLOOD': 'sim-btn-syn',
    'PORT_SCAN': 'sim-btn-scan',
    'EXFILTRATION': 'sim-btn-exfil',
    'BRUTE_FORCE': 'sim-btn-brute'
  };
  const activeBtn = document.getElementById(btnMap[mode]);
  if (activeBtn) activeBtn.classList.add('active');

  try {
    await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode })
    });
  } catch (err) {
    console.error("Simulation set error:", err);
  }
}

// Firewall rules
async function blockIp(ip) {
  try {
    await fetch('/api/firewall/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip })
    });
    fetchTelemetry();
  } catch (err) {
    console.error("Block IP error:", err);
  }
}

async function clearFirewall() {
  try {
    await fetch('/api/firewall/clear', { method: 'POST' });
    fetchTelemetry();
  } catch (err) {
    console.error("Clear firewall error:", err);
  }
}

// Cryptographic Verification Tool
async function auditCustomPayload() {
  const text = document.getElementById('crypto-input').value;
  try {
    const res = await fetch('/api/crypto/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload_text: text })
    });
    const data = await res.json();
    
    document.getElementById('crypto-entropy-val').textContent = `${data.entropy} / 8.00`;
    document.getElementById('crypto-entropy-status').textContent = data.entropy_status;
    document.getElementById('crypto-sha-val').textContent = data.sha256;
    document.getElementById('crypto-aes-val').textContent = data.aes_gcm_ciphertext_hex;

    // Entropy percentage meter
    const pct = Math.min(100, Math.round((data.entropy / 8.0) * 100));
    document.getElementById('crypto-entropy-bar').style.width = `${pct}%`;
  } catch (err) {
    console.error("Crypto audit error:", err);
  }
}

// Auto-run on mount
window.addEventListener('DOMContentLoaded', () => {
  initTelemetryChart();
  auditCustomPayload();
  fetchTelemetry();
  // Poll telemetry every 1.2 seconds
  setInterval(fetchTelemetry, 1200);
});
