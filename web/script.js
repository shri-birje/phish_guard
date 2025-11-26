const API_BASE = (typeof API_BASE_OVERRIDE !== 'undefined')
  ? API_BASE_OVERRIDE
  : window.location.origin;

const urlInput   = document.getElementById('urlInput');
const resultBox  = document.getElementById('result');
const analyzeBtn = document.getElementById('analyzeBtn');
const blockBtn   = document.getElementById('blockBtn');

function showResult(text, color = 'neutral') {
  if (color === 'danger') {
    resultBox.style.background = 'rgba(255, 0, 0, 0.35)';
  } else if (color === 'warn') {
    resultBox.style.background = 'rgba(255,165,0,0.25)';
  } else {
    // safe / neutral
    resultBox.style.background = 'rgba(0,128,0,0.4)';
  }
  resultBox.textContent = text;
}

async function checkPhishing() {
  const url = urlInput.value.trim();
  if (!url) {
    showResult("⚠️ Please enter a URL.", 'warn');
    return;
  }

  showResult("🔍 Analyzing...", 'warn');
  blockBtn.style.display = 'none';

  try {
    const resp = await fetch(`${API_BASE}/api/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!resp.ok) {
      const txt = await resp.text();
      showResult("❌ Server error: " + resp.status + " " + txt, 'danger');
      return;
    }

    const data = await resp.json();

    // Use backend classification instead of showing raw percentage
    const risk   = data.risk_level;   // "Low", "Medium", "High"
    const action = data.action;       // "Allow", "Warn", "Block"
    // const score = data.phishing_score; // available, but we DON'T display it

    let icon   = "";
    let msg    = "";
    let color  = "neutral";

    if (risk === "Low") {
      icon  = "✅";
      msg   = `Safe. The URL "${url}" does not show obvious phishing signals.`;
      color = "safe";
    } else if (risk === "Medium") {
      icon  = "⚠️";
      msg   = `Suspicious. Proceed carefully when using "${url}".`;
      color = "warn";
    } else if (risk === "High") {
      icon  = "🚫";
      msg   = `Dangerous. "${url}" is likely phishing. Do NOT enter any sensitive information.`;
      color = "danger";
    } else {
      icon  = "ℹ️";
      msg   = `Unknown risk level for "${url}".`;
      color = "warn";
    }

    showResult(`${icon} ${msg}`, color);

    // Show block button only for Medium / High risk
    if (risk === "Medium" || risk === "High") {
      blockBtn.style.display = 'inline-block';
      blockBtn.onclick = () => blockUrl(url);
    } else {
      blockBtn.style.display = 'none';
    }

  } catch (err) {
    console.error(err);
    showResult("❌ Error: Unable to contact backend. Is the server reachable?", 'danger');
  }
}

async function blockUrl(url) {
  // Fallback to current input if url param missing
  const target = (url || urlInput.value || '').trim();
  if (!target) {
    alert("No URL to block.");
    return;
  }

  if (!confirm(`Block "${target}" globally?`)) return;

  const token = localStorage.getItem('phishguard_token');
  if (!token) {
    alert("You must log in first to block URLs.\nGo to /login, sign in, then try again.");
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/block`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ url: target, reason: 'blocked via web UI' })
    });

    let data;
    try {
      data = await resp.json();
    } catch (_) {
      data = {};
    }

    if (!resp.ok || data.ok === false) {
      const msg = (data && data.error) ? data.error : (`HTTP ${resp.status}`);
      alert('Error blocking: ' + msg);
      return;
    }

    alert('Blocked: ' + (data.url || target));
    blockBtn.style.display = 'none';
  } catch (e) {
    alert('Request failed: ' + e);
  }
}

analyzeBtn.addEventListener('click', checkPhishing);
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') checkPhishing();
});
