// web/script.js
const API_BASE = (typeof API_BASE_OVERRIDE !== 'undefined') ? API_BASE_OVERRIDE : window.location.origin;

const urlInput = document.getElementById('urlInput');
const resultBox = document.getElementById('result');
const analyzeBtn = document.getElementById('analyzeBtn');
const blockBtn = document.getElementById('blockBtn');

function showResult(text, color='neutral') {
  resultBox.style.background = (color === 'danger') ? 'rgba(255, 0, 0, 0.35)' : (color === 'warn' ? 'rgba(255,165,0,0.25)' : 'rgba(0,128,0,0.4)');
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
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    if (!resp.ok) {
      const txt = await resp.text();
      showResult("❌ Server error: " + resp.status + " " + txt, 'danger');
      return;
    }
    const data = await resp.json();
    const score = data.phishing_score;
    if (score === null || typeof score === 'undefined') {
      showResult("❌ No score returned", 'danger');
      return;
    }
    if (score >= 70) {
      showResult(`🚨 Phishing likely (${score}%). The URL "${url}" is risky.`, 'danger');
      blockBtn.style.display = 'inline-block';
      blockBtn.onclick = () => blockUrl(url);
    } else if (score >= 30) {
      showResult(`⚠️ Suspicious (${score}%). Proceed carefully.`, 'warn');
      blockBtn.style.display = 'inline-block';
      blockBtn.onclick = () => blockUrl(url);
    } else {
      showResult(`✅ Safe! The URL "${url}" appears legitimate. (${score}%)`, 'safe');
      blockBtn.style.display = 'none';
    }
  } catch (err) {
    console.error(err);
    showResult("❌ Error: Unable to contact backend. Is the server reachable?", 'danger');
  }
}

async function blockUrl(url) {
  if (!confirm("Block this URL globally?")) return;
  try {
    const resp = await fetch(`${API_BASE}/api/block`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, reason: 'blocked via web UI'})
    });
    const data = await resp.json();
    if (data.ok) {
      alert('Blocked: ' + url);
      blockBtn.style.display = 'none';
    } else {
      alert('Error blocking: ' + JSON.stringify(data));
    }
  } catch (e) {
    alert('Request failed: ' + e);
  }
}

analyzeBtn.addEventListener('click', checkPhishing);
urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') checkPhishing(); });
