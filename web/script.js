async function checkPhishing() {
    const urlInput = document.getElementById('urlInput').value;
    const resultBox = document.getElementById('result');

    if (!urlInput) {
        resultBox.textContent = "⚠️ Please enter a valid URL.";
        return;
    }

    resultBox.textContent = "🔍 Analyzing...";

    try {
        // ✅ Use the correct backend API endpoint:
        const API_BASE = "https://phish-guard-3uvw.onrender.com";

        const response = await fetch(`${API_BASE}/api/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) {
            throw new Error(`Server responded with ${response.status}`);
        }

        const result = await response.json();

        if (result.risk_level === "High" || result.prediction === "phishing") {
            resultBox.style.background = "rgba(255, 0, 0, 0.4)";
            resultBox.textContent = `🚨 Warning! The URL "${urlInput}" is likely a phishing domain.`;
        } else {
            resultBox.style.background = "rgba(0, 255, 0, 0.3)";
            resultBox.textContent = `✅ Safe! The URL "${urlInput}" appears legitimate.`;
        }

    } catch (error) {
        resultBox.style.background = "rgba(255, 165, 0, 0.3)";
        resultBox.textContent = "❌ Error: Unable to connect to the backend.";
        console.error("Connection error:", error);
    }
}
