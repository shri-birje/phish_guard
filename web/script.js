async function checkPhishing() {
    const urlInput = document.getElementById('urlInput').value;
    const resultBox = document.getElementById('result');

    if (!urlInput) {
        resultBox.textContent = "⚠️ Please enter a valid URL.";
        return;
    }

    resultBox.textContent = "🔍 Analyzing...";
    
    try {
        const response = await fetch('/check_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        const result = await response.json();

        if (result.prediction === "phishing") {
            resultBox.style.background = "rgba(255, 0, 0, 0.4)";
            resultBox.textContent = `🚨 Warning! The URL "${urlInput}" is likely a phishing domain.`;
        } else {
            resultBox.style.background = "rgba(0, 255, 0, 0.3)";
            resultBox.textContent = `✅ Safe! The URL "${urlInput}" appears legitimate.`;
        }

    } catch (error) {
        resultBox.textContent = "❌ Error: Unable to connect to the backend.";
        console.error(error);
    }
}
