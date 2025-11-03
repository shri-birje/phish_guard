chrome.webNavigation.onCompleted.addListener(async (details) => {
  const url = details.url;

  // Ignore Chrome internal pages
  if (!url.startsWith("http")) return;

  try {
    const response = await fetch("http://127.0.0.1:5000/check_url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const result = await response.json();
    console.log("URL Check Result:", result);

    // If phishing detected, show alert or block
    if (result.prediction === "phishing" || result.risk === "High") {
      chrome.scripting.executeScript({
        target: { tabId: details.tabId },
        func: () => {
          alert("⚠️ Warning: This site may be a phishing site! Access blocked.");
          window.location.href = "about:blank";
        }
      });
    }
  } catch (err) {
    console.error("Error checking URL:", err);
  }
});
