document.getElementById("checkBtn").addEventListener("click", async () => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab.url;

  const res = await fetch("http://127.0.0.1:5000/check_url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  const result = await res.json();
  document.getElementById("result").innerText = 
    `Result: ${result.prediction || result.risk || "Unknown"}`;
});
