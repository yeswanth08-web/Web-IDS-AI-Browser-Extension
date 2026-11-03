async function loadTelemetry() {

    const result = await chrome.storage.local.get({
        telemetry: [],
        features: {},
        detection: {}
    });

    const telemetry = result.telemetry;
    const features = result.features;
    const detection = result.detection;


    // ==========================================
    // TELEMETRY
    // ==========================================

    document.getElementById("eventCount").textContent =
        `Events: ${telemetry.length}`;


    // ==========================================
    // CURRENT STATUS
    // ==========================================

    if (telemetry.length > 0) {

        const latest =
            telemetry[telemetry.length - 1];

        document.getElementById("status").textContent =
            `Latest: ${latest.type} — ${latest.domain}`;

    } else {

        document.getElementById("status").textContent =
            "Waiting for browser activity...";
    }


    // ==========================================
    // SECURITY FEATURES
    // ==========================================

    document.getElementById("totalRequests").textContent =
        `Total Requests: ${features.total_requests || 0}`;

    document.getElementById("uniqueDomains").textContent =
        `Unique Domains: ${features.unique_domains || 0}`;

    document.getElementById("navigationCount").textContent =
        `Navigations: ${features.navigation_count || 0}`;

    document.getElementById("thirdPartyRequests").textContent =
        `Third-Party Requests: ${features.third_party_requests || 0}`;

    document.getElementById("thirdPartyRatio").textContent =
        `Third-Party Ratio: ${features.third_party_ratio || 0}`;

    document.getElementById("burstRate").textContent =
        `Request Burst Rate: ${features.request_burst_rate || 0}`;


    // ==========================================
    // DETECTION ENGINE
    // ==========================================

    document.getElementById("detectedDomain").textContent =
        detection.domain || "None";

    document.getElementById("riskScore").textContent =
        `${detection.riskScore || 0}/100`;

    document.getElementById("riskLevel").textContent =
        `${detection.riskLevel || "LOW"} (heuristic)`;


    // ==========================================
    // DETECTION REASONS
    // ==========================================

    const reasonsElement =
        document.getElementById("reasons");

    reasonsElement.innerHTML = "";

    if (
        detection.reasons &&
        detection.reasons.length > 0
    ) {

        detection.reasons.forEach(reason => {

            const li =
                document.createElement("li");

            li.textContent = reason;

            reasonsElement.appendChild(li);
        });

    } else {

        const li =
            document.createElement("li");

        li.textContent =
            "No high-risk heuristic indicators recorded.";

        reasonsElement.appendChild(li);
    }
}


// ==========================================
// CLEAR TELEMETRY
// ==========================================

document.getElementById("clearButton")
    .addEventListener("click", async () => {

        await chrome.storage.local.set({

            telemetry: [],

            features: {},

            detection: {}
        });

        await loadTelemetry();
    });


// ==========================================
// INITIAL LOAD
// ==========================================

loadTelemetry();


// Refresh while popup is open
setInterval(
    loadTelemetry,
    2000
);


// ==========================================
// LOCAL PYTHON NETWORK IDS BACKEND
// ==========================================
const IDS_API = "http://127.0.0.1:8765";

async function loadNetworkIDS() {
    const statusEl = document.getElementById("backendStatus");
    const packetsEl = document.getElementById("packetCount");
    const modelEl = document.getElementById("modelStatus");
    const alertsEl = document.getElementById("networkAlerts");
    try {
        const [statusResponse, alertsResponse] = await Promise.all([
            fetch(`${IDS_API}/api/status`, { cache: "no-store" }),
            fetch(`${IDS_API}/api/alerts?limit=8`, { cache: "no-store" })
        ]);
        if (!statusResponse.ok || !alertsResponse.ok) throw new Error("API request failed");
        const status = await statusResponse.json();
        const alertData = await alertsResponse.json();
        statusEl.textContent = status.running ? "Backend: connected · capture running" : "Backend: connected · capture stopped";
        packetsEl.textContent = `Packets observed: ${status.packets_seen}`;
        modelEl.textContent = status.ml_model_loaded ? "ML model: loaded (trained model)" : "ML model: not trained/loaded";
        alertsEl.replaceChildren();
        if (alertData.alerts.length === 0) {
            const li = document.createElement("li");
            li.textContent = "No network alerts yet.";
            alertsEl.appendChild(li);
        } else {
            for (const alert of alertData.alerts) {
                const li = document.createElement("li");
                const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : "";
                li.textContent = `[${alert.severity}] ${alert.type} — ${alert.source_ip} · ${time}`;
                alertsEl.appendChild(li);
            }
        }
        if (status.capture_error) statusEl.textContent += ` · Error: ${status.capture_error}`;
    } catch (_) {
        statusEl.textContent = "Backend: offline (start backend/main.py via Uvicorn)";
        packetsEl.textContent = "Packets observed: —";
        modelEl.textContent = "ML model: unavailable";
        alertsEl.replaceChildren();
        const li = document.createElement("li");
        li.textContent = "Start the Python backend to view network IDS alerts.";
        alertsEl.appendChild(li);
    }
}

document.getElementById("startCaptureButton").addEventListener("click", async () => {
    try {
        const response = await fetch(`${IDS_API}/api/capture/start`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || "Could not start capture");
        await loadNetworkIDS();
    } catch (error) {
        document.getElementById("backendStatus").textContent = `Could not start capture: ${error.message}`;
    }
});

document.getElementById("stopCaptureButton").addEventListener("click", async () => {
    try {
        await fetch(`${IDS_API}/api/capture/stop`, { method: "POST" });
        await loadNetworkIDS();
    } catch (_) {
        document.getElementById("backendStatus").textContent = "Backend is offline.";
    }
});

loadNetworkIDS();
setInterval(loadNetworkIDS, 3000);
