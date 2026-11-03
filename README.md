# WebGuard AI — Web IDS Browser Extension

**Project status: In development**

WebGuard AI is a student cybersecurity project exploring browser-level website risk indicators and local network traffic monitoring. It currently contains two separate components:

1. **Chrome browser extension:** records per-tab navigation/request metadata and applies transparent, rule-based heuristics to highlight potentially unusual website activity.
2. **Local Python network IDS:** uses Scapy to observe authorized local network traffic and raises heuristic alerts for patterns such as possible port sweeps, TCP SYN bursts, and unusually high packet rates. An optional Random Forest pipeline can be trained using a compatible labelled packet-feature CSV.

> This is an educational prototype, not a production security product. Heuristic alerts are indicators for investigation, not proof that a site or device is malicious or compromised. The browser extension does not currently use a trained ML model to classify websites. The optional ML model applies only to the backend packet-feature schema.

## Current capabilities

### Browser extension

- Chrome Manifest V3 extension.
- Tracks top-level navigation and completed web-request metadata per tab.
- Calculates request count, request rate, unique domains, and third-party request ratio over a rolling 60-second window.
- Applies explainable hostname and activity heuristics and can display an in-page warning when the combined score is high.
- Stores a bounded amount of telemetry locally in `chrome.storage.local`.

### Local network IDS

- FastAPI service bound to `127.0.0.1:8765`.
- Optional Scapy packet capture on a selected local interface.
- Heuristic alerts for possible port sweeps, TCP SYN bursts, and high packet rates.
- Optional trained Random Forest classifier for the documented six-feature packet schema.
- API endpoints for health, status, capture control, and recent alerts.

## Repository layout

```text
Web-IDS-AI-Browser-Extension/
├── extension/                 # Chrome Manifest V3 extension
│   ├── background/            # Browser event collection and heuristics
│   ├── content/               # In-page warning overlay
│   └── popup/                 # Extension dashboard
├── backend/
│   ├── main.py                # Local FastAPI + Scapy network IDS
│   ├── requirements.txt
│   └── ml/
│       ├── train_model.py     # Optional model-training pipeline
│       └── README.md
├── test-site/                 # Local request-volume test page
├── .gitignore
└── README.md
```

## Requirements

- Windows 10/11, macOS, or Linux.
- Python 3.11 or newer (Python 3.11–3.13 are the recommended tested range for the dependency set).
- Google Chrome or a Chromium-based browser supporting Manifest V3.
- Npcap on Windows for Scapy packet capture. Packet capture may require Administrator privileges.

## Run the local backend (Windows PowerShell)

Open PowerShell in the `backend` directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8765
```

Check the service in a browser:

- `http://127.0.0.1:8765/health`
- `http://127.0.0.1:8765/api/status`

Start and inspect capture from a second PowerShell window:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/api/capture/start -ContentType 'application/json' -Body '{}'
Invoke-RestMethod -Uri http://127.0.0.1:8765/api/status
Invoke-RestMethod -Uri http://127.0.0.1:8765/api/alerts
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/api/capture/stop
```

Packet capture requires the correct interface and operating-system permissions. If it fails, inspect `capture_error` in `/api/status`. Only capture traffic on systems and networks you own or have explicit permission to monitor.

## Load the Chrome extension

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose this repository's `extension` folder.
5. Open a normal website and click the WebGuard AI extension icon to view telemetry.

The extension communicates with the backend only through `127.0.0.1:8765`. The browser component cannot observe all packets on the computer; packet capture remains a separate backend function.

## Optional ML model training

No model is included in this repository. This is intentional: an unvalidated placeholder model would be misleading.

The starter training script expects a labelled CSV containing these numeric columns:

```text
Length,TTL,Protocol,IsTCP,IsUDP,IsICMP,Label
```

Run from the `backend` directory:

```powershell
python ml/train_model.py path\to\your_features.csv
```

The script performs a stratified hold-out split and prints precision, recall, F1, and a confusion matrix. It saves the model to `backend/ml/webguard_rf.joblib`; restart the API after training.

**Dataset note:** CIC-IDS2017/2018 are flow-oriented datasets. Their raw columns are not interchangeable with this packet-level schema. A documented feature extraction/mapping step is required before using them. For a credible evaluation, avoid random row leakage where possible by splitting by capture, time, or host, and report false-positive rate and detection latency in addition to precision/recall/F1.

## Local browser test page

The `test-site` folder contains a page that issues a sequence of requests to its own local server. It is intended only to verify that the extension records request activity; it does not simulate malware or prove malicious-site detection.

From the `test-site` directory, run:

```powershell
py -m http.server 8000 --bind 127.0.0.1
```

Then open `http://127.0.0.1:8000` in Chrome with the extension loaded.

## Important limitations and next development goals

- Hostname wording, subdomain structure, request rate, and third-party request ratios are weak signals. Legitimate sites can exhibit these patterns; attackers can avoid them.
- The extension does not currently query a threat-intelligence feed, inspect page content for phishing, validate certificates, or use a trained website-classification model.
- HTTPS payloads are encrypted. The backend does not decrypt TLS traffic or inspect full application-layer request bodies.
- Network rules are heuristic and can produce false positives. A suspected scan or SYN burst is not conclusive evidence of an attack.
- The optional Random Forest is a packet-level baseline and is not pretrained. Its usefulness depends on compatible, representative labelled data and independent evaluation.
- The browser heuristic score and backend IDS alerts are separate signals; they are not combined into a single AI confidence score.

Planned work includes controlled test cases, improved feature engineering, documented datasets, precision/recall/F1 and false-positive evaluation, alert deduplication tests, and a clearer separation between heuristic indicators and ML predictions.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| GET | `/api/status` | Capture and model status |
| POST | `/api/capture/start` | Start authorized local capture; optional JSON `{"interface":"..."}` |
| POST | `/api/capture/stop` | Stop capture |
| GET | `/api/alerts?limit=100` | Retrieve recent alerts |
| DELETE | `/api/alerts` | Clear recent alerts |

## Responsible use

Use packet capture only on networks/devices you own or are authorized to monitor. Keep the backend bound to loopback (`127.0.0.1`); do not expose it to a public or shared network for a demonstration. Do not use the test page or project to scan, stress, or probe third-party systems.
