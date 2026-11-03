"""WebGuard AI local network detection API.

Run from this directory with:
    python -m uvicorn main:app --host 127.0.0.1 --port 8765

Packet capture requires Scapy and may require elevated privileges. Monitor only
networks and devices that you own or are explicitly authorized to administer.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "ml" / "webguard_rf.joblib"
app = FastAPI(title="WebGuard AI Local Network IDS API", version="0.2.0")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1"],
    allow_origin_regex=r"chrome-extension://[a-p]{32}",
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

_lock = threading.RLock()
_running = False
_capture_thread: threading.Thread | None = None
_capture_error: str | None = None
_packets_seen = 0
_alerts: deque[dict[str, Any]] = deque(maxlen=300)
_recent_sources: dict[str, deque[float]] = defaultdict(deque)
_recent_syn: dict[str, deque[float]] = defaultdict(deque)
_recent_ports: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
_last_packet_at: str | None = None
_model = None
_model_load_error: str | None = None

try:
    import joblib
    if MODEL_PATH.exists():
        _model = joblib.load(MODEL_PATH)
except Exception as exc:  # optional until the user trains a compatible model
    _model_load_error = f"{type(exc).__name__}: {exc}"


def _alert(kind: str, severity: str, source: str, message: str, evidence: dict | None = None) -> None:
    now = time.time()
    item = {
        "id": str(time.time_ns()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": kind,
        "severity": severity,
        "source_ip": source,
        "message": message,
        "evidence": evidence or {},
    }
    with _lock:
        # Suppress repeat alerts for the same rule/source for 10 seconds.
        if any(
            old["type"] == kind and old["source_ip"] == source
            and now - _alert_epoch(old) < 10
            for old in list(_alerts)[:20]
        ):
            return
        _alerts.appendleft(item)


def _alert_epoch(item: dict) -> float:
    try:
        return datetime.fromisoformat(item["timestamp"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return 0.0


def _prune_times(items: deque[float], now: float, window: float) -> None:
    while items and now - items[0] > window:
        items.popleft()


def _packet_handler(packet) -> None:
    """Inspect packet metadata only; encrypted application payloads are not decoded."""
    global _packets_seen, _last_packet_at
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        if IP not in packet:
            return
        ip = packet[IP]
        source, destination = str(ip.src), str(ip.dst)
        now = time.time()
        with _lock:
            _packets_seen += 1
            _last_packet_at = datetime.now(timezone.utc).isoformat()
            source_packets = _recent_sources[source]
            source_packets.append(now)
            _prune_times(source_packets, now, 10)

            if TCP in packet:
                tcp = packet[TCP]
                destination_port = int(tcp.dport)
                port_events = _recent_ports[source]
                port_events.append((now, destination, destination_port))
                while port_events and now - port_events[0][0] > 15:
                    port_events.popleft()
                syn_events = _recent_syn[source]
                flags = int(tcp.flags)
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    syn_events.append(now)
                    _prune_times(syn_events, now, 5)

                distinct_ports = len({port for _, _, port in port_events})
                if distinct_ports >= 20:
                    _alert("PORT_SCAN_SUSPECTED", "high", source,
                           "One source contacted many destination ports in a short window; verify the activity.",
                           {"distinct_destination_ports_15s": distinct_ports, "window_seconds": 15})
                if len(syn_events) >= 100:
                    _alert("SYN_BURST_SUSPECTED", "high", source,
                           "A high volume of TCP SYN packets was observed; compare with the normal baseline.",
                           {"syn_packets_5s": len(syn_events), "window_seconds": 5})

            if len(source_packets) >= 300:
                _alert("TRAFFIC_BURST_SUSPECTED", "medium", source,
                       "A high packet rate was observed from one source; this may also be legitimate traffic.",
                       {"packets_10s": len(source_packets), "window_seconds": 10})

        # Optional packet-level model. Its six input features must match train_model.py.
        if _model is not None:
            protocol = 6 if TCP in packet else (17 if UDP in packet else (1 if ICMP in packet else 0))
            feature_row = [[len(packet), int(ip.ttl), protocol,
                            int(TCP in packet), int(UDP in packet), int(ICMP in packet)]]
            try:
                prediction = str(_model.predict(feature_row)[0]).strip().lower()
                if prediction not in {"benign", "normal", "0", "false"}:
                    _alert("ML_CLASSIFIER_ALERT", "medium", source,
                           f"The optional trained packet classifier labelled this packet as {prediction}.",
                           {"prediction": prediction, "destination_ip": destination, "packet_length": len(packet)})
            except Exception as exc:
                with _lock:
                    # Surface an incompatibility instead of silently implying the model is working.
                    global _model_load_error
                    _model_load_error = f"Prediction error: {type(exc).__name__}: {exc}"
    except Exception:
        # Ignore malformed or unsupported packets so one packet cannot stop capture.
        return


def _capture_worker(interface: str | None) -> None:
    global _running, _capture_error
    try:
        from scapy.all import sniff
        while True:
            with _lock:
                if not _running:
                    break
            # A timeout bounds stop latency; stop_filter alone waits for another packet.
            sniff(prn=_packet_handler, store=False, iface=interface or None, timeout=1)
    except Exception as exc:
        with _lock:
            _capture_error = f"{type(exc).__name__}: {exc}"
            _running = False
    finally:
        with _lock:
            _running = False


@app.get("/health")
def health():
    return {"ok": True, "service": "WebGuard AI", "version": "0.2.0"}


@app.get("/api/status")
def status():
    with _lock:
        return {
            "running": _running,
            "packets_seen": _packets_seen,
            "last_packet_at": _last_packet_at,
            "alert_count": len(_alerts),
            "capture_error": _capture_error,
            "ml_model_loaded": _model is not None,
            "ml_model_load_error": _model_load_error,
            "note": "Local packet capture requires authorized monitoring privileges.",
        }


@app.post("/api/capture/start")
def start_capture(payload: dict | None = None):
    global _running, _capture_error, _capture_thread
    payload = payload or {}
    interface = payload.get("interface")
    if interface is not None and (not isinstance(interface, str) or not interface.strip() or len(interface) > 128):
        raise HTTPException(status_code=400, detail="Invalid interface name")
    interface = interface.strip() if isinstance(interface, str) else None
    with _lock:
        if _running:
            return {"started": True, "already_running": True}
        if _capture_thread and _capture_thread.is_alive():
            return {"started": False, "detail": "Previous capture thread is still stopping."}
        _capture_error = None
        _running = True
        _capture_thread = threading.Thread(target=_capture_worker, args=(interface,), daemon=True)
        _capture_thread.start()
    return {"started": True, "interface": interface or "default"}


@app.post("/api/capture/stop")
def stop_capture():
    global _running
    with _lock:
        _running = False
    return {"stopping": True, "note": "The capture loop exits after its current one-second sniff timeout."}


@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    if not 1 <= limit <= 300:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 300")
    with _lock:
        return {"alerts": list(_alerts)[:limit]}


@app.delete("/api/alerts")
def clear_alerts():
    with _lock:
        _alerts.clear()
    return {"cleared": True}
