"""
FastAPI Server for Network Traffic Monitoring and Anomaly Detection
Provides RESTful APIs & serves the cyber-defense operational command center web dashboard.
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
from traffic_monitor import TrafficMonitor
from crypto_engine import CryptoSecurityEngine

app = FastAPI(
    title="SentinX - Autonomous Network Traffic Monitor & AI Anomaly Detection",
    version="2.0.0"
)

# Instantiate engine
monitor = TrafficMonitor()
crypto = CryptoSecurityEngine()

# Ensure static dir
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


class AttackSimRequest(BaseModel):
    mode: str  # NORMAL, SYN_FLOOD, PORT_SCAN, EXFILTRATION, BRUTE_FORCE


class FirewallRuleRequest(BaseModel):
    ip: str


class CryptoVerifyRequest(BaseModel):
    payload_text: str


@app.get("/")
def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Dashboard loading, please refresh in a moment."}


@app.get("/api/telemetry")
def get_telemetry():
    """Returns streaming packet feed, ML telemetry, and security alerts."""
    return monitor.get_dashboard_state()


@app.post("/api/simulate")
def trigger_simulation(req: AttackSimRequest):
    """Dynamically inject attack patterns to test ML anomaly detection."""
    success = monitor.set_simulation_mode(req.mode)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid attack vector mode")
    return {"status": "success", "mode": req.mode}


@app.post("/api/firewall/block")
def block_ip(req: FirewallRuleRequest):
    """Manually add malicious IP to firewall drop table."""
    monitor.block_ip(req.ip)
    return {"status": "blocked", "ip": req.ip}


@app.post("/api/firewall/unblock")
def unblock_ip(req: FirewallRuleRequest):
    """Release an IP from firewall drop table."""
    monitor.unblock_ip(req.ip)
    return {"status": "unblocked", "ip": req.ip}


@app.post("/api/firewall/clear")
def clear_firewall():
    """Flush all firewall drop rules."""
    monitor.clear_blocked_ips()
    return {"status": "cleared"}


@app.post("/api/crypto/audit")
def audit_crypto_payload(req: CryptoVerifyRequest):
    """Performs live cryptographic integrity and Shannon entropy check on input data."""
    raw_bytes = req.payload_text.encode("utf-8")
    analysis = crypto.analyze_crypto_properties(raw_bytes)
    nonce, ciphertext = crypto.encrypt_payload(raw_bytes)
    analysis["aes_gcm_ciphertext_hex"] = ciphertext.hex()
    analysis["aes_gcm_nonce_hex"] = nonce.hex()
    return analysis


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
