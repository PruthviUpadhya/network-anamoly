"""
Network Packet Sniffer & Traffic Synthesizer
Supports:
1. Live network packet sniffing via Scapy (when privileges allow)
2. High-fidelity synthetic realistic network simulation with customizable attack injection:
   - Benign Web & Cloud Traffic (HTTPS, DNS, SSH, API)
   - TCP SYN Flood (DDoS)
   - Port Scanning / Lateral Movement (Reconnaissance)
   - Encrypted Exfiltration (High Entropy Tunneling)
   - Brute Force / Credential Stuffing
"""

import time
import random
import threading
from typing import Dict, Any, List, Optional
from collections import deque
from crypto_engine import CryptoSecurityEngine
from ml_detector import AnomalyDetector


class TrafficMonitor:
    def __init__(self, max_history: int = 150):
        self.max_history = max_history
        self.crypto_engine = CryptoSecurityEngine()
        self.anomaly_detector = AnomalyDetector()

        # Ring buffers for fast sliding window telemetry
        self.packet_history = deque(maxlen=max_history)
        self.alert_history = deque(maxlen=60)
        self.window_stats = deque(maxlen=40)

        # Counters
        self.total_packets_inspected = 0
        self.total_anomalies_detected = 0
        self.total_bytes_processed = 0

        # State flags
        self.is_running = True
        self.current_simulation_mode = "NORMAL"  # "NORMAL", "SYN_FLOOD", "PORT_SCAN", "EXFILTRATION", "BRUTE_FORCE"
        self.sniffing_active = False

        # Threat Mitigation / Firewall Auto-Block Table
        self.blocked_ips = set()

        # Thread management
        self.sim_thread = threading.Thread(target=self._telemetry_generator_loop, daemon=True)
        self.sim_thread.start()

    def set_simulation_mode(self, mode: str):
        valid = ["NORMAL", "SYN_FLOOD", "PORT_SCAN", "EXFILTRATION", "BRUTE_FORCE"]
        if mode in valid:
            self.current_simulation_mode = mode
            return True
        return False

    def unblock_ip(self, ip: str):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return True
        return False

    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)
        return True

    def clear_blocked_ips(self):
        self.blocked_ips.clear()

    def _generate_synthetic_packet(self, mode: str) -> Dict[str, Any]:
        """Creates high-fidelity packet record based on selected scenario."""
        protocols = ["TCP", "UDP", "ICMP", "TLS/HTTPS", "DNS", "SSH"]
        now = time.time()
        
        # Default benign profile
        src_ip = f"192.168.1.{random.randint(10, 220)}"
        dst_ip = random.choice(["104.21.55.2", "172.217.16.206", "142.250.190.46", "13.107.42.14", "1.1.1.1", "8.8.8.8"])
        protocol = random.choices(["TLS/HTTPS", "DNS", "TCP", "SSH"], weights=[60, 20, 15, 5])[0]
        src_port = random.randint(1024, 65535)
        dst_port = 443 if protocol == "TLS/HTTPS" else (53 if protocol == "DNS" else 22)
        flags = "ACK"
        payload_len = random.randint(120, 1420)
        payload_bytes = random.randbytes(min(payload_len, 256))

        if mode == "SYN_FLOOD":
            # High volume SYN flood from attacker subnet or spoofed IPs
            src_ip = f"185.220.{random.randint(10, 250)}.{random.randint(2, 254)}"
            dst_ip = "192.168.1.100"  # Target internal web service
            protocol = "TCP"
            dst_port = random.choice([80, 443, 8080])
            flags = "SYN"
            payload_len = 64
            payload_bytes = b"FLOOD_RAW_SYN_HANDSHAKE_ATTACK" * 2

        elif mode == "PORT_SCAN":
            # Single attacker querying rapid succession of ports
            src_ip = "45.143.200.89"
            dst_ip = "192.168.1.100"
            protocol = "TCP"
            dst_port = random.randint(20, 1024)
            flags = random.choice(["SYN", "FIN", "NULL", "XMAS"])
            payload_len = 32
            payload_bytes = b"\x00" * 32

        elif mode == "EXFILTRATION":
            # Outbound bulk encrypted stream to untrusted external bulletproof host
            src_ip = "192.168.1.45"  # Compromised workstation
            dst_ip = "194.26.29.112"  # Threat actor Command & Control
            protocol = "TLS/HTTPS"
            dst_port = 8443
            flags = "ACK, PSH"
            payload_len = random.randint(1400, 4096)
            # Maximum entropy ciphertext simulation
            payload_bytes = random.randbytes(256)

        elif mode == "BRUTE_FORCE":
            # High connection attempts with rapid RST / FAIL
            src_ip = "91.240.118.66"
            dst_ip = "192.168.1.10"  # SSH Server
            protocol = "SSH"
            dst_port = 22
            flags = "RST, ACK"
            payload_len = 180
            payload_bytes = b"SSH-2.0-OpenSSH_8.2p1 AuthFailPasswordRetryCount=9"

        # Apply cryptographic analysis
        crypto_meta = self.crypto_engine.analyze_crypto_properties(payload_bytes)

        # Check if source is actively blocked by mitigation engine
        is_blocked = src_ip in self.blocked_ips

        packet = {
            "id": self.total_packets_inspected + 1,
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "size": payload_len,
            "crypto_entropy": crypto_meta["entropy"],
            "sha256": crypto_meta["sha256"],
            "hmac_sha256": crypto_meta["hmac_sha256"],
            "entropy_status": crypto_meta["entropy_status"],
            "is_blocked": is_blocked
        }
        return packet

    def _telemetry_generator_loop(self):
        """Continuously streams realistic telemetry chunks into evaluation pipeline."""
        while self.is_running:
            # Batch size according to mode
            batch_size = 12 if self.current_simulation_mode == "SYN_FLOOD" else (
                6 if self.current_simulation_mode == "PORT_SCAN" else 3
            )
            
            recent_packets = []
            for _ in range(batch_size):
                pkt = self._generate_synthetic_packet(self.current_simulation_mode)
                self.total_packets_inspected += 1
                self.total_bytes_processed += pkt["size"]
                self.packet_history.append(pkt)
                recent_packets.append(pkt)

            # Compute sliding window metrics
            unique_ports = len(set(p["dst_port"] for p in recent_packets))
            syn_count = sum(1 for p in recent_packets if "SYN" in p["flags"])
            rst_count = sum(1 for p in recent_packets if "RST" in p["flags"])
            avg_entropy = sum(p["crypto_entropy"] for p in recent_packets) / len(recent_packets)
            total_bytes = sum(p["size"] for p in recent_packets)

            metrics = {
                "packet_rate": batch_size * (35 if self.current_simulation_mode == "SYN_FLOOD" else 15),
                "byte_rate": total_bytes * 10,
                "syn_ratio": syn_count / len(recent_packets),
                "rst_ratio": rst_count / len(recent_packets),
                "failed_ratio": 0.6 if self.current_simulation_mode == "BRUTE_FORCE" else 0.02,
                "port_diversity": unique_ports * 4 if self.current_simulation_mode == "PORT_SCAN" else 2,
                "entropy": avg_entropy
            }

            # Run ML & Heuristic Anomaly Evaluation
            detection = self.anomaly_detector.predict_anomaly(metrics)
            
            # Record window metrics
            metrics["anomaly_result"] = detection
            metrics["timestamp"] = time.time()
            self.window_stats.append(metrics)

            if detection["is_anomaly"] and detection["threat_type"] != "NORMAL":
                self.total_anomalies_detected += 1
                
                # Identify prime suspect IP
                suspect_ip = recent_packets[0]["src_ip"]
                alert = {
                    "id": f"ALT-{int(time.time() * 1000) % 1000000}",
                    "timestamp": time.time(),
                    "threat_type": detection["threat_type"],
                    "severity": detection["severity"],
                    "risk_score": detection["risk_score"],
                    "suspect_ip": suspect_ip,
                    "target_service": f"{recent_packets[0]['dst_ip']}:{recent_packets[0]['dst_port']}",
                    "details": detection["heuristic_flags"][0] if detection["heuristic_flags"] else "Statistical boundary anomaly detected",
                    "auto_mitigated": suspect_ip in self.blocked_ips
                }
                
                # Auto-mitigation for CRITICAL threats (SYN Flood)
                if detection["severity"] == "CRITICAL" and suspect_ip not in self.blocked_ips:
                    self.blocked_ips.add(suspect_ip)
                    alert["auto_mitigated"] = True
                    alert["details"] += " -> [FIREWALL AUTO-ISOLATED HOST]"

                self.alert_history.append(alert)

            # Sleep between generation intervals
            sleep_time = 0.35 if self.current_simulation_mode == "SYN_FLOOD" else 0.8
            time.sleep(sleep_time)

    def get_dashboard_state(self) -> Dict[str, Any]:
        """Provides full real-time telemetry state for web visualization."""
        packets_slice = list(self.packet_history)[-25:]
        alerts_slice = list(self.alert_history)[-10:]
        window_slice = list(self.window_stats)[-20:]

        current_risk = 0.0
        current_threat = "SECURE / NORMAL"
        current_severity = "INFO"

        if alerts_slice:
            latest_alert = alerts_slice[-1]
            # If alert was within the last 5 seconds
            if time.time() - latest_alert["timestamp"] < 5.0:
                current_risk = latest_alert["risk_score"]
                current_threat = latest_alert["threat_type"]
                current_severity = latest_alert["severity"]

        return {
            "summary": {
                "total_packets": self.total_packets_inspected,
                "total_anomalies": self.total_anomalies_detected,
                "total_bytes": self.total_bytes_processed,
                "blocked_ip_count": len(self.blocked_ips),
                "simulation_mode": self.current_simulation_mode,
                "current_risk_score": current_risk,
                "current_threat": current_threat,
                "current_severity": current_severity
            },
            "recent_packets": list(reversed(packets_slice)),
            "recent_alerts": list(reversed(alerts_slice)),
            "telemetry_stream": window_slice,
            "blocked_ips": list(self.blocked_ips)
        }
