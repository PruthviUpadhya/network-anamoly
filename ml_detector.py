"""
ML-Powered Anomaly Detection Engine
Uses Isolation Forest & Adaptive Statistical Z-Score Thresholds
Trained on multi-dimensional network telemetry features:
- packet_rate (packets/sec)
- byte_rate (bytes/sec)
- syn_ratio (SYN packets / Total packets)
- rst_ratio (RST packets / Total packets)
- failed_conn_ratio
- unique_dst_ports (Port scanning metric)
- entropy (Shannon Entropy)
"""

import numpy as np
import time
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        # Isolation Forest optimized for network anomaly detection
        self.model = IsolationForest(
            n_estimators=120,
            contamination=0.08,  # Expect ~8% anomaly baseline
            random_state=42,
            max_samples="auto"
        )
        self.is_trained = False
        self._initialize_baseline_model()

    def _generate_synthetic_baseline(self, samples: int = 1500) -> np.ndarray:
        """
        Synthesizes benign baseline network traffic telemetry plus representative edge cases.
        Features: [packet_rate, byte_rate, syn_ratio, rst_ratio, failed_ratio, port_diversity, entropy]
        """
        np.random.seed(42)
        # Normal web/app traffic:
        normal_packet_rate = np.random.normal(loc=120.0, scale=35.0, size=samples)
        normal_byte_rate = normal_packet_rate * np.random.normal(loc=750.0, scale=180.0, size=samples)
        normal_syn_ratio = np.random.beta(a=2, b=15, size=samples) * 0.15
        normal_rst_ratio = np.random.beta(a=1, b=30, size=samples) * 0.05
        normal_failed_ratio = np.random.beta(a=1, b=25, size=samples) * 0.08
        normal_port_diversity = np.random.uniform(1, 10, size=samples)
        normal_entropy = np.random.normal(loc=4.5, scale=0.8, size=samples)

        # Clip bounds
        normal_packet_rate = np.clip(normal_packet_rate, 5, 400)
        normal_byte_rate = np.clip(normal_byte_rate, 1000, 500000)
        normal_entropy = np.clip(normal_entropy, 1.0, 7.2)

        data = np.column_stack([
            normal_packet_rate,
            normal_byte_rate,
            normal_syn_ratio,
            normal_rst_ratio,
            normal_failed_ratio,
            normal_port_diversity,
            normal_entropy
        ])
        return data

    def _initialize_baseline_model(self):
        """Fits initial model with benign network telemetry distributions."""
        X_train = self._generate_synthetic_baseline(1500)
        X_train_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_train_scaled)
        self.is_trained = True

    def extract_features(self, metrics: Dict[str, Any]) -> np.ndarray:
        """
        Turns telemetry metric dictionary into feature vector:
        [packet_rate, byte_rate, syn_ratio, rst_ratio, failed_ratio, port_diversity, entropy]
        """
        feat = [
            float(metrics.get("packet_rate", 50.0)),
            float(metrics.get("byte_rate", 30000.0)),
            float(metrics.get("syn_ratio", 0.05)),
            float(metrics.get("rst_ratio", 0.02)),
            float(metrics.get("failed_ratio", 0.01)),
            float(metrics.get("port_diversity", 3.0)),
            float(metrics.get("entropy", 4.2))
        ]
        return np.array([feat])

    def predict_anomaly(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates metrics against ML Isolation Forest model & signature heuristics.
        Returns:
            - is_anomaly (bool)
            - anomaly_score (-1.0 to 1.0, lower means more anomalous)
            - severity ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            - threat_category (DDoS, PortScan, Exfiltration, BruteForce, Normal)
            - rule_triggers (list of specific heuristics violated)
        """
        feats = self.extract_features(metrics)
        feats_scaled = self.scaler.transform(feats)
        
        # Isolation Forest score: positive = normal, negative = anomaly
        raw_score = float(self.model.decision_function(feats_scaled)[0])
        pred = int(self.model.predict(feats_scaled)[0])  # -1 is anomaly, 1 is normal
        
        # Rule-based heuristics cross-verification
        heuristics = []
        threat_type = "NORMAL"
        severity = "INFO"

        p_rate = metrics.get("packet_rate", 0)
        syn_ratio = metrics.get("syn_ratio", 0)
        port_div = metrics.get("port_diversity", 0)
        entropy = metrics.get("entropy", 0)
        failed_ratio = metrics.get("failed_ratio", 0)

        # 1. SYN Flood / DDoS Detection
        if p_rate > 350 and syn_ratio > 0.45:
            heuristics.append("Volumetric SYN Flood Signature Detected (High PPS & High SYN ratio)")
            threat_type = "SYN_FLOOD_DDOS"
            severity = "CRITICAL"

        # 2. Port Reconnaissance / Scanning
        elif port_div > 25 and p_rate > 70:
            heuristics.append("Horizontal Port Scan / Reconnaissance Activity (High Port Dispersion)")
            threat_type = "PORT_SCAN_ATTACK"
            severity = "HIGH"

        # 3. Encrypted Data Exfiltration / C2 Tunneling
        elif entropy > 7.4 and metrics.get("byte_rate", 0) > 200000:
            heuristics.append("High Shannon Entropy with Sustained Outbound Flow (Suspected Data Exfiltration)")
            threat_type = "DATA_EXFILTRATION"
            severity = "HIGH"

        # 4. Authentication Brute Force / Web Probing
        elif failed_ratio > 0.4 and p_rate > 50:
            heuristics.append("Elevated Connection Refusal Rate (Credential Brute-Force / Endpoint Probing)")
            threat_type = "AUTH_BRUTE_FORCE"
            severity = "MEDIUM"

        # 5. Isolation Forest Unsupervised Anomaly
        elif pred == -1 or raw_score < -0.05:
            heuristics.append("Statistical Outlier identified by Isolation Forest unsupervised boundary")
            threat_type = "STATISTICAL_BEHAVIORAL_ANOMALY"
            severity = "MEDIUM" if raw_score > -0.15 else "HIGH"

        is_anomaly = (pred == -1) or len(heuristics) > 0 or raw_score < 0.0

        # Confidence percentage (0-100%)
        # Map raw_score from [-0.5, 0.5] to confidence
        risk_score = round(max(0.0, min(100.0, (0.25 - raw_score) * 160.0)), 1)
        if threat_type == "SYN_FLOOD_DDOS":
            risk_score = max(risk_score, 96.5)
        elif threat_type == "PORT_SCAN_ATTACK":
            risk_score = max(risk_score, 88.0)
        elif threat_type == "DATA_EXFILTRATION":
            risk_score = max(risk_score, 91.2)

        return {
            "is_anomaly": is_anomaly,
            "threat_type": threat_type,
            "severity": severity if is_anomaly else "INFO",
            "decision_score": round(raw_score, 4),
            "risk_score": risk_score,
            "heuristic_flags": heuristics,
            "evaluated_at": time.time()
        }
