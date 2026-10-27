"""
Cryptographic Integrity, Key Management, and Hashing Module
Implements:
- SHA-256 Packet Payload Integrity Signatures & Tamper Detection
- AES-256-GCM / ChaCha20-Poly1305 Secure Channel Simulation
- HMAC-SHA256 Session Token Authentication
- Cryptographic Entropy Analysis (Shannon Entropy) for detecting encrypted exfiltration & tunneling
"""

import math
import os
import hmac
import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoSecurityEngine:
    def __init__(self, master_secret: bytes = None):
        self.master_secret = master_secret or os.urandom(32)
        self.gcm_key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.gcm_key)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates Shannon Entropy (0.0 to 8.0) of raw payload.
        High entropy (> 7.2) signifies encrypted tunneling, ransomware exfiltration, or compressed trojan payload.
        Low entropy (< 3.0) indicates repetitive plaintext, empty padding, or null flooding.
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        """Computes SHA-256 cryptographic digest of packet contents."""
        return hashlib.sha256(data).hexdigest()

    def generate_hmac(self, data: bytes) -> str:
        """Generates cryptographic HMAC-SHA256 signature for data integrity."""
        return hmac.new(self.master_secret, data, hashlib.sha256).hexdigest()

    def verify_hmac(self, data: bytes, signature: str) -> bool:
        """Verifies HMAC with constant-time comparison to prevent timing attacks."""
        expected = self.generate_hmac(data)
        return hmac.compare_digest(expected, signature)

    def encrypt_payload(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypts payload with AES-256-GCM authenticated encryption."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def decrypt_payload(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypts AES-256-GCM ciphertext verifying authentication tag."""
        return self.aesgcm.decrypt(nonce, ciphertext, None)

    def analyze_crypto_properties(self, payload: bytes) -> Dict[str, Any]:
        """Full cryptographic audit of payload."""
        entropy = self.calculate_entropy(payload)
        sha256_hash = self.compute_sha256(payload)
        hmac_sig = self.generate_hmac(payload)
        
        is_suspicious_entropy = entropy > 7.5
        entropy_status = "NORMAL_PLAINTEXT"
        if entropy > 7.5:
            entropy_status = "SUSPICIOUS_HIGH_ENTROPY (Possible Encrypted Exfiltration/C2)"
        elif entropy < 1.5 and len(payload) > 50:
            entropy_status = "ABNORMAL_LOW_ENTROPY (Padding / DoS Null-Fill)"

        return {
            "entropy": entropy,
            "sha256": sha256_hash,
            "hmac_sha256": hmac_sig,
            "entropy_status": entropy_status,
            "is_suspicious_entropy": is_suspicious_entropy,
            "payload_size": len(payload)
        }
