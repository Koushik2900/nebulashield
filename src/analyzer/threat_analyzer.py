import re
import numpy as np
from scipy.stats import entropy as scipy_entropy
from typing import Dict, Any

# Dangerous patterns that definitively indicate an attack
_DANGEROUS_PATTERNS = [
    # SQL Injection patterns
    (r"UNION\s+(?:ALL\s+)?SELECT", 35),
    (r"DROP\s+TABLE", 35),
    (r"'\s*OR\s+'?1'?\s*=\s*'?1", 35),
    (r"'\s*OR\s+\d+\s*=\s*\d+", 30),
    (r"--\s*$", 20),
    (r"/\*.*?\*/", 20),
    # Command injection patterns
    (r";\s*(?:cat|whoami|ls|id|pwd|wget|curl|bash|sh)\b", 40),
    (r"\|\s*(?:cat|whoami|ls|id|pwd|wget|curl|bash|sh)\b", 40),
    (r"`[^`]+`", 25),
    # Path traversal patterns
    (r"(?:\.\.[\\/]){2,}", 35),
    # XSS patterns
    (r"<script[\s>]", 35),
    (r"javascript\s*:", 30),
    (r"on(?:error|load|click|mouseover)\s*=", 30),
]

_COMPILED_PATTERNS = [(re.compile(p, re.I | re.S), score) for p, score in _DANGEROUS_PATTERNS]


class ThreatAnalyzer:
    """
    Multi-stage threat detection using heuristics, entropy analysis, and anomaly detection.
    """
    
    def __init__(self):
        self.threat_db = {}
        self.benign_baseline = []
    
    def extract_features(self, payload: str) -> Dict[str, Any]:
        """Extract features from payload for threat analysis"""
        
        # Entropy calculation
        payload_bytes = payload.encode()
        byte_counts = [payload_bytes.count(bytes([i])) for i in range(256)]
        byte_entropy = scipy_entropy([b for b in byte_counts if b > 0]) if sum(byte_counts) > 0 else 0
        
        features = {
            "entropy": byte_entropy,
            "entropy_anomaly": byte_entropy > 6.5,
            
            # SQL Injection indicators
            "sql_keywords_count": sum(1 for kw in [
                "SELECT", "UNION", "INSERT", "DELETE", "DROP", 
                "CREATE", "ALTER", "EXEC", "EXECUTE", "SCRIPT", "OR", "AND"
            ] if kw in payload.upper()),
            "sql_comments": payload.count("--") + payload.count("/*"),
            "suspicious_quotes": payload.count("'") + payload.count('"'),
            
            # XSS indicators
            "script_tags": len(re.findall(r'<script|javascript:|onerror|onload', payload, re.I)),
            "html_entities": len(re.findall(r'&#?\w+;', payload)),
            
            # Path Traversal
            "path_traversal": payload.count("../") + payload.count("..\\"),
            "null_bytes": payload.count("\x00"),
            
            # SSRF/Internal Access
            "internal_ips": len(re.findall(r'(127\.0\.0\.1|169\.254|172\.1[6-9]\.|10\.0)', payload)),
            "localhost_refs": payload.upper().count("LOCALHOST"),
            
            # Protocol confusion
            "protocol_confusion": len(re.findall(r'(file://|gopher://|data:)', payload, re.I)),
            
            # Encoding tricks
            "url_encoding_ratio": len(re.findall(r'%[0-9A-F]{2}', payload, re.I)) / (len(payload) + 1),
            "double_encoding": len(re.findall(r'%25[0-9A-F]{2}', payload, re.I)),
            "unicode_escapes": len(re.findall(r'\\u[0-9A-F]{4}', payload, re.I)),
            
            # Payload metrics
            "payload_length": len(payload),
            "avg_token_length": np.mean([len(t) for t in payload.split()]) if payload.split() else 0,
            "rare_char_ratio": len(re.findall(r'[^\\w\\s\.\-/:@]', payload)) / (len(payload) + 1),
            
            # Command injection
            "command_keywords": sum(1 for cmd in ["WHOAMI", "CAT", "LS", "CMD.EXE", "BIN/SH", "SYSTEM"] 
                                   if cmd in payload.upper()),
            
            # XXE detection
            "xxe_indicators": len(re.findall(r'<!ENTITY|SYSTEM|PUBLIC', payload, re.I)),
        }
        
        return features
    
    def calculate_threat_score(self, features: Dict[str, Any], payload: str = "") -> float:
        """Weighted scoring system for threat assessment"""
        
        score = 0.0

        # --- Base weights ---
        weights = {
            "entropy_anomaly": 15,
            "sql_keywords_count": 8,   # per-keyword contribution; compounded below
            "suspicious_quotes": 5,
            "sql_comments": 20,
            "script_tags": 30,
            "path_traversal": 25,
            "internal_ips": 22,
            "url_encoding_ratio": 12,
            "command_keywords": 25,
            "xxe_indicators": 18,
            "payload_length": 5,
        }
        
        for feature, weight in weights.items():
            if feature in features:
                value = features[feature]
                
                if isinstance(value, bool):
                    score += weight if value else 0
                
                elif isinstance(value, (int, float)):
                    if value > 0:
                        if feature == "payload_length":
                            score += weight * min(value / 1000, 1.0)
                        elif feature == "url_encoding_ratio":
                            score += weight * value
                        elif feature == "sql_keywords_count":
                            # Scale: 1→8, 2→18, 3→30, 4→44 ...
                            score += weight * value + max(0, value - 1) * 2
                        else:
                            score += weight + (min(value - 1, 5) * 2)

        # --- Compound signal bonuses ---
        sql_kw = features.get("sql_keywords_count", 0)
        sql_cm = features.get("sql_comments", 0)
        quotes = features.get("suspicious_quotes", 0)
        cmd_kw = features.get("command_keywords", 0)
        path_tr = features.get("path_traversal", 0)

        # Multiple SQL signals together → big extra penalty
        if sql_kw >= 2 and sql_cm >= 1:
            score += 25
        if sql_kw >= 2 and quotes >= 1:
            score += 15
        if sql_kw >= 1 and quotes >= 2:
            score += 10
        if sql_kw >= 3:
            score += 20
        if sql_cm >= 1 and quotes >= 1:
            score += 10

        # Command injection with pipe/semicolon patterns
        if cmd_kw >= 1 and sql_cm >= 1:
            score += 15
        if cmd_kw >= 2:
            score += 20

        # Path traversal depth bonus
        if path_tr >= 2:
            score += 20

        # --- Pattern-based detection (regex for known dangerous patterns) ---
        if payload:
            for pattern, pattern_score in _COMPILED_PATTERNS:
                if pattern.search(payload):
                    score += pattern_score

        return min(score, 100)

    def detect_anomaly_vs_baseline(self, features: Dict[str, Any]) -> float:
        """Mahalanobis distance-based anomaly detection"""
        if len(self.benign_baseline) < 10:
            return 0.0
        
        try:
            baseline_array = np.array(self.benign_baseline)
            current_array = np.array([
                features.get("entropy", 0),
                features.get("payload_length", 0),
                features.get("rare_char_ratio", 0),
            ])
            
            mean = baseline_array.mean(axis=0)
            cov = np.cov(baseline_array.T)
            
            diff = current_array - mean
            inv_cov = np.linalg.inv(cov + np.eye(len(cov)) * 1e-6)
            distance = np.sqrt(diff @ inv_cov @ diff.T)
            return min(distance / 3, 100)
        except Exception as e:
            return 0.0

    def add_benign_baseline(self, payload: str):
        """Add benign request to baseline for anomaly detection"""
        features = self.extract_features(payload)
        self.benign_baseline.append([
            features.get("entropy", 0),
            features.get("payload_length", 0),
            features.get("rare_char_ratio", 0),
        ])