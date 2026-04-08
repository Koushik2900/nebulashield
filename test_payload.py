#!/usr/bin/env python3
import requests
import json
from src.analyzer.threat_analyzer import ThreatAnalyzer

# Initialize analyzer
analyzer = ThreatAnalyzer()

# Test payloads
test_cases = {
    "SQL Injection": [
        "' OR '1'='1",
        "admin' --",
        "1' UNION SELECT NULL--",
        "1'; DROP TABLE users--"
    ],
    "XSS": [
        "<script>alert('xss')</script>",
        "<img src=x onerror='alert(1)'>",
        "javascript:alert('xss')"
    ],
    "Path Traversal": [
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "....//....//etc/shadow"
    ],
    "Command Injection": [
        "; whoami",
        "| cat /etc/passwd",
        "` ls -la`"
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8000/admin",
        "http://localhost:9000/debug"
    ],
    "Benign": [
        "GET /api/users?id=123",
        "search for electronics",
        "page=1&limit=10"
    ]
}

print("\n" + "="*80)
print("THREAT ANALYZER TEST SUITE".center(80))
print("="*80)

for category, payloads in test_cases.items():
    print(f"\n{'='*80}")
    print(f"CATEGORY: {category}".ljust(40))
    print(f"{'='*80}")
    print(f"{'Payload':<50} {'Score':>10} {'Decision':>10}")
    print(f"{'-'*70}")
    
    for payload in payloads:
        features = analyzer.extract_features(payload)
        score = analyzer.calculate_threat_score(features)
        decision = "🚫 BLOCK" if score > 60 else "✅ ALLOW"
        
        print(f"{payload[:50]:<50} {score:>10.2f} {decision:>10}")

print("\n" + "="*80)
print("TEST COMPLETE".center(80))
print("="*80 + "\n")