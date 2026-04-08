# NebulaShield - Intelligent WAF with AI-Driven Threat Detection

Advanced Web Application Firewall combining heuristic analysis with LLM-based threat detection.

## Features

✅ **Multi-stage threat detection** (Heuristics + Anomaly Detection)
✅ **50+ semantic features** for attack classification
✅ **Entropy-based anomaly detection** (Mahalanobis distance)
✅ **Attack protection**: SQLi, XSS, Path Traversal, SSRF, XXE, Command Injection
✅ **Feedback loop** for continuous improvement
✅ **Prometheus metrics** for monitoring

## Quick Start

### Local Setup
```bash
git clone https://github.com/Koushik2900/nebulashield.git
cd nebulashield

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

pytest tests/
python -m uvicorn src.api.main:app --reload --port 8080
