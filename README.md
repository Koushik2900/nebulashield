# NebulaShield - Intelligent WAF with AI-Driven Threat Detection

**Advanced Web Application Firewall combining heuristic analysis with LLM-based threat detection, deployed on AWS EC2 with Docker Compose.**

![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green?logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- ✅ **Multi-stage threat detection** — Heuristics + ML Classifier + LLM analysis
- ✅ **50+ semantic features** for attack classification
- ✅ **Entropy-based anomaly detection** using Mahalanobis distance
- ✅ **Attack protection**: SQLi, XSS, Path Traversal, SSRF, XXE, Command Injection
- ✅ **Multiple LLM backends**: Groq, Gemini, OpenRouter, OpenAI, Ollama
- ✅ **ML classifier** with auto-training and feedback-driven retraining
- ✅ **Feedback/retraining loop** for continuous improvement
- ✅ **Prometheus metrics** for real-time monitoring
- ✅ **Cloud-ready**: Automated AWS EC2 deployment with Docker Compose
- ✅ **Built-in API docs** via Swagger UI (`/docs`)

---

## Architecture

```
┌──────────────┐         ┌──────────────────────────────────────┐         ┌────────────────┐
│              │         │        AWS EC2 (Docker Compose)      │         │                │
│   Client     │ ──────► │  ┌──────────────────────────────┐   │ ──────► │   Groq / LLM   │
│  (Browser /  │         │  │     NebulaShield WAF API     │   │         │   API Backend   │
│   Postman /  │         │  │         (Port 8080)          │   │         │                │
│    curl)     │         │  │                              │   │         └────────────────┘
│              │         │  │  ┌─────────┐ ┌───────────┐   │   │
└──────────────┘         │  │  │Heuristic│ │ ML Model  │   │   │
                         │  │  │ Engine  │ │Classifier │   │   │
                         │  │  └─────────┘ └───────────┘   │   │
                         │  │  ┌─────────┐ ┌───────────┐   │   │
                         │  │  │Feedback │ │  SQLite   │   │   │
                         │  │  │  Loop   │ │    DB     │   │   │
                         │  │  └─────────┘ └───────────┘   │   │
                         │  └──────────────────────────────┘   │
                         │  ┌──────────────────────────────┐   │
                         │  │   Prometheus (Port 9090)     │   │
                         │  └──────────────────────────────┘   │
                         └──────────────────────────────────────┘
```

**Request Flow:**
1. Client sends HTTP request → WAF middleware intercepts
2. **Stage 1 — Heuristics**: 50+ feature extraction + pattern matching + entropy analysis
3. **Stage 2 — ML Classifier**: Scikit-learn model predicts threat probability
4. **Stage 3 — LLM Analysis** (grey zone 30–70): Groq/Gemini/OpenAI provides second opinion
5. **Weighted score fusion** → BLOCK (>60) or ALLOW
6. All decisions logged to SQLite; analyst feedback drives retraining

---

## Quick Start

### Local Setup

```bash
git clone https://github.com/Koushik2900/nebulashield.git
cd nebulashield

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start the server
python -m uvicorn src.api.main:app --reload --port 8080
```

Open [http://localhost:8080/docs](http://localhost:8080/docs) for Swagger UI.

### Docker (Local)

```bash
cp .env.example .env
# Edit .env with your API key (e.g. GROQ_API_KEY)
docker compose up -d --build
```

---

## ☁️ Cloud Deployment (AWS EC2)

### Automated

```bash
bash scripts/deploy.sh
```

This creates an EC2 instance (Amazon Linux 2023, t2.micro free tier, `ca-central-1`), configures security groups, and bootstraps Docker.

### Manual

```bash
ssh -i nebulashield-key.pem ec2-user@<EC2_PUBLIC_IP>

# On the EC2 instance
sudo yum update -y
sudo yum install -y docker git
sudo systemctl start docker
sudo usermod -aG docker ec2-user

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

git clone https://github.com/Koushik2900/nebulashield.git
cd nebulashield
cp .env.example .env
# Edit .env and add your LLM API key
docker compose up -d --build
```

For full step-by-step instructions, see [docs/AWS_DEPLOYMENT.md](docs/AWS_DEPLOYMENT.md).

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Analyze a payload for threats |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `POST` | `/feedback` | Submit analyst feedback |
| `POST` | `/retrain` | Trigger ML model retraining |
| `GET` | `/docs` | Swagger UI (interactive API docs) |

### Example: Analyze a Payload

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"payload": "SELECT * FROM users WHERE id=1 OR 1=1"}'
```

**Response:**
```json
{
  "action": "BLOCK",
  "threat_score": 85,
  "heuristic_score": 80,
  "ml_score": 90,
  "llm_verdict": "malicious",
  "attack_types": ["sql_injection"],
  "reasoning": "Classic SQL injection pattern detected with boolean-based bypass"
}
```

---

## Configuration

Copy `.env.example` to `.env` and set your preferred LLM backend:

```env
# LLM Backend: groq (default), gemini, openrouter, openai, ollama
LLM_BACKEND=groq

# Groq (free, fastest) — https://console.groq.com/
GROQ_API_KEY=gsk_your_key_here

# Google Gemini (free) — https://aistudio.google.com/apikey
GEMINI_API_KEY=your_key_here

# OpenRouter (free models) — https://openrouter.ai/keys
OPENROUTER_API_KEY=sk-or-your_key_here

# OpenAI (paid) — https://platform.openai.com/api-keys
OPENAI_API_KEY=sk-your_key_here

# Ollama (local, free) — requires Ollama installed locally
OLLAMA_URL=http://ollama:11434
```

---

## Project Structure

```
nebulashield/
├── src/
│   ├── api/
│   │   ├── main.py          # FastAPI application, routes
│   │   └── feedback.py      # Feedback & retraining endpoints
│   └── analyzer/
│       ├── threat_analyzer.py   # Heuristic engine + feature extraction
│       ├── ml_classifier.py     # Scikit-learn ML classifier
│       └── llm_analyzer.py      # LLM backend integrations
├── tests/                   # Pytest test suite
├── scripts/
│   ├── deploy.sh            # AWS EC2 automated deployment
│   └── train_model.py       # Standalone model training script
├── docs/
│   └── AWS_DEPLOYMENT.md    # Full cloud deployment guide
├── data/                    # Training data
├── models/                  # Saved ML model artifacts
├── docker-compose.yml
├── Dockerfile
├── prometheus.yml
├── requirements.txt
└── .env.example
```

---

## Testing

```bash
# Run full test suite
pytest tests/ -v

# Run specific test file
pytest tests/test_threat_analyzer.py -v
pytest tests/test_ml_classifier.py -v
pytest tests/test_api.py -v
```

See [TESTING_REPORT.md](TESTING_REPORT.md) for the full test report.

---

## License

MIT — see [LICENSE](LICENSE) for details.
