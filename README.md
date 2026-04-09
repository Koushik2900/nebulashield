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

# NebulaShield - Intelligent WAF with AI-Driven Threat Detection

Advanced Web Application Firewall combining heuristic analysis with LLM-based threat detection.

---

## Features

- ✅ Multi-stage threat detection (Heuristics + Anomaly Detection)
- ✅ 50+ semantic features for attack classification
- ✅ Entropy-based anomaly detection (Mahalanobis distance)
- ✅ Attack protection: SQLi, XSS, Path Traversal, SSRF, XXE, Command Injection
- ✅ Feedback loop for continuous improvement
- ✅ Prometheus metrics for monitoring
- ✅ **Cloud-ready: Automated AWS EC2 deployment with Docker Compose**
- ✅ Built-in API documentation (Swagger /docs endpoint)

---

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
```

---

## ☁️ Cloud Deployment (AWS EC2)

To deploy NebulaShield to the cloud using our automated shell script:

1. **Provision EC2 via deploy script**
    ```bash
    bash scripts/deploy.sh
    ```

    _This script:_
    - Boots an EC2 instance (Amazon Linux 2023, t2.micro, 32GB disk)
    - Sets up a security group for SSH, HTTP, API, and Prometheus ports
    - Installs Docker & Docker Compose, clones this repo, and preps Prometheus

2. **Configure environment variables**
    ```bash
    ssh -i nebulashield-key.pem ec2-user@<your_public_ip>
    cd nebulashield
    cp .env.example .env
    # Edit .env and add your LLM API keys (e.g., GROQ_API_KEY)
    vi .env
    ```

3. **Start the stack**
    ```bash
    docker compose up -d --build
    ```

4. **Verify**
    - Open [`http://<public_ip>:8080/docs`](http://<public_ip>:8080/docs) (Swagger UI)
    - Check API status: `curl http://<public_ip>:8080/llm/status`
    - Prometheus at [`http://<public_ip>:9090`](http://<public_ip>:9090)

---

## Usage

- **API Analysis:**  
  Send HTTP payloads to `/analyze` for threat classification.
- **View API Docs:**  
  [`/docs`](http://<public_ip>:8080/docs) (Swagger/OpenAPI UI)
- **Monitoring:**  
  See Prometheus metrics at `/ml/status` and `/prometheus`

---

## Screenshots

_Add screenshots of Swagger UI, status endpoint, etc. here upon deployment for reviewers._

---

## LICENSE

MIT

---

## Credits

Developed by [Koushik2900](https://github.com/Koushik2900), 2026

