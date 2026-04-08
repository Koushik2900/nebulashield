# NebulaShield — AWS EC2 Deployment Guide

Deploy NebulaShield to AWS EC2 (t2.micro free tier) in the `ca-central-1` region with a single script.

---

## Prerequisites

### 1. Install AWS CLI

**Windows:**
```powershell
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

**macOS:**
```bash
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o AWSCLIV2.pkg
sudo installer -pkg AWSCLIV2.pkg -target /
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Verify installation:**
```bash
aws --version
# Expected: aws-cli/2.x.x Python/3.x.x ...
```

---

### 2. Create AWS Access Key

1. Sign in to the [AWS Console](https://console.aws.amazon.com/)
2. Navigate to **IAM → Users → Your User → Security Credentials**
3. Click **Create Access Key** → choose **CLI** → click **Next** → **Create Access Key**
4. **Save** both values — you cannot retrieve the Secret Access Key again:
   - Access Key ID (e.g. `AKIAIOSFODNN7EXAMPLE`)
   - Secret Access Key (e.g. `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`)

> **Tip:** Store them in a password manager immediately.

---

### 3. Configure AWS CLI

```bash
aws configure
# AWS Access Key ID [None]:     <paste your Access Key ID>
# AWS Secret Access Key [None]: <paste your Secret Access Key>
# Default region name [None]:   ca-central-1
# Default output format [None]: json
```

**Verify configuration:**
```bash
aws sts get-caller-identity
```
Expected output:
```json
{
    "UserId": "AIDAIOSFODNN7EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-user"
}
```

---

### 4. Create EC2 Key Pair

**Linux / macOS:**
```bash
aws ec2 create-key-pair \
  --key-name nebulashield-key \
  --region ca-central-1 \
  --query 'KeyMaterial' \
  --output text > nebulashield-key.pem

chmod 400 nebulashield-key.pem
```

**Windows PowerShell:**
```powershell
aws ec2 create-key-pair `
  --key-name nebulashield-key `
  --region ca-central-1 `
  --query 'KeyMaterial' `
  --output text | Out-File -Encoding ascii nebulashield-key.pem
```

> Keep `nebulashield-key.pem` in the same directory as the deploy script, or pass its path via `--key-file`.

---

## Deployment

### 5. Create Security Group

The deploy script handles this automatically. To do it manually:

> **Security note:** The commands below open each port to `0.0.0.0/0` (the entire internet) for convenience. For production or long-running deployments, replace `0.0.0.0/0` with your own IP address (e.g. `203.0.113.10/32`) to limit exposure of the WAF API and Prometheus endpoints.

```bash
# Create the group
aws ec2 create-security-group \
  --group-name nebulashield-sg \
  --description "NebulaShield WAF" \
  --region ca-central-1

# Allow SSH
aws ec2 authorize-security-group-ingress \
  --group-name nebulashield-sg \
  --protocol tcp --port 22 \
  --cidr 0.0.0.0/0 \
  --region ca-central-1

# Allow HTTP
aws ec2 authorize-security-group-ingress \
  --group-name nebulashield-sg \
  --protocol tcp --port 80 \
  --cidr 0.0.0.0/0 \
  --region ca-central-1

# Allow WAF API
aws ec2 authorize-security-group-ingress \
  --group-name nebulashield-sg \
  --protocol tcp --port 8080 \
  --cidr 0.0.0.0/0 \
  --region ca-central-1

# Allow Prometheus
aws ec2 authorize-security-group-ingress \
  --group-name nebulashield-sg \
  --protocol tcp --port 9090 \
  --cidr 0.0.0.0/0 \
  --region ca-central-1
```

---

### 6. Run the Deploy Script

From the root of the cloned repository:

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

The script will:
1. Look up the latest Amazon Linux 2023 AMI in `ca-central-1`
2. Create (or reuse) the `nebulashield-sg` security group
3. Launch a `t2.micro` instance with the EC2 user-data bootstrap script
4. Wait for the instance to reach the **running** state
5. Print the public IP address and all service URLs

---

### 7. SSH into the Instance

```bash
ssh -i nebulashield-key.pem ec2-user@<PUBLIC_IP>
```

Once inside, the bootstrap script is still running in the background. Monitor it with:

```bash
sudo tail -f /var/log/cloud-init-output.log
```

Wait until you see `NebulaShield bootstrap complete` before accessing the services.

---

### 8. Deploy with Docker Compose

After SSH-ing in (or after the bootstrap finishes):

```bash
cd /home/ec2-user/nebulashield

# Copy your .env file (from your local machine):
# scp -i nebulashield-key.pem .env ec2-user@<PUBLIC_IP>:/home/ec2-user/nebulashield/.env

cp .env.example .env
# Edit the .env file and add your GROQ_API_KEY (or another LLM key)
nano .env

# Start all services
docker compose up -d
```

---

### 9. Access the Live API

Replace `<PUBLIC_IP>` with the IP printed by the deploy script:

| Service | URL |
|---------|-----|
| Swagger UI (interactive docs) | `http://<PUBLIC_IP>:8080/docs` |
| WAF Analyze Endpoint | `http://<PUBLIC_IP>:8080/analyze` |
| LLM Status | `http://<PUBLIC_IP>:8080/llm/status` |
| ML Model Status | `http://<PUBLIC_IP>:8080/ml/status` |
| Prometheus Metrics | `http://<PUBLIC_IP>:9090` |

**Quick smoke test:**
```bash
curl -s http://<PUBLIC_IP>:8080/health | python3 -m json.tool
```

---

## Stopping / Cleaning Up

**Stop the instance (no compute charge while stopped; EBS storage charges still apply):**
```bash
aws ec2 stop-instances --instance-ids <INSTANCE_ID> --region ca-central-1
```

**Terminate the instance (deletes everything):**
```bash
aws ec2 terminate-instances --instance-ids <INSTANCE_ID> --region ca-central-1
```

**Delete the security group (after instance is terminated):**
```bash
aws ec2 delete-security-group --group-name nebulashield-sg --region ca-central-1
```

**Delete the key pair:**
```bash
aws ec2 delete-key-pair --key-name nebulashield-key --region ca-central-1
rm -f nebulashield-key.pem
```

---

## Troubleshooting

### `Unable to locate credentials`
Run `aws configure` and verify the Access Key ID / Secret Access Key are correct.

### `InvalidKeyPair.NotFound`
The key pair does not exist in `ca-central-1`. Re-run step 4 to create it.

### `InvalidGroup.Duplicate` when creating security group
The group already exists — the deploy script handles this automatically. If running manually, skip the `create-security-group` step and proceed with `authorize-security-group-ingress`.

### SSH: `Permission denied (publickey)`
- Confirm you are using the correct `.pem` file: `ssh -i nebulashield-key.pem ec2-user@<IP>`
- Confirm the permissions are correct: `chmod 400 nebulashield-key.pem`
- The instance may still be booting — wait 60–90 seconds and retry.

### Port 8080 not reachable
- Confirm the security group has port 8080 open (step 5).
- Confirm Docker Compose started successfully: `docker compose ps` on the instance.
- Check container logs: `docker compose logs nebula-waf`

### Docker Compose not found
The bootstrap script installs Docker Compose during first launch. If it hasn't finished yet:
```bash
sudo tail -f /var/log/cloud-init-output.log
```
Wait for the script to complete, then retry.

### `No space left on device`
The t2.micro root volume is 8 GB by default. To increase it:
```bash
aws ec2 modify-volume --volume-id <VOL_ID> --size 20 --region ca-central-1
# Then grow the file system on the instance:
sudo growpart /dev/xvda 1
sudo xfs_growfs /
```

### Instance stuck in `pending` state
Wait up to 5 minutes. If it does not transition to `running`, check the EC2 console for system status checks, then terminate and re-run `deploy.sh`.
