#!/bin/bash
# EC2 User Data — NebulaShield bootstrap script
# Runs automatically as root when the instance first launches.
# Progress is logged to /var/log/cloud-init-output.log

set -e

echo "=== NebulaShield bootstrap starting ==="

# --------------------------------------------------------------------------- #
# 1. System update
# --------------------------------------------------------------------------- #
yum update -y

# --------------------------------------------------------------------------- #
# 2. Install Docker
# --------------------------------------------------------------------------- #
# Amazon Linux 2023 ships docker via the standard repos
yum install docker -y || amazon-linux-extras install docker -y

systemctl start docker
systemctl enable docker

# Allow ec2-user to run docker without sudo
usermod -a -G docker ec2-user

# --------------------------------------------------------------------------- #
# 3. Install Docker Compose (standalone binary)
# --------------------------------------------------------------------------- #
COMPOSE_VERSION=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest \
  | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$COMPOSE_VERSION" ]; then
  echo "ERROR: Could not determine the latest Docker Compose version from GitHub API." >&2
  exit 1
fi

curl -fsSL \
  "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose

chmod +x /usr/local/bin/docker-compose

# Also expose it as the `docker compose` plugin
mkdir -p /usr/local/lib/docker/cli-plugins
ln -sf /usr/local/bin/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose

# --------------------------------------------------------------------------- #
# 4. Install git
# --------------------------------------------------------------------------- #
yum install git -y

# --------------------------------------------------------------------------- #
# 5. Clone NebulaShield
# --------------------------------------------------------------------------- #
cd /home/ec2-user
if ! git clone https://github.com/Koushik2900/nebulashield.git; then
  echo "ERROR: Failed to clone the NebulaShield repository. Check network connectivity and the repository URL." >&2
  exit 1
fi
chown -R ec2-user:ec2-user nebulashield

echo "=== NebulaShield bootstrap complete ==="
echo "Next steps (as ec2-user):"
echo "  cd /home/ec2-user/nebulashield"
echo "  cp .env.example .env && nano .env   # add your LLM API key"
echo "  docker compose up -d"
