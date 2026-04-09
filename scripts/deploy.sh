#!/bin/bash
# deploy.sh — Deploy NebulaShield to AWS EC2 (t2.micro, ca-central-1)
#
# Usage:
#   ./scripts/deploy.sh
#
# Prerequisites:
#   - AWS CLI configured (aws configure)
#   - Key pair "nebulashield-key" already created and nebulashield-key.pem present
#     (see docs/AWS_DEPLOYMENT.md step 4)

set -e

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
REGION="ca-central-1"
KEY_NAME="nebulashield-key"
INSTANCE_TYPE="t2.micro"
SECURITY_GROUP="nebulashield-sg"
INSTANCE_NAME="NebulaShield-WAF"
USER_DATA_SCRIPT="scripts/ec2_user_data.sh"

echo "🚀 Deploying NebulaShield to AWS EC2..."
echo "   Region        : $REGION"
echo "   Instance type : $INSTANCE_TYPE"
echo "   Key pair      : $KEY_NAME"

# --------------------------------------------------------------------------- #
# Verify AWS credentials
# --------------------------------------------------------------------------- #
echo ""
echo "🔑 Verifying AWS credentials..."
aws sts get-caller-identity --region "$REGION" > /dev/null

# --------------------------------------------------------------------------- #
# Resolve the latest Amazon Linux 2023 AMI
# --------------------------------------------------------------------------- #
echo ""
echo "🔍 Looking up latest Amazon Linux 2023 AMI..."
AMI_ID=$(aws ec2 describe-images \
  --region "$REGION" \
  --owners amazon \
  --filters \
    "Name=name,Values=al2023-ami-*-x86_64" \
    "Name=state,Values=available" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)

if [ -z "$AMI_ID" ] || [ "$AMI_ID" = "None" ]; then
  echo "❌ Could not find an Amazon Linux 2023 AMI in $REGION. Exiting."
  exit 1
fi
echo "   AMI: $AMI_ID"

# --------------------------------------------------------------------------- #
# Create security group (idempotent — skip if already exists)
# --------------------------------------------------------------------------- #
echo ""
echo "🔒 Setting up security group '$SECURITY_GROUP'..."

SG_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=$SECURITY_GROUP" \
  --query 'SecurityGroups[0].GroupId' \
  --output text 2>/dev/null || true)

if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SECURITY_GROUP" \
    --description "NebulaShield WAF security group" \
    --region "$REGION" \
    --query 'GroupId' \
    --output text)
  echo "   Created security group: $SG_ID"

  for PORT in 22 80 8080 9090; do
    aws ec2 authorize-security-group-ingress \
      --group-id "$SG_ID" \
      --protocol tcp \
      --port "$PORT" \
      --cidr 0.0.0.0/0 \
      --region "$REGION" > /dev/null
    echo "   Opened port $PORT (0.0.0.0/0)"
  done
  echo ""
  echo "   ⚠️  Security note: ports 8080 and 9090 are open to the internet."
  echo "      For production, restrict the CIDR to your IP or a VPN range."
else
  echo "   Reusing existing security group: $SG_ID"
fi

# --------------------------------------------------------------------------- #
# Launch EC2 instance (32GB root disk)
# --------------------------------------------------------------------------- #
echo ""
echo "⚙️  Launching EC2 instance..."

if [ ! -f "$USER_DATA_SCRIPT" ]; then
  echo "❌ User data script not found: $USER_DATA_SCRIPT"
  echo "   Run this script from the repository root directory."
  exit 1
fi

INSTANCE_ID=$(aws ec2 run-instances \
  --region "$REGION" \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --user-data "file://$USER_DATA_SCRIPT" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":32,"DeleteOnTermination":true,"VolumeType":"gp3"}}]' \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "   Instance ID: $INSTANCE_ID"

# --------------------------------------------------------------------------- #
# Wait for instance to be running
# --------------------------------------------------------------------------- #
echo ""
echo "⏳ Waiting for instance to reach 'running' state (this may take ~60 s)..."
aws ec2 wait instance-running \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION"

# --------------------------------------------------------------------------- #
# Retrieve public IP
# --------------------------------------------------------------------------- #
PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

# --------------------------------------------------------------------------- #
# Print summary
# --------------------------------------------------------------------------- #
echo ""
echo "✅ NebulaShield EC2 instance is running!"
echo ""
echo "   Instance ID : $INSTANCE_ID"
echo "   Public IP   : $PUBLIC_IP"
echo "   Region      : $REGION"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Service URLs"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Swagger UI   : http://$PUBLIC_IP:8080/docs"
echo "  WAF Analyze  : http://$PUBLIC_IP:8080/analyze"
echo "  LLM Status   : http://$PUBLIC_IP:8080/llm/status"
echo "  ML Status    : http://$PUBLIC_IP:8080/ml/status"
echo "  Prometheus   : http://$PUBLIC_IP:9090"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  SSH command:"
echo "    ssh -i nebulashield-key.pem ec2-user@$PUBLIC_IP"
echo ""
echo "⚠️  The bootstrap script is running in the background."
echo "   Wait ~3 minutes, then monitor with:"
echo "     ssh -i nebulashield-key.pem ec2-user@$PUBLIC_IP \\"
echo "       'sudo tail -f /var/log/cloud-init-output.log'"
echo ""
echo "   After bootstrap completes, start the app:"
echo "     ssh -i nebulashield-key.pem ec2-user@$PUBLIC_IP"
echo "     cd nebulashield && cp .env.example .env && vi .env"
echo "     docker compose up -d"