#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
AWS_PROFILE="${AWS_PROFILE:?Set AWS_PROFILE in .env}"

echo "=== Tearing down ALL Part 2 infrastructure ==="
echo "WARNING: This will destroy Lambda, ECS, VPC, NAT gateway, and all related resources."
echo ""

# Source .env for terraform vars
source "$ROOT_DIR/.env"

TF_VARS="-var=anthropic_api_key=$ANTHROPIC_API_KEY -var=scanner_mcp_url=${SCANNER_MCP_URL:-} -var=scanner_mcp_api_key=${SCANNER_MCP_API_KEY:-}"

# Destroy container infra first (has VPC + NAT gateway — costs ~$32/mo!)
echo "--- Destroying container (ECS/VPC) ---"
cd "$ROOT_DIR/container/terraform"
if [ -d ".terraform" ]; then
  terraform destroy -auto-approve $TF_VARS || echo "Container destroy had errors (may not exist)"
else
  echo "Container terraform not initialized, skipping"
fi

# Destroy Lambda infra
echo "--- Destroying Lambda ---"
cd "$ROOT_DIR/lambda/terraform"
if [ -d ".terraform" ]; then
  terraform destroy -auto-approve $TF_VARS || echo "Lambda destroy had errors (may not exist)"
else
  echo "Lambda terraform not initialized, skipping"
fi

# Verify no lingering NAT gateways (costs money!)
echo ""
echo "--- Checking for lingering NAT gateways ---"
NATS=$(aws ec2 describe-nat-gateways --profile "$AWS_PROFILE" --region us-west-2 \
  --filter "Name=state,Values=available" --query 'NatGateways[*].NatGatewayId' --output text 2>/dev/null)

if [ -n "$NATS" ] && [ "$NATS" != "None" ]; then
  echo "WARNING: Found active NAT gateways: $NATS"
  echo "These cost ~\$32/mo each. Delete manually if they're from this project."
else
  echo "No active NAT gateways found. Clean."
fi

echo ""
echo "=== Teardown complete ==="
