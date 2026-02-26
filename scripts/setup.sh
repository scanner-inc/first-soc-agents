#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo "=== Part 2 Environment Setup ==="

# Install Lambda deps
echo "Installing Lambda deps..."
cd "$ROOT_DIR/lambda"
npm install

# Install Container deps
echo "Installing Container deps..."
cd "$ROOT_DIR/container"
npm install

cd "$ROOT_DIR"

# Check .env
if [ ! -f ".env" ]; then
    echo "WARNING: No .env file found. Copy .env.template to .env and fill in values."
fi

# Check AWS auth
AWS_PROFILE="${AWS_PROFILE:?Set AWS_PROFILE in .env}"
echo "Checking AWS auth (profile: $AWS_PROFILE)..."
if aws sts get-caller-identity --profile "$AWS_PROFILE" > /dev/null 2>&1; then
    echo "AWS auth OK: $(aws sts get-caller-identity --profile "$AWS_PROFILE" --query 'Account' --output text)"
else
    echo "WARNING: AWS auth failed. Run: aws sso login --profile $AWS_PROFILE"
fi

echo "=== Setup complete ==="
