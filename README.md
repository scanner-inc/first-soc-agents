# First SOC Agents

Two AI agents for security operations, built with the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk):

1. **SOC Triage Agent** (`lambda/`) - Investigates security alerts via SQS-triggered Lambda. Queries logs through Scanner MCP, classifies severity, and writes structured findings to CloudWatch.

2. **Threat Hunt Agent** (`container/`) - Scheduled ECS Fargate task that combines CISA KEV data with threat intel feeds (ThreatFox, OTX, Feodo Tracker), hunts across historical logs, and posts findings to Slack.

Companion code for the blog series: [Building Your First SOC Agents](https://scanner.dev/blog)

## Prerequisites

- Node.js 22+
- Docker
- Terraform
- AWS CLI (configured with appropriate permissions)
- An [Anthropic API key](https://console.anthropic.com/)
- A [Scanner](https://scanner.dev) account with MCP access
- An [AlienVault OTX](https://otx.alienvault.com/) API key (free)
- An [abuse.ch](https://abuse.ch/) auth key (free)

## Quick Start

```bash
# Install dependencies
./scripts/setup.sh

# Copy and fill in environment variables
cp .env.template .env
# Edit .env with your API keys
```

### SOC Triage Agent (Lambda)

```bash
cd lambda
cp .env.template .env
# Fill in ANTHROPIC_API_KEY and Scanner MCP credentials
./deploy.sh
```

### Threat Hunt Agent (Container)

```bash
cd container
cp .env.template .env
# Fill in all credentials (Anthropic, Scanner, Slack, threat intel APIs)
./deploy.sh
```

## Repo Structure

```
├── lambda/              # SOC triage agent (container-image Lambda)
│   ├── handler.ts       # Lambda function
│   ├── Dockerfile
│   ├── deploy.sh        # Build + deploy pipeline
│   └── terraform/       # Lambda, SQS, IAM, Secrets Manager
├── container/           # Threat hunt agent (ECS Fargate)
│   ├── threat_hunt.ts   # Agent entrypoint
│   ├── Dockerfile
│   ├── deploy.sh        # Build + deploy pipeline
│   └── terraform/       # ECS, VPC, EventBridge, IAM
├── scripts/
│   ├── setup.sh         # Install deps + verify AWS auth
│   └── teardown.sh      # Destroy all infrastructure
├── .env.template        # Root env template (used by scripts/)
└── LICENSE
```

## Teardown

The container agent provisions a NAT gateway (~$32/month). When you're done:

```bash
./scripts/teardown.sh
```

## License

MIT
