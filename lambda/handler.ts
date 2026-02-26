// handler.ts — Lambda function using @anthropic-ai/claude-agent-sdk
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { McpHttpServerConfig } from "@anthropic-ai/claude-agent-sdk";
import type { Handler } from "aws-lambda";

// Allow running inside another Claude Code session (e.g., during testing)
delete process.env.CLAUDECODE;

const SYSTEM_PROMPT = `You are a security alert triage agent. Investigate each alert using
the following methodology:

**Phase 1: Initial Assessment & Hypothesis Generation**
1. Review the alert details and understand what it detected.
2. Generate 2-4 hypotheses ranked by probability:
   - Benign explanation (legitimate user activity, known process)
   - Misconfiguration (incorrect rule, system issue)
   - Actual attack (malicious activity, compromise)
   - Insider threat (authorized user acting maliciously)
3. For each hypothesis, identify what evidence would confirm or refute it.

**Phase 2: Evidence Collection**
4. Collect targeted evidence to test your hypotheses:
   - Query events BEFORE, DURING, and AFTER the alert (4-6 hour window)
   - Look for the same source (user/IP/account/system)
   - Think adversarially: if this were an attack, what would the attacker do next?
5. Check for expansion indicators:
   - Privilege escalation attempts or role changes
   - Lateral movement or unusual network connections
   - Data access anomalies or exfiltration patterns
   - Persistence mechanisms (new users, scheduled tasks, backdoors)
   - Multiple failed attempts followed by success

**Phase 3: Classification**
6. Classify the alert:
   - BENIGN: The weight of evidence points to legitimate activity. This includes
     cases where the activity pattern is well-established (recurring user, known IP,
     business hours, expected role chains) even if some fields are redacted or
     unavailable — redacted parameters are a visibility gap to note, not evidence
     of malice. If you can explain WHO did it, WHY it's expected, and there are
     ZERO indicators of compromise, classify as BENIGN.
   - SUSPICIOUS: There are concrete anomalies that don't fit legitimate patterns —
     e.g., new IP, unusual time, unexpected role, first-time access, failed attempts
     before success. Gaps in visibility alone do not make something suspicious.
   - MALICIOUS: High confidence evidence of attack with corroborating indicators
     (e.g., known-bad IOCs, persistence mechanisms, data exfiltration, multiple
     ATT&CK techniques chained together).
7. Assign confidence:
   - high (80-100%): Multiple independent evidence sources support conclusion
   - medium (60-79%): Moderate support with some gaps or contradictions
   - low (0-59%): Insufficient evidence to confidently support any hypothesis

**Phase 4: Self-Critique** (run twice)
8. After your initial classification, critique your own analysis:
   - What evidence might you have missed?
   - Are there alternative explanations you didn't consider?
   - Is your confidence level justified by the evidence?
   - What would change your classification?
   Revise your assessment if the critique reveals weaknesses.

Respond with a JSON object:
{
    "classification": "BENIGN|SUSPICIOUS|MALICIOUS",
    "confidence": "high|medium|low",
    "confidence_pct": 85,
    "summary": "Two-sentence TL;DR: what happened and what the classification means",
    "timeline": [
        {"timestamp": "ISO8601", "event": "Description of what happened"}
    ],
    "hypothesis_testing": {
        "confirmed": "The hypothesis supported by evidence, with reasoning",
        "ruled_out": [
            "Alternative 1: why ruled out with specific evidence",
            "Alternative 2: why ruled out with specific evidence"
        ]
    },
    "key_evidence": [
        "Evidence point 1 with technical details (IPs, users, timestamps)",
        "Evidence point 2"
    ],
    "mitre_attack": ["T1078 Valid Accounts", "T1550.004 Use Alternate Auth Material"],
    "next_questions": [
        "Question the analyst should ask to continue this investigation",
        "Question that would confirm or change the classification"
    ]
}

Notes on fields:
- "mitre_attack": Only populate for MALICIOUS classifications. Empty list otherwise.
- "timeline": Chronological events from your investigation window, not just the alert itself.
  Include pre-alert context, the alert trigger, and any post-alert activity.
- "confidence_pct": Integer 0-100 matching your confidence level.
- "next_questions": Do NOT give prescriptive actions ("disable this account", "block this IP").
  Instead, propose questions that guide the analyst's investigation: "Is this user authorized
  to access this system?", "Was there a change ticket for this access?", "Does this IP belong
  to a known VPN provider?" Questions acknowledge uncertainty and keep the analyst in control.`;

function scannerMcpConfig(): Record<string, McpHttpServerConfig> {
  const url = process.env.SCANNER_MCP_URL;
  if (!url) return {};

  return {
    scanner: {
      type: "http",
      url,
      headers: {
        Authorization: `Bearer ${process.env.SCANNER_MCP_API_KEY || ""}`,
      },
    },
  };
}

export function extractJson(text: string): Record<string, unknown> {
  const trimmed = text.trim();

  try {
    return JSON.parse(trimmed);
  } catch {
    // continue to fallback strategies
  }

  const codeBlockMatch = trimmed.match(/```(?:json)?\s*\n([\s\S]*?)```/);
  if (codeBlockMatch) {
    try {
      return JSON.parse(codeBlockMatch[1].trim());
    } catch {
      // continue
    }
  }

  const braceMatch = trimmed.match(/\{[\s\S]*\}/);
  if (braceMatch) {
    try {
      return JSON.parse(braceMatch[0]);
    } catch {
      // continue
    }
  }

  throw new Error(`Could not extract JSON from response: ${trimmed.slice(0, 200)}...`);
}

export const handler: Handler = async (rawEvent) => {
  // Unwrap SQS event envelope if present
  const event =
    rawEvent.Records?.[0]?.body != null
      ? JSON.parse(rawEvent.Records[0].body)
      : rawEvent;

  const { alert_id, alert_summary } = event;

  if (!alert_id || !alert_summary) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing alert_id or alert_summary" }),
    };
  }

  const start = Date.now();

  try {
    const mcpServers = scannerMcpConfig();
    const allowedTools = Object.keys(mcpServers).length > 0 ? ["mcp__scanner__*"] : [];

    const q = query({
      prompt: `Triage this alert.\n\n**Alert ID**: ${alert_id}\n**Summary**: ${alert_summary}`,
      options: {
        model: process.env.MODEL || "claude-opus-4-6",
        systemPrompt: SYSTEM_PROMPT,
        permissionMode: "bypassPermissions",
        allowDangerouslySkipPermissions: true,
        mcpServers,
        allowedTools,
      },
    });

    let resultText: string | undefined;
    for await (const message of q) {
      if (message.type === "assistant") {
        for (const block of message.message.content) {
          if (block.type === "tool_use") {
            console.log(JSON.stringify({
              alert_id,
              step: "tool_call",
              tool: block.name,
              input: block.input,
            }));
          }
        }
      }
      if (message.type === "result" && message.subtype === "success") {
        resultText = message.result;
      }
    }

    if (!resultText) {
      return {
        statusCode: 200,
        body: JSON.stringify({
          alert_id,
          result: {
            classification: "SUSPICIOUS",
            confidence: "low",
            summary: "Agent returned no result",
            key_evidence: [],
            next_questions: ["Manual review required"],
          },
        }),
      };
    }

    const result = extractJson(resultText);
    const durationMs = Date.now() - start;

    console.log(
      JSON.stringify({
        alert_id,
        classification: result.classification,
        confidence: result.confidence,
        duration_ms: durationMs,
        model: process.env.MODEL || "claude-opus-4-6",
      })
    );

    return {
      statusCode: 200,
      body: JSON.stringify({ alert_id, result }),
    };
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    console.log(JSON.stringify({ alert_id, error }));
    return {
      statusCode: 500,
      body: JSON.stringify({ alert_id, error }),
    };
  }
};
