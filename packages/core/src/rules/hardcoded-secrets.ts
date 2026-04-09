import type { Rule, RuleMatch } from "./types.js";

const SECRET_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern:
      /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'`][A-Za-z0-9_\-]{16,}["'`]/gi,
    label: "API key",
  },
  {
    pattern:
      /(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`\s]{8,}["'`]/gi,
    label: "Password",
  },
  {
    pattern:
      /(?:secret|token|auth)\s*[:=]\s*["'`][A-Za-z0-9_\-/.+=]{16,}["'`]/gi,
    label: "Secret/Token",
  },
  {
    pattern: /(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["'`][^"'`]+["'`]/gi,
    label: "AWS credential",
  },
  {
    pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
    label: "Private key",
  },
  {
    pattern: /ghp_[A-Za-z0-9]{36,}/g,
    label: "GitHub personal access token",
  },
  {
    pattern: /sk-[A-Za-z0-9]{32,}/g,
    label: "OpenAI API key",
  },
  {
    pattern: /xox[bpas]-[A-Za-z0-9\-]{10,}/g,
    label: "Slack token",
  },
];

export const hardcodedSecretsRule: Rule = {
  id: "SEC003",
  title: "Hardcoded Secret",
  description:
    "A secret, API key, or credential appears to be hardcoded in source code. Secrets should be stored in environment variables or a secrets manager.",
  severity: "critical",
  languages: ["*"],

  detect(content: string, _language: string): RuleMatch[] {
    const lines = content.split("\n");
    const matches: RuleMatch[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comments
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) {
        continue;
      }

      for (const { pattern, label } of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          matches.push({
            line: i + 1,
            snippet: line.trim(),
            metadata: { secretType: label },
          });
          break;
        }
      }
    }

    return matches;
  },
};
