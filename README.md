# AI Security Scanner

Scan codebases for AI-specific security vulnerabilities — prompt injection, hardcoded API keys, PII leakage, and missing LLM output validation.

## Install

```bash
npm install -g @phoenixaihub/ai-security-scanner
```

## Usage

```bash
# Scan a directory
ai-sec scan ./src

# SARIF output for GitHub code scanning
ai-sec scan ./src --format sarif --output results.sarif

# Custom rules
ai-sec scan ./src --rules ./my-rules.yaml
```

## Built-in Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `ai-sec/prompt-injection` | error | Detects user input interpolated into LLM prompts |
| `ai-sec/hardcoded-api-key` | error | Finds hardcoded AI service API keys |
| `ai-sec/pii-leakage` | warning | PII data leaked via logs, responses, or LLM prompts |
| `ai-sec/missing-validation` | error | LLM output used in dangerous sinks (eval, innerHTML, exec) |

## Custom Rules (YAML)

```yaml
- id: custom/no-gpt4
  name: No GPT-4 Usage
  description: Enforce GPT-4 usage policy
  severity: warning
  pattern: "gpt-4"
  message: "GPT-4 usage detected — use approved models only"
```

## License

MIT
