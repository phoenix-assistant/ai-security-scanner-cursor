# Contributing to AI Security Scanner

Thanks for your interest in contributing! This project is open-core — the scanner engine, CLI, and VS Code extension are MIT-licensed and open to contributions.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/your-org/ai-security-scanner.git
cd ai-security-scanner

# Install dependencies
npm install

# Build all packages
npm run build

# Run the CLI
node packages/cli/bin/secscanner.js scan <file>
```

## Project Structure

```
packages/
  core/       — Scanner engine, rules, LLM client
  cli/        — Command-line interface
  vscode-extension/ — VS Code extension
```

## Adding a New Rule

1. Create a file in `packages/core/src/rules/`
2. Implement the `Rule` interface from `types.ts`
3. Export and register it in `packages/core/src/rules/index.ts`
4. Add tests

### Rule Interface

```typescript
interface Rule {
  id: string;          // e.g. "SEC006"
  title: string;       // Human-readable name
  description: string; // What the vulnerability is
  severity: Severity;  // critical | high | medium | low | info
  languages: string[]; // Which languages this applies to, or ["*"]
  detect(content: string, language: string): RuleMatch[];
}
```

## Code Style

- TypeScript strict mode
- ESM modules
- No `any` types
- Descriptive variable names

## Pull Requests

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Ensure `npm run build` passes
5. Submit a PR with a clear description

## Reporting Security Issues

If you find a security vulnerability in the scanner itself, please email security@ai-security-scanner.dev instead of opening a public issue.
