# 🛡️ AI Security Scanner

[![npm](https://img.shields.io/npm/v/@phoenixaihub/security-scanner-core)](https://www.npmjs.com/package/@phoenixaihub/security-scanner-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/phoenix-assistant/ai-security-scanner-cursor/actions/workflows/ci.yml/badge.svg)](https://github.com/phoenix-assistant/ai-security-scanner-cursor/actions)

**AI-native vulnerability scanner** — finds bugs, explains exploits, and fixes code inline. Fast static analysis with optional LLM-powered explanations.

---

## ⚡ Quick Start

```bash
# Install the CLI
npm install -g @phoenixaihub/secscanner

# Scan a project
secscanner scan ./my-app

# Scan a single file
secscanner scan ./src/auth.ts
```

## 🔍 How It Compares

| Feature | AI Security Scanner | Snyk | SonarQube | Semgrep |
|---------|:------------------:|:----:|:---------:|:-------:|
| Zero-config setup | ✅ | ❌ | ❌ | ✅ |
| AI-powered explanations | ✅ | ❌ | ❌ | ❌ |
| Inline fix suggestions | ✅ | ✅ | ✅ | ❌ |
| VS Code extension | ✅ | ✅ | ✅ | ✅ |
| Free & open source | ✅ | Freemium | Freemium | ✅ |
| Scan-on-save | ✅ | ❌ | ❌ | ❌ |
| No account required | ✅ | ❌ | ❌ | ✅ |
| Offline mode | ✅ | ❌ | ❌ | ✅ |

## 🖥️ CLI Usage

```
$ secscanner scan ./example-app

  🛡️  AI Security Scanner v0.1.0
  ─────────────────────────────────

  Scanning ./example-app ...

  src/auth.ts
    ⚠  L12  SQL Injection — User input concatenated into query string
    🔴 L45  Hardcoded Secret — API key found in source code

  src/server.ts
    ⚠  L8   Command Injection — Unsanitized input passed to exec()
    ⚠  L23  Path Traversal — User-controlled path without validation

  ─────────────────────────────────
  4 vulnerabilities found (1 critical, 3 warning)
  Scanned 12 files in 0.3s
```

## 🧩 VS Code Extension

1. Open VS Code
2. Go to Extensions (`Cmd+Shift+X`)
3. Search for **"AI Security Scanner"**
4. Click **Install**
5. Open any supported file — vulnerabilities appear as inline diagnostics

**Commands:**
- `AI Security Scanner: Scan Current File`
- `AI Security Scanner: Scan Workspace`

**Settings:**
- `aiSecurityScanner.enableOnSave` — Auto-scan on save (default: on)
- `aiSecurityScanner.llm.apiKey` — API key for AI explanations

## 📋 Supported Languages & Rules

| Language | SQL Injection | XSS | Command Injection | Path Traversal | Hardcoded Secrets |
|----------|:---:|:---:|:---:|:---:|:---:|
| JavaScript/TypeScript | ✅ | ✅ | ✅ | ✅ | ✅ |
| Python | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go | ✅ | — | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rust | — | — | ✅ | ✅ | ✅ |
| HTML | — | ✅ | — | — | — |

## 📦 Packages

| Package | Description |
|---------|-------------|
| [`@phoenixaihub/security-scanner-core`](packages/core) | Core scanning engine and rule definitions |
| [`@phoenixaihub/secscanner`](packages/cli) | CLI tool |
| [`@phoenixaihub/vscode-security-scanner`](packages/vscode-extension) | VS Code extension |

## 🗺️ Roadmap

1. **Custom rule authoring** — YAML/JSON DSL for user-defined rules
2. **GitHub Actions integration** — CI/CD scanning workflow
3. **SARIF output** — Standard format for IDE/CI consumption
4. **Auto-fix mode** — Apply AI-suggested fixes automatically
5. **PHP & C# support** — Expand language coverage
6. **Dependency scanning** — Check `package.json` / `requirements.txt` for known CVEs
7. **Severity scoring** — CVSS-aligned risk scores per finding
8. **Monorepo support** — Workspace-aware scanning with deduplication
9. **Pre-commit hook** — Block commits with critical vulnerabilities
10. **Dashboard & reporting** — HTML/PDF vulnerability reports

## 📄 License

MIT
