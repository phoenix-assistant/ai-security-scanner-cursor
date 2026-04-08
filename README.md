# AI Security Scanner (Cursor for Security)
> The AI-native vulnerability scanner that lives in your editor — finds bugs, explains exploits, and fixes code before you commit.

## Problem

**Who:** Senior engineers and security leads at mid-size tech companies (50–5000 engineers) shipping code fast without dedicated AppSec per team.

**Pain:** Traditional scanners (Snyk, SonarQube, Semgrep) are noisy, context-free, and bolt-on. Engineers get 400 alerts they can't triage, ignore them, and ship vulnerabilities anyway. Average cost of a breach: $4.5M (IBM 2024). AppSec talent shortage: 3.5M unfilled cybersecurity jobs globally.

**Current solutions:** Snyk runs in CI and drowns you in alerts. SonarQube requires DevOps setup. Semgrep is powerful but regex-based with no fix suggestions. None of them have conversational UX. None explain *why* something is dangerous. None feel like a colleague.

## Solution

**What:** An AI-native IDE extension + CLI that detects vulnerabilities inline, explains them in plain English, suggests context-aware fixes, and verifies exploitability before blocking commits.

**How:** LLM-powered analysis over AST + data flow graphs. Pre-commit hook with exploit simulation against sandboxed code. Conversational security assistant that answers "is this actually exploitable?" in seconds.

**Why us:** We're building the UX that Cursor proved works for coding — applied to security. Not a linter. Not a scanner. A security pair programmer.

## Why Now

- Cursor proved developers want AI inline in their editor — security is the obvious next domain
- LLM code understanding has crossed the threshold where false positive rates are manageable
- SEC now requires public companies to disclose cyber incidents within 4 days — compliance pressure is real
- Snyk's recent layoffs and pricing chaos opened a window
- GitHub Copilot's security features are shallow — no exploit verification, no conversational depth

## Market Landscape

**TAM:** $22B — application security market (2024, growing 18% CAGR)
**SAM:** $4B — developer-first security tools (IDE + pre-commit + CI integration)
**Target:** $2M ARR Year 1, $15M ARR Year 3

### Competitors

| Company | Funding | Users | Gap We Exploit |
|---------|---------|-------|----------------|
| Snyk | $530M | 2.5M devs | Alert fatigue, no conversational UX, no inline fix flow |
| SonarQube | $412M | 300K orgs | Requires infra, not developer-native, no AI context |
| Semgrep | $53M | 100K devs | Pattern-based only, no LLM reasoning, no fix suggestions |
| Shannon | OSS (37.5k★) | Unknown | No IDE integration, no commercial support, no exploitability check |
| GitHub Advanced Security | Microsoft | Millions | Surface-level, no explain/fix loop, locked to GitHub |

### Why We Win

Shannon's GitHub stars prove demand for open, developer-native security tooling — but it has no IDE integration, no conversational layer, and no fix pipeline. We build exactly that, open-core, with the conversational UX that engineers actually want. Our moat is the pre-commit exploit sandbox: no one else verifies exploitability before blocking the commit, which eliminates the false-positive problem that kills adoption of every other tool.

## Technical Architecture

```
┌─────────────────────────────────────────────────────┐
│                   IDE Extension                      │
│  (VS Code / JetBrains / Cursor / Neovim LSP)        │
│   inline diagnostics │ chat sidebar │ fix apply      │
└──────────────┬──────────────────────────────────────┘
               │ LSP / gRPC
┌──────────────▼──────────────────────────────────────┐
│              Analysis Engine (local daemon)          │
│   AST parser → data flow → LLM reasoning → verdict  │
│   Languages: Python, JS/TS, Go, Java, Rust, Ruby    │
└──────┬───────────────────────────────────┬──────────┘
       │                                   │
┌──────▼──────┐                   ┌────────▼──────────┐
│  Vuln DB    │                   │  Exploit Sandbox  │
│  (OSV +     │                   │  (WASM container  │
│  NVD +      │                   │   exploit proof   │
│  custom)    │                   │   of concept)     │
└─────────────┘                   └───────────────────┘
       │
┌──────▼──────────────────────────────────────────────┐
│              Pre-commit Hook / CI Gate               │
│   blocks on HIGH+EXPLOITABLE, warns on MEDIUM        │
└─────────────────────────────────────────────────────┘
```

### Stack
| Component | Technology | Why |
|-----------|------------|-----|
| IDE Extension | TypeScript + LSP | Universal IDE support, Cursor/VS Code native |
| Analysis Engine | Rust | Performance — must not slow down typing |
| AST/Data Flow | tree-sitter + custom | Multi-language, battle-tested |
| LLM Reasoning | Claude Sonnet via API (local model option) | Best code reasoning, privacy option |
| Exploit Sandbox | WASM + seccomp | Safe, fast, no VM overhead |
| Vuln Database | SQLite + OSV/NVD sync | Local-first, offline capable |
| CLI/CI | Go | Fast binary distribution |

### Key Technical Decisions
1. **Local daemon, not cloud-only** — Security teams won't send code to cloud. Local daemon processes code, only sends sanitized context to LLM. Enterprise can run fully air-gapped with local model.
2. **Exploit verification before blocking** — False positives kill adoption. We only block commits when we can demonstrate exploitability in the sandbox, not just pattern-match.
3. **Open core** — Core scanner open-source (drives adoption), enterprise features (SSO, audit logs, policy engine, team dashboards) behind paywall.

## Build Plan

**Timeline:** 6 weeks to production-ready v1

### Week 1-2: Foundation
- Rust analysis engine with tree-sitter AST parsing for Python + JS
- LLM integration with prompt templates for vuln reasoning
- SQLite vuln DB synced from OSV
- Basic CLI: `secscanner scan <file>`
- CI/CD: GitHub Actions, release binaries

### Week 3-4: Core Product
- VS Code extension with inline diagnostics (squiggles + hover cards)
- Chat sidebar: "why is this dangerous?" → conversational response
- Fix suggestion with one-click apply
- Pre-commit hook installer (`secscanner install-hook`)
- WASM exploit sandbox for top 10 vuln classes (SQLi, XSS, path traversal, SSRF...)

### Week 5-6: Production Ready
- Go, Java, Rust language support
- JetBrains plugin
- Team policy configuration (YAML)
- Documentation site (Docusaurus)
- Landing page + waitlist
- Telemetry + error reporting (opt-in)

### Month 2-3: Growth
- GitHub Actions integration (CI gate)
- SARIF output for GitHub Security tab
- SSO (SAML/OIDC) — enterprise gate
- Audit log API
- Slack/Teams alerts for new vulns in PRs

### Month 4-6: Moat
- Proprietary vuln intelligence feed from scanning OSS ecosystem
- Team-level vulnerability trending dashboards
- AI remediation campaigns (fix all SQLi in codebase in one session)
- VS Code marketplace + JetBrains marketplace prominence
- Partnerships with security-focused hosting providers

## Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| GitHub ships competitive inline security | H | H | Move faster, deeper exploit verification, open-source moat |
| LLM false positive rate unacceptable | M | H | Exploit sandbox as final gate — only block verified issues |
| Enterprises won't send code to LLM | M | M | Local model support (Ollama/llama.cpp) from day 1 |
| Snyk copies conversational UX | M | M | OSS community moat + speed advantage |
| WASM sandbox escape | L | H | Defense in depth: seccomp + namespace isolation + timeout |

## Monetization

**Model:** Open-core. Free CLI + VS Code extension. Paid: teams, enterprise, CI integration.

**Year 1 Path to $1M ARR:**
| Segment | Price | Customers | ARR |
|---------|-------|-----------|-----|
| Team (5–50 devs) | $49/dev/mo | 200 teams avg 10 devs | $588K |
| Startup (51–200 devs) | $29/dev/mo | 50 companies avg 80 devs | $278K |
| Enterprise POC | $25K/yr | 5 | $125K |
| **Total** | | | **~$991K** |

**Year 3 Vision:** $15M ARR via enterprise expansion (500+ dev orgs at $100K+/yr) and proprietary vuln intelligence subscription.

## Verdict

🟢 BUILD

**Reasoning:** The market timing is exceptional — Cursor proved the "AI in your editor" UX is what developers actually want, and no one has applied it seriously to security. Shannon's 37.5k stars with no IDE integration is a giant flashing signal. The exploit verification sandbox is a genuine technical moat that eliminates the false-positive problem that has killed every previous tool's adoption. This is a $22B market with clear enterprise willingness to pay.

**First customer:** Security-conscious Series B/C startups (Retool, Linear, Vercel-tier companies) whose engineering teams are too fast for traditional AppSec. Reach via GitHub Sponsors on Shannon + Semgrep GitHub Issues + r/netsec launch.
