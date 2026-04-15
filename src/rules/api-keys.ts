import { Rule, Finding } from '../types';

const KEY_PATTERNS = [
  { regex: /sk-[a-zA-Z0-9]{20,}/g, msg: 'Hardcoded OpenAI API key detected' },
  { regex: /sk-ant-[a-zA-Z0-9-]{20,}/g, msg: 'Hardcoded Anthropic API key detected' },
  { regex: /sk-or-[a-zA-Z0-9-]{20,}/g, msg: 'Hardcoded OpenRouter API key detected' },
  { regex: /AIza[a-zA-Z0-9_-]{35}/g, msg: 'Hardcoded Google AI API key detected' },
  { regex: /ghp_[a-zA-Z0-9]{36}/g, msg: 'Hardcoded GitHub token detected' },
  { regex: /xai-[a-zA-Z0-9]{20,}/g, msg: 'Hardcoded xAI/Grok API key detected' },
  { regex: /(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY)\s*=\s*["'][^"']{10,}["']/g, msg: 'API key assigned as string literal' },
];

export const apiKeysRule: Rule = {
  id: 'ai-sec/hardcoded-api-key',
  name: 'Hardcoded AI API Key Detection',
  description: 'Detects hardcoded API keys for AI services',
  severity: 'error',
  scan(content: string, filePath: string): Finding[] {
    if (/\.(md|txt|lock)$/.test(filePath)) return [];
    const findings: Finding[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*(\/\/|#|\/\*|\*)/.test(line) && /example|placeholder|dummy|test|fake/i.test(line)) continue;
      for (const p of KEY_PATTERNS) {
        p.regex.lastIndex = 0;
        const m = p.regex.exec(line);
        if (m) {
          findings.push({
            ruleId: this.id, severity: this.severity, message: p.msg,
            file: filePath, line: i + 1, column: m.index + 1, snippet: lines[i].trim(),
          });
        }
      }
    }
    return findings;
  },
};
