import { Rule, Finding } from '../types';

const PII_PATTERNS = [
  { regex: /\b(ssn|social.?security|tax.?id)\b.*\b(log|print|console|send|emit|response|res\.json|res\.send)\b/gi, msg: 'Potential SSN/tax ID leakage to output' },
  { regex: /\b(log|print|console|send|emit|response)\b.*\b(ssn|social.?security|tax.?id)\b/gi, msg: 'Potential SSN/tax ID leakage to output' },
  { regex: /\b(password|passwd|secret|credit.?card|card.?number)\b.*\b(log|print|console|send|res\.)\b/gi, msg: 'Sensitive data potentially logged or sent in response' },
  { regex: /\b(log|print|console)\b.*\b(password|passwd|secret|credit.?card)\b/gi, msg: 'Sensitive data potentially logged' },
  { regex: /\b(email|phone|address|dob|date.?of.?birth)\b.*\b(prompt|system_message|messages|completion)\b/gi, msg: 'PII fields referenced in LLM prompt context — potential data leakage to model' },
];

export const piiLeakRule: Rule = {
  id: 'ai-sec/pii-leakage',
  name: 'PII Leakage Detection',
  description: 'Detects patterns where PII may be leaked through logging, responses, or LLM prompts',
  severity: 'warning',
  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const p of PII_PATTERNS) {
        p.regex.lastIndex = 0;
        const m = p.regex.exec(lines[i]);
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
