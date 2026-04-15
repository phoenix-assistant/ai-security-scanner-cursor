import { Rule, Finding } from '../types';

const PATTERNS = [
  { regex: /\b(completion|response|result|output|answer|generated)\b\s*[\[.]\s*(text|content|message|choices)\b[^;]*(?:eval|exec|innerHTML|dangerouslySetInnerHTML|child_process|spawn|Function\()/gi, msg: 'LLM response used in dangerous sink without validation' },
  { regex: /\beval\s*\(\s*(completion|response|result|output|llm|ai|generated)/gi, msg: 'LLM output passed to eval() — code injection risk' },
  { regex: /\binnerHTML\s*=\s*(completion|response|result|output|llm|ai)/gi, msg: 'LLM output assigned to innerHTML — XSS risk' },
  { regex: /JSON\.parse\s*\(\s*(completion|response|result|output|llm|ai)\b[^)]*\)\s*(?!.*catch)/gi, msg: 'LLM output parsed as JSON without error handling' },
  { regex: /\b(exec|spawn|execSync)\s*\(\s*(completion|response|result|output|llm|ai)/gi, msg: 'LLM output passed to shell execution — command injection risk' },
];

export const validationRule: Rule = {
  id: 'ai-sec/missing-validation',
  name: 'Missing LLM Output Validation',
  description: 'Detects cases where LLM responses are used without proper validation or sanitization',
  severity: 'error',
  scan(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const p of PATTERNS) {
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
