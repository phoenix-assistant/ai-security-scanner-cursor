import { Rule, Finding } from '../types';

const PATTERNS = [
  { regex: /(\$\{[^}]*\}|` ?\+[^+]*\+).*\b(prompt|system_prompt|messages|chat|completion)\b/gi, msg: 'User input interpolated into LLM prompt — potential prompt injection' },
  { regex: /\b(prompt|system_message|messages)\s*[=:]\s*[`"'].*\$\{/gi, msg: 'Template literal used in prompt construction with interpolation' },
  { regex: /\.(create|chat|complete|generate)\s*\(\s*\{[^}]*(\$\{|` ?\+|\+ *user|\+ *input|\+ *req\.)/gi, msg: 'Dynamic user input passed directly to LLM API call' },
  { regex: /f["'].*\{(user_input|request|query|input|message)\}.*["']\s*#?\s*(prompt|system|llm)/gi, msg: 'F-string with user input in prompt context' },
];

export const promptInjectionRule: Rule = {
  id: 'ai-sec/prompt-injection',
  name: 'Prompt Injection Detection',
  description: 'Detects patterns where user input may be interpolated into LLM prompts without sanitization',
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
            ruleId: this.id,
            severity: this.severity,
            message: p.msg,
            file: filePath,
            line: i + 1,
            column: m.index + 1,
            snippet: lines[i].trim(),
          });
        }
      }
    }
    return findings;
  },
};
