import type { Rule, RuleMatch } from "./types.js";

const SQL_INJECTION_PATTERNS = [
  /(?:query|execute|exec|raw)\s*\(\s*[`"'].*\$\{/g,
  /(?:query|execute|exec|raw)\s*\(\s*[^,)]*\+\s*(?:req\.|params\.|query\.|body\.)/g,
  /(?:query|execute|exec|raw)\s*\(\s*`[^`]*\$\{[^}]*(?:req|params|query|body|input|user)/g,
  /f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{.*\}/gi,
  /["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*["']\s*\+\s*\w+/gi,
  /\.format\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
  /cursor\.execute\(\s*f["']/g,
  /cursor\.execute\(\s*["'].*%s/g,
];

export const sqlInjectionRule: Rule = {
  id: "SEC001",
  title: "SQL Injection",
  description:
    "User-controlled input is concatenated or interpolated directly into a SQL query, enabling SQL injection attacks.",
  severity: "critical",
  languages: ["javascript", "typescript", "python", "ruby", "java", "go"],

  detect(content: string, language: string): RuleMatch[] {
    const lines = content.split("\n");
    const matches: RuleMatch[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of SQL_INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          matches.push({
            line: i + 1,
            snippet: line.trim(),
          });
          break;
        }
      }
    }

    return matches;
  },
};
