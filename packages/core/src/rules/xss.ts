import type { Rule, RuleMatch } from "./types.js";

const XSS_PATTERNS = [
  /\.innerHTML\s*=\s*(?!['"`]<)/g,
  /\.outerHTML\s*=\s*(?!['"`]<)/g,
  /document\.write\s*\(/g,
  /document\.writeln\s*\(/g,
  /\.insertAdjacentHTML\s*\(/g,
  /dangerouslySetInnerHTML\s*=\s*\{/g,
  /\beval\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/g,
  /v-html\s*=/g,
  /\[innerHTML\]\s*=/g,
  /\{\{\{.*\}\}\}/g,
  /\|safe\b/g,
  /mark_safe\s*\(/g,
];

export const xssRule: Rule = {
  id: "SEC002",
  title: "Cross-Site Scripting (XSS)",
  description:
    "Unsanitized data is rendered as HTML, allowing attackers to inject malicious scripts into web pages.",
  severity: "high",
  languages: [
    "javascript",
    "typescript",
    "html",
    "python",
    "ruby",
    "vue",
    "svelte",
  ],

  detect(content: string, _language: string): RuleMatch[] {
    const lines = content.split("\n");
    const matches: RuleMatch[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of XSS_PATTERNS) {
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
