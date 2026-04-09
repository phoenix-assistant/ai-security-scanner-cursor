import type { Rule, RuleMatch } from "./types.js";

const SSRF_PATTERNS = [
  /fetch\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/g,
  /fetch\s*\(\s*[^,)]*\+\s*(?:req\.|params\.|query\.|body\.)/g,
  /fetch\s*\(\s*`[^`]*\$\{[^}]*(?:req|params|query|body|input|url)/g,
  /axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)/g,
  /axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*`[^`]*\$\{/g,
  /(?:http|urllib|requests)\.(?:get|post|put|delete|request)\s*\(\s*(?:request\.|params\[|input)/g,
  /new\s+URL\s*\(\s*(?:req\.|params\.|query\.|body\.)/g,
  /HttpClient.*\.send\s*\(\s*(?:req\.|params\.)/g,
  /open-uri.*\(\s*(?:params|request)/g,
];

export const ssrfRule: Rule = {
  id: "SEC005",
  title: "Server-Side Request Forgery (SSRF)",
  description:
    "User-controlled input is used to make HTTP requests from the server, allowing attackers to access internal services, metadata endpoints, or perform port scanning.",
  severity: "high",
  languages: ["javascript", "typescript", "python", "ruby", "go", "java"],

  detect(content: string, _language: string): RuleMatch[] {
    const lines = content.split("\n");
    const matches: RuleMatch[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of SSRF_PATTERNS) {
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
