import type { Rule, RuleMatch } from "./types.js";

const PATH_TRAVERSAL_PATTERNS = [
  /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/g,
  /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*[^,)]*\+\s*(?:req\.|params\.|query\.|body\.)/g,
  /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*`[^`]*\$\{/g,
  /path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)/g,
  /open\(\s*(?:request\.|params\[|f["'])/g,
  /send_file\s*\(\s*(?:params|request)/g,
  /\.\.\/|\.\.\\|%2e%2e/gi,
  /os\.path\.join\s*\([^)]*(?:request\.|input)/g,
];

export const pathTraversalRule: Rule = {
  id: "SEC004",
  title: "Path Traversal",
  description:
    "User-controlled input is used to construct file system paths without sanitization, allowing attackers to read or write arbitrary files.",
  severity: "high",
  languages: ["javascript", "typescript", "python", "ruby", "go", "java"],

  detect(content: string, _language: string): RuleMatch[] {
    const lines = content.split("\n");
    const matches: RuleMatch[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of PATH_TRAVERSAL_PATTERNS) {
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
