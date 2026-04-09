import type { Finding, ScanResult } from "./findings.js";
import type { Rule } from "./rules/types.js";
import { builtinRules } from "./rules/index.js";

export interface ScanOptions {
  rules?: Rule[];
  file?: string;
}

export class Scanner {
  private readonly rules: Rule[];

  constructor(rules?: Rule[]) {
    this.rules = rules ?? builtinRules;
  }

  scan(content: string, language: string, options?: ScanOptions): ScanResult {
    const start = performance.now();
    const findings: Finding[] = [];
    const file = options?.file ?? "<stdin>";

    const applicableRules = this.rules.filter(
      (rule) => rule.languages.includes("*") || rule.languages.includes(language)
    );

    for (const rule of applicableRules) {
      const matches = rule.detect(content, language);

      for (const match of matches) {
        findings.push({
          id: `${rule.id}-${match.line}`,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          file,
          line: match.line,
          column: match.column,
          endLine: match.endLine,
          endColumn: match.endColumn,
          snippet: match.snippet,
          ruleId: rule.id,
          language,
        });
      }
    }

    // Sort by severity (critical first), then by line
    const severityOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };

    findings.sort((a, b) => {
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.line - b.line;
    });

    return {
      findings,
      filesScanned: 1,
      duration: performance.now() - start,
    };
  }

  static inferLanguage(filename: string): string {
    const ext = filename.split(".").pop()?.toLowerCase() ?? "";
    const map: Record<string, string> = {
      js: "javascript",
      jsx: "javascript",
      ts: "typescript",
      tsx: "typescript",
      py: "python",
      rb: "ruby",
      go: "go",
      java: "java",
      rs: "rust",
      html: "html",
      vue: "vue",
      svelte: "svelte",
    };
    return map[ext] ?? ext;
  }
}
