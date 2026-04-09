import type { Finding } from "../findings.js";

export interface RuleMatch {
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  metadata?: Record<string, unknown>;
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Finding["severity"];
  languages: string[];
  detect(content: string, language: string): RuleMatch[];
}
