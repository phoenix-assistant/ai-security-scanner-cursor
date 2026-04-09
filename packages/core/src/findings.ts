export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  explanation?: string;
  fix?: string;
  ruleId: string;
  language: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  duration: number;
}
