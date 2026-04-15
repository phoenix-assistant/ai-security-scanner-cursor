export interface Finding {
  ruleId: string;
  severity: 'error' | 'warning' | 'note';
  message: string;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: 'error' | 'warning' | 'note';
  scan(content: string, filePath: string): Finding[];
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  rulesApplied: number;
}

export interface CustomRuleConfig {
  id: string;
  name: string;
  description: string;
  severity: 'error' | 'warning' | 'note';
  pattern: string;
  message: string;
}

export interface SarifReport {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: { driver: { name: string; version: string; rules: SarifRule[] } };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

export interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number; startColumn: number } } }[];
}
