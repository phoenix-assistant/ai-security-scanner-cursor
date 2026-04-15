import { Finding, ScanResult, SarifReport } from './types';

export function formatText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`\n🔍 AI Security Scanner Results`);
  lines.push(`   Files scanned: ${result.filesScanned} | Rules applied: ${result.rulesApplied} | Findings: ${result.findings.length}\n`);

  if (result.findings.length === 0) {
    lines.push('✅ No issues found.\n');
    return lines.join('\n');
  }

  const grouped = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const arr = grouped.get(f.ruleId) || [];
    arr.push(f);
    grouped.set(f.ruleId, arr);
  }

  for (const [ruleId, findings] of grouped) {
    const icon = findings[0].severity === 'error' ? '❌' : findings[0].severity === 'warning' ? '⚠️' : 'ℹ️';
    lines.push(`${icon} ${ruleId} (${findings.length} finding${findings.length > 1 ? 's' : ''})`);
    for (const f of findings) {
      lines.push(`   ${f.file}:${f.line}:${f.column} — ${f.message}`);
      if (f.snippet) lines.push(`   │ ${f.snippet}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function formatSarif(result: ScanResult): SarifReport {
  const ruleMap = new Map<string, Finding>();
  for (const f of result.findings) {
    if (!ruleMap.has(f.ruleId)) ruleMap.set(f.ruleId, f);
  }

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ai-security-scanner',
          version: '1.0.0',
          rules: Array.from(ruleMap.entries()).map(([id, f]) => ({
            id,
            name: id,
            shortDescription: { text: f.message },
            defaultConfiguration: { level: f.severity === 'note' ? 'note' : f.severity },
          })),
        },
      },
      results: result.findings.map((f) => ({
        ruleId: f.ruleId,
        level: f.severity === 'note' ? 'note' : f.severity,
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line, startColumn: f.column },
          },
        }],
      })),
    }],
  };
}
