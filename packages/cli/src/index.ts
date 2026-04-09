import { readFileSync, statSync, readdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { Scanner } from "@ai-security-scanner/core";
import type { Finding, ScanResult } from "@ai-security-scanner/core";

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m",
} as const;

const SEVERITY_COLORS: Record<string, string> = {
  critical: `${COLORS.bgRed}${COLORS.white}${COLORS.bold} CRITICAL ${COLORS.reset}`,
  high: `${COLORS.red}${COLORS.bold} HIGH ${COLORS.reset}`,
  medium: `${COLORS.yellow}${COLORS.bold} MEDIUM ${COLORS.reset}`,
  low: `${COLORS.blue} LOW ${COLORS.reset}`,
  info: `${COLORS.dim} INFO ${COLORS.reset}`,
};

const SCANNABLE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".go", ".java", ".rs",
  ".html", ".vue", ".svelte",
]);

function usage(): void {
  console.log(`
${COLORS.bold}secscanner${COLORS.reset} — AI Security Scanner CLI

${COLORS.bold}USAGE${COLORS.reset}
  secscanner scan <file|directory>  Scan for vulnerabilities
  secscanner --help                 Show this help

${COLORS.bold}EXAMPLES${COLORS.reset}
  secscanner scan src/
  secscanner scan app.ts
`);
}

function collectFiles(target: string): string[] {
  const stat = statSync(target);
  if (stat.isFile()) return [target];

  const files: string[] = [];
  const entries = readdirSync(target, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const fullPath = join(target, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath));
    } else if (entry.isFile()) {
      const ext = "." + (entry.name.split(".").pop() ?? "");
      if (SCANNABLE_EXTENSIONS.has(ext)) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

function printFindings(findings: Finding[]): void {
  for (const f of findings) {
    const sev = SEVERITY_COLORS[f.severity] ?? f.severity;
    console.log(`${sev} ${COLORS.bold}${f.title}${COLORS.reset} ${COLORS.dim}[${f.ruleId}]${COLORS.reset}`);
    console.log(`  ${COLORS.cyan}${f.file}:${f.line}${COLORS.reset}`);
    console.log(`  ${COLORS.dim}${f.snippet}${COLORS.reset}`);
    console.log(`  ${f.description}`);
    console.log();
  }
}

function printSummary(result: ScanResult): void {
  const counts: Record<string, number> = {};
  for (const f of result.findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  console.log(`${COLORS.bold}─── Scan Complete ───${COLORS.reset}`);
  console.log(`Files scanned: ${result.filesScanned}`);
  console.log(`Duration: ${result.duration.toFixed(0)}ms`);
  console.log(`Findings: ${result.findings.length}`);
  if (result.findings.length > 0) {
    const parts: string[] = [];
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      if (counts[sev]) parts.push(`${sev}: ${counts[sev]}`);
    }
    console.log(`  ${parts.join(" | ")}`);
  }
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  if (args[0] !== "scan" || !args[1]) {
    console.error("Usage: secscanner scan <file|directory>");
    process.exit(1);
  }

  const target = resolve(args[1]);
  const scanner = new Scanner();

  let files: string[] = [];
  try {
    files = collectFiles(target);
  } catch {
    console.error(`Error: cannot access "${target}"`);
    process.exit(1);
  }

  if (files.length === 0) {
    console.log("No scannable files found.");
    process.exit(0);
  }

  const allFindings: Finding[] = [];
  let totalDuration = 0;

  for (const file of files) {
    const content = readFileSync(file, "utf-8");
    const language = Scanner.inferLanguage(file);
    const result = scanner.scan(content, language, { file });
    allFindings.push(...result.findings);
    totalDuration += result.duration;
  }

  console.log();
  if (allFindings.length > 0) {
    printFindings(allFindings);
  }

  printSummary({
    findings: allFindings,
    filesScanned: files.length,
    duration: totalDuration,
  });

  process.exit(allFindings.some((f) => f.severity === "critical") ? 2 : 0);
}

main();
