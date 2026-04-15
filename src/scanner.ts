import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import * as yaml from 'js-yaml';
import { Rule, Finding, ScanResult, CustomRuleConfig } from './types';
import { promptInjectionRule } from './rules/prompt-injection';
import { apiKeysRule } from './rules/api-keys';
import { piiLeakRule } from './rules/pii-leak';
import { validationRule } from './rules/validation';

const DEFAULT_RULES: Rule[] = [promptInjectionRule, apiKeysRule, piiLeakRule, validationRule];

const EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.rs', '.rb', '.php', '.yaml', '.yml', '.json', '.env', '.toml']);
const IGNORE = ['node_modules', 'dist', '.git', 'vendor', '__pycache__', '.next', 'build'];

function loadCustomRules(rulesPath: string): Rule[] {
  const content = fs.readFileSync(rulesPath, 'utf-8');
  const configs = yaml.load(content) as CustomRuleConfig[];
  if (!Array.isArray(configs)) return [];
  return configs.map((c) => ({
    id: c.id,
    name: c.name,
    description: c.description,
    severity: c.severity,
    scan(fileContent: string, filePath: string): Finding[] {
      const findings: Finding[] = [];
      const regex = new RegExp(c.pattern, 'gi');
      const lines = fileContent.split('\n');
      for (let i = 0; i < lines.length; i++) {
        regex.lastIndex = 0;
        const m = regex.exec(lines[i]);
        if (m) {
          findings.push({ ruleId: c.id, severity: c.severity, message: c.message, file: filePath, line: i + 1, column: m.index + 1, snippet: lines[i].trim() });
        }
      }
      return findings;
    },
  }));
}

export async function scan(target: string, options: { rules?: string; ruleIds?: string[] } = {}): Promise<ScanResult> {
  let rules = [...DEFAULT_RULES];
  if (options.rules && options.rules !== 'default') {
    try { rules = [...rules, ...loadCustomRules(options.rules)]; } catch {}
  }
  if (options.ruleIds) {
    rules = rules.filter((r) => options.ruleIds!.includes(r.id));
  }

  const stat = fs.statSync(target);
  let files: string[];
  if (stat.isDirectory()) {
    files = await glob('**/*', {
      cwd: target, absolute: true, nodir: true,
      ignore: IGNORE.map((i) => `**/${i}/**`),
    });
    files = files.filter((f) => EXTENSIONS.has(path.extname(f)));
  } else {
    files = [path.resolve(target)];
  }

  const findings: Finding[] = [];
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const relPath = stat.isDirectory() ? path.relative(target, file) : path.basename(file);
      for (const rule of rules) {
        findings.push(...rule.scan(content, relPath));
      }
    } catch {}
  }

  return { findings, filesScanned: files.length, rulesApplied: rules.length };
}
