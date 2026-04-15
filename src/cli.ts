#!/usr/bin/env node
import { Command } from 'commander';
import { scan } from './scanner';
import { formatText, formatSarif } from './reporter';

const program = new Command();

program
  .name('ai-sec')
  .description('Scan codebases for AI-specific security vulnerabilities')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan a directory or file for AI security issues')
  .argument('<target>', 'Directory or file to scan')
  .option('--rules <path>', 'Rules to use (\"default\" or path to YAML)', 'default')
  .option('--format <format>', 'Output format (text or sarif)', 'text')
  .option('--output <path>', 'Write output to file')
  .action(async (target: string, opts: { rules: string; format: string; output?: string }) => {
    try {
      const result = await scan(target, { rules: opts.rules });
      let output: string;
      if (opts.format === 'sarif') {
        output = JSON.stringify(formatSarif(result), null, 2);
      } else {
        output = formatText(result);
      }

      if (opts.output) {
        const fs = await import('fs');
        fs.writeFileSync(opts.output, output);
        console.log(`Output written to ${opts.output}`);
      } else {
        console.log(output);
      }

      process.exit(result.findings.some((f) => f.severity === 'error') ? 1 : 0);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(2);
    }
  });

program.parse();
