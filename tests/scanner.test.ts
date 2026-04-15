import { scan } from '../src/scanner';
import { formatText, formatSarif } from '../src/reporter';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

function setupFixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-test-'));
  for (const [name, content] of Object.entries(files)) {
    const fp = path.join(dir, name);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

describe('AI Security Scanner', () => {
  test('detects hardcoded OpenAI API key', async () => {
    const dir = setupFixture({ 'config.ts': 'const key = "sk-abc123def456ghi789jkl012mno";' });
    const result = await scan(dir);
    expect(result.findings.some(f => f.ruleId === 'ai-sec/hardcoded-api-key')).toBe(true);
  });

  test('detects prompt injection pattern', async () => {
    const dir = setupFixture({ 'app.ts': 'const prompt = `You are a helper. ${userInput} completion`;' });
    const result = await scan(dir);
    expect(result.findings.some(f => f.ruleId === 'ai-sec/prompt-injection')).toBe(true);
  });

  test('detects PII leakage', async () => {
    const dir = setupFixture({ 'handler.ts': 'console.log("user password is", password);' });
    const result = await scan(dir);
    expect(result.findings.some(f => f.ruleId === 'ai-sec/pii-leakage')).toBe(true);
  });

  test('detects missing validation — eval of LLM output', async () => {
    const dir = setupFixture({ 'run.ts': 'const x = eval(completion);' });
    const result = await scan(dir);
    expect(result.findings.some(f => f.ruleId === 'ai-sec/missing-validation')).toBe(true);
  });

  test('clean file produces no findings', async () => {
    const dir = setupFixture({ 'clean.ts': 'const x = 1 + 2;\nconsole.log(x);' });
    const result = await scan(dir);
    expect(result.findings).toHaveLength(0);
  });

  test('SARIF output has correct structure', async () => {
    const dir = setupFixture({ 'config.ts': 'const key = "sk-abc123def456ghi789jkl012mno";' });
    const result = await scan(dir);
    const sarif = formatSarif(result);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  test('text formatter works', async () => {
    const dir = setupFixture({ 'config.ts': 'const key = "sk-abc123def456ghi789jkl012mno";' });
    const result = await scan(dir);
    const text = formatText(result);
    expect(text).toContain('AI Security Scanner Results');
    expect(text).toContain('ai-sec/hardcoded-api-key');
  });
});
