import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  analyzeWorkspace,
  formatCheckReport,
  INFORMATION_URI,
  syncWorkspace
} from '../src/index.js';

describe('Sync Scrubbing & Check SARIF / Secret Redaction', () => {
  it('sync --write-example never copies real .env secrets and scrubs leaked secrets from .env.example', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-guard-sync-'));
    try {
      const realEnvSecret = ['sk', 'live', 'R9m2K8p4X7q1W6z5N3b0V8c4'].join('_');
      const leakedExampleToken = ['gh', 'p_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');

      fs.mkdirSync(path.join(tmpDir, 'src'));
      fs.writeFileSync(
        path.join(tmpDir, 'src', 'index.ts'),
        [
          'export const port = process.env.PORT;',
          'export const stripe = process.env.STRIPE_SECRET_KEY;',
          'export const gh = process.env.GITHUB_ACCESS_TOKEN;'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpDir, '.env'),
        [
          'PORT=4567',
          `STRIPE_SECRET_KEY=${realEnvSecret}`,
          'INTERNAL_ONLY_TOKEN=super_private_value_99887766'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpDir, '.env.example'),
        `GITHUB_ACCESS_TOKEN=${leakedExampleToken}\n`,
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpDir, '.env.schema.json'),
        JSON.stringify({
          PORT: { type: 'port', required: true, default: 3000 },
          STRIPE_SECRET_KEY: { type: 'secret', required: true },
          GITHUB_ACCESS_TOKEN: { type: 'secret', required: true }
        }),
        'utf8'
      );

      const syncRes = syncWorkspace({
        rootDir: tmpDir,
        writeExample: true
      });

      assert.equal(syncRes.scrubbedSecretsInExampleCount, 1);
      assert.ok(syncRes.writtenExamplePath);

      const writtenExample = fs.readFileSync(path.join(tmpDir, '.env.example'), 'utf8');
      assert.equal(writtenExample.includes(realEnvSecret), false);
      assert.equal(writtenExample.includes('4567'), false);
      assert.equal(writtenExample.includes('super_private_value_99887766'), false);
      assert.equal(writtenExample.includes(leakedExampleToken), false);
      assert.ok(writtenExample.includes('PORT=3000'));
      assert.ok(writtenExample.includes('STRIPE_SECRET_KEY='));
      assert.ok(writtenExample.includes('GITHUB_ACCESS_TOKEN='));
      assert.ok(writtenExample.includes('INTERNAL_ONLY_TOKEN='));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('emits valid SARIF 2.1.0 and redacts all secret values across pretty, json, markdown, and sarif', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-guard-sarif-'));
    try {
      const leakedExampleKey = ['AK', 'IA', 'IOSFODNN7EXAMPLE99'].join('');
      const weakSecretVal = 'changeme';

      fs.mkdirSync(path.join(tmpDir, 'src'));
      fs.writeFileSync(
        path.join(tmpDir, 'src', 'server.ts'),
        [
          'const a = process.env.AWS_ACCESS_KEY;',
          'const b = process.env.JWT_SECRET;',
          'const c = process.env.UNDOCUMENTED_CODE_VAR;',
          'const d = process.env.MISSING_FROM_ENV_VAR;'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpDir, '.env'),
        [
          `AWS_ACCESS_KEY=${leakedExampleKey}`,
          `JWT_SECRET=${weakSecretVal}`,
          'PORT=99999'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpDir, '.env.example'),
        [
          `AWS_ACCESS_KEY=${leakedExampleKey}`,
          'JWT_SECRET=',
          'MISSING_FROM_ENV_VAR=',
          'PORT=3000'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpDir, '.env.schema.json'),
        JSON.stringify({
          PORT: { type: 'port', required: true }
        }),
        'utf8'
      );

      const report = analyzeWorkspace({ rootDir: tmpDir });
      const ruleIds = new Set(report.findings.map((f) => f.ruleId));
      assert.ok(ruleIds.has('ENV001'), 'Should flag real secret in .env.example');
      assert.ok(ruleIds.has('ENV002'), 'Should flag missing required var');
      assert.ok(ruleIds.has('ENV003'), 'Should flag weak secret in .env');
      assert.ok(ruleIds.has('ENV004'), 'Should flag invalid port in schema');
      assert.ok(ruleIds.has('ENV006'), 'Should flag undocumented code var');

      for (const fmt of ['pretty', 'json', 'markdown', 'sarif'] as const) {
        const formatted = formatCheckReport(report, fmt);
        assert.equal(
          formatted.includes(leakedExampleKey),
          false,
          `Format '${fmt}' must never print leaked secret value`
        );
        assert.equal(
          formatted.includes(weakSecretVal),
          false,
          `Format '${fmt}' must never print weak secret value`
        );
      }

      const sarifObj = JSON.parse(formatCheckReport(report, 'sarif')) as {
        $schema: string;
        version: string;
        runs: Array<{
          tool: {
            driver: {
              name: string;
              informationUri: string;
              rules: Array<{ id: string }>;
            };
          };
          results: Array<{
            ruleId: string;
            ruleIndex: number;
            level: string;
            properties: { redactedValue: string };
          }>;
        }>;
      };

      assert.equal(sarifObj.version, '2.1.0');
      assert.ok(sarifObj.$schema.includes('sarif-2.1.0'));
      assert.equal(sarifObj.runs.length, 1);
      const run = sarifObj.runs[0]!;
      assert.equal(run.tool.driver.informationUri, INFORMATION_URI);
      assert.ok(run.results.length >= 5);

      for (const result of run.results) {
        const ruleAtIdx = run.tool.driver.rules[result.ruleIndex];
        assert.ok(ruleAtIdx, 'ruleIndex must point to valid rule descriptor');
        assert.equal(ruleAtIdx.id, result.ruleId);
        assert.equal(result.properties.redactedValue, '***');
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
