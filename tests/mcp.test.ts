import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

describe('Secret-Safe MCP Server (Stdio Handshake, Non-Disclosure & Path Containment)', () => {
  it('completes live stdio handshake, exposes clean tool descriptions, blocks traversal, and never leaks secrets', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'env-guard-mcp-'));
    const mcpEntrypoint = path.resolve(process.cwd(), 'dist', 'mcp.js');
    assert.equal(fs.existsSync(mcpEntrypoint), true, 'dist/mcp.js must exist');

    // Construct synthetic canary secrets dynamically so zero literal secrets exist in repo files
    const canaryEnvSecret = ['sk', 'live', 'MCP_CANARY_9876543210_ABCDEF'].join('_');
    const canaryWeakSecret = ['my', 'weak', 'canary', 'pass'].join('_');
    const canaryExampleLeak = ['gh', 'p_', 'MCPEXAMPLELEAK1234567890ABCDEFGHIJKL'].join('');

    try {
      fs.mkdirSync(path.join(tmpRoot, 'src'));
      fs.writeFileSync(
        path.join(tmpRoot, 'src', 'service.py'),
        [
          'import os',
          'api_key = os.getenv("PAYMENT_SECRET_KEY")',
          'db_pwd = os.environ["DB_PASSWORD"]',
          'undoc = os.getenv("UNDOCUMENTED_PY_KEY")'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpRoot, '.env'),
        [
          `PAYMENT_SECRET_KEY=${canaryEnvSecret}`,
          `DB_PASSWORD=${canaryWeakSecret}`,
          'APP_PORT=3000'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpRoot, '.env.example'),
        [
          `PAYMENT_SECRET_KEY=${canaryExampleLeak}`,
          'DB_PASSWORD=',
          'APP_PORT=3000'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(tmpRoot, '.env.schema.json'),
        JSON.stringify({
          PAYMENT_SECRET_KEY: { type: 'secret', required: true },
          DB_PASSWORD: { type: 'secret', required: true, minEntropy: 3.5 },
          APP_PORT: { type: 'port', required: true }
        }),
        'utf8'
      );

      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [mcpEntrypoint, '--root', tmpRoot],
        stderr: 'pipe'
      });

      const client = new Client(
        { name: 'env-guard-test-client', version: '1.0.0' },
        { capabilities: {} }
      );

      await client.connect(transport);

      try {
        // 1. Verify tools/list contract & mcp-doctor hygiene (no angle brackets or override text)
        const toolsList = await client.listTools();
        const toolNames = toolsList.tools.map((t) => t.name).sort();
        assert.deepEqual(toolNames, [
          'check_env_drift',
          'list_env_keys',
          'validate_env_schema'
        ]);

        for (const tool of toolsList.tools) {
          assert.ok(tool.description && tool.description.length > 15);
          assert.equal(tool.description.includes('<'), false, `Tool ${tool.name} description must not contain '<'`);
          assert.equal(tool.description.includes('>'), false, `Tool ${tool.name} description must not contain '>'`);
        }

        const assertNoCanaryLeaked = (rawText: string, label: string): void => {
          assert.equal(rawText.includes(canaryEnvSecret), false, `${label} leaked .env strong secret`);
          assert.equal(rawText.includes(canaryWeakSecret), false, `${label} leaked .env weak secret`);
          assert.equal(rawText.includes(canaryExampleLeak), false, `${label} leaked .env.example secret`);
          assert.equal(rawText.includes('3000'), false, `${label} leaked APP_PORT value`);
        };

        // 2. Call list_env_keys
        const listRes = await client.callTool({ name: 'list_env_keys', arguments: {} });
        assert.notEqual(listRes.isError, true);
        const listText = JSON.stringify(listRes);
        assertNoCanaryLeaked(listText, 'list_env_keys');

        const listFirstBlock = (listRes.content as Array<{ type: string; text: string }>)[0]!;
        const listPayload = JSON.parse(listFirstBlock.text) as {
          keys: Array<{ key: string; hasEnvValue: boolean; inExample: boolean; codeLocations: string[] }>;
        };
        const paymentItem = listPayload.keys.find((k) => k.key === 'PAYMENT_SECRET_KEY');
        assert.ok(paymentItem);
        assert.equal(paymentItem.hasEnvValue, true);
        assert.equal(paymentItem.inExample, true);
        assert.deepEqual(paymentItem.codeLocations, ['src/service.py:2']);

        // 3. Call check_env_drift
        const driftRes = await client.callTool({ name: 'check_env_drift', arguments: {} });
        assert.notEqual(driftRes.isError, true);
        const driftText = JSON.stringify(driftRes);
        assertNoCanaryLeaked(driftText, 'check_env_drift');

        const driftFirstBlock = (driftRes.content as Array<{ type: string; text: string }>)[0]!;
        const driftPayload = JSON.parse(driftFirstBlock.text) as {
          status: string;
          undocumented: string[];
          findings: Array<{ ruleId: string; redactedValue: string }>;
        };
        assert.equal(driftPayload.status, 'drift_detected');
        assert.ok(driftPayload.undocumented.includes('UNDOCUMENTED_PY_KEY'));
        assert.ok(driftPayload.findings.some((f) => f.ruleId === 'ENV001'));
        assert.ok(driftPayload.findings.every((f) => f.redactedValue === '***'));

        // 4. Call validate_env_schema
        const schemaRes = await client.callTool({
          name: 'validate_env_schema',
          arguments: { schemaPath: '.env.schema.json' }
        });
        assert.notEqual(schemaRes.isError, true);
        const schemaText = JSON.stringify(schemaRes);
        assertNoCanaryLeaked(schemaText, 'validate_env_schema');

        const schemaFirstBlock = (schemaRes.content as Array<{ type: string; text: string }>)[0]!;
        const schemaPayload = JSON.parse(schemaFirstBlock.text) as {
          valid: boolean;
          rules: Array<{ key: string; status: string }>;
        };
        assert.equal(schemaPayload.valid, false);
        const paymentRule = schemaPayload.rules.find((r) => r.key === 'PAYMENT_SECRET_KEY');
        assert.equal(paymentRule?.status, 'valid');
        const dbRule = schemaPayload.rules.find((r) => r.key === 'DB_PASSWORD');
        assert.equal(dbRule?.status, 'weak_secret');

        // 5. Verify path traversal & NUL injection are safely blocked without crashing server
        for (const maliciousPath of [
          '../../etc/passwd',
          '..\\..\\Windows\\win.ini',
          '\\\\127.0.0.1\\c$\\.env',
          'sub\0evil'
        ]) {
          const blocked = await client.callTool({
            name: 'list_env_keys',
            arguments: { subpath: maliciousPath }
          });
          assert.equal(blocked.isError, true);
          const blockedStr = JSON.stringify(blocked);
          assert.equal(blockedStr.includes(tmpRoot), false, 'Error must not leak local host path');
        }

        // Server stays healthy after blocked traversal probes
        const postProbeRes = await client.callTool({ name: 'list_env_keys', arguments: {} });
        assert.notEqual(postProbeRes.isError, true);
      } finally {
        await client.close();
      }
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
