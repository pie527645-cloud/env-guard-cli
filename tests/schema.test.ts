import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  createNullMap,
  parseEnvSchemaJson,
  validateEnvAgainstSchema
} from '../src/index.js';

describe('.env.schema.json Type & Secret Validator', () => {
  it('validates string, int, port, url, bool, email, secret, enum, required, and default rules', () => {
    const schemaJson = JSON.stringify({
      variables: {
        APP_NAME: { type: 'string', required: true, minLength: 3 },
        WORKER_COUNT: { type: 'int', required: true, min: 1, max: 32 },
        HTTP_PORT: { type: 'port', required: true, default: 8080 },
        WEBHOOK_URL: { type: 'url', required: true },
        ENABLE_METRICS: { type: 'bool', default: false },
        ALERT_CONTACT: { type: 'email', required: true },
        LOG_LEVEL: { type: 'enum', values: ['debug', 'info', 'warn', 'error'], default: 'info' },
        SIGNING_SECRET: { type: 'secret', required: true }
      }
    });

    const parsedSchema = parseEnvSchemaJson(schemaJson);
    assert.equal(parsedSchema.errors.length, 0);
    assert.equal(Object.getPrototypeOf(parsedSchema.properties), null);

    // Construct synthetic values dynamically so zero literal secrets or emails sit in repo text
    const validContact = ['alerts', 'example.org'].join('@');
    const strongSecret = ['v9K2', 'mP7q', 'X4nL', '8zR1', 'wT6y', 'B3cF'].join('_');

    const validEnv = createNullMap<string>();
    validEnv['APP_NAME'] = 'billing-service';
    validEnv['WORKER_COUNT'] = '4';
    validEnv['WEBHOOK_URL'] = 'https://hooks.example.com/events';
    validEnv['ALERT_CONTACT'] = validContact;
    validEnv['SIGNING_SECRET'] = strongSecret;

    const okReport = validateEnvAgainstSchema(validEnv, parsedSchema);
    assert.equal(okReport.valid, true);

    const serializedReport = JSON.stringify(okReport);
    assert.equal(serializedReport.includes(strongSecret), false);
    assert.equal(serializedReport.includes(validContact), false);
  });

  it('flags invalid types, out-of-range ports, weak secrets, and missing required vars without echoing values', () => {
    const schemaJson = JSON.stringify({
      HTTP_PORT: { type: 'port', required: true },
      WORKER_COUNT: { type: 'int', required: true },
      WEBHOOK_URL: { type: 'url', required: true },
      ENABLE_METRICS: { type: 'bool', required: true },
      ALERT_CONTACT: { type: 'email', required: true },
      LOG_LEVEL: { type: 'enum', values: ['debug', 'info'], required: true },
      SIGNING_SECRET: { type: 'secret', required: true },
      MISSING_REQ: { type: 'string', required: true }
    });

    const parsedSchema = parseEnvSchemaJson(schemaJson);
    const badSecretCanary = ['canary', 'bad', 'port', '99112233'].join('_');

    const badEnv = createNullMap<string>();
    badEnv['HTTP_PORT'] = '70000';
    badEnv['WORKER_COUNT'] = badSecretCanary;
    badEnv['WEBHOOK_URL'] = 'not-a-url';
    badEnv['ENABLE_METRICS'] = 'maybe';
    badEnv['ALERT_CONTACT'] = 'invalid-address-format';
    badEnv['LOG_LEVEL'] = 'trace';
    badEnv['SIGNING_SECRET'] = 'changeme';

    const report = validateEnvAgainstSchema(badEnv, parsedSchema);
    assert.equal(report.valid, false);

    const byKey = new Map(report.rules.map((r) => [r.key, r]));
    assert.equal(byKey.get('HTTP_PORT')?.status, 'type_error');
    assert.equal(byKey.get('WORKER_COUNT')?.status, 'type_error');
    assert.equal(byKey.get('WEBHOOK_URL')?.status, 'type_error');
    assert.equal(byKey.get('ENABLE_METRICS')?.status, 'type_error');
    assert.equal(byKey.get('ALERT_CONTACT')?.status, 'type_error');
    assert.equal(byKey.get('LOG_LEVEL')?.status, 'type_error');
    assert.equal(byKey.get('SIGNING_SECRET')?.status, 'weak_secret');
    assert.equal(byKey.get('MISSING_REQ')?.status, 'missing_required');

    // Ensure raw env values are NEVER echoed even in type mismatch messages
    const fullJson = JSON.stringify(report);
    assert.equal(fullJson.includes(badSecretCanary), false);
    assert.equal(fullJson.includes('70000'), false);
  });

  it('ignores prototype pollution keys in .env.schema.json', () => {
    const raw = '{"__proto__":{"type":"string"},"constructor":{"type":"int"},"SAFE_PORT":{"type":"port"}}';
    const parsed = parseEnvSchemaJson(raw);
    assert.deepEqual(Object.keys(parsed.properties), ['SAFE_PORT']);
  });
});
