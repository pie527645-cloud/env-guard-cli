import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { EnvParseError, parseEnv, serializeEnv } from '../src/index.js';

describe('.env Spec-Compliant Parser & Serializer', () => {
  it('strips UTF-8 BOM and normalizes CRLF and standalone CR line endings', () => {
    const raw = '\uFEFFFIRST=alpha\r\nSECOND=beta\rTHIRD="line1\r\nline2"\r\n';
    const parsed = parseEnv(raw);
    assert.equal(parsed.errors.length, 0);
    assert.equal(Object.getPrototypeOf(parsed.values), null);
    assert.equal(Object.getPrototypeOf(parsed.rawValues), null);
    assert.equal(parsed.values['FIRST'], 'alpha');
    assert.equal(parsed.values['SECOND'], 'beta');
    assert.equal(parsed.values['THIRD'], 'line1\nline2');
  });

  it('supports export keyword, full-line comments, inline comments, and URL hash preservation', () => {
    const raw = [
      '# Full-line comment',
      '  # Indented comment',
      'export APP_ENV = production # active environment',
      'PUBLIC_URL=https://example.com/callback#section1 # trailing inline comment',
      'HEX_COLOR=#ff8800',
      'EMPTY_COMMENTED= # intentionally empty',
      'export=literal_export_key'
    ].join('\n');

    const parsed = parseEnv(raw);
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.values['APP_ENV'], 'production');
    assert.equal(parsed.values['PUBLIC_URL'], 'https://example.com/callback#section1');
    assert.equal(parsed.values['HEX_COLOR'], '#ff8800');
    assert.equal(parsed.values['EMPTY_COMMENTED'], '');
    assert.equal(parsed.values['export'], 'literal_export_key');

    const appEnvEntry = parsed.entries.find((e) => e.key === 'APP_ENV');
    assert.ok(appEnvEntry);
    assert.equal(appEnvEntry.exported, true);
    assert.equal(appEnvEntry.inlineComment, 'active environment');
  });

  it('handles unquoted, single-quoted, double-quoted, multiline, and escape sequences', () => {
    const raw = [
      'UNQUOTED=  hello world  ',
      "SINGLE_MULTI='first line",
      'second line with \\n literal and ${UNQUOTED}\' # comment after single',
      'DOUBLE_ESCAPES="col1\\tcol2\\nrow2\\r\\nquote:\\"slash:\\\\dollar:\\${UNQUOTED}"',
      'DOUBLE_MULTI="alpha',
      'beta"'
    ].join('\n');

    const parsed = parseEnv(raw);
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.values['UNQUOTED'], 'hello world');
    assert.equal(
      parsed.values['SINGLE_MULTI'],
      'first line\nsecond line with \\n literal and ${UNQUOTED}'
    );
    assert.equal(
      parsed.values['DOUBLE_ESCAPES'],
      'col1\tcol2\nrow2\r\nquote:"slash:\\dollar:${UNQUOTED}'
    );
    assert.equal(parsed.values['DOUBLE_MULTI'], 'alpha\nbeta');
  });

  it('interpolates ${VAR}, ${VAR:-default}, ${VAR-default}, forward refs, and nested fallbacks', () => {
    const raw = [
      'FULL_URL="${PROTOCOL:-https}://${HOST}:${PORT:-8443}/${API_PATH}"',
      'HOST=api.example.com',
      'PORT=',
      'EMPTY_CHECK=${PORT-9000}',
      'API_PATH=${CUSTOM_PATH:-${FALLBACK_VER:-v2}/items}'
    ].join('\n');

    const parsed = parseEnv(raw);
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.values['FULL_URL'], 'https://api.example.com:8443/v2/items');
    // PORT is defined as empty string, so `${PORT-9000}` keeps '' while `${PORT:-8443}` uses '8443'
    assert.equal(parsed.values['EMPTY_CHECK'], '');
  });

  it('detects direct and multi-hop circular variable references without infinite recursion', () => {
    const raw = [
      'NODE_A=${NODE_B}',
      'NODE_B=${NODE_C}',
      'NODE_C=${NODE_A}',
      'SELF_REF=${SELF_REF}'
    ].join('\n');

    const parsed = parseEnv(raw);
    const cycleErrors = parsed.errors.filter((e) => e.code === 'CIRCULAR_REFERENCE');
    assert.ok(cycleErrors.length >= 2);
    assert.ok(cycleErrors.some((e) => e.message.includes('NODE_A -> NODE_B -> NODE_C -> NODE_A')));
    assert.ok(cycleErrors.some((e) => e.message.includes('SELF_REF -> SELF_REF')));

    assert.throws(() => parseEnv(raw, { throwOnError: true }), EnvParseError);
  });

  it('resists prototype pollution keys using null-prototype maps', () => {
    const raw = '__proto__=polluted\nconstructor=safe\nprototype=clean\nNORMAL_KEY=ok\n';
    const parsed = parseEnv(raw);
    assert.equal(Object.getPrototypeOf(parsed.values), null);
    assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
    assert.equal(parsed.values['NORMAL_KEY'], 'ok');
  });

  it('round-trips serialized environment maps cleanly', () => {
    const original: Record<string, string> = {
      SIMPLE: 'value',
      WITH_SPACES: 'hello world',
      WITH_SPECIAL: 'line1\nline2\t"quoted" #hash ${literal}'
    };
    const serialized = serializeEnv(original, { sortKeys: true });
    const reparsed = parseEnv(serialized);
    assert.equal(reparsed.errors.length, 0);
    assert.equal(reparsed.values['SIMPLE'], original['SIMPLE']);
    assert.equal(reparsed.values['WITH_SPACES'], original['WITH_SPACES']);
    assert.equal(reparsed.values['WITH_SPECIAL'], original['WITH_SPECIAL']);
  });

  it('completes 500 KB pathological input in linear time (ReDoS benchmark)', () => {
    // Construct ~500 KB .env with long unquoted lines, slashes, spaces, hashes, and nested vars
    const repeatedValue = '/a/b/c/'.repeat(60) + '   ';
    const lines: string[] = [];
    let totalChars = 0;
    let idx = 0;
    while (totalChars < 500 * 1024) {
      const line = `BENCH_KEY_${idx}=${repeatedValue} # trailing comment ${idx}\n`;
      lines.push(line);
      totalChars += line.length;
      idx++;
    }
    const payload = lines.join('');
    assert.ok(payload.length >= 500 * 1024);

    const t0 = performance.now();
    const res = parseEnv(payload);
    const elapsedMs = performance.now() - t0;

    assert.equal(res.errors.length, 0);
    assert.equal(res.entries.length, idx);
    assert.ok(elapsedMs < 1500, `Expected linear parse < 1500ms, took ${elapsedMs.toFixed(1)}ms`);
  });
});
