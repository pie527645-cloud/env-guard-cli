import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import {
  GitignoreMatcher,
  scanSourceContent,
  scanWorkspaceCode
} from '../src/index.js';

describe('Polyglot Code Reference Scanner & Linear Gitignore Matcher', () => {
  it('extracts TS/JS process.env and import.meta.env references while skipping comments/strings', () => {
    const code = [
      '// process.env.COMMENTED_OUT',
      '/* import.meta.env.BLOCK_COMMENTED */',
      'const fake = "process.env.IN_STRING";',
      'const a = process.env.TS_DOT_VAR;',
      "const b = process.env['TS_SINGLE_BRACKET'];",
      'const c = process.env["TS_DOUBLE_BRACKET"];',
      'const d = import.meta.env.VITE_PUBLIC_ORIGIN;',
      'const e = `https://${process.env.TS_TEMPLATE_HOST}/api`;'
    ].join('\n');

    const refs = scanSourceContent(code, 'src/app.ts', 'ts-js');
    const keys = refs.map((r) => r.key);
    assert.deepEqual(keys, [
      'TS_DOT_VAR',
      'TS_SINGLE_BRACKET',
      'TS_DOUBLE_BRACKET',
      'VITE_PUBLIC_ORIGIN',
      'TS_TEMPLATE_HOST'
    ]);
  });

  it('extracts Python os.environ and os.getenv references accurately', () => {
    const pyCode = [
      '# os.getenv("PY_COMMENTED")',
      '"""',
      'os.environ["PY_DOCSTRING"]',
      '"""',
      'import os',
      'db_host = os.environ["PY_DB_HOST"]',
      "db_port = os.environ.get('PY_DB_PORT', '5432')",
      "cache_url = os.getenv('PY_CACHE_URL')"
    ].join('\n');

    const refs = scanSourceContent(pyCode, 'service/settings.py', 'python');
    assert.deepEqual(
      refs.map((r) => r.key),
      ['PY_DB_HOST', 'PY_DB_PORT', 'PY_CACHE_URL']
    );
  });

  it('extracts Go os.Getenv and os.LookupEnv references accurately', () => {
    const goCode = [
      'package main',
      'import "os"',
      '// os.Getenv("GO_IGNORED")',
      'func main() {',
      '  addr := os.Getenv("GO_BIND_ADDR")',
      '  token, ok := os.LookupEnv(`GO_SERVICE_MODE`)',
      '}'
    ].join('\n');

    const refs = scanSourceContent(goCode, 'cmd/main.go', 'go');
    assert.deepEqual(
      refs.map((r) => r.key),
      ['GO_BIND_ADDR', 'GO_SERVICE_MODE']
    );
  });

  it('extracts Rust env::var and option_env! / env! references accurately', () => {
    const rsCode = [
      'use std::env;',
      '// env::var("RS_IGNORED")',
      'fn load() {',
      '  let a = env::var("RS_RUNTIME_KEY").unwrap();',
      '  let b = std::env::var("RS_STD_KEY").ok();',
      '  let c = option_env!("RS_COMPILE_OPT");',
      '  let d = env!("RS_BUILD_TAG");',
      '}'
    ].join('\n');

    const refs = scanSourceContent(rsCode, 'src/lib.rs', 'rust');
    assert.deepEqual(
      refs.map((r) => r.key),
      ['RS_RUNTIME_KEY', 'RS_STD_KEY', 'RS_COMPILE_OPT', 'RS_BUILD_TAG']
    );
  });

  it('enforces .gitignore <= 4096 rule cap, O(1) bracket guard, negation, and >512KB / binary skip', () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'env-guard-scan-'));
    try {
      const overlongRule = 'a'.repeat(4100);
      const gitignore = [
        '# ignore generated',
        'ignored_dir/',
        '*.gen.ts',
        '!keep.gen.ts',
        'unclosed_[bracket.ts',
        '[a-c]_temp.py',
        overlongRule
      ].join('\n');

      const matcher = new GitignoreMatcher(gitignore);
      assert.equal(matcher.isIgnored('ignored_dir/sub.ts', false), true);
      assert.equal(matcher.isIgnored('foo.gen.ts', false), true);
      assert.equal(matcher.isIgnored('keep.gen.ts', false), false);
      assert.equal(matcher.isIgnored('unclosed_[bracket.ts', false), true);
      assert.equal(matcher.isIgnored('b_temp.py', false), true);
      assert.equal(matcher.isIgnored('z_temp.py', false), false);

      fs.writeFileSync(path.join(tmpRoot, '.gitignore'), gitignore, 'utf8');
      fs.mkdirSync(path.join(tmpRoot, 'ignored_dir'));
      fs.mkdirSync(path.join(tmpRoot, 'node_modules'));
      fs.mkdirSync(path.join(tmpRoot, 'src'));

      fs.writeFileSync(
        path.join(tmpRoot, 'ignored_dir', 'skip.ts'),
        'const x = process.env.SHOULD_SKIP_IGNORED;\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpRoot, 'node_modules', 'pkg.js'),
        'const x = process.env.SHOULD_SKIP_NODE_MODULES;\n',
        'utf8'
      );
      // Binary file with NUL byte
      fs.writeFileSync(
        path.join(tmpRoot, 'src', 'binary.js'),
        Buffer.from('const x = process.env.SHOULD_SKIP_BIN;\0\x01\x02', 'utf8')
      );
      // Oversized file (> 512 KB)
      fs.writeFileSync(
        path.join(tmpRoot, 'src', 'oversized.ts'),
        '// ' + 'x'.repeat(520 * 1024) + '\nconst y = process.env.SHOULD_SKIP_LARGE;\n',
        'utf8'
      );
      // Valid file
      fs.writeFileSync(
        path.join(tmpRoot, 'src', 'valid.ts'),
        'export const port = process.env.ACTIVE_PORT;\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpRoot, 'keep.gen.ts'),
        'export const mode = process.env.NEGATED_KEEP_VAR;\n',
        'utf8'
      );

      const res = scanWorkspaceCode(tmpRoot);
      const foundKeys = Object.keys(res.byKey).sort();
      assert.deepEqual(foundKeys, ['ACTIVE_PORT', 'NEGATED_KEEP_VAR']);
      assert.equal(Object.getPrototypeOf(res.byKey), null);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('scans 500 KB source file and pathological wildcard patterns in linear time', () => {
    const chunk = 'const value = someObject.property; // /* not closed on single line \n';
    const bigCode = chunk.repeat(Math.ceil((500 * 1024) / chunk.length)) + 'const z = process.env.FINAL_KEY;\n';
    assert.ok(bigCode.length >= 500 * 1024);

    const t0 = performance.now();
    const refs = scanSourceContent(bigCode, 'big.ts', 'ts-js');
    const elapsed = performance.now() - t0;

    assert.equal(refs.length, 1);
    assert.equal(refs[0]!.key, 'FINAL_KEY');
    assert.ok(elapsed < 1500, `Expected linear scan < 1500ms, took ${elapsed.toFixed(1)}ms`);

    const matcher = new GitignoreMatcher('*a*a*a*a*a*a*b\n');
    const t1 = performance.now();
    const ignored = matcher.isIgnored('a'.repeat(500) + 'c', false);
    const matchElapsed = performance.now() - t1;
    assert.equal(ignored, false);
    assert.ok(matchElapsed < 200, `Expected linear glob match < 200ms, took ${matchElapsed.toFixed(1)}ms`);
  });
});
