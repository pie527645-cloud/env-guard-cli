import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  isMainModule,
  PathSecurityError,
  resolveCanonicalRoot,
  resolveContainedPath,
  runCli
} from '../src/index.js';

function captureIo(): {
  stdoutBuf: string[];
  stderrBuf: string[];
  io: { stdout: (m: string) => void; stderr: (m: string) => void };
} {
  const stdoutBuf: string[] = [];
  const stderrBuf: string[] = [];
  return {
    stdoutBuf,
    stderrBuf,
    io: {
      stdout: (m: string) => stdoutBuf.push(m),
      stderr: (m: string) => stderrBuf.push(m)
    }
  };
}

describe('CLI Commands, Exit Codes, Symlink Entrypoint & Path Containment', () => {
  it('blocks .., UNC, cross-drive, NUL-byte, and symlink escapes outside root', () => {
    const outerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-guard-outer-'));
    const rootDir = path.join(outerDir, 'workspace');
    fs.mkdirSync(rootDir);
    const outsideSecretFile = path.join(outerDir, 'outside.env');
    fs.writeFileSync(outsideSecretFile, 'SECRET=outside\n', 'utf8');

    try {
      const canonicalRoot = resolveCanonicalRoot(rootDir);

      assert.throws(
        () => resolveContainedPath(canonicalRoot, '../outside.env'),
        PathSecurityError
      );
      assert.throws(
        () => resolveContainedPath(canonicalRoot, '..\\outside.env'),
        PathSecurityError
      );
      assert.throws(
        () => resolveContainedPath(canonicalRoot, '\\\\evil-server\\share\\.env'),
        PathSecurityError
      );
      assert.throws(
        () => resolveContainedPath(canonicalRoot, '//evil-server/share/.env'),
        PathSecurityError
      );
      assert.throws(
        () => resolveContainedPath(canonicalRoot, 'sub\0evil/.env'),
        PathSecurityError
      );
      assert.throws(
        () => resolveContainedPath(canonicalRoot, 'Z:\\escape\\.env'),
        PathSecurityError
      );

      // Test symlink escape if OS user permissions allow creating symlinks
      const linkPath = path.join(rootDir, 'escaped-link');
      let symlinkCreated = false;
      try {
        fs.symlinkSync(outerDir, linkPath, 'junction');
        symlinkCreated = true;
      } catch {
        // Ignore if privilege unavailable
      }
      if (symlinkCreated) {
        assert.throws(
          () => resolveContainedPath(canonicalRoot, 'escaped-link/outside.env'),
          PathSecurityError
        );
      }
    } finally {
      fs.rmSync(outerDir, { recursive: true, force: true });
    }
  });

  it('returns exit code 0 on clean workspace, 1 on findings >= fail-on, and 2 on security/usage errors', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-guard-cli-'));
    try {
      const strongVal = ['Zx9', 'Qp4', 'Lm7', 'Kr2', 'Wt8', 'Bn5'].join('_');
      fs.mkdirSync(path.join(tmpDir, 'src'));
      fs.writeFileSync(
        path.join(tmpDir, 'src', 'app.ts'),
        'export const port = process.env.PORT;\nexport const key = process.env.API_SECRET;\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpDir, '.env'),
        `PORT=8080\nAPI_SECRET=${strongVal}\n`,
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpDir, '.env.example'),
        'PORT=8080\nAPI_SECRET=\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpDir, '.env.schema.json'),
        JSON.stringify({
          PORT: { type: 'port', required: true },
          API_SECRET: { type: 'secret', required: true }
        }),
        'utf8'
      );

      const okRun = captureIo();
      const code0 = await runCli(['check', tmpDir, '--format', 'json'], okRun.io);
      assert.equal(code0, 0);
      assert.equal(okRun.stdoutBuf.join('\n').includes(strongVal), false);

      // Introduce undocumented code variable (medium severity)
      fs.writeFileSync(
        path.join(tmpDir, 'src', 'extra.ts'),
        'export const x = process.env.UNDOC_VAR;\n',
        'utf8'
      );

      const failMed = captureIo();
      const code1 = await runCli(
        ['check', tmpDir, '--env', '.env', '--fail-on', 'medium'],
        failMed.io
      );
      assert.equal(code1, 1);

      // Path traversal on --env must return exit code 2
      const errRun = captureIo();
      const code2 = await runCli(['check', tmpDir, '--env', '../../outside.env'], errRun.io);
      assert.equal(code2, 2);

      // mcp --help must return exit code 0
      const mcpHelp = captureIo();
      const helpCode = await runCli(['mcp', '--help'], mcpHelp.io);
      assert.equal(helpCode, 0);
      assert.ok(mcpHelp.stdoutBuf.join('\n').includes('--root'));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('executes compiled dist/cli.js subprocess and verifies canonical realpath main-module check', () => {
    const cliDist = path.resolve(process.cwd(), 'dist', 'cli.js');
    assert.equal(fs.existsSync(cliDist), true, 'dist/cli.js must be built');

    const res = spawnSync(process.execPath, [cliDist, '--help'], {
      encoding: 'utf8',
      shell: false
    });
    assert.equal(res.status, 0);
    assert.ok(res.stdout.includes('Usage: env-guard'));

    // Verify canonical isMainModule matches real path
    assert.equal(isMainModule(pathToFileURL(cliDist).href, cliDist), true);
  });
});
