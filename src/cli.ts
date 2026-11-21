#!/usr/bin/env node
import {
  analyzeWorkspace,
  doesFindingTriggerFailOn,
  syncWorkspace,
  type FindingSeverity
} from './analyzer/workspaceAnalyzer.js';
import {
  formatCheckReport,
  formatSyncReport,
  PACKAGE_VERSION,
  type CheckOutputFormat,
  type SyncOutputFormat
} from './formatters/reportFormatter.js';
import { getMcpHelpText, isMainModule, runMcpEntrypoint } from './mcp.js';

export interface CliIo {
  stdout: (msg: string) => void;
  stderr: (msg: string) => void;
}

const DEFAULT_IO: CliIo = {
  stdout: (msg) => process.stdout.write(msg + '\n'),
  stderr: (msg) => process.stderr.write(msg + '\n')
};

function getMainHelpText(): string {
  return [
    'Usage: env-guard <command> [options]',
    '',
    'Commands:',
    '  sync [dir]     Compare code references against .env, .env.example, and schema; optionally write scrubbed .env.example',
    '  check [dir]    Validate environment hygiene, schema types, missing/undocumented keys, and leaked secrets',
    '  mcp            Start the secret-safe Model Context Protocol (MCP) server over stdio',
    '',
    'Global Options:',
    '  -h, --help     Display help information',
    '  -v, --version  Display package version'
  ].join('\n');
}

function getSyncHelpText(): string {
  return [
    'Usage: env-guard sync [dir] [--write-example] [--schema .env.schema.json] [--format pretty|json]',
    '',
    'Options:',
    '  --write-example   Write a scrubbed .env.example with placeholders/empty values (never copies .env secrets)',
    '  --schema path     Relative path to schema JSON file (default: .env.schema.json)',
    '  --format fmt      Output format: pretty or json (default: pretty)',
    '  -h, --help        Display help for sync'
  ].join('\n');
}

function getCheckHelpText(): string {
  return [
    'Usage: env-guard check [dir] [--env .env] [--example .env.example] [--schema .env.schema.json] [--format pretty|json|markdown|sarif] [--fail-on critical|high|medium|low]',
    '',
    'Options:',
    '  --env path        Relative path to environment file (default: .env)',
    '  --example path    Relative path to example file (default: .env.example)',
    '  --schema path     Relative path to schema JSON file (default: .env.schema.json)',
    '  --format fmt      Output format: pretty, json, markdown, or sarif (default: pretty)',
    '  --fail-on level   Minimum severity causing exit code 1: critical, high, medium, or low (default: medium)',
    '  -h, --help        Display help for check'
  ].join('\n');
}

const VALID_CHECK_FORMATS = new Set<string>(['pretty', 'json', 'markdown', 'sarif']);
const VALID_SYNC_FORMATS = new Set<string>(['pretty', 'json']);
const VALID_SEVERITIES = new Set<string>(['critical', 'high', 'medium', 'low']);

async function handleSyncCommand(args: string[], io: CliIo): Promise<number> {
  let dir: string | undefined;
  let writeExample = false;
  let schemaFile: string | undefined;
  let explicitSchemaFile = false;
  let format: SyncOutputFormat = 'pretty';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '-h' || arg === '--help') {
      io.stdout(getSyncHelpText());
      return 0;
    }
    if (arg === '--write-example') {
      writeExample = true;
      continue;
    }
    if (arg === '--schema') {
      const val = args[i + 1];
      if (!val || val.startsWith('-')) {
        io.stderr('Error: --schema requires a relative file path.');
        return 2;
      }
      schemaFile = val;
      explicitSchemaFile = true;
      i++;
      continue;
    }
    if (arg.startsWith('--schema=')) {
      schemaFile = arg.slice('--schema='.length);
      explicitSchemaFile = true;
      continue;
    }
    if (arg === '--format') {
      const val = args[i + 1];
      if (!val || !VALID_SYNC_FORMATS.has(val)) {
        io.stderr('Error: --format for sync must be pretty or json.');
        return 2;
      }
      format = val as SyncOutputFormat;
      i++;
      continue;
    }
    if (arg.startsWith('--format=')) {
      const val = arg.slice('--format='.length);
      if (!VALID_SYNC_FORMATS.has(val)) {
        io.stderr('Error: --format for sync must be pretty or json.');
        return 2;
      }
      format = val as SyncOutputFormat;
      continue;
    }
    if (arg.startsWith('-')) {
      io.stderr(`Error: Unknown option '${arg}' for sync.`);
      return 2;
    }
    if (dir !== undefined) {
      io.stderr(`Error: Unexpected positional argument '${arg}'.`);
      return 2;
    }
    dir = arg;
  }

  try {
    const report = syncWorkspace({
      rootDir: dir ?? process.cwd(),
      ...(schemaFile !== undefined ? { schemaFile, explicitSchemaFile } : {}),
      writeExample
    });
    io.stdout(formatSyncReport(report, format));
    return 0;
  } catch (err) {
    io.stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

async function handleCheckCommand(args: string[], io: CliIo): Promise<number> {
  let dir: string | undefined;
  let envFile: string | undefined;
  let explicitEnvFile = false;
  let exampleFile: string | undefined;
  let explicitExampleFile = false;
  let schemaFile: string | undefined;
  let explicitSchemaFile = false;
  let format: CheckOutputFormat = 'pretty';
  let failOn: FindingSeverity = 'medium';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '-h' || arg === '--help') {
      io.stdout(getCheckHelpText());
      return 0;
    }
    if (arg === '--env') {
      const val = args[i + 1];
      if (!val) {
        io.stderr('Error: --env requires a relative file path.');
        return 2;
      }
      envFile = val;
      explicitEnvFile = true;
      i++;
      continue;
    }
    if (arg.startsWith('--env=')) {
      envFile = arg.slice('--env='.length);
      explicitEnvFile = true;
      continue;
    }
    if (arg === '--example') {
      const val = args[i + 1];
      if (!val) {
        io.stderr('Error: --example requires a relative file path.');
        return 2;
      }
      exampleFile = val;
      explicitExampleFile = true;
      i++;
      continue;
    }
    if (arg.startsWith('--example=')) {
      exampleFile = arg.slice('--example='.length);
      explicitExampleFile = true;
      continue;
    }
    if (arg === '--schema') {
      const val = args[i + 1];
      if (!val) {
        io.stderr('Error: --schema requires a relative file path.');
        return 2;
      }
      schemaFile = val;
      explicitSchemaFile = true;
      i++;
      continue;
    }
    if (arg.startsWith('--schema=')) {
      schemaFile = arg.slice('--schema='.length);
      explicitSchemaFile = true;
      continue;
    }
    if (arg === '--format') {
      const val = args[i + 1];
      if (!val || !VALID_CHECK_FORMATS.has(val)) {
        io.stderr('Error: --format for check must be pretty, json, markdown, or sarif.');
        return 2;
      }
      format = val as CheckOutputFormat;
      i++;
      continue;
    }
    if (arg.startsWith('--format=')) {
      const val = arg.slice('--format='.length);
      if (!VALID_CHECK_FORMATS.has(val)) {
        io.stderr('Error: --format for check must be pretty, json, markdown, or sarif.');
        return 2;
      }
      format = val as CheckOutputFormat;
      continue;
    }
    if (arg === '--fail-on') {
      const val = args[i + 1];
      if (!val || !VALID_SEVERITIES.has(val)) {
        io.stderr('Error: --fail-on must be critical, high, medium, or low.');
        return 2;
      }
      failOn = val as FindingSeverity;
      i++;
      continue;
    }
    if (arg.startsWith('--fail-on=')) {
      const val = arg.slice('--fail-on='.length);
      if (!VALID_SEVERITIES.has(val)) {
        io.stderr('Error: --fail-on must be critical, high, medium, or low.');
        return 2;
      }
      failOn = val as FindingSeverity;
      continue;
    }
    if (arg.startsWith('-')) {
      io.stderr(`Error: Unknown option '${arg}' for check.`);
      return 2;
    }
    if (dir !== undefined) {
      io.stderr(`Error: Unexpected positional argument '${arg}'.`);
      return 2;
    }
    dir = arg;
  }

  try {
    const report = analyzeWorkspace({
      rootDir: dir ?? process.cwd(),
      ...(envFile !== undefined ? { envFile, explicitEnvFile } : {}),
      ...(exampleFile !== undefined ? { exampleFile, explicitExampleFile } : {}),
      ...(schemaFile !== undefined ? { schemaFile, explicitSchemaFile } : {})
    });
    io.stdout(formatCheckReport(report, format));
    return doesFindingTriggerFailOn(report.findings, failOn) ? 1 : 0;
  } catch (err) {
    io.stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

export async function runCli(argv: string[], io: CliIo = DEFAULT_IO): Promise<number> {
  if (argv.length === 0) {
    io.stdout(getMainHelpText());
    return 0;
  }

  const first = argv[0]!;
  if (first === '-h' || first === '--help') {
    io.stdout(getMainHelpText());
    return 0;
  }
  if (first === '-v' || first === '--version') {
    io.stdout(PACKAGE_VERSION);
    return 0;
  }

  const rest = argv.slice(1);
  if (first === 'sync') {
    return handleSyncCommand(rest, io);
  }
  if (first === 'check') {
    return handleCheckCommand(rest, io);
  }
  if (first === 'mcp') {
    if (rest.includes('-h') || rest.includes('--help')) {
      io.stdout(getMcpHelpText());
      return 0;
    }
    return runMcpEntrypoint(rest, io);
  }

  io.stderr(`Error: Unknown command '${first}'. Run 'env-guard --help' for usage.`);
  return 2;
}

if (isMainModule(import.meta.url)) {
  runCli(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    }
  );
}
