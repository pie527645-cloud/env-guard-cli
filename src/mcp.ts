#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  MAX_FILE_BYTES,
  PathSecurityError,
  readBoundedTextFile,
  resolveCanonicalRoot,
  resolveContainedPath
} from './security/pathGuard.js';
import { createNullMap } from './security/secretHygiene.js';
import { parseEnv } from './parser/index.js';
import { parseEnvSchemaJson, validateEnvAgainstSchema } from './scanner/index.js';
import { analyzeWorkspace } from './analyzer/workspaceAnalyzer.js';
import { PACKAGE_VERSION } from './formatters/reportFormatter.js';

export function isMainModule(metaUrl: string, argv1: string | undefined = process.argv[1]): boolean {
  if (!argv1) {
    return false;
  }
  const selfPath = fileURLToPath(metaUrl);
  try {
    const invokedCanonical = fs.realpathSync(path.resolve(argv1));
    const selfCanonical = fs.realpathSync(selfPath);
    return invokedCanonical === selfCanonical;
  } catch {
    return path.resolve(argv1) === path.resolve(selfPath);
  }
}

function safeErrorText(err: unknown): string {
  if (err instanceof PathSecurityError) {
    return `${err.code}: ${err.message}`;
  }
  return 'Operation rejected due to invalid input or unreadable workspace target.';
}

export interface ListEnvKeysPayload {
  subpath: string;
  totalKeys: number;
  envExists: boolean;
  exampleExists: boolean;
  schemaExists: boolean;
  keys: Array<{
    key: string;
    hasEnvValue: boolean;
    isDefinedInEnv: boolean;
    inExample: boolean;
    inSchema: boolean;
    inCode: boolean;
    maskedLength: string;
    codeLocations: string[];
    validationStatus: 'valid' | 'invalid' | 'missing' | 'unvalidated';
  }>;
}

export function executeListEnvKeys(canonicalRoot: string, subpath?: string): ListEnvKeysPayload {
  const normalizedSub = subpath && subpath.trim().length > 0 ? subpath.trim() : '.';
  const report = analyzeWorkspace({
    rootDir: canonicalRoot,
    subpath: normalizedSub
  });

  return {
    subpath: normalizedSub,
    totalKeys: report.keys.length,
    envExists: report.envExists,
    exampleExists: report.exampleExists,
    schemaExists: report.schemaExists,
    keys: report.keys.map((k) => ({
      key: k.key,
      hasEnvValue: k.hasEnvValue,
      isDefinedInEnv: k.isDefinedInEnv,
      inExample: k.inExample,
      inSchema: k.inSchema,
      inCode: k.inCode,
      maskedLength: k.maskedLength,
      codeLocations: k.codeLocations,
      validationStatus: k.validationStatus
    }))
  };
}

export interface CheckEnvDriftPayload {
  subpath: string;
  status: 'pass' | 'drift_detected';
  summary: {
    totalKeys: number;
    missingCount: number;
    unusedCount: number;
    undocumentedCount: number;
    findingsCount: number;
  };
  missing: string[];
  unused: string[];
  undocumented: string[];
  findings: Array<{
    ruleId: string;
    ruleName: string;
    severity: string;
    key: string;
    location: string;
    redactedValue: '***';
    message: string;
  }>;
}

export function executeCheckEnvDrift(canonicalRoot: string, subpath?: string): CheckEnvDriftPayload {
  const normalizedSub = subpath && subpath.trim().length > 0 ? subpath.trim() : '.';
  const report = analyzeWorkspace({
    rootDir: canonicalRoot,
    subpath: normalizedSub
  });

  return {
    subpath: normalizedSub,
    status: report.findings.length === 0 ? 'pass' : 'drift_detected',
    summary: {
      totalKeys: report.keys.length,
      missingCount: report.missingKeys.length,
      unusedCount: report.unusedKeys.length,
      undocumentedCount: report.undocumentedKeys.length,
      findingsCount: report.findings.length
    },
    missing: report.missingKeys,
    unused: report.unusedKeys,
    undocumented: report.undocumentedKeys,
    findings: report.findings.map((f) => ({
      ruleId: f.ruleId,
      ruleName: f.ruleName,
      severity: f.severity,
      key: f.key,
      location: `${f.file}:${f.line}`,
      redactedValue: '***',
      message: f.message
    }))
  };
}

export interface ValidateEnvSchemaPayload {
  schemaPath: string;
  valid: boolean;
  schemaErrors: string[];
  checkedKeys: number;
  rules: Array<{
    key: string;
    expectedType: string;
    required: boolean;
    hasEnvValue: boolean;
    inExample: boolean;
    maskedLength: string;
    status: 'valid' | 'missing_required' | 'type_error' | 'weak_secret';
    message: string;
  }>;
}

export function executeValidateEnvSchema(
  canonicalRoot: string,
  schemaPath?: string
): ValidateEnvSchemaPayload {
  const relSchema = schemaPath && schemaPath.trim().length > 0 ? schemaPath.trim() : '.env.schema.json';
  const resolvedSchemaFile = resolveContainedPath(canonicalRoot, relSchema);

  if (!fs.existsSync(resolvedSchemaFile)) {
    throw new PathSecurityError('Schema file does not exist in workspace.', 'SCHEMA_NOT_FOUND');
  }
  if (fs.lstatSync(resolvedSchemaFile).isSymbolicLink()) {
    throw new PathSecurityError('Symbolic link schema files are blocked.', 'SYMLINK_BLOCKED');
  }

  const schemaRead = readBoundedTextFile(resolvedSchemaFile, {
    maxBytes: MAX_FILE_BYTES,
    rejectBinary: true
  });
  if (schemaRead.content === undefined) {
    throw new PathSecurityError('Schema file exceeds size limit or is binary.', 'INVALID_SCHEMA_FILE');
  }

  const schemaDir = path.dirname(resolvedSchemaFile);
  // Ensure schemaDir itself is contained in canonicalRoot
  resolveContainedPath(canonicalRoot, path.relative(canonicalRoot, schemaDir));

  const envPath = resolveContainedPath(schemaDir, '.env');
  const examplePath = resolveContainedPath(schemaDir, '.env.example');

  let envValues = createNullMap<string>();
  if (fs.existsSync(envPath) && !fs.lstatSync(envPath).isSymbolicLink()) {
    const envRead = readBoundedTextFile(envPath, {
      maxBytes: MAX_FILE_BYTES,
      rejectBinary: true
    });
    if (envRead.content !== undefined) {
      envValues = parseEnv(envRead.content, { interpolate: true }).values;
    }
  }

  let exampleValues = createNullMap<string>();
  if (fs.existsSync(examplePath) && !fs.lstatSync(examplePath).isSymbolicLink()) {
    const exRead = readBoundedTextFile(examplePath, {
      maxBytes: MAX_FILE_BYTES,
      rejectBinary: true
    });
    if (exRead.content !== undefined) {
      exampleValues = parseEnv(exRead.content, { interpolate: true }).values;
    }
  }

  const parsedSchema = parseEnvSchemaJson(schemaRead.content);
  const validation = validateEnvAgainstSchema(envValues, parsedSchema, exampleValues);

  return {
    schemaPath: relSchema,
    valid: validation.valid,
    schemaErrors: parsedSchema.errors,
    checkedKeys: validation.rules.length,
    rules: validation.rules.map((r) => ({
      key: r.key,
      expectedType: r.expectedType,
      required: r.required,
      hasEnvValue: r.hasEnvValue,
      inExample: r.inExample,
      maskedLength: r.maskedLength,
      status: r.status,
      message: r.message
    }))
  };
}

export function createEnvGuardMcpServer(rootDir: string): McpServer {
  const canonicalRoot = resolveCanonicalRoot(rootDir);

  const server = new McpServer(
    {
      name: 'env-guard',
      version: PACKAGE_VERSION
    },
    {
      maxToolInputElements: 128
    }
  );

  const readOnlyAnnotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  };

  server.registerTool(
    'list_env_keys',
    {
      title: 'List Environment Keys',
      description:
        'List environment variable keys discovered across source code, .env.example, .env.schema.json, and .env presence flags within the workspace without exposing any values.',
      inputSchema: z.strictObject({
        subpath: z
          .string()
          .max(512)
          .optional()
          .describe('Optional relative directory path inside the workspace root.')
      }),
      annotations: readOnlyAnnotations
    },
    async (args) => {
      try {
        const payload = executeListEnvKeys(canonicalRoot, args.subpath);
        return {
          content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }]
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: safeErrorText(err) }) }]
        };
      }
    }
  );

  server.registerTool(
    'check_env_drift',
    {
      title: 'Check Environment Drift',
      description:
        'Check workspace environment configuration for missing required variables, unused variables, undocumented keys, and redacted secret hygiene findings without exposing secret values.',
      inputSchema: z.strictObject({
        subpath: z
          .string()
          .max(512)
          .optional()
          .describe('Optional relative directory path inside the workspace root.')
      }),
      annotations: readOnlyAnnotations
    },
    async (args) => {
      try {
        const payload = executeCheckEnvDrift(canonicalRoot, args.subpath);
        return {
          content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }]
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: safeErrorText(err) }) }]
        };
      }
    }
  );

  server.registerTool(
    'validate_env_schema',
    {
      title: 'Validate Environment Schema',
      description:
        'Validate workspace environment variables against a .env.schema.json specification and report rule compliance status without returning secret values.',
      inputSchema: z.strictObject({
        schemaPath: z
          .string()
          .max(512)
          .optional()
          .describe('Optional relative path to .env.schema.json inside the workspace root.')
      }),
      annotations: readOnlyAnnotations
    },
    async (args) => {
      try {
        const payload = executeValidateEnvSchema(canonicalRoot, args.schemaPath);
        return {
          content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }]
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: safeErrorText(err) }) }]
        };
      }
    }
  );

  return server;
}

export function getMcpHelpText(): string {
  return [
    'Usage: env-guard mcp [--root dir]',
    '',
    'Launches the secret-safe env-guard Model Context Protocol (MCP) server over stdio.',
    '',
    'Options:',
    '  --root dir   Workspace root directory to confine all MCP file access (default: current working directory)',
    '  -h, --help   Display this help message'
  ].join('\n');
}

export async function startStdioMcpServer(rootDir: string): Promise<void> {
  const server = createEnvGuardMcpServer(rootDir);
  const transport = new StdioServerTransport();

  const shutdown = async (): Promise<void> => {
    try {
      await server.close();
    } catch {
      // Ignore close errors
    }
  };

  process.stdin.once('end', () => {
    void shutdown();
  });
  process.stdin.once('close', () => {
    void shutdown();
  });

  await server.connect(transport);
}

export async function runMcpEntrypoint(
  argv: string[],
  io: { stdout: (msg: string) => void; stderr: (msg: string) => void } = {
    stdout: (m) => process.stdout.write(m + '\n'),
    stderr: (m) => process.stderr.write(m + '\n')
  }
): Promise<number> {
  let rootDir = process.cwd();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '-h' || arg === '--help') {
      io.stdout(getMcpHelpText());
      return 0;
    }
    if (arg === '--root') {
      const val = argv[i + 1];
      if (!val || val.startsWith('-')) {
        io.stderr('Error: --root requires a directory path.');
        return 2;
      }
      rootDir = val;
      i++;
      continue;
    }
    if (arg.startsWith('--root=')) {
      rootDir = arg.slice('--root='.length);
      if (!rootDir) {
        io.stderr('Error: --root requires a directory path.');
        return 2;
      }
      continue;
    }
    io.stderr(`Error: Unknown option '${arg}' for mcp command.`);
    return 2;
  }

  try {
    await startStdioMcpServer(rootDir);
    return 0;
  } catch (err) {
    io.stderr(`Error starting MCP server: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

if (isMainModule(import.meta.url)) {
  runMcpEntrypoint(process.argv.slice(2)).then(
    (code) => {
      if (code !== 0) {
        process.exitCode = code;
      }
    },
    (err: unknown) => {
      process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    }
  );
}
