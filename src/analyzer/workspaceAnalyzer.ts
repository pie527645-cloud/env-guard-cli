import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  MAX_FILE_BYTES,
  PathSecurityError,
  readBoundedTextFile,
  resolveCanonicalRoot,
  resolveContainedPath,
  toPosixRelative
} from '../security/pathGuard.js';
import {
  createNullMap,
  detectRealSecretInExample,
  detectWeakSecretInEnv,
  hasOwn,
  maskValueLength,
  type MaskedLengthBucket
} from '../security/secretHygiene.js';
import {
  generateScrubbedExample,
  parseEnv,
  type EnvEntry,
  type EnvParseResult
} from '../parser/index.js';
import {
  parseEnvSchemaJson,
  scanWorkspaceCode,
  validateEnvAgainstSchema,
  type CodeScanResult,
  type ParsedEnvSchema,
  type SchemaValidationReport
} from '../scanner/index.js';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export type RuleId =
  | 'ENV001'
  | 'ENV002'
  | 'ENV003'
  | 'ENV004'
  | 'ENV005'
  | 'ENV006'
  | 'ENV007';

export interface DriftFinding {
  ruleId: RuleId;
  ruleName: string;
  severity: FindingSeverity;
  key: string;
  file: string;
  line: number;
  redactedValue: '***';
  message: string;
}

export interface KeyInventoryItem {
  key: string;
  hasEnvValue: boolean;
  isDefinedInEnv: boolean;
  inExample: boolean;
  inSchema: boolean;
  inCode: boolean;
  maskedLength: MaskedLengthBucket;
  codeLocations: string[];
  validationStatus: 'valid' | 'invalid' | 'missing' | 'unvalidated';
}

export interface WorkspaceCheckOptions {
  rootDir: string;
  subpath?: string;
  envFile?: string;
  exampleFile?: string;
  schemaFile?: string;
  explicitEnvFile?: boolean;
  explicitExampleFile?: boolean;
  explicitSchemaFile?: boolean;
}

export interface WorkspaceCheckReport {
  targetDir: string;
  envExists: boolean;
  exampleExists: boolean;
  schemaExists: boolean;
  scannedFilesCount: number;
  keys: KeyInventoryItem[];
  findings: DriftFinding[];
  missingKeys: string[];
  undocumentedKeys: string[];
  unusedKeys: string[];
  schemaReport: SchemaValidationReport | null;
}

export interface WorkspaceSyncOptions {
  rootDir: string;
  subpath?: string;
  schemaFile?: string;
  explicitSchemaFile?: boolean;
  writeExample?: boolean;
}

export interface WorkspaceSyncReport {
  targetDir: string;
  writtenExamplePath: string | null;
  allKeys: string[];
  inCode: string[];
  inEnv: string[];
  inExample: string[];
  inSchema: string[];
  missingInExample: string[];
  missingInEnv: string[];
  unusedInCode: string[];
  scrubbedSecretsInExampleCount: number;
}

export const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

export function doesFindingTriggerFailOn(
  findings: DriftFinding[],
  failOn: FindingSeverity
): boolean {
  const minRank = SEVERITY_RANK[failOn];
  for (let i = 0; i < findings.length; i++) {
    if (SEVERITY_RANK[findings[i]!.severity] >= minRank) {
      return true;
    }
  }
  return false;
}

function loadOptionalBoundedText(
  fullPath: string,
  explicit: boolean,
  label: string
): { exists: boolean; content: string } {
  if (!fs.existsSync(fullPath)) {
    if (explicit) {
      throw new PathSecurityError(`Specified ${label} file was not found.`, 'FILE_NOT_FOUND');
    }
    return { exists: false, content: '' };
  }
  let lstat: fs.Stats;
  try {
    lstat = fs.lstatSync(fullPath);
  } catch {
    throw new PathSecurityError(`Unable to stat ${label} file.`, 'STAT_ERROR');
  }
  if (lstat.isSymbolicLink()) {
    throw new PathSecurityError(`Symbolic link ${label} files are blocked for security.`, 'SYMLINK_BLOCKED');
  }
  const readRes = readBoundedTextFile(fullPath, {
    maxBytes: MAX_FILE_BYTES,
    rejectBinary: true
  });
  if (readRes.skippedReason === 'too_large') {
    throw new PathSecurityError(`${label} file exceeds maximum size limit of 512 KB.`, 'FILE_TOO_LARGE');
  }
  if (readRes.skippedReason === 'binary' || readRes.content === undefined) {
    throw new PathSecurityError(`${label} file is binary or not a regular text file.`, 'INVALID_TEXT_FILE');
  }
  return { exists: true, content: readRes.content };
}

function buildEntryLineMap(entries: EnvEntry[]): Record<string, number> {
  const lineMap = createNullMap<number>();
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    lineMap[e.key] = e.line;
  }
  return lineMap;
}

export function analyzeWorkspace(options: WorkspaceCheckOptions): WorkspaceCheckReport {
  const canonicalRoot = resolveCanonicalRoot(options.rootDir);
  const targetDir = options.subpath
    ? resolveContainedPath(canonicalRoot, options.subpath)
    : canonicalRoot;

  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    throw new PathSecurityError('Target directory does not exist or is not a directory.', 'INVALID_TARGET_DIR');
  }

  const envPath = resolveContainedPath(
    targetDir,
    options.envFile ?? '.env'
  );
  // Also enforce containment against canonicalRoot
  resolveContainedPath(canonicalRoot, path.relative(canonicalRoot, envPath));

  const examplePath = resolveContainedPath(
    targetDir,
    options.exampleFile ?? '.env.example'
  );
  resolveContainedPath(canonicalRoot, path.relative(canonicalRoot, examplePath));

  const schemaPath = resolveContainedPath(
    targetDir,
    options.schemaFile ?? '.env.schema.json'
  );
  resolveContainedPath(canonicalRoot, path.relative(canonicalRoot, schemaPath));

  const envLoaded = loadOptionalBoundedText(envPath, Boolean(options.explicitEnvFile), 'environment');
  const exampleLoaded = loadOptionalBoundedText(examplePath, Boolean(options.explicitExampleFile), 'example');
  const schemaLoaded = loadOptionalBoundedText(schemaPath, Boolean(options.explicitSchemaFile), 'schema');

  const envRelUri = toPosixRelative(targetDir, envPath);
  const exampleRelUri = toPosixRelative(targetDir, examplePath);
  const schemaRelUri = toPosixRelative(targetDir, schemaPath);

  const envParsed: EnvParseResult = envLoaded.exists
    ? parseEnv(envLoaded.content, { interpolate: true })
    : { values: createNullMap(), rawValues: createNullMap(), entries: [], errors: [] };

  const exampleParsed: EnvParseResult = exampleLoaded.exists
    ? parseEnv(exampleLoaded.content, { interpolate: true })
    : { values: createNullMap(), rawValues: createNullMap(), entries: [], errors: [] };

  let parsedSchema: ParsedEnvSchema | null = null;
  if (schemaLoaded.exists) {
    parsedSchema = parseEnvSchemaJson(schemaLoaded.content);
  }

  const codeScan: CodeScanResult = scanWorkspaceCode(targetDir);

  const findings: DriftFinding[] = [];

  // 1. Parse/interpolation errors in .env and .env.example (ENV005)
  for (let i = 0; i < envParsed.errors.length; i++) {
    const diag = envParsed.errors[i]!;
    findings.push({
      ruleId: 'ENV005',
      ruleName: 'env-parse-error',
      severity: 'high',
      key: diag.key ?? '(syntax)',
      file: envRelUri,
      line: diag.line,
      redactedValue: '***',
      message: `${diag.message}`
    });
  }
  for (let i = 0; i < exampleParsed.errors.length; i++) {
    const diag = exampleParsed.errors[i]!;
    findings.push({
      ruleId: 'ENV005',
      ruleName: 'env-parse-error',
      severity: 'high',
      key: diag.key ?? '(syntax)',
      file: exampleRelUri,
      line: diag.line,
      redactedValue: '***',
      message: `${diag.message}`
    });
  }

  // 2. Real secrets accidentally committed in .env.example (ENV001 - critical)
  if (exampleLoaded.exists) {
    for (let i = 0; i < exampleParsed.entries.length; i++) {
      const entry = exampleParsed.entries[i]!;
      const checkResolved = detectRealSecretInExample(entry.key, entry.value);
      const checkRaw = checkResolved ?? detectRealSecretInExample(entry.key, entry.rawValue);
      if (checkRaw !== null) {
        findings.push({
          ruleId: 'ENV001',
          ruleName: 'real-secret-in-example',
          severity: 'critical',
          key: entry.key,
          file: exampleRelUri,
          line: entry.line,
          redactedValue: '***',
          message: `Potential real secret detected for '${entry.key}' (***) in ${exampleRelUri}: ${checkRaw.reason}.`
        });
      }
    }
  }

  // 3. Schema validation (ENV002 missing required, ENV003 weak secret, ENV004 type failure, ENV005 schema syntax)
  const envLineByKey = buildEntryLineMap(envParsed.entries);
  const exampleLineByKey = buildEntryLineMap(exampleParsed.entries);
  let schemaReport: SchemaValidationReport | null = null;
  const schemaReportedMissing = createNullMap<boolean>();
  const schemaReportedSecret = createNullMap<boolean>();
  const schemaStatusByKey = createNullMap<'valid' | 'invalid' | 'missing'>();

  if (parsedSchema) {
    for (let i = 0; i < parsedSchema.errors.length; i++) {
      findings.push({
        ruleId: 'ENV005',
        ruleName: 'env-parse-error',
        severity: 'high',
        key: '(schema)',
        file: schemaRelUri,
        line: 1,
        redactedValue: '***',
        message: parsedSchema.errors[i]!
      });
    }

    schemaReport = validateEnvAgainstSchema(
      envParsed.values,
      parsedSchema,
      exampleParsed.values
    );

    for (let i = 0; i < schemaReport.rules.length; i++) {
      const ruleRes = schemaReport.rules[i]!;
      const lineNum = hasOwn(envLineByKey, ruleRes.key) ? envLineByKey[ruleRes.key]! : 1;

      if (ruleRes.status === 'missing_required') {
        schemaReportedMissing[ruleRes.key] = true;
        schemaStatusByKey[ruleRes.key] = 'missing';
        findings.push({
          ruleId: 'ENV002',
          ruleName: 'missing-required-env',
          severity: 'high',
          key: ruleRes.key,
          file: envLoaded.exists ? envRelUri : schemaRelUri,
          line: lineNum,
          redactedValue: '***',
          message: ruleRes.message
        });
      } else if (ruleRes.status === 'type_error') {
        schemaStatusByKey[ruleRes.key] = 'invalid';
        findings.push({
          ruleId: 'ENV004',
          ruleName: 'schema-type-mismatch',
          severity: 'high',
          key: ruleRes.key,
          file: envRelUri,
          line: lineNum,
          redactedValue: '***',
          message: ruleRes.message
        });
      } else if (ruleRes.status === 'weak_secret') {
        schemaReportedSecret[ruleRes.key] = true;
        schemaStatusByKey[ruleRes.key] = 'invalid';
        findings.push({
          ruleId: 'ENV003',
          ruleName: 'weak-secret-value',
          severity: 'high',
          key: ruleRes.key,
          file: envRelUri,
          line: lineNum,
          redactedValue: '***',
          message: ruleRes.message
        });
      } else {
        schemaStatusByKey[ruleRes.key] = 'valid';
      }
    }
  }

  // Collect union of all known keys
  const allKeySet = createNullMap<boolean>();
  const addKeysFrom = (obj: Record<string, unknown>): void => {
    const ks = Object.keys(obj);
    for (let i = 0; i < ks.length; i++) {
      const k = ks[i]!;
      if (k !== '__proto__' && k !== 'constructor' && k !== 'prototype') {
        allKeySet[k] = true;
      }
    }
  };
  addKeysFrom(envParsed.values);
  addKeysFrom(exampleParsed.values);
  addKeysFrom(codeScan.byKey);
  if (parsedSchema) {
    addKeysFrom(parsedSchema.properties);
  }

  const sortedKeys = Object.keys(allKeySet).sort();
  const missingKeys: string[] = [];
  const undocumentedKeys: string[] = [];
  const unusedKeys: string[] = [];
  const keyInventory: KeyInventoryItem[] = [];

  for (let i = 0; i < sortedKeys.length; i++) {
    const key = sortedKeys[i]!;
    const isDefinedInEnv = hasOwn(envParsed.values, key);
    const envVal = isDefinedInEnv ? envParsed.values[key]! : undefined;
    const hasEnvValue = envVal !== undefined && envVal.length > 0;
    const inExample = hasOwn(exampleParsed.values, key);
    const inSchema = parsedSchema !== null && hasOwn(parsedSchema.properties, key);
    const inCode = hasOwn(codeScan.byKey, key);
    const codeRefs = inCode ? codeScan.byKey[key]! : [];
    const codeLocations = codeRefs.map((r) => `${r.file}:${r.line}`);

    const schemaSpec = inSchema && parsedSchema ? parsedSchema.properties[key] : undefined;
    const isOptionalWithDefault =
      schemaSpec !== undefined &&
      (schemaSpec.default !== undefined || schemaSpec.required === false);

    // 4. Weak secret heuristic check on .env values not already checked as schema `secret` (ENV003)
    let heuristicFailed = false;
    if (envLoaded.exists && isDefinedInEnv && !hasOwn(schemaReportedSecret, key)) {
      const forceSecret = schemaSpec?.type === 'secret';
      // Skip heuristic if schema explicitly typed this key as non-secret bool/port/int/enum
      const explicitlyNonSecretType =
        schemaSpec !== undefined &&
        (schemaSpec.type === 'port' ||
          schemaSpec.type === 'int' ||
          schemaSpec.type === 'bool' ||
          schemaSpec.type === 'enum');
      if (!explicitlyNonSecretType) {
        const weak = detectWeakSecretInEnv(key, envVal!, forceSecret);
        if (weak !== null) {
          heuristicFailed = true;
          findings.push({
            ruleId: 'ENV003',
            ruleName: 'weak-secret-value',
            severity: 'high',
            key,
            file: envRelUri,
            line: hasOwn(envLineByKey, key) ? envLineByKey[key]! : 1,
            redactedValue: '***',
            message: `Weak or placeholder value detected for '${key}' (***) in ${envRelUri}: ${weak.reason}.`
          });
        }
      }
    }

    // 5. Missing required keys in .env (ENV002) when referenced in code or .env.example and .env exists
    const isMissingFromEnv = !isDefinedInEnv;
    if (hasOwn(schemaReportedMissing, key)) {
      missingKeys.push(key);
    } else if (
      envLoaded.exists &&
      isMissingFromEnv &&
      (inCode || inExample) &&
      !isOptionalWithDefault
    ) {
      missingKeys.push(key);
      const firstRef = codeRefs[0];
      findings.push({
        ruleId: 'ENV002',
        ruleName: 'missing-required-env',
        severity: 'high',
        key,
        file: firstRef ? firstRef.file : exampleRelUri,
        line: firstRef ? firstRef.line : (hasOwn(exampleLineByKey, key) ? exampleLineByKey[key]! : 1),
        redactedValue: '***',
        message: `Environment variable '${key}' is required by ${inCode ? 'source code' : exampleRelUri} but missing in ${envRelUri}.`
      });
    }

    // 6. Undocumented variables missing from .env.example (ENV006 - medium)
    if (!inExample && (inCode || (exampleLoaded.exists && isDefinedInEnv))) {
      undocumentedKeys.push(key);
      const firstRef = codeRefs[0];
      findings.push({
        ruleId: 'ENV006',
        ruleName: 'undocumented-env-var',
        severity: 'medium',
        key,
        file: firstRef ? firstRef.file : envRelUri,
        line: firstRef ? firstRef.line : (hasOwn(envLineByKey, key) ? envLineByKey[key]! : 1),
        redactedValue: '***',
        message: `Environment variable '${key}' is ${inCode ? 'referenced in code' : `defined in ${envRelUri}`} but undocumented in ${exampleRelUri}.`
      });
    }

    // 7. Unused variables when code files exist (ENV007 - low)
    if (codeScan.scannedFilesCount > 0 && !inCode && !inSchema && (isDefinedInEnv || inExample)) {
      unusedKeys.push(key);
      findings.push({
        ruleId: 'ENV007',
        ruleName: 'unused-env-var',
        severity: 'low',
        key,
        file: isDefinedInEnv ? envRelUri : exampleRelUri,
        line: isDefinedInEnv
          ? (hasOwn(envLineByKey, key) ? envLineByKey[key]! : 1)
          : (hasOwn(exampleLineByKey, key) ? exampleLineByKey[key]! : 1),
        redactedValue: '***',
        message: `Environment variable '${key}' is defined in ${isDefinedInEnv ? envRelUri : exampleRelUri} but not referenced in scanned code.`
      });
    }

    let validationStatus: KeyInventoryItem['validationStatus'] = 'unvalidated';
    if (hasOwn(schemaStatusByKey, key)) {
      const st = schemaStatusByKey[key]!;
      validationStatus = heuristicFailed && st === 'valid' ? 'invalid' : st;
    } else if (heuristicFailed) {
      validationStatus = 'invalid';
    } else if (missingKeys.includes(key)) {
      validationStatus = 'missing';
    } else if (isDefinedInEnv) {
      validationStatus = 'valid';
    }

    keyInventory.push({
      key,
      hasEnvValue,
      isDefinedInEnv,
      inExample,
      inSchema,
      inCode,
      maskedLength: maskValueLength(envVal),
      codeLocations,
      validationStatus
    });
  }

  return {
    targetDir,
    envExists: envLoaded.exists,
    exampleExists: exampleLoaded.exists,
    schemaExists: schemaLoaded.exists,
    scannedFilesCount: codeScan.scannedFilesCount,
    keys: keyInventory,
    findings,
    missingKeys,
    undocumentedKeys,
    unusedKeys,
    schemaReport
  };
}

export function syncWorkspace(options: WorkspaceSyncOptions): WorkspaceSyncReport {
  const canonicalRoot = resolveCanonicalRoot(options.rootDir);
  const targetDir = options.subpath
    ? resolveContainedPath(canonicalRoot, options.subpath)
    : canonicalRoot;

  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    throw new PathSecurityError('Target directory does not exist or is not a directory.', 'INVALID_TARGET_DIR');
  }

  const envPath = resolveContainedPath(targetDir, '.env');
  const examplePath = resolveContainedPath(targetDir, '.env.example');
  const schemaPath = resolveContainedPath(targetDir, options.schemaFile ?? '.env.schema.json');
  resolveContainedPath(canonicalRoot, path.relative(canonicalRoot, schemaPath));

  const envLoaded = loadOptionalBoundedText(envPath, false, 'environment');
  const exampleLoaded = loadOptionalBoundedText(examplePath, false, 'example');
  const schemaLoaded = loadOptionalBoundedText(schemaPath, Boolean(options.explicitSchemaFile), 'schema');

  // Parse .env ONLY to extract key names; discard values immediately!
  const envKeyNames = envLoaded.exists
    ? Object.keys(parseEnv(envLoaded.content, { interpolate: false }).rawValues).sort()
    : [];

  const exampleParsed = exampleLoaded.exists
    ? parseEnv(exampleLoaded.content, { interpolate: false })
    : { values: createNullMap<string>(), rawValues: createNullMap<string>(), entries: [], errors: [] };

  let parsedSchema: ParsedEnvSchema | null = null;
  if (schemaLoaded.exists) {
    parsedSchema = parseEnvSchemaJson(schemaLoaded.content);
    if (parsedSchema.errors.length > 0) {
      throw new PathSecurityError(parsedSchema.errors[0]!, 'INVALID_SCHEMA');
    }
  }

  const codeScan = scanWorkspaceCode(targetDir);

  const inCode = Object.keys(codeScan.byKey).sort();
  const inEnv = envKeyNames;
  const inExample = Object.keys(exampleParsed.rawValues).sort();
  const inSchema = parsedSchema ? Object.keys(parsedSchema.properties).sort() : [];

  const unionMap = createNullMap<boolean>();
  for (const list of [inCode, inEnv, inExample, inSchema]) {
    for (let i = 0; i < list.length; i++) {
      const k = list[i]!;
      if (k !== '__proto__' && k !== 'constructor' && k !== 'prototype') {
        unionMap[k] = true;
      }
    }
  }
  const allKeys = Object.keys(unionMap).sort();

  const inExampleSet = new Set(inExample);
  const inEnvSet = new Set(inEnv);
  const inCodeSet = new Set(inCode);

  const missingInExample = allKeys.filter((k) => !inExampleSet.has(k));
  const missingInEnv = allKeys.filter((k) => {
    if (inEnvSet.has(k)) return false;
    if (parsedSchema && hasOwn(parsedSchema.properties, k)) {
      const sp = parsedSchema.properties[k]!;
      if (sp.required === false || sp.default !== undefined) {
        return false;
      }
    }
    return inCodeSet.has(k) || inExampleSet.has(k) || Boolean(parsedSchema?.properties[k]?.required);
  });

  const unusedInCode =
    codeScan.scannedFilesCount > 0
      ? allKeys.filter((k) => !inCodeSet.has(k))
      : [];

  let scrubbedSecretsInExampleCount = 0;
  for (let i = 0; i < inExample.length; i++) {
    const k = inExample[i]!;
    const existingVal = exampleParsed.rawValues[k] ?? '';
    if (detectRealSecretInExample(k, existingVal) !== null) {
      scrubbedSecretsInExampleCount++;
    }
  }

  let writtenExamplePath: string | null = null;
  if (options.writeExample) {
    // Verify examplePath is not an existing symlink escaping root
    if (fs.existsSync(examplePath) && fs.lstatSync(examplePath).isSymbolicLink()) {
      throw new PathSecurityError('Refusing to overwrite symbolic link .env.example.', 'SYMLINK_BLOCKED');
    }
    const scrubbedContent = generateScrubbedExample({
      allKeys,
      existingExampleValues: exampleParsed.rawValues,
      ...(parsedSchema ? { schemaProperties: parsedSchema.properties } : {})
    });
    fs.writeFileSync(examplePath, scrubbedContent, 'utf8');
    writtenExamplePath = examplePath;
  }

  return {
    targetDir,
    writtenExamplePath,
    allKeys,
    inCode,
    inEnv,
    inExample,
    inSchema,
    missingInExample,
    missingInEnv,
    unusedInCode,
    scrubbedSecretsInExampleCount
  };
}
