import {
  createNullMap,
  detectWeakSecretInEnv,
  hasOwn,
  maskValueLength,
  type MaskedLengthBucket
} from '../security/secretHygiene.js';

export type EnvSchemaType =
  | 'string'
  | 'int'
  | 'port'
  | 'url'
  | 'bool'
  | 'email'
  | 'secret'
  | 'enum';

export interface SchemaPropertySpec {
  type: EnvSchemaType;
  required?: boolean;
  default?: string | number | boolean;
  values?: string[];
  description?: string;
  minEntropy?: number;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  allowEmpty?: boolean;
}

export interface ParsedEnvSchema {
  properties: Record<string, SchemaPropertySpec>;
  errors: string[];
}

export interface SchemaRuleCheckResult {
  key: string;
  expectedType: EnvSchemaType;
  required: boolean;
  hasEnvValue: boolean;
  inExample: boolean;
  maskedLength: MaskedLengthBucket;
  status: 'valid' | 'missing_required' | 'type_error' | 'weak_secret';
  message: string;
}

export interface SchemaValidationReport {
  valid: boolean;
  rules: SchemaRuleCheckResult[];
}

const VALID_TYPES = new Set<string>([
  'string',
  'int',
  'integer',
  'port',
  'url',
  'bool',
  'boolean',
  'email',
  'secret',
  'enum'
]);

const ALLOWED_URL_PROTOCOLS = new Set<string>([
  'http:',
  'https:',
  'postgres:',
  'postgresql:',
  'mysql:',
  'redis:',
  'rediss:',
  'mongodb:',
  'mongodb+srv:',
  'ws:',
  'wss:',
  'amqp:',
  'amqps:'
]);

const SCHEMA_META_KEYS = new Set<string>([
  '$schema',
  '$id',
  'title',
  'description',
  'version',
  'type',
  'required',
  'additionalProperties'
]);

function normalizeSchemaType(raw: unknown): EnvSchemaType | null {
  if (typeof raw !== 'string') return null;
  const lower = raw.toLowerCase();
  if (!VALID_TYPES.has(lower)) return null;
  if (lower === 'integer') return 'int';
  if (lower === 'boolean') return 'bool';
  return lower as EnvSchemaType;
}

function isBannedProtoKey(key: string): boolean {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}

export function parseEnvSchemaJson(rawJsonText: string): ParsedEnvSchema {
  const properties = createNullMap<SchemaPropertySpec>();
  const errors: string[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJsonText);
  } catch (err) {
    return {
      properties,
      errors: [`Invalid JSON in schema file: ${err instanceof Error ? err.message : 'parse error'}`]
    };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      properties,
      errors: ['Schema root must be a JSON object.']
    };
  }

  const rootObj = parsed as Record<string, unknown>;
  const topLevelRequired = new Set<string>();
  if (hasOwn(rootObj, 'required') && Array.isArray(rootObj.required)) {
    for (let i = 0; i < rootObj.required.length; i++) {
      const item = rootObj.required[i];
      if (typeof item === 'string' && !isBannedProtoKey(item)) {
        topLevelRequired.add(item);
      }
    }
  }

  let rawMapSource: Record<string, unknown> = rootObj;
  if (
    hasOwn(rootObj, 'variables') &&
    rootObj.variables !== null &&
    typeof rootObj.variables === 'object' &&
    !Array.isArray(rootObj.variables)
  ) {
    rawMapSource = rootObj.variables as Record<string, unknown>;
  } else if (
    hasOwn(rootObj, 'properties') &&
    rootObj.properties !== null &&
    typeof rootObj.properties === 'object' &&
    !Array.isArray(rootObj.properties)
  ) {
    rawMapSource = rootObj.properties as Record<string, unknown>;
  }

  const keys = Object.keys(rawMapSource);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    if (isBannedProtoKey(key)) {
      continue;
    }
    if (rawMapSource === rootObj && SCHEMA_META_KEYS.has(key)) {
      continue;
    }

    const def = rawMapSource[key];
    if (def === null || typeof def !== 'object' || Array.isArray(def)) {
      errors.push(`Schema definition for '${key}' must be an object.`);
      continue;
    }
    const defObj = def as Record<string, unknown>;
    const normalizedType = normalizeSchemaType(hasOwn(defObj, 'type') ? defObj.type : 'string');
    if (!normalizedType) {
      errors.push(`Invalid schema type for '${key}'. Supported types: string, int, port, url, bool, email, secret, enum.`);
      continue;
    }

    let enumValues: string[] | undefined;
    if (normalizedType === 'enum') {
      const rawEnum = hasOwn(defObj, 'values')
        ? defObj.values
        : hasOwn(defObj, 'enum')
          ? defObj.enum
          : undefined;
      if (!Array.isArray(rawEnum) || rawEnum.length === 0 || !rawEnum.every((v) => typeof v === 'string')) {
        errors.push(`Enum variable '${key}' must specify a non-empty string array in 'values'.`);
        continue;
      }
      enumValues = [...rawEnum];
    }

    const isReq =
      (hasOwn(defObj, 'required') && typeof defObj.required === 'boolean'
        ? defObj.required
        : false) || topLevelRequired.has(key);

    const spec: SchemaPropertySpec = {
      type: normalizedType,
      required: isReq
    };

    if (
      hasOwn(defObj, 'default') &&
      (typeof defObj.default === 'string' ||
        typeof defObj.default === 'number' ||
        typeof defObj.default === 'boolean')
    ) {
      spec.default = defObj.default;
    }
    if (enumValues) {
      spec.values = enumValues;
    }
    if (hasOwn(defObj, 'description') && typeof defObj.description === 'string') {
      spec.description = defObj.description;
    }
    if (hasOwn(defObj, 'minEntropy') && typeof defObj.minEntropy === 'number') {
      spec.minEntropy = defObj.minEntropy;
    }
    if (hasOwn(defObj, 'minLength') && typeof defObj.minLength === 'number') {
      spec.minLength = defObj.minLength;
    }
    if (hasOwn(defObj, 'maxLength') && typeof defObj.maxLength === 'number') {
      spec.maxLength = defObj.maxLength;
    }
    if (hasOwn(defObj, 'min') && typeof defObj.min === 'number') {
      spec.min = defObj.min;
    }
    if (hasOwn(defObj, 'max') && typeof defObj.max === 'number') {
      spec.max = defObj.max;
    }
    if (hasOwn(defObj, 'allowEmpty') && typeof defObj.allowEmpty === 'boolean') {
      spec.allowEmpty = defObj.allowEmpty;
    }

    properties[key] = spec;
  }

  return { properties, errors };
}

function isStrictBase10Int(val: string): number | null {
  if (val.length === 0 || val.length > 20) {
    return null;
  }
  let start = 0;
  if (val.charCodeAt(0) === 0x2d /* '-' */ || val.charCodeAt(0) === 0x2b /* '+' */) {
    start = 1;
  }
  if (start >= val.length) {
    return null;
  }
  for (let i = start; i < val.length; i++) {
    const code = val.charCodeAt(i);
    if (code < 0x30 || code > 0x39) {
      return null;
    }
  }
  const num = Number(val);
  if (!Number.isSafeInteger(num)) {
    return null;
  }
  return num;
}

function isValidLinearEmail(val: string): boolean {
  if (val.length < 5 || val.length > 254) {
    return false;
  }
  const atIdx = val.indexOf('@');
  if (atIdx <= 0 || atIdx > 64 || val.indexOf('@', atIdx + 1) !== -1) {
    return false;
  }
  const local = val.slice(0, atIdx);
  const domain = val.slice(atIdx + 1);
  if (domain.length < 3 || domain.length > 253) {
    return false;
  }

  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return false;
  }
  for (let i = 0; i < local.length; i++) {
    const c = local.charCodeAt(i);
    const ok =
      (c >= 0x30 && c <= 0x39) ||
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      c === 0x2e || // .
      c === 0x5f || // _
      c === 0x2d || // -
      c === 0x2b;   // +
    if (!ok) {
      return false;
    }
  }

  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) {
    return false;
  }
  const labels = domain.split('.');
  if (labels.length < 2) {
    return false;
  }
  const tld = labels[labels.length - 1]!;
  if (tld.length < 2) {
    return false;
  }
  for (let i = 0; i < tld.length; i++) {
    const tc = tld.charCodeAt(i);
    if (!((tc >= 0x41 && tc <= 0x5a) || (tc >= 0x61 && tc <= 0x7a))) {
      return false;
    }
  }
  for (let l = 0; l < labels.length; l++) {
    const label = labels[l]!;
    if (label.length === 0 || label.length > 63 || label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    for (let k = 0; k < label.length; k++) {
      const lc = label.charCodeAt(k);
      const ok =
        (lc >= 0x30 && lc <= 0x39) ||
        (lc >= 0x41 && lc <= 0x5a) ||
        (lc >= 0x61 && lc <= 0x7a) ||
        lc === 0x2d;
      if (!ok) {
        return false;
      }
    }
  }
  return true;
}

function isValidUrlValue(val: string): boolean {
  if (val.length === 0 || val.length > 2048) {
    return false;
  }
  for (let i = 0; i < val.length; i++) {
    const c = val.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) {
      return false;
    }
  }
  try {
    const u = new URL(val);
    if (!ALLOWED_URL_PROTOCOLS.has(u.protocol)) {
      return false;
    }
    return u.hostname.length > 0;
  } catch {
    return false;
  }
}

/**
 * Validates parsed `.env` values against `.env.schema.json` rules.
 * SECURITY INVARIANT: Raw `.env` values are NEVER included in messages or returned fields.
 */
export function validateEnvAgainstSchema(
  envValues: Record<string, string>,
  schema: ParsedEnvSchema,
  exampleValues: Record<string, string> = createNullMap<string>()
): SchemaValidationReport {
  const rules: SchemaRuleCheckResult[] = [];
  const keys = Object.keys(schema.properties).sort();
  let allValid = schema.errors.length === 0;

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    const spec = schema.properties[key]!;
    const isPresent = hasOwn(envValues, key);
    const rawVal = isPresent ? envValues[key]! : undefined;
    const hasNonEmpty = rawVal !== undefined && rawVal.length > 0;
    const inExample = hasOwn(exampleValues, key);
    const maskedLength = maskValueLength(rawVal);
    const isRequired = Boolean(spec.required);

    // Resolve effective value (use schema default when missing or empty if default exists)
    let effectiveVal: string | undefined = rawVal;
    if ((!isPresent || rawVal === '') && spec.default !== undefined) {
      effectiveVal = String(spec.default);
    }

    if (effectiveVal === undefined || (effectiveVal === '' && !spec.allowEmpty)) {
      if (isRequired && spec.default === undefined) {
        allValid = false;
        rules.push({
          key,
          expectedType: spec.type,
          required: true,
          hasEnvValue: hasNonEmpty,
          inExample,
          maskedLength,
          status: 'missing_required',
          message: `Required variable '${key}' (type: ${spec.type}) is missing or empty in environment file.`
        });
      } else {
        rules.push({
          key,
          expectedType: spec.type,
          required: isRequired,
          hasEnvValue: hasNonEmpty,
          inExample,
          maskedLength,
          status: 'valid',
          message: `Optional variable '${key}' is unset.`
        });
      }
      continue;
    }

    // Type-specific validation (never echoing effectiveVal!)
    switch (spec.type) {
      case 'string': {
        if (spec.minLength !== undefined && effectiveVal.length < spec.minLength) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'string',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) is shorter than minLength ${spec.minLength}.`
          });
        } else if (spec.maxLength !== undefined && effectiveVal.length > spec.maxLength) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'string',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) exceeds maxLength ${spec.maxLength}.`
          });
        } else {
          rules.push({
            key,
            expectedType: 'string',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies string constraint.`
          });
        }
        break;
      }

      case 'int': {
        const parsedInt = isStrictBase10Int(effectiveVal.trim());
        if (parsedInt === null) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'int',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) must be a valid integer.`
          });
        } else if (spec.min !== undefined && parsedInt < spec.min) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'int',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) is less than minimum allowed integer ${spec.min}.`
          });
        } else if (spec.max !== undefined && parsedInt > spec.max) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'int',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) exceeds maximum allowed integer ${spec.max}.`
          });
        } else {
          rules.push({
            key,
            expectedType: 'int',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies int constraint.`
          });
        }
        break;
      }

      case 'port': {
        const portNum = isStrictBase10Int(effectiveVal.trim());
        if (portNum === null || portNum < 1 || portNum > 65535) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'port',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) must be a valid TCP/UDP port integer between 1 and 65535.`
          });
        } else {
          rules.push({
            key,
            expectedType: 'port',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies port constraint (1..65535).`
          });
        }
        break;
      }

      case 'url': {
        if (!isValidUrlValue(effectiveVal.trim())) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'url',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) must be a valid URL with a supported scheme.`
          });
        } else {
          rules.push({
            key,
            expectedType: 'url',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies url constraint.`
          });
        }
        break;
      }

      case 'bool': {
        const lower = effectiveVal.trim().toLowerCase();
        if (
          lower !== 'true' &&
          lower !== 'false' &&
          lower !== '1' &&
          lower !== '0' &&
          lower !== 'yes' &&
          lower !== 'no'
        ) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'bool',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) must be a boolean (true, false, 1, 0, yes, no).`
          });
        } else {
          rules.push({
            key,
            expectedType: 'bool',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies bool constraint.`
          });
        }
        break;
      }

      case 'email': {
        if (!isValidLinearEmail(effectiveVal.trim())) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'email',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) must be a valid email address.`
          });
        } else {
          rules.push({
            key,
            expectedType: 'email',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies email constraint.`
          });
        }
        break;
      }

      case 'enum': {
        const allowed = spec.values ?? [];
        if (!allowed.includes(effectiveVal)) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'enum',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'type_error',
            message: `Variable '${key}' (***) must be one of [${allowed.join(', ')}].`
          });
        } else {
          rules.push({
            key,
            expectedType: 'enum',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Variable '${key}' satisfies enum constraint.`
          });
        }
        break;
      }

      case 'secret': {
        const weakCheck = detectWeakSecretInEnv(key, effectiveVal, true, {
          minLength: spec.minLength ?? 16,
          minEntropy: spec.minEntropy ?? 3.0
        });
        if (weakCheck !== null) {
          allValid = false;
          rules.push({
            key,
            expectedType: 'secret',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'weak_secret',
            message: `Secret variable '${key}' (***): ${weakCheck.reason}.`
          });
        } else {
          rules.push({
            key,
            expectedType: 'secret',
            required: isRequired,
            hasEnvValue: hasNonEmpty,
            inExample,
            maskedLength,
            status: 'valid',
            message: `Secret variable '${key}' satisfies entropy and non-placeholder policy.`
          });
        }
        break;
      }
    }
  }

  return {
    valid: allValid,
    rules
  };
}
