export function createNullMap<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

export function hasOwn(obj: object, key: string): boolean {
  return Object.hasOwn(obj, key);
}

export type MaskedLengthBucket =
  | 'unset'
  | 'empty (0)'
  | '*** (1-7 chars)'
  | '*** (8-15 chars)'
  | '*** (16+ chars)';

export function maskValueLength(value: string | undefined): MaskedLengthBucket {
  if (value === undefined) {
    return 'unset';
  }
  const len = value.length;
  if (len === 0) {
    return 'empty (0)';
  }
  if (len < 8) {
    return '*** (1-7 chars)';
  }
  if (len < 16) {
    return '*** (8-15 chars)';
  }
  return '*** (16+ chars)';
}

export function computeShannonEntropy(value: string): number {
  const len = value.length;
  if (len === 0) {
    return 0;
  }
  const counts = createNullMap<number>();
  for (let i = 0; i < len; i++) {
    const ch = value[i]!;
    counts[ch] = (hasOwn(counts, ch) ? counts[ch]! : 0) + 1;
  }
  let entropy = 0;
  const keys = Object.keys(counts);
  for (let i = 0; i < keys.length; i++) {
    const p = counts[keys[i]!]! / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const SECRET_EXACT_TOKENS = new Set([
  'SECRET',
  'SECRETS',
  'PASSWORD',
  'PASSWD',
  'PWD',
  'TOKEN',
  'APIKEY',
  'PRIVKEY',
  'PRIVATEKEY',
  'CREDENTIAL',
  'CREDENTIALS',
  'PASSPHRASE'
]);

const CONNECTION_URL_SUFFIXES = ['DATABASE_URL', 'DB_URL', 'REDIS_URL', 'MONGODB_URI', 'MONGO_URL', 'AMQP_URL', 'DSN', 'CONNECTION_STRING'];

function splitKeyTokens(key: string): string[] {
  const upper = key.toUpperCase();
  const tokens: string[] = [];
  let current = '';
  for (let i = 0; i < upper.length; i++) {
    const code = upper.charCodeAt(i);
    const isAlnum = (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a);
    if (isAlnum) {
      current += upper[i]!;
    } else if (current.length > 0) {
      tokens.push(current);
      current = '';
    }
  }
  if (current.length > 0) {
    tokens.push(current);
  }
  return tokens;
}

export function isConnectionUrlKey(key: string): boolean {
  const upper = key.toUpperCase();
  for (let i = 0; i < CONNECTION_URL_SUFFIXES.length; i++) {
    const suffix = CONNECTION_URL_SUFFIXES[i]!;
    if (upper === suffix || upper.endsWith('_' + suffix)) {
      return true;
    }
  }
  return false;
}

export function isLikelySecretKey(key: string): boolean {
  const upper = key.toUpperCase();
  // Explicitly non-secret public flags
  if (upper.endsWith('_PUBLIC_KEY_ID') || upper.endsWith('_KEY_ID') || upper === 'PUBLIC_URL') {
    return false;
  }
  const tokens = splitKeyTokens(upper);
  for (let i = 0; i < tokens.length; i++) {
    if (SECRET_EXACT_TOKENS.has(tokens[i]!)) {
      return true;
    }
  }
  // Compound key suffixes like API_KEY, PRIVATE_KEY, SIGNING_KEY, ACCESS_KEY, ENCRYPTION_KEY, CLIENT_KEY, AUTH_KEY
  if (tokens.length >= 2 && tokens[tokens.length - 1] === 'KEY') {
    const prev = tokens[tokens.length - 2]!;
    if (
      prev === 'API' ||
      prev === 'PRIVATE' ||
      prev === 'SIGNING' ||
      prev === 'ACCESS' ||
      prev === 'ENCRYPTION' ||
      prev === 'MASTER' ||
      prev === 'WEBHOOK' ||
      prev === 'AUTH' ||
      prev === 'SERVICE' ||
      prev === 'SECRET'
    ) {
      return true;
    }
  }
  return false;
}

const KNOWN_PLACEHOLDERS = new Set([
  'changeme',
  'change_me',
  'change-me',
  'password',
  'passwd',
  'pass',
  'secret',
  'mysecret',
  'my_secret',
  '1234',
  '12345',
  '123456',
  '1234567',
  '12345678',
  '123456789',
  '1234567890',
  'admin',
  'root',
  'default',
  'example',
  'placeholder',
  'replace_me',
  'replace-me',
  'replaceme',
  'your_api_key',
  'your-api-key',
  'your_secret',
  'your-secret',
  'your_secret_here',
  'your-secret-here',
  'your_token_here',
  'your-token-here',
  'insert_here',
  'todo',
  'fixme',
  'tbd',
  'xxx',
  'xxxx',
  'xxxxx',
  'xxxxxx',
  'test',
  'testing',
  'dummy',
  'sample',
  'none',
  'null',
  'undefined',
  'qwerty',
  'letmein',
  'abcdef'
]);

export function isPlaceholderValue(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return true;
  }
  const lower = trimmed.toLowerCase();
  if (KNOWN_PLACEHOLDERS.has(lower)) {
    return true;
  }
  if (
    lower.startsWith('your_') ||
    lower.startsWith('your-') ||
    lower.startsWith('replace_') ||
    lower.startsWith('replace-') ||
    lower.startsWith('example_') ||
    lower.startsWith('example-') ||
    lower.startsWith('placeholder_') ||
    lower.startsWith('dummy_')
  ) {
    return true;
  }
  if (trimmed.startsWith('<') && trimmed.endsWith('>') && trimmed.length <= 64) {
    return true;
  }
  // Check repeated single character like "xxxxxxxxxxxx" or "000000000000"
  let allSame = true;
  const first = lower.charCodeAt(0);
  for (let i = 1; i < lower.length; i++) {
    if (lower.charCodeAt(i) !== first) {
      allSame = false;
      break;
    }
  }
  if (allSame) {
    return true;
  }
  return false;
}

function isAsciiAlnumOrTokenChar(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f || // _
    code === 0x2d    // -
  );
}

function isAllAlnumRange(str: string, start: number): boolean {
  if (str.length <= start) return false;
  for (let i = start; i < str.length; i++) {
    if (!isAsciiAlnumOrTokenChar(str.charCodeAt(i))) {
      return false;
    }
  }
  return true;
}

function looksLikeJwt(val: string): boolean {
  if (!val.startsWith('eyJ') || val.length < 36) {
    return false;
  }
  const firstDot = val.indexOf('.');
  if (firstDot <= 3) return false;
  const secondDot = val.indexOf('.', firstDot + 1);
  if (secondDot <= firstDot + 3 || secondDot >= val.length - 4) return false;
  if (val.indexOf('.', secondDot + 1) !== -1) return false;
  return true;
}

function extractUrlPassword(val: string): string | null {
  try {
    const parsed = new URL(val);
    if (parsed.password && parsed.password.length > 0) {
      return decodeURIComponent(parsed.password);
    }
  } catch {
    // Not a URL
  }
  return null;
}

// Prefixes assembled without literal live credential tokens in source
const HIGH_CONFIDENCE_PREFIXES: ReadonlyArray<{ prefix: string; minTotalLen: number; label: string }> = [
  { prefix: 'sk' + '_live_', minTotalLen: 20, label: 'Stripe live secret key prefix' },
  { prefix: 'rk' + '_live_', minTotalLen: 20, label: 'Stripe restricted live key prefix' },
  { prefix: 'sk' + '-proj-', minTotalLen: 24, label: 'API project secret key prefix' },
  { prefix: 'sk' + '-ant-', minTotalLen: 24, label: 'API secret key prefix' },
  { prefix: 'gh' + 'p_', minTotalLen: 30, label: 'GitHub personal access token prefix' },
  { prefix: 'gh' + 'o_', minTotalLen: 30, label: 'GitHub OAuth token prefix' },
  { prefix: 'gh' + 's_', minTotalLen: 30, label: 'GitHub server token prefix' },
  { prefix: 'github' + '_pat_', minTotalLen: 30, label: 'GitHub fine-grained PAT prefix' },
  { prefix: 'AK' + 'IA', minTotalLen: 20, label: 'AWS access key ID prefix' },
  { prefix: 'AS' + 'IA', minTotalLen: 20, label: 'AWS temporary access key prefix' },
  { prefix: 'xo' + 'xb-', minTotalLen: 24, label: 'Slack bot token prefix' },
  { prefix: 'xo' + 'xp-', minTotalLen: 24, label: 'Slack user token prefix' },
  { prefix: 'AI' + 'za', minTotalLen: 35, label: 'Google API key prefix' },
  { prefix: 'SG' + '.', minTotalLen: 30, label: 'SendGrid API key prefix' }
];

export function detectRealSecretInExample(key: string, value: string): { reason: string } | null {
  const trimmed = value.trim();
  if (trimmed.length === 0 || isPlaceholderValue(trimmed)) {
    return null;
  }

  // PEM private key check
  if (trimmed.includes('-----BEGIN ') && trimmed.includes('PRIVATE KEY-----')) {
    return { reason: 'PEM private key block found in example file' };
  }

  // Known credential prefixes
  for (let i = 0; i < HIGH_CONFIDENCE_PREFIXES.length; i++) {
    const item = HIGH_CONFIDENCE_PREFIXES[i]!;
    if (trimmed.startsWith(item.prefix) && trimmed.length >= item.minTotalLen) {
      const rest = trimmed.slice(item.prefix.length);
      if (!isPlaceholderValue(rest)) {
        return { reason: `Credential matching ${item.label} found in example file` };
      }
    }
  }

  // Generic sk-... token shape
  if (trimmed.startsWith('sk-') && trimmed.length >= 24 && isAllAlnumRange(trimmed, 3)) {
    const rest = trimmed.slice(3);
    if (!isPlaceholderValue(rest) && computeShannonEntropy(rest) >= 3.3) {
      return { reason: 'High-entropy sk- secret token found in example file' };
    }
  }

  // JWT check
  if (looksLikeJwt(trimmed)) {
    return { reason: 'JWT token structure found in example file' };
  }

  // Embedded URL password check
  const urlPwd = extractUrlPassword(trimmed);
  if (urlPwd !== null && !isPlaceholderValue(urlPwd) && urlPwd.length >= 8 && computeShannonEntropy(urlPwd) >= 3.0) {
    return { reason: 'Non-placeholder credential embedded in connection URL inside example file' };
  }

  // High-entropy secret assigned to a secret-named variable in .env.example
  if (isLikelySecretKey(key) && trimmed.length >= 16) {
    const entropy = computeShannonEntropy(trimmed);
    if (entropy >= 3.5) {
      return { reason: 'High-entropy value assigned to secret variable in example file' };
    }
  }

  return null;
}

export interface SecretStrengthOptions {
  minLength?: number;
  minEntropy?: number;
}

export function detectWeakSecretInEnv(
  key: string,
  value: string,
  forceSecretCheck = false,
  options: SecretStrengthOptions = {}
): { reason: string } | null {
  const minLength = options.minLength ?? 12;
  const minEntropy = options.minEntropy ?? 2.8;

  // Connection URL password check (e.g., DATABASE_URL=postgres://user:password@localhost/db)
  if (!forceSecretCheck && isConnectionUrlKey(key)) {
    const urlPwd = extractUrlPassword(value.trim());
    if (urlPwd !== null && isPlaceholderValue(urlPwd)) {
      return { reason: 'Connection URL contains a weak or placeholder password' };
    }
    return null;
  }

  if (!forceSecretCheck && !isLikelySecretKey(key)) {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return { reason: 'Secret variable has an empty value' };
  }

  if (isPlaceholderValue(trimmed)) {
    return { reason: 'Secret variable uses a known weak or placeholder value' };
  }

  if (trimmed.length < minLength) {
    return { reason: `Secret variable is shorter than minimum length (${minLength})` };
  }

  const entropy = computeShannonEntropy(trimmed);
  if (entropy < minEntropy) {
    return { reason: `Secret variable has insufficient Shannon entropy (< ${minEntropy.toFixed(1)} bits/char)` };
  }

  return null;
}
