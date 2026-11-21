import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  MAX_FILE_BYTES,
  readBoundedTextFile,
  resolveCanonicalRoot,
  toPosixRelative
} from '../security/pathGuard.js';
import { createNullMap, hasOwn } from '../security/secretHygiene.js';
import { GitignoreMatcher } from './gitignore.js';

export type SupportedLanguage = 'ts-js' | 'python' | 'go' | 'rust';

export interface CodeEnvReference {
  key: string;
  file: string;
  line: number;
  language: SupportedLanguage;
  expression: string;
}

export interface CodeScanResult {
  references: CodeEnvReference[];
  byKey: Record<string, CodeEnvReference[]>;
  scannedFilesCount: number;
  skippedFilesCount: number;
}

const HARD_SKIPPED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'dist-test',
  'build',
  'out',
  'target',
  '.next',
  '.nuxt',
  '.turbo',
  '.venv',
  'venv',
  '__pycache__',
  'vendor',
  'coverage'
]);

const EXTENSION_TO_LANG: Record<string, SupportedLanguage> = {
  '.ts': 'ts-js',
  '.tsx': 'ts-js',
  '.js': 'ts-js',
  '.jsx': 'ts-js',
  '.mjs': 'ts-js',
  '.cjs': 'ts-js',
  '.mts': 'ts-js',
  '.cts': 'ts-js',
  '.py': 'python',
  '.go': 'go',
  '.rs': 'rust'
};

const JS_PROTOTYPE_PROPERTIES = new Set([
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  'constructor',
  '__proto__'
]);

function isIdentStart(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    code === 0x5f ||                  // _
    code === 0x24                     // $
  );
}

function isIdentBody(code: number): boolean {
  return isIdentStart(code) || (code >= 0x30 && code <= 0x39);
}

function isValidEnvKey(key: string): boolean {
  if (key.length === 0 || key.length > 256) {
    return false;
  }
  const first = key.charCodeAt(0);
  if (
    !((first >= 0x41 && first <= 0x5a) || (first >= 0x61 && first <= 0x7a) || first === 0x5f)
  ) {
    return false;
  }
  for (let i = 1; i < key.length; i++) {
    const c = key.charCodeAt(i);
    if (
      !(
        (c >= 0x41 && c <= 0x5a) ||
        (c >= 0x61 && c <= 0x7a) ||
        (c >= 0x30 && c <= 0x39) ||
        c === 0x5f
      )
    ) {
      return false;
    }
  }
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    return false;
  }
  return true;
}

function isWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d;
}

function skipWs(src: string, pos: number): number {
  let i = pos;
  while (i < src.length && isWhitespace(src.charCodeAt(i))) {
    i++;
  }
  return i;
}

function readIdent(src: string, pos: number): { ident: string; nextPos: number } | null {
  if (pos >= src.length || !isIdentStart(src.charCodeAt(pos))) {
    return null;
  }
  let i = pos + 1;
  while (i < src.length && isIdentBody(src.charCodeAt(i))) {
    i++;
  }
  return { ident: src.slice(pos, i), nextPos: i };
}

function readStringLiteralArg(
  src: string,
  pos: number,
  allowBacktick: boolean
): { value: string; nextPos: number } | null {
  if (pos >= src.length) return null;
  const quote = src.charCodeAt(pos);
  if (
    quote !== 0x27 /* '\'' */ &&
    quote !== 0x22 /* '"' */ &&
    !(allowBacktick && quote === 0x60 /* '`' */)
  ) {
    return null;
  }
  let i = pos + 1;
  let val = '';
  while (i < src.length) {
    const c = src.charCodeAt(i);
    if (c === quote) {
      return { value: val, nextPos: i + 1 };
    }
    if (quote === 0x60 /* '`' */ && c === 0x24 /* '$' */ && i + 1 < src.length && src.charCodeAt(i + 1) === 0x7b /* '{' */) {
      // Dynamic template literal interpolation cannot be resolved statically
      return null;
    }
    if (c === 0x5c /* '\\' */ && quote !== 0x60) {
      if (i + 1 >= src.length) return null;
      val += src[i + 1]!;
      i += 2;
      continue;
    }
    if (c === 0x0a && quote !== 0x60) {
      return null;
    }
    val += src[i]!;
    i++;
  }
  return null;
}

function countNewlines(src: string, start: number, end: number): number {
  let count = 0;
  for (let i = start; i < end && i < src.length; i++) {
    if (src.charCodeAt(i) === 0x0a) {
      count++;
    }
  }
  return count;
}

/**
 * Linear single-pass scanner for TS/JS, Python, Go, and Rust source code.
 * Zero backtracking regular expressions; O(N) runtime.
 */
export function scanSourceContent(
  content: string,
  relFile: string,
  language: SupportedLanguage
): CodeEnvReference[] {
  const refs: CodeEnvReference[] = [];
  const len = content.length;
  let i = 0;
  let line = 1;

  // Stack of open brace depths when inside JS/TS `${ ... }` template literal expressions
  const templateBraceDepths: number[] = [];

  const pushRef = (key: string, refLine: number, expression: string): void => {
    if (!isValidEnvKey(key)) return;
    refs.push({
      key,
      file: relFile,
      line: refLine,
      language,
      expression
    });
  };

  // Helper to consume remainder of a JS template literal starting right after '`' or '}'
  const consumeTemplateStringPart = (): void => {
    while (i < len) {
      const tc = content.charCodeAt(i);
      if (tc === 0x5c /* '\\' */) {
        if (i + 1 < len && content.charCodeAt(i + 1) === 0x0a) {
          line++;
        }
        i += 2;
        continue;
      }
      if (tc === 0x60 /* '`' */) {
        i++;
        return;
      }
      if (tc === 0x24 /* '$' */ && i + 1 < len && content.charCodeAt(i + 1) === 0x7b /* '{' */) {
        templateBraceDepths.push(0);
        i += 2;
        return;
      }
      if (tc === 0x0a) {
        line++;
      }
      i++;
    }
  };

  while (i < len) {
    const ch = content.charCodeAt(i);

    if (ch === 0x0a /* '\n' */) {
      line++;
      i++;
      continue;
    }

    // Comments
    if (language === 'python') {
      if (ch === 0x23 /* '#' */) {
        while (i < len && content.charCodeAt(i) !== 0x0a) i++;
        continue;
      }
      // Python triple-quoted strings ''' or """
      if (
        (ch === 0x27 || ch === 0x22) &&
        i + 2 < len &&
        content.charCodeAt(i + 1) === ch &&
        content.charCodeAt(i + 2) === ch
      ) {
        i += 3;
        while (i < len) {
          if (content.charCodeAt(i) === 0x5c) {
            if (i + 1 < len && content.charCodeAt(i + 1) === 0x0a) line++;
            i += 2;
            continue;
          }
          if (
            i + 2 < len &&
            content.charCodeAt(i) === ch &&
            content.charCodeAt(i + 1) === ch &&
            content.charCodeAt(i + 2) === ch
          ) {
            i += 3;
            break;
          }
          if (content.charCodeAt(i) === 0x0a) line++;
          i++;
        }
        continue;
      }
    } else {
      // C-family comments: // and /* ... */
      if (ch === 0x2f /* '/' */ && i + 1 < len) {
        const next = content.charCodeAt(i + 1);
        if (next === 0x2f /* '/' */) {
          i += 2;
          while (i < len && content.charCodeAt(i) !== 0x0a) i++;
          continue;
        }
        if (next === 0x2a /* '*' */) {
          i += 2;
          while (i < len) {
            if (content.charCodeAt(i) === 0x2a && i + 1 < len && content.charCodeAt(i + 1) === 0x2f) {
              i += 2;
              break;
            }
            if (content.charCodeAt(i) === 0x0a) line++;
            i++;
          }
          continue;
        }
      }
    }

    // Track JS/TS template literal `${ ... }` braces
    if (language === 'ts-js' && templateBraceDepths.length > 0) {
      if (ch === 0x7b /* '{' */) {
        templateBraceDepths[templateBraceDepths.length - 1]!++;
        i++;
        continue;
      }
      if (ch === 0x7d /* '}' */) {
        const topDepth = templateBraceDepths[templateBraceDepths.length - 1]!;
        if (topDepth === 0) {
          templateBraceDepths.pop();
          i++;
          consumeTemplateStringPart();
          continue;
        }
        templateBraceDepths[templateBraceDepths.length - 1]!--;
        i++;
        continue;
      }
    }

    // String literals outside matched calls
    if (ch === 0x22 /* '"' */ || (ch === 0x27 /* '\'' */ && language !== 'rust')) {
      i++;
      while (i < len) {
        const sc = content.charCodeAt(i);
        if (sc === 0x5c /* '\\' */) {
          if (i + 1 < len && content.charCodeAt(i + 1) === 0x0a) line++;
          i += 2;
          continue;
        }
        if (sc === ch) {
          i++;
          break;
        }
        if (sc === 0x0a) {
          line++;
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    if (ch === 0x60 /* '`' */) {
      if (language === 'ts-js') {
        i++;
        consumeTemplateStringPart();
        continue;
      }
      if (language === 'go') {
        i++;
        while (i < len && content.charCodeAt(i) !== 0x60) {
          if (content.charCodeAt(i) === 0x0a) line++;
          i++;
        }
        if (i < len) i++;
        continue;
      }
    }

    // Identifiers and env patterns
    if (isIdentStart(ch)) {
      const prevCode = i > 0 ? content.charCodeAt(i - 1) : 0;
      const precededByDotOrColon = prevCode === 0x2e /* '.' */ || prevCode === 0x3a /* ':' */;
      const tokenLine = line;
      const firstIdent = readIdent(content, i);
      if (!firstIdent) {
        i++;
        continue;
      }

      if (language === 'ts-js' && !precededByDotOrColon) {
        // Pattern 1: process.env.X or process.env['X']
        if (firstIdent.ident === 'process') {
          let p = skipWs(content, firstIdent.nextPos);
          if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
            p = skipWs(content, p + 1);
            const second = readIdent(content, p);
            if (second && second.ident === 'env') {
              p = skipWs(content, second.nextPos);
              if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
                p = skipWs(content, p + 1);
                const keyIdent = readIdent(content, p);
                if (keyIdent && !JS_PROTOTYPE_PROPERTIES.has(keyIdent.ident)) {
                  const afterKey = skipWs(content, keyIdent.nextPos);
                  if (afterKey >= len || content.charCodeAt(afterKey) !== 0x28 /* '(' */) {
                    pushRef(keyIdent.ident, tokenLine, `process.env.${keyIdent.ident}`);
                    line += countNewlines(content, i, keyIdent.nextPos);
                    i = keyIdent.nextPos;
                    continue;
                  }
                }
              } else if (p < len && content.charCodeAt(p) === 0x5b /* '[' */) {
                p = skipWs(content, p + 1);
                const strArg = readStringLiteralArg(content, p, true);
                if (strArg) {
                  const closeP = skipWs(content, strArg.nextPos);
                  if (closeP < len && content.charCodeAt(closeP) === 0x5d /* ']' */) {
                    pushRef(strArg.value, tokenLine, `process.env['${strArg.value}']`);
                    line += countNewlines(content, i, closeP + 1);
                    i = closeP + 1;
                    continue;
                  }
                }
              }
            }
          }
        }

        // Pattern 2: import.meta.env.X or import.meta.env['X']
        if (firstIdent.ident === 'import') {
          let p = skipWs(content, firstIdent.nextPos);
          if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
            p = skipWs(content, p + 1);
            const metaIdent = readIdent(content, p);
            if (metaIdent && metaIdent.ident === 'meta') {
              p = skipWs(content, metaIdent.nextPos);
              if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
                p = skipWs(content, p + 1);
                const envIdent = readIdent(content, p);
                if (envIdent && envIdent.ident === 'env') {
                  p = skipWs(content, envIdent.nextPos);
                  if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
                    p = skipWs(content, p + 1);
                    const keyIdent = readIdent(content, p);
                    if (keyIdent && !JS_PROTOTYPE_PROPERTIES.has(keyIdent.ident)) {
                      const afterKey = skipWs(content, keyIdent.nextPos);
                      if (afterKey >= len || content.charCodeAt(afterKey) !== 0x28 /* '(' */) {
                        pushRef(keyIdent.ident, tokenLine, `import.meta.env.${keyIdent.ident}`);
                        line += countNewlines(content, i, keyIdent.nextPos);
                        i = keyIdent.nextPos;
                        continue;
                      }
                    }
                  } else if (p < len && content.charCodeAt(p) === 0x5b /* '[' */) {
                    p = skipWs(content, p + 1);
                    const strArg = readStringLiteralArg(content, p, true);
                    if (strArg) {
                      const closeP = skipWs(content, strArg.nextPos);
                      if (closeP < len && content.charCodeAt(closeP) === 0x5d /* ']' */) {
                        pushRef(strArg.value, tokenLine, `import.meta.env['${strArg.value}']`);
                        line += countNewlines(content, i, closeP + 1);
                        i = closeP + 1;
                        continue;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      } else if (language === 'python' && !precededByDotOrColon) {
        // os.environ['X'], os.environ.get('X'), os.getenv('X'), or imported environ[...] / getenv(...)
        let afterEnvironPos = -1;
        let isGetenvCall = false;
        let callPrefix = '';

        if (firstIdent.ident === 'os') {
          let p = skipWs(content, firstIdent.nextPos);
          if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
            p = skipWs(content, p + 1);
            const member = readIdent(content, p);
            if (member?.ident === 'environ') {
              afterEnvironPos = member.nextPos;
              callPrefix = 'os.environ';
            } else if (member?.ident === 'getenv') {
              afterEnvironPos = member.nextPos;
              isGetenvCall = true;
              callPrefix = 'os.getenv';
            }
          }
        } else if (firstIdent.ident === 'environ') {
          afterEnvironPos = firstIdent.nextPos;
          callPrefix = 'environ';
        } else if (firstIdent.ident === 'getenv') {
          afterEnvironPos = firstIdent.nextPos;
          isGetenvCall = true;
          callPrefix = 'getenv';
        }

        if (afterEnvironPos !== -1) {
          let p = skipWs(content, afterEnvironPos);
          if (isGetenvCall && p < len && content.charCodeAt(p) === 0x28 /* '(' */) {
            p = skipWs(content, p + 1);
            const strArg = readStringLiteralArg(content, p, false);
            if (strArg) {
              const afterStr = skipWs(content, strArg.nextPos);
              if (afterStr < len && (content.charCodeAt(afterStr) === 0x29 || content.charCodeAt(afterStr) === 0x2c)) {
                pushRef(strArg.value, tokenLine, `${callPrefix}('${strArg.value}')`);
                line += countNewlines(content, i, strArg.nextPos);
                i = strArg.nextPos;
                continue;
              }
            }
          } else if (!isGetenvCall && p < len) {
            if (content.charCodeAt(p) === 0x5b /* '[' */) {
              p = skipWs(content, p + 1);
              const strArg = readStringLiteralArg(content, p, false);
              if (strArg) {
                const closeP = skipWs(content, strArg.nextPos);
                if (closeP < len && content.charCodeAt(closeP) === 0x5d /* ']' */) {
                  pushRef(strArg.value, tokenLine, `${callPrefix}['${strArg.value}']`);
                  line += countNewlines(content, i, closeP + 1);
                  i = closeP + 1;
                  continue;
                }
              }
            } else if (content.charCodeAt(p) === 0x2e /* '.' */) {
              p = skipWs(content, p + 1);
              const getIdent = readIdent(content, p);
              if (getIdent?.ident === 'get') {
                p = skipWs(content, getIdent.nextPos);
                if (p < len && content.charCodeAt(p) === 0x28 /* '(' */) {
                  p = skipWs(content, p + 1);
                  const strArg = readStringLiteralArg(content, p, false);
                  if (strArg) {
                    const afterStr = skipWs(content, strArg.nextPos);
                    if (
                      afterStr < len &&
                      (content.charCodeAt(afterStr) === 0x29 || content.charCodeAt(afterStr) === 0x2c)
                    ) {
                      pushRef(strArg.value, tokenLine, `${callPrefix}.get('${strArg.value}')`);
                      line += countNewlines(content, i, strArg.nextPos);
                      i = strArg.nextPos;
                      continue;
                    }
                  }
                }
              }
            }
          }
        }
      } else if (language === 'go' && !precededByDotOrColon) {
        // os.Getenv("X") and os.LookupEnv("X")
        if (firstIdent.ident === 'os') {
          let p = skipWs(content, firstIdent.nextPos);
          if (p < len && content.charCodeAt(p) === 0x2e /* '.' */) {
            p = skipWs(content, p + 1);
            const fnIdent = readIdent(content, p);
            if (fnIdent && (fnIdent.ident === 'Getenv' || fnIdent.ident === 'LookupEnv')) {
              p = skipWs(content, fnIdent.nextPos);
              if (p < len && content.charCodeAt(p) === 0x28 /* '(' */) {
                p = skipWs(content, p + 1);
                const strArg = readStringLiteralArg(content, p, true);
                if (strArg) {
                  const closeP = skipWs(content, strArg.nextPos);
                  if (closeP < len && content.charCodeAt(closeP) === 0x29 /* ')' */) {
                    pushRef(strArg.value, tokenLine, `os.${fnIdent.ident}("${strArg.value}")`);
                    line += countNewlines(content, i, closeP + 1);
                    i = closeP + 1;
                    continue;
                  }
                }
              }
            }
          }
        }
      } else if (language === 'rust') {
        // std::env::var("X"), env::var("X"), env::var_os("X"), env!("X"), option_env!("X")
        let envIdentEnd = -1;
        if (!precededByDotOrColon && firstIdent.ident === 'std') {
          let p = skipWs(content, firstIdent.nextPos);
          if (p + 1 < len && content.charCodeAt(p) === 0x3a && content.charCodeAt(p + 1) === 0x3a) {
            p = skipWs(content, p + 2);
            const nextIdent = readIdent(content, p);
            if (nextIdent?.ident === 'env') {
              envIdentEnd = nextIdent.nextPos;
            }
          }
        } else if (firstIdent.ident === 'env') {
          envIdentEnd = firstIdent.nextPos;
        }

        if (envIdentEnd !== -1) {
          let p = skipWs(content, envIdentEnd);
          if (p + 1 < len && content.charCodeAt(p) === 0x3a && content.charCodeAt(p + 1) === 0x3a) {
            p = skipWs(content, p + 2);
            const fnIdent = readIdent(content, p);
            if (fnIdent && (fnIdent.ident === 'var' || fnIdent.ident === 'var_os')) {
              p = skipWs(content, fnIdent.nextPos);
              if (p < len && content.charCodeAt(p) === 0x28 /* '(' */) {
                p = skipWs(content, p + 1);
                const strArg = readStringLiteralArg(content, p, false);
                if (strArg) {
                  const closeP = skipWs(content, strArg.nextPos);
                  if (closeP < len && content.charCodeAt(closeP) === 0x29 /* ')' */) {
                    pushRef(strArg.value, tokenLine, `env::${fnIdent.ident}("${strArg.value}")`);
                    line += countNewlines(content, i, closeP + 1);
                    i = closeP + 1;
                    continue;
                  }
                }
              }
            }
          } else if (p < len && content.charCodeAt(p) === 0x21 /* '!' */) {
            p = skipWs(content, p + 1);
            if (p < len && content.charCodeAt(p) === 0x28 /* '(' */) {
              p = skipWs(content, p + 1);
              const strArg = readStringLiteralArg(content, p, false);
              if (strArg) {
                const afterStr = skipWs(content, strArg.nextPos);
                if (afterStr < len && (content.charCodeAt(afterStr) === 0x29 || content.charCodeAt(afterStr) === 0x2c)) {
                  pushRef(strArg.value, tokenLine, `env!("${strArg.value}")`);
                  line += countNewlines(content, i, strArg.nextPos);
                  i = strArg.nextPos;
                  continue;
                }
              }
            }
          }
        }

        if (firstIdent.ident === 'option_env') {
          let p = skipWs(content, firstIdent.nextPos);
          if (p < len && content.charCodeAt(p) === 0x21 /* '!' */) {
            p = skipWs(content, p + 1);
            if (p < len && content.charCodeAt(p) === 0x28 /* '(' */) {
              p = skipWs(content, p + 1);
              const strArg = readStringLiteralArg(content, p, false);
              if (strArg) {
                const afterStr = skipWs(content, strArg.nextPos);
                if (afterStr < len && (content.charCodeAt(afterStr) === 0x29 || content.charCodeAt(afterStr) === 0x2c)) {
                  pushRef(strArg.value, tokenLine, `option_env!("${strArg.value}")`);
                  line += countNewlines(content, i, strArg.nextPos);
                  i = strArg.nextPos;
                  continue;
                }
              }
            }
          }
        }
      }

      i = firstIdent.nextPos;
      continue;
    }

    i++;
  }

  return refs;
}

export function scanWorkspaceCode(rootDir: string): CodeScanResult {
  const canonicalRoot = resolveCanonicalRoot(rootDir);
  const matcher = new GitignoreMatcher();

  const rootGitignorePath = path.join(canonicalRoot, '.gitignore');
  if (fs.existsSync(rootGitignorePath)) {
    try {
      const giRead = readBoundedTextFile(rootGitignorePath, {
        maxBytes: MAX_FILE_BYTES,
        rejectBinary: true
      });
      if (giRead.content !== undefined) {
        matcher.addRulesFromContent(giRead.content);
      }
    } catch {
      // Ignore unreadable .gitignore
    }
  }

  const references: CodeEnvReference[] = [];
  const byKey = createNullMap<CodeEnvReference[]>();
  let scannedFilesCount = 0;
  let skippedFilesCount = 0;

  const walk = (currentDir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (let idx = 0; idx < entries.length; idx++) {
      const entry = entries[idx]!;
      const name = entry.name;

      // Never traverse symlinks during recursive walk
      if (entry.isSymbolicLink()) {
        skippedFilesCount++;
        continue;
      }

      const fullPath = path.join(currentDir, name);
      const posixRel = toPosixRelative(canonicalRoot, fullPath);

      if (entry.isDirectory()) {
        if (HARD_SKIPPED_DIRS.has(name)) {
          continue;
        }
        if (matcher.isIgnored(posixRel, true)) {
          continue;
        }
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      if (matcher.isIgnored(posixRel, false)) {
        skippedFilesCount++;
        continue;
      }

      const ext = path.extname(name).toLowerCase();
      if (!hasOwn(EXTENSION_TO_LANG, ext)) {
        continue;
      }
      const language = EXTENSION_TO_LANG[ext]!;

      let fileRes: ReturnType<typeof readBoundedTextFile>;
      try {
        fileRes = readBoundedTextFile(fullPath, {
          maxBytes: MAX_FILE_BYTES,
          rejectBinary: true
        });
      } catch {
        skippedFilesCount++;
        continue;
      }

      if (fileRes.content === undefined) {
        skippedFilesCount++;
        continue;
      }

      scannedFilesCount++;
      const fileRefs = scanSourceContent(fileRes.content, posixRel, language);
      for (let r = 0; r < fileRefs.length; r++) {
        const ref = fileRefs[r]!;
        references.push(ref);
        if (!hasOwn(byKey, ref.key)) {
          byKey[ref.key] = [];
        }
        byKey[ref.key]!.push(ref);
      }
    }
  };

  walk(canonicalRoot);

  return {
    references,
    byKey,
    scannedFilesCount,
    skippedFilesCount
  };
}
