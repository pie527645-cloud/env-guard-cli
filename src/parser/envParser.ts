import { createNullMap, hasOwn } from '../security/secretHygiene.js';

export type QuoteStyle = 'none' | 'single' | 'double';

export type EnvErrorCode =
  | 'INVALID_KEY'
  | 'MISSING_EQUALS'
  | 'UNTERMINATED_QUOTE'
  | 'TRAILING_CHARACTERS'
  | 'CIRCULAR_REFERENCE';

export interface EnvParseDiagnostic {
  code: EnvErrorCode;
  message: string;
  line: number;
  key?: string;
}

export interface EnvEntry {
  key: string;
  rawValue: string;
  value: string;
  quoteStyle: QuoteStyle;
  exported: boolean;
  line: number;
  endLine: number;
  inlineComment?: string;
}

export interface EnvParseResult {
  values: Record<string, string>;
  rawValues: Record<string, string>;
  entries: EnvEntry[];
  errors: EnvParseDiagnostic[];
}

export interface ParseEnvOptions {
  interpolate?: boolean;
  externalEnv?: Record<string, string | undefined>;
  throwOnError?: boolean;
}

export class EnvParseError extends Error {
  public readonly diagnostics: EnvParseDiagnostic[];

  constructor(message: string, diagnostics: EnvParseDiagnostic[]) {
    super(message);
    this.name = 'EnvParseError';
    this.diagnostics = diagnostics;
  }
}

type TemplateSegment =
  | { kind: 'text'; text: string }
  | {
      kind: 'var';
      name: string;
      mode: 'plain' | 'colon_dash' | 'dash';
      fallback: TemplateSegment[];
    };

interface InternalEntry {
  entry: EnvEntry;
  segments: TemplateSegment[];
}

function isHorizontalWs(code: number): boolean {
  return code === 0x20 /* ' ' */ || code === 0x09 /* '\t' */;
}

function isKeyStartChar(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    code === 0x5f                     // _
  );
}

function isKeyBodyChar(code: number): boolean {
  return (
    isKeyStartChar(code) ||
    (code >= 0x30 && code <= 0x39) || // 0-9
    code === 0x2e                     // .
  );
}

function isVarNameChar(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    (code >= 0x30 && code <= 0x39) ||
    code === 0x5f
  );
}

/**
 * Normalizes UTF-8 BOM and CRLF/CR line endings in a single O(N) pass.
 */
function normalizeSource(input: string): string {
  let start = 0;
  if (input.length > 0 && input.charCodeAt(0) === 0xfeff) {
    start = 1;
  }
  let needsRewrite = start > 0;
  if (!needsRewrite) {
    for (let i = 0; i < input.length; i++) {
      if (input.charCodeAt(i) === 0x0d /* '\r' */) {
        needsRewrite = true;
        break;
      }
    }
  }
  if (!needsRewrite) {
    return input;
  }
  const chunks: string[] = [];
  let chunkStart = start;
  for (let i = start; i < input.length; i++) {
    if (input.charCodeAt(i) === 0x0d /* '\r' */) {
      if (i > chunkStart) {
        chunks.push(input.slice(chunkStart, i));
      }
      chunks.push('\n');
      if (i + 1 < input.length && input.charCodeAt(i + 1) === 0x0a /* '\n' */) {
        i++;
      }
      chunkStart = i + 1;
    }
  }
  if (chunkStart < input.length) {
    chunks.push(input.slice(chunkStart));
  }
  return chunks.join('');
}

function appendTextSegment(segments: TemplateSegment[], text: string): void {
  if (text.length === 0) return;
  const last = segments[segments.length - 1];
  if (last && last.kind === 'text') {
    last.text += text;
  } else {
    segments.push({ kind: 'text', text });
  }
}

/**
 * Parses ${VAR}, ${VAR:-default}, or ${VAR-default} starting at `pos` where source[pos] === '$' and source[pos+1] === '{'.
 * Returns null if braces are not validly closed or var name is invalid, allowing literal fallback.
 */
function parseBracedInterpolation(
  source: string,
  pos: number,
  endLimit: number,
  depth = 0
): { segment: TemplateSegment; nextPos: number } | null {
  if (depth > 16) {
    return null;
  }
  let i = pos + 2; // skip '${'
  const nameStart = i;
  while (i < endLimit && isVarNameChar(source.charCodeAt(i))) {
    i++;
  }
  if (i === nameStart) {
    return null;
  }
  const varName = source.slice(nameStart, i);
  if (i >= endLimit) {
    return null;
  }

  const nextCode = source.charCodeAt(i);
  if (nextCode === 0x7d /* '}' */) {
    return {
      segment: { kind: 'var', name: varName, mode: 'plain', fallback: [] },
      nextPos: i + 1
    };
  }

  let mode: 'colon_dash' | 'dash' | null = null;
  if (nextCode === 0x3a /* ':' */ && i + 1 < endLimit && source.charCodeAt(i + 1) === 0x2d /* '-' */) {
    mode = 'colon_dash';
    i += 2;
  } else if (nextCode === 0x2d /* '-' */) {
    mode = 'dash';
    i += 1;
  }

  if (mode === null) {
    return null;
  }

  const fallbackSegments: TemplateSegment[] = [];
  let buf = '';
  while (i < endLimit) {
    const code = source.charCodeAt(i);
    if (code === 0x7d /* '}' */) {
      appendTextSegment(fallbackSegments, buf);
      return {
        segment: { kind: 'var', name: varName, mode, fallback: fallbackSegments },
        nextPos: i + 1
      };
    }
    if (code === 0x5c /* '\\' */ && i + 1 < endLimit) {
      const esc = source.charCodeAt(i + 1);
      if (esc === 0x7d || esc === 0x24 || esc === 0x5c) {
        buf += source[i + 1]!;
        i += 2;
        continue;
      }
    }
    if (code === 0x24 /* '$' */ && i + 1 < endLimit && source.charCodeAt(i + 1) === 0x7b /* '{' */) {
      const nested = parseBracedInterpolation(source, i, endLimit, depth + 1);
      if (nested) {
        appendTextSegment(fallbackSegments, buf);
        buf = '';
        fallbackSegments.push(nested.segment);
        i = nested.nextPos;
        continue;
      }
    }
    buf += source[i]!;
    i++;
  }

  return null;
}

function segmentsToRawText(segments: TemplateSegment[]): string {
  let out = '';
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    if (seg.kind === 'text') {
      out += seg.text;
    } else if (seg.mode === 'plain') {
      out += '${' + seg.name + '}';
    } else {
      const op = seg.mode === 'colon_dash' ? ':-' : '-';
      out += '${' + seg.name + op + segmentsToRawText(seg.fallback) + '}';
    }
  }
  return out;
}

export function parseEnv(input: string, options: ParseEnvOptions = {}): EnvParseResult {
  const interpolate = options.interpolate ?? true;
  const source = normalizeSource(input);
  const len = source.length;

  const values = createNullMap<string>();
  const rawValues = createNullMap<string>();
  const entries: EnvEntry[] = [];
  const errors: EnvParseDiagnostic[] = [];
  const internalByKey = createNullMap<InternalEntry>();
  const internalList: InternalEntry[] = [];

  let i = 0;
  let line = 1;

  const skipToEndOfLine = (): void => {
    while (i < len && source.charCodeAt(i) !== 0x0a /* '\n' */) {
      i++;
    }
    if (i < len && source.charCodeAt(i) === 0x0a) {
      i++;
      line++;
    }
  };

  while (i < len) {
    // Skip leading horizontal whitespace
    while (i < len && isHorizontalWs(source.charCodeAt(i))) {
      i++;
    }

    if (i >= len) {
      break;
    }

    const ch = source.charCodeAt(i);
    // Blank line
    if (ch === 0x0a /* '\n' */) {
      i++;
      line++;
      continue;
    }

    // Full-line comment
    if (ch === 0x23 /* '#' */) {
      skipToEndOfLine();
      continue;
    }

    const startLine = line;
    let exported = false;

    // Check optional `export ` keyword followed by horizontal whitespace
    if (
      i + 6 < len &&
      source.startsWith('export', i) &&
      isHorizontalWs(source.charCodeAt(i + 6))
    ) {
      let probe = i + 6;
      while (probe < len && isHorizontalWs(source.charCodeAt(probe))) {
        probe++;
      }
      // Only treat `export` as keyword if not immediately `export = ...`
      if (probe < len && source.charCodeAt(probe) !== 0x3d /* '=' */) {
        exported = true;
        i = probe;
      }
    }

    // Parse key
    if (i >= len || !isKeyStartChar(source.charCodeAt(i))) {
      errors.push({
        code: 'INVALID_KEY',
        message: `Invalid environment variable key at line ${startLine}.`,
        line: startLine
      });
      skipToEndOfLine();
      continue;
    }

    const keyStart = i;
    i++;
    while (i < len && isKeyBodyChar(source.charCodeAt(i))) {
      i++;
    }
    const key = source.slice(keyStart, i);

    // Skip horizontal whitespace before '='
    while (i < len && isHorizontalWs(source.charCodeAt(i))) {
      i++;
    }

    if (i >= len || source.charCodeAt(i) !== 0x3d /* '=' */) {
      errors.push({
        code: 'MISSING_EQUALS',
        message: `Expected '=' after key '${key}' at line ${startLine}.`,
        line: startLine,
        key
      });
      skipToEndOfLine();
      continue;
    }

    // Consume '='
    i++;

    // Skip horizontal whitespace immediately after '='
    while (i < len && isHorizontalWs(source.charCodeAt(i))) {
      i++;
    }

    let quoteStyle: QuoteStyle = 'none';
    let inlineComment: string | undefined;
    const segments: TemplateSegment[] = [];
    let rawValue = '';

    if (i >= len || source.charCodeAt(i) === 0x0a /* '\n' */) {
      // Empty unquoted value
      if (i < len && source.charCodeAt(i) === 0x0a) {
        i++;
        line++;
      }
    } else if (source.charCodeAt(i) === 0x23 /* '#' */) {
      // Empty value followed immediately by comment (e.g. `FOO= # comment` or `FOO=#comment`? Wait: `FOO=#bar` without space after `=` vs `FOO= # bar`)
      // Note: if there was whitespace before `#` or right after `=`, check previous char
      const prevCode = source.charCodeAt(i - 1);
      if (isHorizontalWs(prevCode)) {
        const commentStart = i + 1;
        while (i < len && source.charCodeAt(i) !== 0x0a) {
          i++;
        }
        inlineComment = source.slice(commentStart, i).trim();
        if (i < len && source.charCodeAt(i) === 0x0a) {
          i++;
          line++;
        }
      } else {
        // Unquoted value starting with '#' directly after '=' e.g. COLOR=#fff
        const lineEndStart = i;
        let lineEnd = i;
        while (lineEnd < len && source.charCodeAt(lineEnd) !== 0x0a) {
          lineEnd++;
        }
        let valueEnd = lineEnd;
        for (let k = lineEndStart; k < lineEnd; k++) {
          if (source.charCodeAt(k) === 0x23 /* '#' */ && k > lineEndStart && isHorizontalWs(source.charCodeAt(k - 1))) {
            valueEnd = k;
            inlineComment = source.slice(k + 1, lineEnd).trim();
            break;
          }
        }
        while (valueEnd > lineEndStart && isHorizontalWs(source.charCodeAt(valueEnd - 1))) {
          valueEnd--;
        }
        const unquotedSlice = source.slice(lineEndStart, valueEnd);
        rawValue = unquotedSlice;
        appendTextSegment(segments, unquotedSlice);
        i = lineEnd;
        if (i < len && source.charCodeAt(i) === 0x0a) {
          i++;
          line++;
        }
      }
    } else if (source.charCodeAt(i) === 0x27 /* '\'' */) {
      // Single-quoted value (literal, multiline allowed, no escape expansion, no interpolation)
      quoteStyle = 'single';
      i++; // skip opening '\''
      const valStart = i;
      let closed = false;
      while (i < len) {
        const c = source.charCodeAt(i);
        if (c === 0x27 /* '\'' */) {
          rawValue = source.slice(valStart, i);
          appendTextSegment(segments, rawValue);
          i++; // consume closing '\''
          closed = true;
          break;
        }
        if (c === 0x0a /* '\n' */) {
          line++;
        }
        i++;
      }

      if (!closed) {
        errors.push({
          code: 'UNTERMINATED_QUOTE',
          message: `Unterminated single-quoted value for key '${key}' starting at line ${startLine}.`,
          line: startLine,
          key
        });
        rawValue = source.slice(valStart, i);
        appendTextSegment(segments, rawValue);
      } else {
        // Consume trailing horizontal whitespace and optional inline comment
        while (i < len && isHorizontalWs(source.charCodeAt(i))) {
          i++;
        }
        if (i < len && source.charCodeAt(i) === 0x23 /* '#' */) {
          const commentStart = i + 1;
          while (i < len && source.charCodeAt(i) !== 0x0a) {
            i++;
          }
          inlineComment = source.slice(commentStart, i).trim();
        } else if (i < len && source.charCodeAt(i) !== 0x0a) {
          errors.push({
            code: 'TRAILING_CHARACTERS',
            message: `Unexpected trailing characters after single-quoted value for key '${key}' at line ${line}.`,
            line,
            key
          });
          while (i < len && source.charCodeAt(i) !== 0x0a) {
            i++;
          }
        }
        if (i < len && source.charCodeAt(i) === 0x0a) {
          i++;
          line++;
        }
      }
    } else if (source.charCodeAt(i) === 0x22 /* '"' */) {
      // Double-quoted value (multiline allowed, escape sequences expanded, interpolation supported)
      quoteStyle = 'double';
      i++; // skip opening '"'
      let buf = '';
      let closed = false;

      while (i < len) {
        const c = source.charCodeAt(i);
        if (c === 0x22 /* '"' */) {
          appendTextSegment(segments, buf);
          i++; // consume closing '"'
          closed = true;
          break;
        }
        if (c === 0x5c /* '\\' */) {
          if (i + 1 >= len) {
            buf += '\\';
            i++;
            break;
          }
          const esc = source.charCodeAt(i + 1);
          if (esc === 0x6e /* 'n' */) {
            buf += '\n';
          } else if (esc === 0x72 /* 'r' */) {
            buf += '\r';
          } else if (esc === 0x74 /* 't' */) {
            buf += '\t';
          } else if (esc === 0x22 /* '"' */) {
            buf += '"';
          } else if (esc === 0x5c /* '\\' */) {
            buf += '\\';
          } else if (esc === 0x24 /* '$' */) {
            buf += '$';
          } else {
            if (esc === 0x0a /* '\n' */) {
              line++;
            }
            buf += '\\' + source[i + 1]!;
          }
          i += 2;
          continue;
        }
        if (c === 0x24 /* '$' */ && i + 1 < len && source.charCodeAt(i + 1) === 0x7b /* '{' */) {
          // Find closing quote limit? Note: inside double quotes, interpolation cannot cross an unescaped closing '"'
          // Scan ahead to find unescaped '"' to bound the interpolation
          let quoteBound = i + 2;
          while (quoteBound < len) {
            const qc = source.charCodeAt(quoteBound);
            if (qc === 0x5c) {
              quoteBound += 2;
              continue;
            }
            if (qc === 0x22) {
              break;
            }
            quoteBound++;
          }
          const interp = parseBracedInterpolation(source, i, Math.min(quoteBound, len));
          if (interp) {
            appendTextSegment(segments, buf);
            buf = '';
            // Count any newlines inside interpolation fallback
            for (let k = i; k < interp.nextPos; k++) {
              if (source.charCodeAt(k) === 0x0a) line++;
            }
            segments.push(interp.segment);
            i = interp.nextPos;
            continue;
          }
        }
        if (c === 0x0a /* '\n' */) {
          line++;
        }
        buf += source[i]!;
        i++;
      }

      if (!closed) {
        appendTextSegment(segments, buf);
      }
      rawValue = segmentsToRawText(segments);

      if (!closed) {
        errors.push({
          code: 'UNTERMINATED_QUOTE',
          message: `Unterminated double-quoted value for key '${key}' starting at line ${startLine}.`,
          line: startLine,
          key
        });
      } else {
        while (i < len && isHorizontalWs(source.charCodeAt(i))) {
          i++;
        }
        if (i < len && source.charCodeAt(i) === 0x23 /* '#' */) {
          const commentStart = i + 1;
          while (i < len && source.charCodeAt(i) !== 0x0a) {
            i++;
          }
          inlineComment = source.slice(commentStart, i).trim();
        } else if (i < len && source.charCodeAt(i) !== 0x0a) {
          errors.push({
            code: 'TRAILING_CHARACTERS',
            message: `Unexpected trailing characters after double-quoted value for key '${key}' at line ${line}.`,
            line,
            key
          });
          while (i < len && source.charCodeAt(i) !== 0x0a) {
            i++;
          }
        }
        if (i < len && source.charCodeAt(i) === 0x0a) {
          i++;
          line++;
        }
      }
    } else {
      // Unquoted value: single line, strip inline `#` comment when preceded by whitespace, trim trailing whitespace
      let lineEnd = i;
      while (lineEnd < len && source.charCodeAt(lineEnd) !== 0x0a) {
        lineEnd++;
      }
      let valueEnd = lineEnd;
      for (let k = i; k < lineEnd; k++) {
        const kc = source.charCodeAt(k);
        if (kc === 0x5c /* '\\' */ && k + 1 < lineEnd) {
          k++;
          continue;
        }
        if (kc === 0x23 /* '#' */ && k > i && isHorizontalWs(source.charCodeAt(k - 1))) {
          valueEnd = k;
          inlineComment = source.slice(k + 1, lineEnd).trim();
          break;
        }
      }
      while (valueEnd > i && isHorizontalWs(source.charCodeAt(valueEnd - 1))) {
        valueEnd--;
      }

      let buf = '';
      let p = i;
      while (p < valueEnd) {
        const pc = source.charCodeAt(p);
        if (pc === 0x5c /* '\\' */ && p + 1 < valueEnd) {
          const next = source.charCodeAt(p + 1);
          if (next === 0x24 /* '$' */ || next === 0x23 /* '#' */ || next === 0x5c /* '\\' */) {
            buf += source[p + 1]!;
            p += 2;
            continue;
          }
        }
        if (pc === 0x24 /* '$' */ && p + 1 < valueEnd && source.charCodeAt(p + 1) === 0x7b /* '{' */) {
          const interp = parseBracedInterpolation(source, p, valueEnd);
          if (interp) {
            appendTextSegment(segments, buf);
            buf = '';
            segments.push(interp.segment);
            p = interp.nextPos;
            continue;
          }
        }
        buf += source[p]!;
        p++;
      }
      appendTextSegment(segments, buf);
      rawValue = segmentsToRawText(segments);

      i = lineEnd;
      if (i < len && source.charCodeAt(i) === 0x0a) {
        i++;
        line++;
      }
    }

    const endLine = line > startLine && source.charCodeAt(Math.max(0, i - 1)) === 0x0a ? line - 1 : line;

    const entry: EnvEntry = {
      key,
      rawValue,
      value: rawValue,
      quoteStyle,
      exported,
      line: startLine,
      endLine: Math.max(startLine, endLine),
      ...(inlineComment !== undefined ? { inlineComment } : {})
    };

    const internal: InternalEntry = { entry, segments };
    entries.push(entry);
    internalList.push(internal);
    internalByKey[key] = internal;
    rawValues[key] = rawValue;
  }

  // Interpolation phase with cycle detection
  if (!interpolate) {
    for (let idx = 0; idx < internalList.length; idx++) {
      const item = internalList[idx]!;
      values[item.entry.key] = item.entry.rawValue;
    }
  } else {
    const resolvedCache = createNullMap<string>();
    const reportedCycles = createNullMap<boolean>();
    const visiting = new Set<string>();
    const chain: string[] = [];

    const evaluateSegments = (segs: TemplateSegment[], ownerKey: string, ownerLine: number): string => {
      let result = '';
      for (let s = 0; s < segs.length; s++) {
        const seg = segs[s]!;
        if (seg.kind === 'text') {
          result += seg.text;
          continue;
        }
        const targetName = seg.name;
        if (visiting.has(targetName)) {
          const cycleStart = chain.indexOf(targetName);
          const cyclePath = [...chain.slice(cycleStart >= 0 ? cycleStart : 0), targetName].join(' -> ');
          if (!hasOwn(reportedCycles, cyclePath)) {
            reportedCycles[cyclePath] = true;
            errors.push({
              code: 'CIRCULAR_REFERENCE',
              message: `Circular variable interpolation detected: ${cyclePath}`,
              line: ownerLine,
              key: ownerKey
            });
          }
          continue;
        }

        let targetDefined = false;
        let targetVal = '';

        if (hasOwn(internalByKey, targetName)) {
          targetDefined = true;
          targetVal = resolveEntryKey(targetName);
        } else if (options.externalEnv && hasOwn(options.externalEnv, targetName) && options.externalEnv[targetName] !== undefined) {
          targetDefined = true;
          targetVal = options.externalEnv[targetName]!;
        }

        if (seg.mode === 'plain') {
          result += targetDefined ? targetVal : '';
        } else if (seg.mode === 'colon_dash') {
          if (targetDefined && targetVal.length > 0) {
            result += targetVal;
          } else {
            result += evaluateSegments(seg.fallback, ownerKey, ownerLine);
          }
        } else {
          // 'dash': use fallback only when unset
          if (targetDefined) {
            result += targetVal;
          } else {
            result += evaluateSegments(seg.fallback, ownerKey, ownerLine);
          }
        }
      }
      return result;
    };

    const resolveEntryKey = (targetKey: string): string => {
      if (hasOwn(resolvedCache, targetKey)) {
        return resolvedCache[targetKey]!;
      }
      const item = internalByKey[targetKey];
      if (!item) {
        return '';
      }
      if (item.entry.quoteStyle === 'single') {
        resolvedCache[targetKey] = item.entry.rawValue;
        return item.entry.rawValue;
      }
      visiting.add(targetKey);
      chain.push(targetKey);
      const evaluated = evaluateSegments(item.segments, targetKey, item.entry.line);
      chain.pop();
      visiting.delete(targetKey);
      resolvedCache[targetKey] = evaluated;
      return evaluated;
    };

    // Evaluate all entries; also support duplicate keys where final assignment wins in `values`
    for (let idx = 0; idx < internalList.length; idx++) {
      const item = internalList[idx]!;
      const k = item.entry.key;
      if (internalByKey[k] === item) {
        const finalVal = resolveEntryKey(k);
        item.entry.value = finalVal;
        values[k] = finalVal;
      } else {
        // Earlier overridden assignment of the same key
        if (item.entry.quoteStyle === 'single') {
          item.entry.value = item.entry.rawValue;
        } else {
          visiting.add(k);
          chain.push(k);
          item.entry.value = evaluateSegments(item.segments, k, item.entry.line);
          chain.pop();
          visiting.delete(k);
        }
      }
    }
  }

  if (options.throwOnError && errors.length > 0) {
    throw new EnvParseError(errors[0]!.message, errors);
  }

  return {
    values,
    rawValues,
    entries,
    errors
  };
}
