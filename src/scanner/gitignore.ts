export const MAX_GITIGNORE_RULE_LENGTH = 4096;

interface CompiledIgnoreRule {
  negated: boolean;
  directoryOnly: boolean;
  anchored: boolean;
  segments: string[];
  hasBracketBySegment: boolean[];
  closingBracketMaps: Array<Int32Array | null>;
}

function stripTrailingUnescapedSpaces(raw: string): string {
  let end = raw.length;
  while (end > 0 && (raw.charCodeAt(end - 1) === 0x20 || raw.charCodeAt(end - 1) === 0x09)) {
    // Check if escaped with backslash
    if (end >= 2 && raw.charCodeAt(end - 2) === 0x5c /* '\\' */) {
      break;
    }
    end--;
  }
  return end === raw.length ? raw : raw.slice(0, end);
}

/**
 * Precomputes closing ']' indices in O(L) so '[' bracket checks at match time have an O(1) guard.
 */
function buildBracketMap(seg: string): { hasBracket: boolean; map: Int32Array | null } {
  if (seg.indexOf('[') === -1) {
    return { hasBracket: false, map: null };
  }
  const map = new Int32Array(seg.length).fill(-1);
  for (let i = 0; i < seg.length; i++) {
    if (seg.charCodeAt(i) === 0x5c /* '\\' */) {
      i++;
      continue;
    }
    if (seg.charCodeAt(i) === 0x5b /* '[' */) {
      let j = i + 1;
      if (j < seg.length && (seg.charCodeAt(j) === 0x21 /* '!' */ || seg.charCodeAt(j) === 0x5e /* '^' */)) {
        j++;
      }
      if (j < seg.length && seg.charCodeAt(j) === 0x5d /* ']' */) {
        j++; // literal ']' right at start of class
      }
      while (j < seg.length) {
        if (seg.charCodeAt(j) === 0x5c /* '\\' */) {
          j += 2;
          continue;
        }
        if (seg.charCodeAt(j) === 0x5d /* ']' */) {
          map[i] = j;
          break;
        }
        j++;
      }
    }
  }
  return { hasBracket: true, map };
}

function matchBracketClass(
  seg: string,
  openIdx: number,
  closeIdx: number,
  targetCharCode: number
): boolean {
  let i = openIdx + 1;
  let negate = false;
  if (i < closeIdx && (seg.charCodeAt(i) === 0x21 /* '!' */ || seg.charCodeAt(i) === 0x5e /* '^' */)) {
    negate = true;
    i++;
  }
  let matched = false;
  while (i < closeIdx) {
    let startCode = seg.charCodeAt(i);
    if (startCode === 0x5c /* '\\' */ && i + 1 < closeIdx) {
      i++;
      startCode = seg.charCodeAt(i);
    }
    if (
      i + 2 < closeIdx &&
      seg.charCodeAt(i + 1) === 0x2d /* '-' */
    ) {
      let endIdx = i + 2;
      let endCode = seg.charCodeAt(endIdx);
      if (endCode === 0x5c && endIdx + 1 < closeIdx) {
        endIdx++;
        endCode = seg.charCodeAt(endIdx);
      }
      if (targetCharCode >= startCode && targetCharCode <= endCode) {
        matched = true;
      }
      i = endIdx + 1;
    } else {
      if (targetCharCode === startCode) {
        matched = true;
      }
      i++;
    }
  }
  return negate ? !matched : matched;
}

/**
 * Pure linear two-pointer wildcard matcher for a single path segment (no '/' inside).
 * Zero RegExp compilation; O(1) '[' bracket guard.
 */
function matchSegmentLinear(
  pattern: string,
  hasBracket: boolean,
  bracketMap: Int32Array | null,
  text: string
): boolean {
  if (pattern === '*') {
    return true;
  }
  let p = 0;
  let t = 0;
  let starP = -1;
  let starT = 0;

  while (t < text.length) {
    if (p < pattern.length) {
      const pc = pattern.charCodeAt(p);
      if (pc === 0x2a /* '*' */) {
        starP = p;
        starT = t;
        p++;
        continue;
      }
      if (pc === 0x3f /* '?' */) {
        p++;
        t++;
        continue;
      }
      if (hasBracket && pc === 0x5b /* '[' */ && bracketMap !== null) {
        const closeIdx = bracketMap[p]!;
        if (closeIdx !== -1) {
          if (matchBracketClass(pattern, p, closeIdx, text.charCodeAt(t))) {
            p = closeIdx + 1;
            t++;
            continue;
          }
        } else if (text.charCodeAt(t) === 0x5b) {
          // Unclosed '[' treated literally in O(1)
          p++;
          t++;
          continue;
        }
      } else if (pc === 0x5c /* '\\' */ && p + 1 < pattern.length) {
        if (pattern.charCodeAt(p + 1) === text.charCodeAt(t)) {
          p += 2;
          t++;
          continue;
        }
      } else if (pc === text.charCodeAt(t)) {
        p++;
        t++;
        continue;
      }
    }

    if (starP !== -1) {
      p = starP + 1;
      starT++;
      t = starT;
      continue;
    }

    return false;
  }

  while (p < pattern.length && pattern.charCodeAt(p) === 0x2a /* '*' */) {
    p++;
  }

  return p === pattern.length;
}

function matchPathSegments(
  rule: CompiledIgnoreRule,
  pathParts: string[],
  startIndex: number
): boolean {
  const patParts = rule.segments;
  const P = patParts.length;
  const T = pathParts.length - startIndex;

  // Iterative DP over path segments for '**' support (typical segment count <= 16)
  let dp = new Uint8Array(T + 1);
  dp[0] = 1;

  for (let pi = 0; pi < P; pi++) {
    const seg = patParts[pi]!;
    const nextDp = new Uint8Array(T + 1);

    if (seg === '**') {
      // '**' matches 0 or more path segments
      let seen = false;
      for (let ti = 0; ti <= T; ti++) {
        if (dp[ti] === 1) {
          seen = true;
        }
        if (seen) {
          nextDp[ti] = 1;
        }
      }
    } else {
      const hasBracket = rule.hasBracketBySegment[pi]!;
      const bMap = rule.closingBracketMaps[pi]!;
      for (let ti = 0; ti < T; ti++) {
        if (dp[ti] === 1) {
          const candidateSeg = pathParts[startIndex + ti]!;
          if (matchSegmentLinear(seg, hasBracket, bMap, candidateSeg)) {
            nextDp[ti + 1] = 1;
          }
        }
      }
    }

    dp = nextDp;
  }

  // In gitignore, if a pattern matches a directory prefix (e.g. `build` matching `build/out.js`),
  // Wait: if `directoryOnly` is false, `foo/bar` matches `foo/bar` OR anything inside `foo/bar/...`
  if (dp[T] === 1) {
    return true;
  }
  return false;
}

function parseSingleGitignoreRule(rawLine: string): CompiledIgnoreRule | null {
  // Enforce strict rule length cap <= 4096
  if (rawLine.length === 0 || rawLine.length > MAX_GITIGNORE_RULE_LENGTH) {
    return null;
  }

  const line = stripTrailingUnescapedSpaces(rawLine);
  if (line.length === 0) {
    return null;
  }

  // Unescaped leading '#' is a comment
  if (line.charCodeAt(0) === 0x23 /* '#' */) {
    return null;
  }

  let cursor = 0;
  let negated = false;
  if (line.charCodeAt(0) === 0x21 /* '!' */) {
    negated = true;
    cursor = 1;
  } else if (
    line.length >= 2 &&
    line.charCodeAt(0) === 0x5c /* '\\' */ &&
    (line.charCodeAt(1) === 0x23 || line.charCodeAt(1) === 0x21)
  ) {
    cursor = 1;
  }

  let body = line.slice(cursor);
  if (body.length === 0) {
    return null;
  }

  // Strip trailing slashes linearly (no regex!)
  let directoryOnly = false;
  let bodyEnd = body.length;
  while (bodyEnd > 0 && body.charCodeAt(bodyEnd - 1) === 0x2f /* '/' */) {
    directoryOnly = true;
    bodyEnd--;
  }
  if (bodyEnd === 0) {
    return null;
  }
  body = body.slice(0, bodyEnd);

  // Check leading slash linearly
  let anchored = false;
  if (body.charCodeAt(0) === 0x2f /* '/' */) {
    anchored = true;
    let bodyStart = 0;
    while (bodyStart < body.length && body.charCodeAt(bodyStart) === 0x2f) {
      bodyStart++;
    }
    body = body.slice(bodyStart);
  }

  if (body.length === 0) {
    return null;
  }

  // In gitignore, any slash in the middle anchors the pattern to the root
  if (!anchored && body.indexOf('/') !== -1) {
    anchored = true;
  }

  const rawSegments = body.split('/').filter((s) => s.length > 0);
  if (rawSegments.length === 0) {
    return null;
  }

  const hasBracketBySegment: boolean[] = [];
  const closingBracketMaps: Array<Int32Array | null> = [];
  for (let i = 0; i < rawSegments.length; i++) {
    const info = buildBracketMap(rawSegments[i]!);
    hasBracketBySegment.push(info.hasBracket);
    closingBracketMaps.push(info.map);
  }

  return {
    negated,
    directoryOnly,
    anchored,
    segments: rawSegments,
    hasBracketBySegment,
    closingBracketMaps
  };
}

export class GitignoreMatcher {
  private readonly rules: CompiledIgnoreRule[] = [];

  constructor(gitignoreContent?: string) {
    if (gitignoreContent) {
      this.addRulesFromContent(gitignoreContent);
    }
  }

  public addRulesFromContent(content: string): void {
    let lineStart = 0;
    const len = content.length;
    for (let i = 0; i <= len; i++) {
      const isEnd = i === len;
      const code = isEnd ? 0x0a : content.charCodeAt(i);
      if (code === 0x0a /* '\n' */) {
        let lineEnd = i;
        if (lineEnd > lineStart && content.charCodeAt(lineEnd - 1) === 0x0d /* '\r' */) {
          lineEnd--;
        }
        const lineLen = lineEnd - lineStart;
        // O(1) length cap guard before even slicing
        if (lineLen > 0 && lineLen <= MAX_GITIGNORE_RULE_LENGTH) {
          const compiled = parseSingleGitignoreRule(content.slice(lineStart, lineEnd));
          if (compiled) {
            this.rules.push(compiled);
          }
        }
        lineStart = i + 1;
      }
    }
  }

  /**
   * Evaluates whether a POSIX relative path (e.g. `src/generated/foo.ts`) is ignored.
   */
  public isIgnored(posixRelPath: string, isDirectory: boolean): boolean {
    if (this.rules.length === 0 || posixRelPath === '' || posixRelPath === '.') {
      return false;
    }

    const parts = posixRelPath.split('/').filter((p) => p.length > 0);
    if (parts.length === 0) {
      return false;
    }

    let ignored = false;
    for (let r = 0; r < this.rules.length; r++) {
      const rule = this.rules[r]!;

      let matched = false;
      if (rule.anchored) {
        // Test full path or directory prefix
        for (let prefixLen = 1; prefixLen <= parts.length; prefixLen++) {
          const prefixIsDir = prefixLen < parts.length ? true : isDirectory;
          if (rule.directoryOnly && !prefixIsDir) {
            continue;
          }
          const subParts = prefixLen === parts.length ? parts : parts.slice(0, prefixLen);
          if (matchPathSegments(rule, subParts, 0)) {
            matched = true;
            break;
          }
        }
      } else {
        // Unanchored single-segment pattern (or '**/...' pattern): can match any component or suffix
        if (rule.segments.length === 1 && rule.segments[0] !== '**') {
          const seg = rule.segments[0]!;
          const hasB = rule.hasBracketBySegment[0]!;
          const bMap = rule.closingBracketMaps[0]!;
          for (let idx = 0; idx < parts.length; idx++) {
            const compIsDir = idx < parts.length - 1 ? true : isDirectory;
            if (rule.directoryOnly && !compIsDir) {
              continue;
            }
            if (matchSegmentLinear(seg, hasB, bMap, parts[idx]!)) {
              matched = true;
              break;
            }
          }
        } else {
          for (let start = 0; start < parts.length; start++) {
            if (rule.directoryOnly && !isDirectory) {
              continue;
            }
            if (matchPathSegments(rule, parts, start)) {
              matched = true;
              break;
            }
          }
        }
      }

      if (matched) {
        ignored = !rule.negated;
      }
    }

    return ignored;
  }
}
