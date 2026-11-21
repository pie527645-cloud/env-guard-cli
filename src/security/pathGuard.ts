import * as fs from 'node:fs';
import * as path from 'node:path';

export const MAX_FILE_BYTES = 512 * 1024; // 512 KB hard cap
export const MAX_PATH_LENGTH = 1024;

export class PathSecurityError extends Error {
  public readonly code: string;

  constructor(message: string, code = 'PATH_SECURITY_ERROR') {
    super(message);
    this.name = 'PathSecurityError';
    this.code = code;
  }
}

export function hasInvalidPathChars(input: string): boolean {
  if (input.length > MAX_PATH_LENGTH) {
    return true;
  }
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
    // Check for lone UTF-16 surrogates
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function isUncOrSchemePath(input: string): boolean {
  if (input.startsWith('\\\\') || input.startsWith('//')) {
    return true;
  }
  // Reject URL schemes like http://, file://, etc.
  const colonIdx = input.indexOf(':');
  if (colonIdx > 1) {
    return true;
  }
  // Reject Windows alternate data streams or secondary colons
  if (colonIdx === 1 && input.indexOf(':', 2) !== -1) {
    return true;
  }
  return false;
}

export function resolveCanonicalRoot(rootDir: string): string {
  if (!rootDir || hasInvalidPathChars(rootDir)) {
    throw new PathSecurityError('Invalid root directory path.', 'INVALID_ROOT');
  }
  if (rootDir.startsWith('\\\\') || rootDir.startsWith('//')) {
    throw new PathSecurityError('UNC paths are not permitted as workspace root.', 'UNC_BLOCKED');
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(rootDir);
  } catch {
    throw new PathSecurityError('Workspace root directory does not exist.', 'ROOT_NOT_FOUND');
  }
  if (!stat.isDirectory()) {
    throw new PathSecurityError('Workspace root path is not a directory.', 'ROOT_NOT_DIRECTORY');
  }
  return fs.realpathSync.native(rootDir);
}

function isWithinRoot(canonicalRoot: string, candidatePath: string): boolean {
  const rel = path.relative(canonicalRoot, candidatePath);
  if (rel === '') {
    return true;
  }
  if (rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) {
    return false;
  }
  return true;
}

/**
 * Resolves a target path strictly inside canonicalRoot.
 * Blocks '..', UNC paths, drive-letter escapes, NUL/control bytes, and symlink escapes.
 */
export function resolveContainedPath(canonicalRoot: string, targetSubpath: string): string {
  if (hasInvalidPathChars(targetSubpath)) {
    throw new PathSecurityError('Target path contains prohibited characters or exceeds length cap.', 'INVALID_PATH');
  }
  if (isUncOrSchemePath(targetSubpath)) {
    throw new PathSecurityError('UNC, URL scheme, or alternate data stream paths are blocked.', 'UNC_OR_SCHEME_BLOCKED');
  }

  // Block cross-drive paths on Windows (e.g. D:\foo when root is C:\bar, or drive-relative C:foo)
  if (targetSubpath.length >= 2 && targetSubpath.charCodeAt(1) === 0x3a /* ':' */) {
    const third = targetSubpath.length > 2 ? targetSubpath.charCodeAt(2) : 0;
    if (third !== 0x5c /* '\\' */ && third !== 0x2f /* '/' */) {
      throw new PathSecurityError('Drive-relative paths are blocked.', 'DRIVE_ESCAPE_BLOCKED');
    }
    const rootDrive = canonicalRoot.slice(0, 2).toUpperCase();
    const targetDrive = targetSubpath.slice(0, 2).toUpperCase();
    if (rootDrive !== targetDrive) {
      throw new PathSecurityError('Cross-drive path escapes workspace root.', 'DRIVE_ESCAPE_BLOCKED');
    }
  }

  // Reject Windows-style backslash parent traversal consistently on POSIX hosts as well
  if (process.platform !== 'win32' && targetSubpath.includes('\\')) {
    const posixCheck = path.posix.normalize(targetSubpath.split('\\').join('/'));
    if (posixCheck === '..' || posixCheck.startsWith('../') || posixCheck.startsWith('/')) {
      throw new PathSecurityError('Path escapes workspace root boundary.', 'PATH_TRAVERSAL_BLOCKED');
    }
  }

  const candidate = path.resolve(canonicalRoot, targetSubpath || '.');
  if (!isWithinRoot(canonicalRoot, candidate)) {
    throw new PathSecurityError('Path escapes workspace root boundary.', 'PATH_TRAVERSAL_BLOCKED');
  }

  // Walk upward to the deepest existing ancestor and verify realpath containment against symlinks
  let current = candidate;
  const trailingSegments: string[] = [];
  while (true) {
    try {
      fs.lstatSync(current);
      break;
    } catch {
      const parent = path.dirname(current);
      if (parent === current) {
        throw new PathSecurityError('Unable to resolve path ancestor within workspace root.', 'ANCESTOR_NOT_FOUND');
      }
      trailingSegments.push(path.basename(current));
      current = parent;
    }
  }

  let realExisting: string;
  try {
    realExisting = fs.realpathSync.native(current);
  } catch {
    throw new PathSecurityError('Failed to resolve canonical target path.', 'REALPATH_FAILED');
  }

  if (!isWithinRoot(canonicalRoot, realExisting)) {
    throw new PathSecurityError('Symlink target escapes workspace root boundary.', 'SYMLINK_ESCAPE_BLOCKED');
  }

  trailingSegments.reverse();
  const finalResolved = trailingSegments.length > 0
    ? path.join(realExisting, ...trailingSegments)
    : realExisting;

  if (!isWithinRoot(canonicalRoot, finalResolved)) {
    throw new PathSecurityError('Resolved path escapes workspace root boundary.', 'PATH_TRAVERSAL_BLOCKED');
  }

  return finalResolved;
}

export interface ReadFileOptions {
  maxBytes?: number;
  rejectBinary?: boolean;
}

export function isBinaryBuffer(buf: Buffer): boolean {
  const checkLen = Math.min(buf.length, 4096);
  for (let i = 0; i < checkLen; i++) {
    if (buf[i] === 0x00) {
      return true;
    }
  }
  return false;
}

export function readBoundedTextFile(
  filePath: string,
  options: ReadFileOptions = {}
): { content: string; skippedReason?: undefined } | { content?: undefined; skippedReason: 'too_large' | 'binary' | 'not_file' } {
  const maxBytes = options.maxBytes ?? MAX_FILE_BYTES;
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) {
    return { skippedReason: 'not_file' };
  }
  if (stat.size > maxBytes) {
    return { skippedReason: 'too_large' };
  }
  const buf = fs.readFileSync(filePath);
  if (buf.length > maxBytes) {
    return { skippedReason: 'too_large' };
  }
  if (options.rejectBinary && isBinaryBuffer(buf)) {
    return { skippedReason: 'binary' };
  }
  return { content: buf.toString('utf8') };
}

export function toPosixRelative(canonicalRoot: string, targetPath: string): string {
  const rel = path.relative(canonicalRoot, targetPath);
  if (rel === '') {
    return '.';
  }
  let out = '';
  for (let i = 0; i < rel.length; i++) {
    const ch = rel.charCodeAt(i);
    out += ch === 0x5c /* '\\' */ ? '/' : rel[i]!;
  }
  return out;
}
