/**
 * File cleaner core — pure, dependency-free TypeScript.
 *
 * Detects and removes trailing "junk" bytes appended after the last valid
 * top-level chunk of a media/image/archive file. Such bytes are typically
 * added by bad downloads or external tampering and break some players.
 *
 * Ported from the original Python GUI (packages/desktop-legacy/file_cleaner_gui.py)
 * and the Perl script (videocleaner.pl). Operates entirely on in-memory bytes
 * so it can run client-side in the browser.
 */

export type FileType =
  | "mp4/mov"
  | "wmv"
  | "mkv"
  | "jpeg"
  | "png"
  | "zip"
  | "pdf"
  | "avi"
  | "unknown";

/** Junk larger than this is treated as a false positive and left untouched. */
export const JUNK_BYTE_LIMIT = 1000;

export interface CleanResult {
  fileType: FileType;
  /** Number of trailing junk bytes detected (before applying the safety limit). */
  junkBytes: number;
  /** True when junk was found within the safe range and removed. */
  cleaned: boolean;
  /** Why the file was or wasn't cleaned — for UI logging. */
  reason:
    | "cleaned"
    | "no-junk"
    | "false-positive"
    | "unknown-type"
    | "too-small";
  /** Cleaned bytes. Equals the input slice when nothing was removed. */
  data: Uint8Array;
  /** The removed trailing bytes (backup), empty when nothing removed. */
  junk: Uint8Array;
}

function eq(buf: Uint8Array, offset: number, bytes: number[]): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (buf[offset + i] !== bytes[i]) return false;
  }
  return true;
}

function ascii(buf: Uint8Array, start: number, end: number): string {
  let s = "";
  for (let i = start; i < end; i++) s += String.fromCharCode(buf[i]);
  return s;
}

export function getFileType(buf: Uint8Array): FileType {
  if (buf.length < 12) {
    // Fall through to the smaller-signature checks below.
  }
  const tag = ascii(buf, 4, 8);
  if (["ftyp", "moov", "mdat", "free", "skip"].includes(tag)) return "mp4/mov";
  if (eq(buf, 0, [0x30, 0x26, 0xb2, 0x75])) return "wmv";
  if (eq(buf, 0, [0x1a, 0x45, 0xdf, 0xa3])) return "mkv";
  if (eq(buf, 0, [0xff, 0xd8])) return "jpeg";
  if (eq(buf, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  if (eq(buf, 0, [0x50, 0x4b, 0x03, 0x04])) return "zip";
  if (eq(buf, 0, [0x25, 0x50, 0x44, 0x46])) return "pdf"; // %PDF
  if (eq(buf, 0, [0x52, 0x49, 0x46, 0x46]) && eq(buf, 8, [0x41, 0x56, 0x49, 0x20]))
    return "avi"; // RIFF....AVI
  return "unknown";
}

function minChunkSize(type: FileType): number {
  switch (type) {
    case "mp4/mov":
      return 8;
    case "wmv":
      return 24;
    case "mkv":
      return 16;
    case "jpeg":
      return 2;
    case "png":
      return 8;
    case "zip":
      return 4;
    case "pdf":
      return 4;
    case "avi":
      return 12;
    default:
      throw new Error("Unknown file type");
  }
}

/** Read an EBML/Matroska variable-length integer at `pos`. Returns [value, byteLength]. */
function readVint(buf: Uint8Array, pos: number): [number | null, number] {
  if (pos >= buf.length) return [null, 0];
  const first = buf[pos];
  let mask = 0x80;
  let length = 1;
  while (length <= 8 && (first & mask) === 0) {
    mask >>= 1;
    length += 1;
  }
  if (length > 8) return [null, 0];
  const valueMask = (1 << (7 - length + 1)) - 1;
  let value = first & valueMask;
  for (let i = 1; i < length; i++) {
    if (pos + i >= buf.length) return [null, 0];
    // Use multiplication to stay safe past 32 bits.
    value = value * 256 + buf[pos + i];
  }
  return [value, length];
}

/**
 * Find the number of trailing junk bytes in `buf`.
 * Returns -1 when the type can't be parsed.
 */
export function findTrailingJunkBytes(buf: Uint8Array): {
  type: FileType;
  junk: number;
} {
  const size = buf.length;
  if (size < 16) return { type: "unknown", junk: -1 };

  const type = getFileType(buf);
  if (type === "unknown") return { type, junk: -1 };

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const min = minChunkSize(type);
  let pos = 0;
  let lastValidEnd = 0;

  if (type === "jpeg") {
    pos = 0;
    while (pos < size) {
      const b = buf[pos];
      pos += 1;
      if (b === 0xff && pos < size && buf[pos] === 0xd9) {
        pos += 1;
        lastValidEnd = pos;
        break;
      }
    }
    return { type, junk: size - lastValidEnd };
  }

  if (type === "png") {
    pos = 8; // skip signature
    lastValidEnd = pos;
    while (pos < size) {
      if (size - pos < 12) break;
      const len = view.getUint32(pos, false);
      const chunkType = ascii(buf, pos + 4, pos + 8);
      pos += 8 + len + 4; // length + type + data + CRC
      lastValidEnd = pos;
      if (chunkType === "IEND") break;
    }
    return { type, junk: size - lastValidEnd };
  }

  if (type === "mkv") {
    while (pos < size) {
      const remaining = size - pos;
      if (remaining < min) break;
      const [id, idLen] = readVint(buf, pos);
      if (id === null) break;
      const [len, lenLen] = readVint(buf, pos + idLen);
      if (len === null || len > remaining) break;
      pos += idLen + lenLen + len;
      lastValidEnd = pos;
    }
    return { type, junk: size - lastValidEnd };
  }

  if (type === "pdf") {
    const window = 1024;
    const eof = [0x25, 0x25, 0x45, 0x4f, 0x46]; // %%EOF
    lastValidEnd = size;
    let start = Math.max(0, size - window);
    let found = false;
    while (start >= 0) {
      // search this window backwards for the EOF marker
      for (let i = Math.min(size, start + window) - eof.length; i >= start; i--) {
        if (eq(buf, i, eof)) {
          lastValidEnd = i + eof.length;
          found = true;
          break;
        }
      }
      if (found || start === 0) break;
      start = Math.max(0, start - window);
    }
    return { type, junk: size - lastValidEnd };
  }

  if (type === "zip") {
    // End of Central Directory record signature PK\x05\x06
    const eocd = [0x50, 0x4b, 0x05, 0x06];
    for (let i = size - 22; i >= 0; i--) {
      if (eq(buf, i, eocd)) {
        lastValidEnd = i + 22;
        break;
      }
    }
    return { type, junk: size - lastValidEnd };
  }

  // mp4/mov, wmv, avi — walk top-level chunks
  while (pos < size) {
    const remaining = size - pos;
    if (remaining < min) break;

    let chunkLength = 0;
    if (type === "mp4/mov") {
      chunkLength = view.getUint32(pos, false); // big-endian, includes 8-byte header
      if (chunkLength === 1) {
        // 64-bit extended size follows the 8-byte header
        if (pos + 16 > size) break;
        const hi = view.getUint32(pos + 8, false);
        const lo = view.getUint32(pos + 12, false);
        chunkLength = hi * 0x100000000 + lo;
      }
    } else if (type === "wmv") {
      const lo = view.getUint32(pos + 16, true);
      const hi = view.getUint32(pos + 20, true);
      chunkLength = hi * 0x100000000 + lo; // little-endian 64-bit, full object size
    } else if (type === "avi") {
      chunkLength = view.getUint32(pos + 4, true) + 8; // little-endian + 8-byte header
    }

    if (chunkLength <= 0 || chunkLength > remaining) break;
    pos += chunkLength;
    lastValidEnd = pos;
  }

  return { type, junk: size - lastValidEnd };
}

/**
 * Clean a file's bytes: detect trailing junk and, when safe, strip it.
 * Pure — returns a new result, never mutates the input.
 */
export function cleanFile(input: Uint8Array): CleanResult {
  if (input.length < 16) {
    return {
      fileType: "unknown",
      junkBytes: 0,
      cleaned: false,
      reason: "too-small",
      data: input,
      junk: new Uint8Array(0),
    };
  }

  const { type, junk } = findTrailingJunkBytes(input);

  if (junk === -1) {
    return {
      fileType: type,
      junkBytes: 0,
      cleaned: false,
      reason: "unknown-type",
      data: input,
      junk: new Uint8Array(0),
    };
  }

  if (junk > JUNK_BYTE_LIMIT) {
    return {
      fileType: type,
      junkBytes: junk,
      cleaned: false,
      reason: "false-positive",
      data: input,
      junk: new Uint8Array(0),
    };
  }

  if (junk > 0) {
    const cut = input.length - junk;
    return {
      fileType: type,
      junkBytes: junk,
      cleaned: true,
      reason: "cleaned",
      data: input.subarray(0, cut),
      junk: input.subarray(cut),
    };
  }

  return {
    fileType: type,
    junkBytes: 0,
    cleaned: false,
    reason: "no-junk",
    data: input,
    junk: new Uint8Array(0),
  };
}
