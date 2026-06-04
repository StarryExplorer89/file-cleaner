import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanFile, findTrailingJunkBytes, getFileType } from "../src/index.ts";

function concat(...parts: number[][]): Uint8Array {
  return new Uint8Array(parts.flat());
}

function u32be(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

const FTYP = [0x66, 0x74, 0x79, 0x70]; // "ftyp"
const MDAT = [0x6d, 0x64, 0x61, 0x74]; // "mdat"
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const IHDR = [0x49, 0x48, 0x44, 0x52];
const IEND = [0x49, 0x45, 0x4e, 0x44];

function mp4(extraJunk: number): Uint8Array {
  const box1 = concat(u32be(16), FTYP, [0, 0, 0, 0, 0, 0, 0, 0]); // 16 bytes
  const box2 = concat(u32be(16), MDAT, [1, 1, 1, 1, 1, 1, 1, 1]); // 16 bytes
  const junk = Array.from({ length: extraJunk }, () => 0xaa);
  return concat([...box1], [...box2], junk);
}

function png(extraJunk: number): Uint8Array {
  const ihdr = concat(u32be(13), IHDR, new Array(13).fill(7), [0, 0, 0, 0]); // crc
  const iend = concat(u32be(0), IEND, [0, 0, 0, 0]);
  const junk = Array.from({ length: extraJunk }, () => 0xbb);
  return concat(PNG_SIG, [...ihdr], [...iend], junk);
}

test("detects file types", () => {
  assert.equal(getFileType(mp4(0)), "mp4/mov");
  assert.equal(getFileType(png(0)), "png");
  assert.equal(getFileType(new Uint8Array(20)), "unknown");
});

test("mp4: strips trailing junk", () => {
  const r = cleanFile(mp4(5));
  assert.equal(r.cleaned, true);
  assert.equal(r.junkBytes, 5);
  assert.equal(r.data.length, 32);
  assert.equal(r.junk.length, 5);
});

test("mp4: clean file untouched", () => {
  const r = cleanFile(mp4(0));
  assert.equal(r.cleaned, false);
  assert.equal(r.reason, "no-junk");
  assert.equal(r.data.length, 32);
});

test("png: strips trailing junk after IEND", () => {
  const r = cleanFile(png(10));
  assert.equal(r.fileType, "png");
  assert.equal(r.cleaned, true);
  assert.equal(r.junkBytes, 10);
});

test("false positive: huge trailing block is left untouched", () => {
  const r = cleanFile(mp4(2000));
  assert.equal(r.cleaned, false);
  assert.equal(r.reason, "false-positive");
  assert.equal(r.junkBytes, 2000);
});

test("unknown type reported", () => {
  const buf = new Uint8Array(64).fill(0x42);
  const { junk } = findTrailingJunkBytes(buf);
  assert.equal(junk, -1);
});
