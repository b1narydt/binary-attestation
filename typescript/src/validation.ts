import { secp256k1 } from '@noble/curves/secp256k1.js';

import { Denial, type AttestationSubject, type U64Decimal } from './types.js';

export const MAX_U64 = 18_446_744_073_709_551_615n;
export const MAX_STRING_BYTES = 1024;
export const MAX_COMPONENTS = 32;
export const MAX_BINDING_EDGES = 64;
export const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
export const MAX_ENDORSEMENTS_BYTES = 4 * 1024 * 1024;
export const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;

const encoder = new TextEncoder();
const b64url = /^[A-Za-z0-9_-]*$/u;
const u64 = /^(?:0|[1-9][0-9]{0,19})$/u;
const brc100 = /^[0-9a-f]{66}$/u;

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function validateString(value: unknown, name: string, max = MAX_STRING_BYTES): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\0') ||
    value !== value.normalize('NFC')
  ) {
    throw new Denial('malformed', `${name} must be non-empty NFC text without NUL`);
  }
  if (utf8(value).byteLength > max) throw new Denial('resource_limit', `${name} is too long`);
  return value;
}

/** Preserves JSON scalar typing before a field-specific validator is applied. */
export function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new Denial('malformed', `${name} must be a string`);
  return value;
}

export function decodeB64Url(
  value: unknown,
  name: string,
  exactBytes?: number,
  maxBytes?: number,
): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !b64url.test(value) ||
    value.includes('=')
  ) {
    throw new Denial('malformed', `${name} is not unpadded base64url`);
  }
  if (value.length % 4 === 1)
    throw new Denial('malformed', `${name} has impossible base64url length`);
  // Check before atob allocates a decoded copy. Unpadded base64url has at
  // most three decoded bytes for every four encoded characters.
  const allocationLimit =
    maxBytes === undefined
      ? exactBytes
      : exactBytes === undefined
        ? maxBytes
        : Math.min(maxBytes, exactBytes);
  if (allocationLimit !== undefined && value.length > Math.ceil((allocationLimit * 4) / 3))
    throw new Denial('resource_limit', `${name} is too large`);
  const padded =
    value.replace(/-/gu, '+').replace(/_/gu, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  let bytes: Uint8Array;
  try {
    const binary = globalThis.atob(padded);
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Denial('malformed', `${name} is not base64url`);
  }
  if (encodeB64Url(bytes) !== value)
    throw new Denial('malformed', `${name} is not canonical base64url`);
  if (exactBytes !== undefined && bytes.byteLength !== exactBytes)
    throw new Denial('malformed', `${name} has wrong length`);
  if (maxBytes !== undefined && bytes.byteLength > maxBytes)
    throw new Denial('resource_limit', `${name} is too large`);
  return bytes;
}

export function encodeB64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

export function parseU64(value: unknown, name: string): bigint {
  if (typeof value !== 'string' || !u64.test(value))
    throw new Denial('malformed', `${name} is not canonical unsigned u64`);
  const result = BigInt(value);
  if (result > MAX_U64) throw new Denial('malformed', `${name} exceeds u64`);
  return result;
}

export function u64Decimal(value: bigint): U64Decimal {
  if (value < 0n || value > MAX_U64) throw new Denial('malformed', 'u64 out of range');
  return value.toString();
}

export function validateSubject(value: unknown): AttestationSubject {
  if (!isRecord(value) || !hasOnly(value, ['type', 'value']))
    throw new Denial('malformed', 'invalid subject shape');
  const type = validateString(value.type, 'subject.type');
  const subjectValue = validateString(value.value, 'subject.value');
  if (type === 'brc100-public-key') validateBrc100PublicKey(subjectValue);
  return { type, value: subjectValue };
}

export function validateBrc100PublicKey(value: string): string {
  if (!brc100.test(value))
    throw new Denial('malformed', 'BRC-100 public key must be lowercase compressed hex');
  try {
    const point = secp256k1.ProjectivePoint.fromHex(value);
    if (!point.equals(secp256k1.ProjectivePoint.fromHex(value))) throw new Error('invalid point');
  } catch {
    throw new Denial('malformed', 'BRC-100 public key is not a valid compressed secp256k1 point');
  }
  return value;
}

export function subjectEqual(left: AttestationSubject, right: AttestationSubject): boolean {
  return left.type === right.type && left.value === right.value;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let result = 0;
  for (let index = 0; index < left.byteLength; index += 1) result |= left[index]! ^ right[index]!;
  return result === 0;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function hasOnly(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

export function hasOnlyOptional(
  record: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): boolean {
  const actual = Object.keys(record);
  return (
    required.every((key) => Object.hasOwn(record, key)) &&
    actual.every((key) => required.includes(key) || optional.includes(key))
  );
}
