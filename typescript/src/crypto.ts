import { sha256 } from '@noble/hashes/sha2.js';
import { sha512 } from '@noble/hashes/sha2.js';

export const sha256Bytes = (value: Uint8Array): Uint8Array => sha256(value);
export const sha512Bytes = (value: Uint8Array): Uint8Array => sha512(value);
