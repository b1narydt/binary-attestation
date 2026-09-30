import { sha256Bytes, sha512Bytes } from './crypto.js';
import {
  decodeB64Url,
  encodeB64Url,
  hasOnly,
  hasOnlyOptional,
  isRecord,
  parseU64,
  requireString,
  u64Decimal,
  utf8,
  validateString,
  validateSubject,
} from './validation.js';
import {
  Denial,
  type AttestationChallengeV1,
  type SecuritySnapshotBodyV1,
  type SignedSecuritySnapshotV1,
} from './types.js';

const challengeKeys = [
  'protocolVersion',
  'challengeId',
  'nonce',
  'subject',
  'audience',
  'context',
  'contextDigest',
  'policyId',
  'policyDigest',
  'securityEpoch',
  'trustDigest',
  'issuedAtMs',
  'expiresAtMs',
] as const;

function field(value: Uint8Array): Uint8Array {
  if (value.byteLength > 0xffff_ffff)
    throw new Denial('resource_limit', 'transcript field is too large');
  const result = new Uint8Array(4 + value.byteLength);
  new DataView(result.buffer).setUint32(0, value.byteLength, false);
  result.set(value, 4);
  return result;
}

function u64be(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  const view = new DataView(result.buffer);
  view.setBigUint64(0, value, false);
  return result;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

export function validateChallenge(value: unknown, maxTtlMs = 300_000n): AttestationChallengeV1 {
  if (!isRecord(value) || !hasOnly(value, challengeKeys))
    throw new Denial('malformed', 'invalid challenge shape');
  if (value.protocolVersion !== 1) throw new Denial('unsupported_version');
  const challenge: AttestationChallengeV1 = {
    protocolVersion: 1,
    challengeId: requireString(value.challengeId, 'challengeId'),
    nonce: requireString(value.nonce, 'nonce'),
    subject: validateSubject(value.subject),
    audience: validateString(value.audience, 'audience'),
    context: validateString(value.context, 'context'),
    contextDigest: requireString(value.contextDigest, 'contextDigest'),
    policyId: validateString(value.policyId, 'policyId'),
    policyDigest: requireString(value.policyDigest, 'policyDigest'),
    securityEpoch: requireString(value.securityEpoch, 'securityEpoch'),
    trustDigest: requireString(value.trustDigest, 'trustDigest'),
    issuedAtMs: requireString(value.issuedAtMs, 'issuedAtMs'),
    expiresAtMs: requireString(value.expiresAtMs, 'expiresAtMs'),
  };
  decodeB64Url(challenge.challengeId, 'challengeId', 16);
  decodeB64Url(challenge.nonce, 'nonce', 32);
  decodeB64Url(challenge.contextDigest, 'contextDigest', 32);
  decodeB64Url(challenge.policyDigest, 'policyDigest', 32);
  decodeB64Url(challenge.trustDigest, 'trustDigest', 32);
  const issued = parseU64(challenge.issuedAtMs, 'issuedAtMs');
  const expires = parseU64(challenge.expiresAtMs, 'expiresAtMs');
  parseU64(challenge.securityEpoch, 'securityEpoch');
  if (issued >= expires || expires - issued > maxTtlMs)
    throw new Denial('malformed', 'invalid challenge lifetime');
  return challenge;
}

export function challengePreimage(challengeInput: AttestationChallengeV1): Uint8Array {
  const challenge = validateChallenge(challengeInput);
  return concat([
    utf8('BINARY-BCAP1-CHALLENGE\0'),
    field(decodeB64Url(challenge.challengeId, 'challengeId', 16)),
    field(decodeB64Url(challenge.nonce, 'nonce', 32)),
    field(utf8(challenge.subject.type)),
    field(utf8(challenge.subject.value)),
    field(utf8(challenge.audience)),
    field(utf8(challenge.context)),
    field(decodeB64Url(challenge.contextDigest, 'contextDigest', 32)),
    field(utf8(challenge.policyId)),
    field(decodeB64Url(challenge.policyDigest, 'policyDigest', 32)),
    u64be(parseU64(challenge.securityEpoch, 'securityEpoch')),
    field(decodeB64Url(challenge.trustDigest, 'trustDigest', 32)),
    u64be(parseU64(challenge.issuedAtMs, 'issuedAtMs')),
    u64be(parseU64(challenge.expiresAtMs, 'expiresAtMs')),
  ]);
}

export function bindingDigest(challenge: AttestationChallengeV1): Uint8Array {
  return sha512Bytes(challengePreimage(challenge));
}

export function bindingDigestB64Url(challenge: AttestationChallengeV1): string {
  return encodeB64Url(bindingDigest(challenge));
}

/** RFC 8785 JSON canonicalization for JSON values accepted by the core. */
export function jcs(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string')
    return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Denial('malformed', 'non-finite JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (!isRecord(value)) throw new Denial('malformed', 'non-JSON value');
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`)
    .join(',')}}`;
}

export function jcsBytes(value: unknown): Uint8Array {
  return utf8(jcs(value));
}

function validateSnapshotBody(value: unknown): SecuritySnapshotBodyV1 {
  const keys = [
    'securityEpoch',
    'policyId',
    'policyDigest',
    'providerArtifacts',
    'trustMaterial',
    'validFromMs',
    'validUntilMs',
    'signerKeyId',
  ];
  if (!isRecord(value) || !hasOnly(value, keys))
    throw new Denial('malformed', 'invalid security snapshot body');
  if (!Array.isArray(value.providerArtifacts) || !isRecord(value.trustMaterial))
    throw new Denial('malformed', 'invalid snapshot collections');
  if (value.providerArtifacts.length > 32)
    throw new Denial('resource_limit', 'too many provider artifacts');
  const body: SecuritySnapshotBodyV1 = {
    securityEpoch: requireString(value.securityEpoch, 'securityEpoch'),
    policyId: validateString(value.policyId, 'policyId'),
    policyDigest: requireString(value.policyDigest, 'policyDigest'),
    providerArtifacts: value.providerArtifacts.map((artifact) => validateArtifact(artifact)),
    trustMaterial: value.trustMaterial,
    validFromMs: requireString(value.validFromMs, 'validFromMs'),
    validUntilMs: requireString(value.validUntilMs, 'validUntilMs'),
    signerKeyId: validateString(value.signerKeyId, 'signerKeyId'),
  };
  decodeB64Url(body.policyDigest, 'policyDigest', 32);
  const from = parseU64(body.validFromMs, 'validFromMs');
  const until = parseU64(body.validUntilMs, 'validUntilMs');
  parseU64(body.securityEpoch, 'securityEpoch');
  if (from >= until) throw new Denial('malformed', 'invalid snapshot lifetime');
  return body;
}

function validateArtifact(value: unknown): SecuritySnapshotBodyV1['providerArtifacts'][number] {
  const keys = ['artifactId', 'provider', 'mediaType', 'canonicalization', 'content', 'digest'];
  if (!isRecord(value) || !hasOnly(value, keys))
    throw new Denial('malformed', 'invalid provider artifact');
  const artifact = {
    artifactId: validateString(value.artifactId, 'artifactId'),
    provider: validateString(value.provider, 'provider'),
    mediaType: validateString(value.mediaType, 'mediaType'),
    canonicalization: validateString(value.canonicalization, 'canonicalization'),
    content: requireString(value.content, 'artifact.content'),
    digest: requireString(value.digest, 'artifact.digest'),
  };
  const content = decodeB64Url(artifact.content, 'artifact.content');
  const digest = decodeB64Url(artifact.digest, 'artifact.digest', 32);
  if (!equalDigest(sha256Bytes(content), digest))
    throw new Denial('malformed', 'provider artifact digest mismatch');
  return artifact;
}

function equalDigest(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let mismatch = 0;
  for (let i = 0; i < left.byteLength; i += 1) mismatch |= left[i]! ^ right[i]!;
  return mismatch === 0;
}

export function validateSecuritySnapshot(value: unknown): SignedSecuritySnapshotV1 {
  const keys = ['body', 'trustDigest', 'algorithm', 'signature'];
  if (!isRecord(value) || !hasOnly(value, keys))
    throw new Denial('malformed', 'invalid signed snapshot');
  const body = validateSnapshotBody(value.body);
  const snapshot: SignedSecuritySnapshotV1 = {
    body,
    trustDigest: requireString(value.trustDigest, 'trustDigest'),
    algorithm: validateString(value.algorithm, 'algorithm'),
    signature: requireString(value.signature, 'snapshot.signature'),
  };
  const trustDigest = decodeB64Url(snapshot.trustDigest, 'trustDigest', 32);
  decodeB64Url(snapshot.signature, 'snapshot.signature');
  if (!equalDigest(sha256Bytes(jcsBytes(body)), trustDigest))
    throw new Denial('trust_snapshot_invalid', 'trust digest mismatch');
  return snapshot;
}

export function snapshotIsValid(snapshot: SignedSecuritySnapshotV1, nowMs: bigint): boolean {
  const body = validateSecuritySnapshot(snapshot).body;
  return (
    parseU64(body.validFromMs, 'validFromMs') <= nowMs &&
    nowMs < parseU64(body.validUntilMs, 'validUntilMs')
  );
}

export function decimalNow(nowMs: bigint): string {
  return u64Decimal(nowMs);
}
