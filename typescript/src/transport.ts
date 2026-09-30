import { sha256Bytes } from './crypto.js';
import { jcs, validateChallenge } from './transcript.js';
import {
  decodeB64Url,
  equalBytes,
  hasOnly,
  isRecord,
  requireString,
  subjectEqual,
  validateSubject,
} from './validation.js';
import { validateEvidenceBundle } from './bundle.js';
import {
  Denial,
  type AttestationSubject,
  type AuthenticatedMessage,
  type BCAP1TransportMessageV1,
  type BCAP1TransportProfile,
} from './types.js';

export function validateTransportMessage<T extends 'challenge' | 'evidence'>(input: {
  message: unknown;
  authenticatedPeer: AttestationSubject;
  localSubject: AttestationSubject;
  profile: BCAP1TransportProfile;
  expectedType: T;
  /** Required for evidence and supplied from the stored challenge selected by challengeId. */
  expectedEvidenceContextDigest?: string;
}): AuthenticatedMessage<
  T extends 'challenge'
    ? ReturnType<typeof validateChallenge>
    : ReturnType<typeof validateEvidenceBundle>
> {
  const {
    message,
    authenticatedPeer,
    localSubject,
    profile,
    expectedType,
    expectedEvidenceContextDigest,
  } = input;
  const parsed = parseTransport(message);
  if (parsed.messageType !== expectedType)
    throw new Denial('malformed', 'wrong transport message type');
  if (!subjectEqual(authenticatedPeer, parsed.sender)) throw new Denial('subject_unauthenticated');
  if (!subjectEqual(localSubject, parsed.recipient)) throw new Denial('subject_mismatch');
  const payloadBytes = decodeB64Url(parsed.payload, 'payload', undefined, 16 * 1024 * 1024);
  const payloadDigest = decodeB64Url(parsed.payloadDigest, 'payloadDigest', 32);
  if (!equalBytes(sha256Bytes(payloadBytes), payloadDigest))
    throw new Denial('binding_mismatch', 'payload digest mismatch');
  let payloadUnknown: unknown;
  try {
    payloadUnknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes));
  } catch {
    throw new Denial('malformed', 'payload is not JSON');
  }
  if (new TextDecoder().decode(payloadBytes) !== jcs(payloadUnknown))
    throw new Denial('malformed', 'payload is not exact JCS');
  const payload =
    expectedType === 'challenge'
      ? validateChallenge(payloadUnknown)
      : validateEvidenceBundle(payloadUnknown);
  if (
    expectedType === 'challenge' &&
    (!subjectEqual((payload as ReturnType<typeof validateChallenge>).subject, parsed.recipient) ||
      !equalBytes(
        decodeB64Url(
          (payload as ReturnType<typeof validateChallenge>).contextDigest,
          'contextDigest',
          32,
        ),
        decodeB64Url(parsed.contextDigest, 'contextDigest', 32),
      ))
  ) {
    throw new Denial('binding_mismatch', 'challenge recipient or context digest mismatch');
  }
  if (expectedType === 'evidence') {
    if (
      !subjectEqual((payload as ReturnType<typeof validateEvidenceBundle>).subject, parsed.sender)
    )
      throw new Denial('subject_mismatch', 'evidence sender does not match bundle subject');
    if (expectedEvidenceContextDigest === undefined)
      throw new Denial('malformed', 'stored challenge context is required for evidence');
    if (
      !equalBytes(
        decodeB64Url(expectedEvidenceContextDigest, 'stored contextDigest', 32),
        decodeB64Url(parsed.contextDigest, 'contextDigest', 32),
      )
    ) {
      throw new Denial('binding_mismatch', 'evidence context digest mismatch');
    }
  }
  return {
    authenticatedPeer,
    transportProfile: profile,
    messageId: parsed.messageId,
    payload,
  } as AuthenticatedMessage<
    T extends 'challenge'
      ? ReturnType<typeof validateChallenge>
      : ReturnType<typeof validateEvidenceBundle>
  >;
}

function parseTransport(value: unknown): BCAP1TransportMessageV1 {
  const keys = [
    'protocolVersion',
    'messageType',
    'messageId',
    'sender',
    'recipient',
    'contextDigest',
    'payloadEncoding',
    'payload',
    'payloadDigest',
  ];
  if (!isRecord(value) || !hasOnly(value, keys))
    throw new Denial('malformed', 'invalid transport message shape');
  if (value.protocolVersion !== 1) throw new Denial('unsupported_version');
  if (value.messageType !== 'challenge' && value.messageType !== 'evidence')
    throw new Denial('malformed', 'invalid message type');
  if (value.payloadEncoding !== 'rfc8785-jcs')
    throw new Denial('malformed', 'unsupported payload encoding');
  const result: BCAP1TransportMessageV1 = {
    protocolVersion: 1,
    messageType: value.messageType,
    messageId: requireString(value.messageId, 'messageId'),
    sender: validateSubject(value.sender),
    recipient: validateSubject(value.recipient),
    contextDigest: requireString(value.contextDigest, 'contextDigest'),
    payloadEncoding: 'rfc8785-jcs',
    payload: requireString(value.payload, 'payload'),
    payloadDigest: requireString(value.payloadDigest, 'payloadDigest'),
  };
  decodeB64Url(result.messageId, 'messageId', 16);
  decodeB64Url(result.contextDigest, 'contextDigest', 32);
  decodeB64Url(result.payload, 'payload');
  decodeB64Url(result.payloadDigest, 'payloadDigest', 32);
  return result;
}
