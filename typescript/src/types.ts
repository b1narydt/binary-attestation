/** BCAP1 v1 provider-neutral, browser-safe types. */
export type B64Url = string;
export type U64Decimal = string;

export interface AttestationSubject {
  type: string;
  value: string;
}

export interface ProviderPolicyArtifactV1 {
  artifactId: string;
  provider: string;
  mediaType: string;
  canonicalization: string;
  content: B64Url;
  digest: B64Url;
}

export interface SecuritySnapshotBodyV1 {
  securityEpoch: U64Decimal;
  policyId: string;
  policyDigest: B64Url;
  providerArtifacts: ProviderPolicyArtifactV1[];
  trustMaterial: Record<string, unknown>;
  validFromMs: U64Decimal;
  validUntilMs: U64Decimal;
  signerKeyId: string;
}

export interface SignedSecuritySnapshotV1 {
  body: SecuritySnapshotBodyV1;
  trustDigest: B64Url;
  algorithm: string;
  signature: B64Url;
}

export interface AttestationChallengeV1 {
  protocolVersion: 1;
  challengeId: B64Url;
  nonce: B64Url;
  subject: AttestationSubject;
  audience: string;
  context: string;
  contextDigest: B64Url;
  policyId: string;
  policyDigest: B64Url;
  securityEpoch: U64Decimal;
  trustDigest: B64Url;
  issuedAtMs: U64Decimal;
  expiresAtMs: U64Decimal;
}

export interface EvidenceComponentV1 {
  componentId: string;
  provider: string;
  mediaType: string;
  evidence: B64Url;
  endorsements?: B64Url;
  untrustedMetadata?: Record<string, string>;
}

export interface EvidenceBindingEdgeV1 {
  parentComponentId: string;
  childComponentId: string;
  relation: string;
  evidence?: B64Url;
}

export interface EvidenceBundleV1 {
  protocolVersion: 1;
  challengeId: B64Url;
  subject: AttestationSubject;
  components: EvidenceComponentV1[];
  bindingEdges?: EvidenceBindingEdgeV1[];
}

export interface VerifiedComponentV1 {
  componentId: string;
  provider: string;
  evidenceDigest: B64Url;
  bindingDigest: B64Url;
  platform: Record<string, string | number | boolean>;
  measurements: Record<string, B64Url | string>;
  tcb: Record<string, string | number | boolean>;
  advisories: string[];
  validUntilMs: U64Decimal;
}

export interface VerifiedClaimsV1 {
  protocolVersion: 1;
  subject: AttestationSubject;
  audience: string;
  context: string;
  contextDigest: B64Url;
  policyId: string;
  policyDigest: B64Url;
  securityEpoch: U64Decimal;
  trustDigest: B64Url;
  bindingDigest: B64Url;
  subjectBinding: string;
  components: VerifiedComponentV1[];
  verifiedAtMs: U64Decimal;
  validUntilMs: U64Decimal;
}

export type DenialCode =
  | 'malformed'
  | 'unsupported_version'
  | 'unsupported_provider'
  | 'resource_limit'
  | 'challenge_unknown'
  | 'challenge_expired'
  | 'challenge_used'
  | 'binding_mismatch'
  | 'subject_mismatch'
  | 'subject_unauthenticated'
  | 'security_epoch_changed'
  | 'trust_snapshot_invalid'
  | 'workload_subject_unbound'
  | 'gpu_remote_unbound'
  | 'release_fence_unavailable'
  | 'root_untrusted'
  | 'endorsements_missing'
  | 'endorsements_stale'
  | 'signature_invalid'
  | 'revoked'
  | 'tcb_disallowed'
  | 'debug_mode'
  | 'measurement_mismatch'
  | 'component_missing'
  | 'component_unbound'
  | 'policy_unknown'
  | 'policy_mismatch'
  | 'lease_used'
  | 'consumer_mismatch'
  | 'recipient_mismatch'
  | 'verifier_unavailable'
  | 'clock_unavailable'
  | 'internal_error';

export class Denial extends Error {
  override readonly name = 'Denial';
  constructor(
    readonly code: DenialCode,
    message: string = code,
  ) {
    super(message);
  }
}

export type VerificationDecision =
  { decision: 'allow'; claims: VerifiedClaimsV1 } | { decision: 'deny'; denial: DenialCode };

export interface EvidenceVerifier {
  readonly provider: string;
  verify(
    component: EvidenceComponentV1,
    expectedBinding: Uint8Array,
    nowMs: bigint,
    snapshot: SignedSecuritySnapshotV1,
  ): Promise<VerifiedComponentV1>;
}

export interface BindingRelationVerifier {
  readonly relation: string;
  verify(
    parent: VerifiedComponentV1,
    child: VerifiedComponentV1,
    edge: EvidenceBindingEdgeV1,
    expectedBinding: Uint8Array,
    snapshot: SignedSecuritySnapshotV1,
  ): Promise<void>;
}

export interface PolicyEvaluator {
  readonly policyId: string;
  readonly policyDigest: B64Url;
  evaluate(input: {
    challenge: AttestationChallengeV1;
    components: readonly VerifiedComponentV1[];
    snapshot: SignedSecuritySnapshotV1;
    nowMs: bigint;
  }): Promise<{ subjectBinding: string; validUntilMs: U64Decimal }>;
}

export interface SecuritySnapshotSource {
  /** Must provide a linearizable, current snapshot view. */
  current(): SignedSecuritySnapshotV1 | undefined;
  /**
   * A linearizable admission fence. Implementations MUST serialize this with
   * snapshot publication, verify the exact expected epoch/policy/trust
   * revision remains current, obtain trusted time at the transaction's
   * linearization point, and durably record the admission there. It MUST
   * return only after that transaction commits; callers mirror the local
   * terminal allow only afterward. Distributed stores must not invoke
   * side-effect callbacks from their transaction or implement this as a read
   * followed by a later write.
   */
  fence(
    expected: Pick<
      AttestationChallengeV1,
      'securityEpoch' | 'policyDigest' | 'trustDigest' | 'expiresAtMs'
    >,
    /** Called by the store inside its linearization point, never before it. */
    trustedNowMs: () => bigint,
    admission: { challengeId: B64Url; claims: VerifiedClaimsV1 },
  ): void;
}

export type SecuritySnapshotStore = SecuritySnapshotSource;

export type BCAP1TransportProfile =
  'brc103-websocket-v1' | 'brc104-https-v1' | 'brc103-atlas-messagebox-v1';

export interface BCAP1TransportMessageV1 {
  protocolVersion: 1;
  messageType: 'challenge' | 'evidence';
  messageId: B64Url;
  sender: AttestationSubject;
  recipient: AttestationSubject;
  contextDigest: B64Url;
  payloadEncoding: 'rfc8785-jcs';
  payload: B64Url;
  payloadDigest: B64Url;
}

export interface AuthenticatedMessage<T> {
  authenticatedPeer: AttestationSubject;
  transportProfile: BCAP1TransportProfile;
  messageId: string;
  payload: T;
}

/** A carrier adapter may implement this only after authenticating its BRC peer. */
export interface AuthenticatedAttestationChannel {
  readonly localSubject: AttestationSubject;
  readonly profile: BCAP1TransportProfile;
  sendChallenge(peer: AttestationSubject, challenge: AttestationChallengeV1): Promise<void>;
  receiveChallenge(signal?: AbortSignal): Promise<AuthenticatedMessage<AttestationChallengeV1>>;
  sendEvidence(peer: AttestationSubject, bundle: EvidenceBundleV1): Promise<void>;
  receiveEvidence(signal?: AbortSignal): Promise<AuthenticatedMessage<EvidenceBundleV1>>;
}
