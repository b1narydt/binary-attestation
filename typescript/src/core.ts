import { verifyBundleComponents, validateEvidenceBundle, VerifierRegistry } from './bundle.js';
import {
  bindingDigest,
  decimalNow,
  snapshotIsValid,
  validateChallenge,
  validateSecuritySnapshot,
} from './transcript.js';
import {
  decodeB64Url,
  encodeB64Url,
  equalBytes,
  parseU64,
  subjectEqual,
  u64Decimal,
  validateString,
  validateSubject,
} from './validation.js';
import {
  Denial,
  type AttestationChallengeV1,
  type AttestationSubject,
  type EvidenceBundleV1,
  type PolicyEvaluator,
  type SecuritySnapshotSource,
  type SignedSecuritySnapshotV1,
  type VerificationDecision,
  type VerifiedClaimsV1,
} from './types.js';

type ChallengeState =
  | { state: 'ISSUED'; challenge: AttestationChallengeV1 }
  | { state: 'VERIFYING'; challenge: AttestationChallengeV1 }
  | { state: 'CONSUMED_ALLOW'; challenge: AttestationChallengeV1; claims: VerifiedClaimsV1 }
  | { state: 'CONSUMED_DENY'; challenge: AttestationChallengeV1; denial: Denial['code'] }
  | { state: 'EXPIRED'; challenge: AttestationChallengeV1 };

export interface Clock {
  nowMs(): bigint;
}
export const systemClock: Clock = { nowMs: () => BigInt(Date.now()) };

export class InMemoryChallengeStore {
  readonly #states = new Map<string, ChallengeState>();
  readonly #maxPerSubject: number;
  readonly #maxTotal: number;

  constructor(limits: { maxOutstandingPerSubject?: number; maxOutstanding?: number } = {}) {
    this.#maxPerSubject = limits.maxOutstandingPerSubject ?? 4;
    this.#maxTotal = limits.maxOutstanding ?? 10_000;
    if (
      !Number.isInteger(this.#maxPerSubject) ||
      this.#maxPerSubject < 1 ||
      this.#maxPerSubject > 8 ||
      !Number.isInteger(this.#maxTotal) ||
      this.#maxTotal < 1 ||
      this.#maxTotal > 100_000
    ) {
      throw new Denial('resource_limit', 'invalid outstanding challenge limits');
    }
  }

  issue(challenge: AttestationChallengeV1, nowMs: bigint): void {
    if (this.#states.has(challenge.challengeId))
      throw new Denial('malformed', 'duplicate challenge ID');
    this.expireIssued(nowMs);
    const outstanding = [...this.#states.values()].filter(isOutstanding);
    if (
      outstanding.length >= this.#maxTotal ||
      outstanding.filter((state) => subjectEqual(state.challenge.subject, challenge.subject))
        .length >= this.#maxPerSubject
    ) {
      throw new Denial('resource_limit', 'outstanding challenge limit reached');
    }
    this.#states.set(challenge.challengeId, { state: 'ISSUED', challenge });
  }

  claim(challengeId: string, nowMs: bigint): AttestationChallengeV1 {
    const state = this.#states.get(challengeId);
    if (!state) throw new Denial('challenge_unknown');
    if (state.state !== 'ISSUED') {
      if (state.state === 'EXPIRED') throw new Denial('challenge_expired');
      throw new Denial('challenge_used');
    }
    if (nowMs < parseU64(state.challenge.issuedAtMs, 'issuedAtMs')) {
      this.#states.set(challengeId, {
        state: 'CONSUMED_DENY',
        challenge: state.challenge,
        denial: 'malformed',
      });
      throw new Denial('malformed', 'challenge is issued in the future');
    }
    if (nowMs >= parseU64(state.challenge.expiresAtMs, 'expiresAtMs')) {
      this.#states.set(challengeId, { state: 'EXPIRED', challenge: state.challenge });
      throw new Denial('challenge_expired');
    }
    this.#states.set(challengeId, { state: 'VERIFYING', challenge: state.challenge });
    return state.challenge;
  }

  allow(challengeId: string, claims: VerifiedClaimsV1): void {
    const state = this.#states.get(challengeId);
    if (!state || state.state !== 'VERIFYING') throw new Denial('internal_error');
    this.#states.set(challengeId, { state: 'CONSUMED_ALLOW', challenge: state.challenge, claims });
  }

  deny(challengeId: string, denial: Denial['code']): void {
    const state = this.#states.get(challengeId);
    if (!state || state.state !== 'VERIFYING') return;
    this.#states.set(challengeId, { state: 'CONSUMED_DENY', challenge: state.challenge, denial });
  }

  state(challengeId: string): ChallengeState | undefined {
    return this.#states.get(challengeId);
  }

  private expireIssued(nowMs: bigint): void {
    for (const [id, state] of this.#states) {
      if (state.state === 'ISSUED' && nowMs >= parseU64(state.challenge.expiresAtMs, 'expiresAtMs'))
        this.#states.set(id, { state: 'EXPIRED', challenge: state.challenge });
    }
  }
}

function isOutstanding(state: ChallengeState): boolean {
  return state.state === 'ISSUED' || state.state === 'VERIFYING';
}

export interface ChallengeRequest {
  subject: AttestationSubject;
  audience: string;
  context: string;
  contextDigest: string;
  policyId: string;
  policyDigest: string;
  ttlMs: bigint;
}

export class AttestationCore {
  constructor(
    readonly snapshots: SecuritySnapshotSource,
    readonly registry: VerifierRegistry,
    readonly challenges = new InMemoryChallengeStore(),
    readonly clock: Clock = systemClock,
    readonly random: (length: number) => Uint8Array = secureRandom,
    readonly maxTtlMs = 300_000n,
  ) {}

  issue(request: ChallengeRequest): AttestationChallengeV1 {
    const now = this.now();
    const snapshot = this.currentSnapshot(now);
    if (request.ttlMs <= 0n || request.ttlMs > this.maxTtlMs)
      throw new Denial('resource_limit', 'invalid challenge TTL');
    const subject = validateSubject(request.subject);
    const audience = validateString(request.audience, 'audience');
    const context = validateString(request.context, 'context');
    decodeB64Url(request.contextDigest, 'contextDigest', 32);
    decodeB64Url(request.policyDigest, 'policyDigest', 32);
    if (
      request.policyId !== snapshot.body.policyId ||
      !equalBytes(
        decodeB64Url(request.policyDigest, 'policyDigest', 32),
        decodeB64Url(snapshot.body.policyDigest, 'snapshot policyDigest', 32),
      )
    )
      throw new Denial('policy_mismatch');
    const challenge: AttestationChallengeV1 = {
      protocolVersion: 1,
      challengeId: encodeB64Url(this.random(16)),
      nonce: encodeB64Url(this.random(32)),
      subject,
      audience,
      context,
      contextDigest: request.contextDigest,
      policyId: request.policyId,
      policyDigest: request.policyDigest,
      securityEpoch: snapshot.body.securityEpoch,
      trustDigest: snapshot.trustDigest,
      issuedAtMs: u64Decimal(now),
      expiresAtMs: u64Decimal(now + request.ttlMs),
    };
    this.challenges.issue(validateChallenge(challenge, this.maxTtlMs), now);
    return challenge;
  }

  async verify(input: {
    bundle: EvidenceBundleV1;
    authenticatedSubject: AttestationSubject;
    policy: PolicyEvaluator;
  }): Promise<VerificationDecision> {
    let challengeId: string | undefined;
    try {
      const bundle = validateEvidenceBundle(input.bundle);
      challengeId = bundle.challengeId;
      const now = this.now();
      const challenge = this.challenges.claim(bundle.challengeId, now);
      try {
        this.requireSubject(challenge, bundle, input.authenticatedSubject);
        const snapshot = this.currentSnapshot(now);
        this.requireSnapshotMatches(challenge, snapshot);
        if (
          input.policy.policyId !== challenge.policyId ||
          !equalBytes(
            decodeB64Url(input.policy.policyDigest, 'policy digest', 32),
            decodeB64Url(challenge.policyDigest, 'challenge policy digest', 32),
          )
        )
          throw new Denial('policy_mismatch');
        const components = await verifyBundleComponents({
          challenge,
          bundle,
          registry: this.registry,
          snapshot,
          nowMs: now,
        });
        const appraisal = await input.policy.evaluate({
          challenge,
          components,
          snapshot,
          nowMs: now,
        });
        const finalNow = this.now();
        const finalSnapshot = this.currentSnapshot(finalNow);
        this.requireSnapshotMatches(challenge, finalSnapshot);
        if (finalNow >= parseU64(challenge.expiresAtMs, 'expiresAtMs'))
          throw new Denial('challenge_expired');
        const validUntil = minU64(
          appraisal.validUntilMs,
          challenge.expiresAtMs,
          finalSnapshot.body.validUntilMs,
          ...components.map((component) => component.validUntilMs),
        );
        const claims: VerifiedClaimsV1 = {
          protocolVersion: 1,
          subject: challenge.subject,
          audience: challenge.audience,
          context: challenge.context,
          contextDigest: challenge.contextDigest,
          policyId: challenge.policyId,
          policyDigest: challenge.policyDigest,
          securityEpoch: challenge.securityEpoch,
          trustDigest: challenge.trustDigest,
          bindingDigest: encodeB64Url(bindingDigest(challenge)),
          subjectBinding: validateString(appraisal.subjectBinding, 'subjectBinding'),
          components: [...components],
          verifiedAtMs: decimalNow(finalNow),
          validUntilMs: validUntil,
        };
        this.challenges.allow(challenge.challengeId, claims);
        return { decision: 'allow', claims };
      } catch (error) {
        const denial = asDenial(error);
        this.challenges.deny(challenge.challengeId, denial.code);
        return { decision: 'deny', denial: denial.code };
      }
    } catch (error) {
      const denial = asDenial(error);
      return { decision: 'deny', denial: denial.code };
    }
  }

  private currentSnapshot(now: bigint): SignedSecuritySnapshotV1 {
    try {
      const candidate = this.snapshots.current();
      if (!candidate) throw new Denial('trust_snapshot_invalid', 'no current snapshot');
      const snapshot = validateSecuritySnapshot(candidate);
      if (!snapshotIsValid(snapshot, now))
        throw new Denial('trust_snapshot_invalid', 'snapshot outside validity window');
      return snapshot;
    } catch {
      throw new Denial('trust_snapshot_invalid');
    }
  }

  private requireSnapshotMatches(
    challenge: AttestationChallengeV1,
    snapshot: SignedSecuritySnapshotV1,
  ): void {
    if (
      challenge.securityEpoch !== snapshot.body.securityEpoch ||
      !equalBytes(
        decodeB64Url(challenge.trustDigest, 'challenge trustDigest', 32),
        decodeB64Url(snapshot.trustDigest, 'snapshot trustDigest', 32),
      ) ||
      !equalBytes(
        decodeB64Url(challenge.policyDigest, 'challenge policyDigest', 32),
        decodeB64Url(snapshot.body.policyDigest, 'snapshot policyDigest', 32),
      )
    ) {
      throw new Denial('security_epoch_changed');
    }
  }

  private requireSubject(
    challenge: AttestationChallengeV1,
    bundle: EvidenceBundleV1,
    authenticated: AttestationSubject,
  ): void {
    if (!subjectEqual(challenge.subject, bundle.subject)) throw new Denial('subject_mismatch');
    if (!subjectEqual(challenge.subject, validateSubject(authenticated)))
      throw new Denial('subject_unauthenticated');
  }

  private now(): bigint {
    try {
      return this.clock.nowMs();
    } catch {
      throw new Denial('clock_unavailable');
    }
  }
}

function secureRandom(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  if (!globalThis.crypto?.getRandomValues)
    throw new Denial('internal_error', 'secure random source unavailable');
  return globalThis.crypto.getRandomValues(bytes);
}

function minU64(...values: string[]): string {
  return u64Decimal(
    values
      .map((value) => parseU64(value, 'validUntilMs'))
      .reduce((smallest, value) => (value < smallest ? value : smallest)),
  );
}

function asDenial(error: unknown): Denial {
  return error instanceof Denial ? error : new Denial('internal_error');
}
