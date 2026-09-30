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
    const stored = validateChallenge(structuredClone(challenge));
    const issuedAt = parseU64(stored.issuedAtMs, 'issuedAtMs');
    const expiresAt = parseU64(stored.expiresAtMs, 'expiresAtMs');
    if (issuedAt !== nowMs || nowMs >= expiresAt)
      throw new Denial('malformed', 'challenge issue time is invalid');
    if (this.#states.has(stored.challengeId))
      throw new Denial('malformed', 'duplicate challenge ID');
    this.expireIssued(nowMs);
    const outstanding = [...this.#states.values()].filter(isOutstanding);
    if (
      outstanding.length >= this.#maxTotal ||
      outstanding.filter((state) => subjectEqual(state.challenge.subject, stored.subject)).length >=
        this.#maxPerSubject
    ) {
      throw new Denial('resource_limit', 'outstanding challenge limit reached');
    }
    this.#states.set(stored.challengeId, { state: 'ISSUED', challenge: stored });
  }

  claim(
    challengeId: string,
    authenticatedSubject: AttestationSubject,
    bundleSubject: AttestationSubject,
    nowMs: bigint,
  ): AttestationChallengeV1 {
    const state = this.#states.get(challengeId);
    if (!state) throw new Denial('challenge_unknown');
    if (state.state !== 'ISSUED') {
      if (state.state === 'EXPIRED') throw new Denial('challenge_expired');
      throw new Denial('challenge_used');
    }
    if (!subjectEqual(state.challenge.subject, bundleSubject)) throw new Denial('subject_mismatch');
    if (!subjectEqual(state.challenge.subject, authenticatedSubject))
      throw new Denial('subject_unauthenticated');
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
    return structuredClone(state.challenge);
  }

  allow(challengeId: string, claims: VerifiedClaimsV1): void {
    const state = this.#states.get(challengeId);
    if (!state || state.state !== 'VERIFYING') throw new Denial('internal_error');
    this.#states.set(challengeId, {
      state: 'CONSUMED_ALLOW',
      challenge: state.challenge,
      claims: structuredClone(claims),
    });
  }

  deny(challengeId: string, denial: Denial['code']): void {
    const state = this.#states.get(challengeId);
    if (!state || state.state !== 'VERIFYING') return;
    this.#states.set(challengeId, { state: 'CONSUMED_DENY', challenge: state.challenge, denial });
  }

  state(challengeId: string): ChallengeState | undefined {
    const state = this.#states.get(challengeId);
    return state === undefined ? undefined : structuredClone(state);
  }

  private expireIssued(nowMs: bigint): void {
    for (const [id, state] of this.#states) {
      if (state.state === 'ISSUED' && nowMs >= parseU64(state.challenge.expiresAtMs, 'expiresAtMs'))
        this.#states.set(id, { state: 'EXPIRED', challenge: state.challenge });
    }
  }
}

/**
 * In-memory linearizable snapshot store. `publish` and `fence` are synchronous
 * critical sections; a distributed replacement must give them the same single
 * serialization point.
 */
export class InMemorySecuritySnapshotStore implements SecuritySnapshotSource {
  #snapshot: SignedSecuritySnapshotV1 | undefined;
  readonly #admissions = new Map<string, VerifiedClaimsV1>();

  constructor(snapshot?: SignedSecuritySnapshotV1) {
    if (snapshot) this.publish(snapshot);
  }

  current(): SignedSecuritySnapshotV1 | undefined {
    return this.#snapshot === undefined ? undefined : structuredClone(this.#snapshot);
  }

  publish(snapshot: SignedSecuritySnapshotV1): void {
    const next = validateSecuritySnapshot(structuredClone(snapshot));
    if (
      this.#snapshot !== undefined &&
      parseU64(next.body.securityEpoch, 'securityEpoch') <=
        parseU64(this.#snapshot.body.securityEpoch, 'securityEpoch')
    ) {
      throw new Denial('trust_snapshot_invalid', 'security epoch must increase');
    }
    this.#snapshot = next;
  }

  fence(
    expected: Pick<AttestationChallengeV1, 'securityEpoch' | 'policyDigest' | 'trustDigest'>,
    nowMs: bigint,
    admission: { challengeId: string; claims: VerifiedClaimsV1 },
  ): void {
    const snapshot = this.#snapshot;
    if (!snapshot || !snapshotIsValid(snapshot, nowMs)) throw new Denial('trust_snapshot_invalid');
    if (!snapshotMatches(expected, snapshot)) throw new Denial('security_epoch_changed');
    if (this.#admissions.has(admission.challengeId)) throw new Denial('challenge_used');
    this.#admissions.set(admission.challengeId, structuredClone(admission.claims));
  }

  admission(challengeId: string): VerifiedClaimsV1 | undefined {
    const claims = this.#admissions.get(challengeId);
    return claims === undefined ? undefined : structuredClone(claims);
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
  readonly maxTtlMs: bigint;
  constructor(
    readonly snapshots: SecuritySnapshotSource,
    readonly registry: VerifierRegistry,
    readonly challenges = new InMemoryChallengeStore(),
    readonly clock: Clock = systemClock,
    readonly random: (length: number) => Uint8Array = secureRandom,
    maxTtlMs = 300_000n,
  ) {
    if (maxTtlMs <= 0n || maxTtlMs > 300_000n)
      throw new Denial('resource_limit', 'invalid maximum challenge TTL');
    this.maxTtlMs = maxTtlMs;
  }

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
    try {
      const bundle = validateEvidenceBundle(input.bundle);
      const now = this.now();
      const authenticatedSubject = validateSubject(input.authenticatedSubject);
      const challenge = this.challenges.claim(
        bundle.challengeId,
        authenticatedSubject,
        bundle.subject,
        now,
      );
      try {
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
        if (finalNow >= parseU64(challenge.expiresAtMs, 'expiresAtMs'))
          throw new Denial('challenge_expired');
        const policyValidUntil = parseU64(appraisal.validUntilMs, 'policy validUntilMs');
        if (policyValidUntil <= finalNow)
          throw new Denial('policy_mismatch', 'policy result is already expired');
        const validUntil = minU64(
          appraisal.validUntilMs,
          challenge.expiresAtMs,
          snapshot.body.validUntilMs,
          ...components.map((component) => component.validUntilMs),
        );
        if (parseU64(validUntil, 'validUntilMs') <= finalNow)
          throw new Denial('policy_mismatch', 'final claims are already expired');
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
        // The shared store transaction, not this local cache write, is the
        // authorization linearization point.
        this.snapshots.fence(challenge, finalNow, { challengeId: challenge.challengeId, claims });
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

  private now(): bigint {
    try {
      return this.clock.nowMs();
    } catch {
      throw new Denial('clock_unavailable');
    }
  }
}

function snapshotMatches(
  expected: Pick<AttestationChallengeV1, 'securityEpoch' | 'policyDigest' | 'trustDigest'>,
  snapshot: SignedSecuritySnapshotV1,
): boolean {
  return (
    expected.securityEpoch === snapshot.body.securityEpoch &&
    equalBytes(
      decodeB64Url(expected.trustDigest, 'challenge trustDigest', 32),
      decodeB64Url(snapshot.trustDigest, 'snapshot trustDigest', 32),
    ) &&
    equalBytes(
      decodeB64Url(expected.policyDigest, 'challenge policyDigest', 32),
      decodeB64Url(snapshot.body.policyDigest, 'snapshot policyDigest', 32),
    )
  );
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
