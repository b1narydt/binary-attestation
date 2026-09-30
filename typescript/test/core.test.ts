import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import snapshotVectors from '../../vectors/bcap1-security-snapshot-jcs.json' with { type: 'json' };
import transcriptVectors from '../../vectors/bcap1-transcript.json' with { type: 'json' };
import transportVectors from '../../vectors/bcap1-transport.json' with { type: 'json' };

import {
  AttestationCore,
  challengePreimage,
  Denial,
  InMemoryChallengeStore,
  VerifierRegistry,
  bindingDigest,
  decodeB64Url,
  encodeB64Url,
  jcsBytes,
  sha256Bytes,
  validateSecuritySnapshot,
  validateChallenge,
  validateTransportMessage,
  type AttestationChallengeV1,
  type EvidenceComponentV1,
  type PolicyEvaluator,
  type SignedSecuritySnapshotV1,
} from '../src/index.js';

const bytes = (length: number, fill = 7) => encodeB64Url(new Uint8Array(length).fill(fill));
const subject = {
  type: 'brc100-public-key',
  value: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
};
const wrongSubject = {
  type: 'brc100-public-key',
  value: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
};

function snapshot(epoch = '1', policyDigest = bytes(32, 2)): SignedSecuritySnapshotV1 {
  const body = {
    securityEpoch: epoch,
    policyId: 'https://policy.example/v1',
    policyDigest,
    providerArtifacts: [],
    trustMaterial: {},
    validFromMs: '0',
    validUntilMs: '9999999999999',
    signerKeyId: 'key-1',
  };
  return {
    body,
    trustDigest: encodeB64Url(sha256Bytes(jcsBytes(body))),
    algorithm: 'test',
    signature: bytes(64, 3),
  };
}

function setup(now = 1_000n) {
  let current = snapshot();
  let clock = now;
  let randomByte = 9;
  const registry = new VerifierRegistry().registerProvider({
    provider: 'portable-test',
    async verify(component, expectedBinding) {
      return {
        componentId: component.componentId,
        provider: component.provider,
        evidenceDigest: bytes(32),
        bindingDigest: encodeB64Url(expectedBinding),
        platform: {},
        measurements: {},
        tcb: {},
        advisories: [],
        validUntilMs: '9000',
      };
    },
  });
  const core = new AttestationCore(
    { current: () => current },
    registry,
    undefined,
    { nowMs: () => clock },
    (length) => new Uint8Array(length).fill(randomByte++),
  );
  const policy: PolicyEvaluator = {
    policyId: current.body.policyId,
    policyDigest: current.body.policyDigest,
    async evaluate() {
      return { subjectBinding: 'brc103', validUntilMs: '8000' };
    },
  };
  const issue = () =>
    core.issue({
      subject,
      audience: 'https://rp.example',
      context: 'urn:ceremony:1',
      contextDigest: bytes(32, 4),
      policyId: current.body.policyId,
      policyDigest: current.body.policyDigest,
      ttlMs: 100n,
    });
  const bundle = (
    challenge: AttestationChallengeV1,
    overrides: Partial<EvidenceComponentV1> = {},
  ) => ({
    protocolVersion: 1 as const,
    challengeId: challenge.challengeId,
    subject,
    components: [
      {
        componentId: 'cpu',
        provider: 'portable-test',
        mediaType: 'application/test',
        evidence: bytes(1),
        ...overrides,
      },
    ],
  });
  return {
    core,
    policy,
    issue,
    bundle,
    setClock: (value: bigint) => {
      clock = value;
    },
    setSnapshot: (value: SignedSecuritySnapshotV1) => {
      current = value;
    },
  };
}

describe('BCAP1 A0 strict validation', () => {
  it('consumes immutable transcript KATs byte-for-byte', () => {
    for (const vector of transcriptVectors.valid) {
      const challenge = validateChallenge(vector.input);
      expect(hex(bindingDigest(challenge))).toBe(vector.bindingDigestHex);
      expect(hex(challengePreimage(challenge))).toBe(vector.preimageHex);
    }
    for (const mutation of transcriptVectors.mutations) {
      const base = transcriptVectors.valid.find((vector) => vector.id === mutation.base);
      if (!base) throw new Error(`missing mutation base ${mutation.base}`);
      const input = structuredClone(base.input) as Record<string, unknown>;
      setPath(input, mutation.path, mutation.value);
      const challenge = validateChallenge(input);
      expect(hex(challengePreimage(challenge))).toBe(mutation.preimageHex);
      expect(hex(bindingDigest(challenge))).toBe(mutation.bindingDigestHex);
    }
  });

  it('consumes transcript rejection vectors fail-closed', () => {
    for (const rejection of transcriptVectors.rejections) {
      const fixture = rejection.id.includes('brc100') ? 'representative-brc100' : 'zero-minimum';
      const base = transcriptVectors.valid.find((vector) => vector.id === fixture);
      if (!base) throw new Error(`missing rejection base ${fixture}`);
      const input = structuredClone(base.input) as Record<string, unknown>;
      setPath(input, rejection.field, rejection.value);
      expect(() => validateChallenge(input), rejection.id).toThrow(Denial);
    }
  });

  it('consumes signed snapshot JCS vectors', () => {
    for (const vector of snapshotVectors.valid) {
      const verified = validateSecuritySnapshot(vector.signedSnapshot);
      expect(new TextDecoder().decode(jcsBytes(verified.body))).toBe(vector.bodyJcsUtf8);
      expect(hex(sha256Bytes(jcsBytes(verified.body)))).toBe(vector.trustDigestHex);
    }
  });
  it('rejects JSON numeric and noncanonical u64 fields without coercion', () => {
    const challenge = {
      protocolVersion: 1 as const,
      challengeId: bytes(16),
      nonce: bytes(32),
      subject,
      audience: 'a',
      context: 'c',
      contextDigest: bytes(32),
      policyId: 'p',
      policyDigest: bytes(32),
      securityEpoch: '1',
      trustDigest: bytes(32),
      issuedAtMs: '1',
      expiresAtMs: '2',
    };
    for (const value of [
      1,
      9_007_199_254_740_992,
      '01',
      '+1',
      '-0',
      '1e1',
      '18446744073709551616',
    ]) {
      expect(() => validateChallenge({ ...challenge, securityEpoch: value })).toThrow(Denial);
    }
  });

  it('rejects padding, NFC aliases, unknown fields, and invalid compressed BRC-100 keys', () => {
    const baseline = {
      protocolVersion: 1 as const,
      challengeId: bytes(16),
      nonce: bytes(32),
      subject,
      audience: 'a',
      context: 'c',
      contextDigest: bytes(32),
      policyId: 'p',
      policyDigest: bytes(32),
      securityEpoch: '1',
      trustDigest: bytes(32),
      issuedAtMs: '1',
      expiresAtMs: '2',
    };
    expect(() => validateChallenge({ ...baseline, nonce: `${baseline.nonce}=` })).toThrow(Denial);
    expect(() => validateChallenge({ ...baseline, audience: 'e\u0301' })).toThrow(Denial);
    expect(() => validateChallenge({ ...baseline, extra: true })).toThrow(Denial);
    expect(() =>
      validateChallenge({
        ...baseline,
        subject: { type: 'brc100-public-key', value: `02${'00'.repeat(32)}` },
      }),
    ).toThrow(Denial);
  });

  it('uses a fixed field-length transcript where each mutation changes the digest', () => {
    const { issue } = setup();
    const challenge = issue();
    const original = encodeB64Url(bindingDigest(challenge));
    expect(
      encodeB64Url(bindingDigest({ ...challenge, audience: 'https://other.example' })),
    ).not.toBe(original);
    expect(encodeB64Url(bindingDigest({ ...challenge, nonce: bytes(32, 8) }))).not.toBe(original);
  });
});

describe('BCAP1 A1 lifecycle and plugin boundary', () => {
  it('atomically allows one response and denies the raced replay', async () => {
    const { core, policy, issue, bundle } = setup();
    const challenge = issue();
    const input = { bundle: bundle(challenge), authenticatedSubject: subject, policy };
    const [first, second] = await Promise.all([core.verify(input), core.verify(input)]);
    expect([first, second].filter((result) => result.decision === 'allow')).toHaveLength(1);
    expect([first, second].find((result) => result.decision === 'deny')).toMatchObject({
      denial: 'challenge_used',
    });
  });

  it('returns challenge_used for any response after a claim, even when clock has passed expiry', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { core, policy, issue, bundle, setClock } = setup();
    const challenge = issue();
    const slowPolicy: PolicyEvaluator = {
      ...policy,
      async evaluate() {
        await gate;
        return { subjectBinding: 'brc103', validUntilMs: '8000' };
      },
    };
    const first = core.verify({
      bundle: bundle(challenge),
      authenticatedSubject: subject,
      policy: slowPolicy,
    });
    await Promise.resolve();
    setClock(1_100n);
    expect(
      await core.verify({ bundle: bundle(challenge), authenticatedSubject: subject, policy }),
    ).toMatchObject({ denial: 'challenge_used' });
    release();
    expect(await first).toMatchObject({ denial: 'challenge_expired' });
  });

  it('consumes as denial when verification crosses expiry or the epoch changes', async () => {
    const expiry = setup();
    const challenge = expiry.issue();
    expiry.setClock(1_100n);
    expect(
      await expiry.core.verify({
        bundle: expiry.bundle(challenge),
        authenticatedSubject: subject,
        policy: expiry.policy,
      }),
    ).toMatchObject({ decision: 'deny', denial: 'challenge_expired' });

    const race = setup();
    const current = race.issue();
    race.setSnapshot(snapshot('2', race.policy.policyDigest));
    expect(
      await race.core.verify({
        bundle: race.bundle(current),
        authenticatedSubject: subject,
        policy: race.policy,
      }),
    ).toMatchObject({ decision: 'deny', denial: 'security_epoch_changed' });
  });

  it('refuses a wrong authenticated peer and a missing provider without delegation', async () => {
    const { core, policy, issue, bundle } = setup();
    const challenge = issue();
    expect(
      await core.verify({ bundle: bundle(challenge), authenticatedSubject: wrongSubject, policy }),
    ).toMatchObject({ denial: 'subject_unauthenticated' });
    const second = issue();
    expect(
      await core.verify({
        bundle: bundle(second, { provider: 'not-installed' }),
        authenticatedSubject: subject,
        policy,
      }),
    ).toMatchObject({ denial: 'unsupported_provider' });
  });

  it('accepts indirect bindings only through a registered edge and refuses invalid graphs', async () => {
    const fixture = setup();
    fixture.core.registry
      .registerProvider({
        provider: 'indirect',
        async verify(component, expectedBinding) {
          return {
            componentId: component.componentId,
            provider: component.provider,
            evidenceDigest: bytes(32),
            bindingDigest:
              component.componentId === 'root' ? encodeB64Url(expectedBinding) : bytes(64, 0),
            platform: {},
            measurements: {},
            tcb: {},
            advisories: [],
            validUntilMs: '9000',
          };
        },
      })
      .registerRelation({ relation: 'test-edge', async verify() {} });
    const valid = fixture.issue();
    const base = {
      protocolVersion: 1 as const,
      challengeId: valid.challengeId,
      subject,
      components: [
        {
          componentId: 'root',
          provider: 'indirect',
          mediaType: 'application/test',
          evidence: bytes(1),
        },
        {
          componentId: 'child',
          provider: 'indirect',
          mediaType: 'application/test',
          evidence: bytes(1),
        },
      ],
    };
    expect(
      await fixture.core.verify({
        bundle: {
          ...base,
          bindingEdges: [
            { parentComponentId: 'root', childComponentId: 'child', relation: 'test-edge' },
          ],
        },
        authenticatedSubject: subject,
        policy: fixture.policy,
      }),
    ).toMatchObject({ decision: 'allow' });

    const unbound = fixture.issue();
    expect(
      await fixture.core.verify({
        bundle: { ...base, challengeId: unbound.challengeId },
        authenticatedSubject: subject,
        policy: fixture.policy,
      }),
    ).toMatchObject({ denial: 'component_unbound' });
    const dangling = fixture.issue();
    expect(
      await fixture.core.verify({
        bundle: {
          ...base,
          challengeId: dangling.challengeId,
          bindingEdges: [
            { parentComponentId: 'gone', childComponentId: 'child', relation: 'test-edge' },
          ],
        },
        authenticatedSubject: subject,
        policy: fixture.policy,
      }),
    ).toMatchObject({ denial: 'component_unbound' });
    const duplicate = fixture.issue();
    expect(
      await fixture.core.verify({
        bundle: {
          ...base,
          challengeId: duplicate.challengeId,
          components: [...base.components, { ...base.components[0]! }],
        },
        authenticatedSubject: subject,
        policy: fixture.policy,
      }),
    ).toMatchObject({ denial: 'malformed' });
    const duplicateEdge = fixture.issue();
    expect(
      await fixture.core.verify({
        bundle: {
          ...base,
          challengeId: duplicateEdge.challengeId,
          bindingEdges: [
            { parentComponentId: 'root', childComponentId: 'child', relation: 'test-edge' },
            { parentComponentId: 'root', childComponentId: 'child', relation: 'test-edge' },
          ],
        },
        authenticatedSubject: subject,
        policy: fixture.policy,
      }),
    ).toMatchObject({ denial: 'malformed' });
    const cyclic = fixture.issue();
    expect(
      await fixture.core.verify({
        bundle: {
          ...base,
          challengeId: cyclic.challengeId,
          components: [
            ...base.components,
            {
              componentId: 'second-child',
              provider: 'indirect',
              mediaType: 'application/test',
              evidence: bytes(1),
            },
          ],
          bindingEdges: [
            { parentComponentId: 'child', childComponentId: 'second-child', relation: 'test-edge' },
            { parentComponentId: 'second-child', childComponentId: 'child', relation: 'test-edge' },
          ],
        },
        authenticatedSubject: subject,
        policy: fixture.policy,
      }),
    ).toMatchObject({ denial: 'component_unbound' });
  });

  it('refuses a future-issued challenge terminally and releases outstanding slots after terminal or expiry', async () => {
    const store = new InMemoryChallengeStore({ maxOutstandingPerSubject: 1, maxOutstanding: 1 });
    const { issue } = setup();
    const first = issue();
    store.issue(first, 1_000n);
    expect(() => store.claim(first.challengeId, 999n)).toThrow(Denial);
    const expiring = { ...first, challengeId: bytes(16, 11), issuedAtMs: '1', expiresAtMs: '2' };
    store.issue(expiring, 1n);
    const next = { ...first, challengeId: bytes(16, 12) };
    expect(() => store.issue(next, 1n)).toThrow(Denial);
    store.issue(next, 2n); // expiry sweeps the outstanding entry
  });
});

describe('BCAP1 transport and browser boundary', () => {
  it('consumes transport JCS/digest vectors', () => {
    for (const vector of transportVectors.valid) {
      expect(new TextDecoder().decode(decodeB64Url(vector.message.payload, 'payload'))).toBe(
        vector.payloadJcsUtf8,
      );
      expect(hex(sha256Bytes(decodeB64Url(vector.message.payload, 'payload')))).toBe(
        vector.payloadDigestHex,
      );
      const output = validateTransportMessage({
        message: vector.message,
        authenticatedPeer: vector.authenticatedPeer,
        localSubject: vector.authenticatedLocalSubject,
        profile: 'brc103-websocket-v1',
        expectedType: vector.payloadType as 'challenge' | 'evidence',
        ...(vector.payloadType === 'evidence'
          ? { expectedEvidenceContextDigest: vector.message.contextDigest }
          : {}),
      });
      expect(output.messageId).toBe(vector.message.messageId);
    }
  });
  it('requires the authenticated peer, recipient, digest, and exact JCS payload', () => {
    const { issue } = setup();
    const challenge = issue();
    const payload = jcsBytes(challenge);
    const message = {
      protocolVersion: 1 as const,
      messageType: 'challenge' as const,
      messageId: bytes(16, 6),
      sender: wrongSubject,
      recipient: subject,
      contextDigest: challenge.contextDigest,
      payloadEncoding: 'rfc8785-jcs' as const,
      payload: encodeB64Url(payload),
      payloadDigest: encodeB64Url(sha256Bytes(payload)),
    };
    expect(
      validateTransportMessage({
        message,
        authenticatedPeer: wrongSubject,
        localSubject: subject,
        profile: 'brc103-websocket-v1',
        expectedType: 'challenge',
      }).payload,
    ).toEqual(challenge);
    expect(() =>
      validateTransportMessage({
        message: { ...message, payloadDigest: bytes(32, 8) },
        authenticatedPeer: wrongSubject,
        localSubject: subject,
        profile: 'brc103-websocket-v1',
        expectedType: 'challenge',
      }),
    ).toThrow(Denial);
    expect(() =>
      validateTransportMessage({
        message,
        authenticatedPeer: subject,
        localSubject: subject,
        profile: 'brc103-websocket-v1',
        expectedType: 'challenge',
      }),
    ).toThrow(Denial);
  });

  it('requires the stored challenge context for evidence envelopes', () => {
    const { issue, bundle } = setup();
    const challenge = issue();
    const evidence = bundle(challenge);
    const payload = jcsBytes(evidence);
    const message = {
      protocolVersion: 1 as const,
      messageType: 'evidence' as const,
      messageId: bytes(16, 6),
      sender: subject,
      recipient: wrongSubject,
      contextDigest: challenge.contextDigest,
      payloadEncoding: 'rfc8785-jcs' as const,
      payload: encodeB64Url(payload),
      payloadDigest: encodeB64Url(sha256Bytes(payload)),
    };
    expect(() =>
      validateTransportMessage({
        message,
        authenticatedPeer: subject,
        localSubject: wrongSubject,
        profile: 'brc103-websocket-v1',
        expectedType: 'evidence',
      }),
    ).toThrow(Denial);
    expect(() =>
      validateTransportMessage({
        message: { ...message, contextDigest: bytes(32, 99) },
        authenticatedPeer: subject,
        localSubject: wrongSubject,
        profile: 'brc103-websocket-v1',
        expectedType: 'evidence',
        expectedEvidenceContextDigest: challenge.contextDigest,
      }),
    ).toThrow(Denial);
  });

  it('keeps native, network, Atlas, MPC, sealing, and release dependencies out of source', () => {
    const source = readFileSync(resolve(import.meta.dirname, '../src/index.ts'), 'utf8');
    expect(source).not.toMatch(/node:|atlas|dstack|dcap|nvat|mpc|seal|broker|fetch\(/iu);
  });
});

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function setPath(target: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split('.');
  let current: Record<string, unknown> = target;
  for (const part of parts.slice(0, -1)) {
    const next = current[part];
    if (typeof next !== 'object' || next === null || Array.isArray(next))
      throw new Error(`bad vector path ${path}`);
    current = next as Record<string, unknown>;
  }
  current[parts.at(-1)!] = value;
}
