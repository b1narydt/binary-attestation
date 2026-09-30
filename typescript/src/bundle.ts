import { sha256Bytes } from './crypto.js';
import { bindingDigest } from './transcript.js';
import {
  decodeB64Url,
  encodeB64Url,
  equalBytes,
  hasOnly,
  hasOnlyOptional,
  isRecord,
  parseU64,
  requireString,
  validateString,
  validateSubject,
} from './validation.js';
import {
  Denial,
  type AttestationChallengeV1,
  type BindingRelationVerifier,
  type EvidenceBindingEdgeV1,
  type EvidenceBundleV1,
  type EvidenceComponentV1,
  type EvidenceVerifier,
  type SignedSecuritySnapshotV1,
  type VerifiedComponentV1,
} from './types.js';

export function validateEvidenceBundle(value: unknown): EvidenceBundleV1 {
  const required = ['protocolVersion', 'challengeId', 'subject', 'components'];
  if (!isRecord(value) || !hasOnlyOptional(value, required, ['bindingEdges']))
    throw new Denial('malformed', 'invalid evidence bundle shape');
  if (value.protocolVersion !== 1) throw new Denial('unsupported_version');
  const componentsRaw = value.components;
  if (!Array.isArray(componentsRaw) || componentsRaw.length === 0)
    throw new Denial('malformed', 'components must be a non-empty array');
  if (componentsRaw.length > 32) throw new Denial('resource_limit', 'too many components');
  let encodedBundleUpperBound = 0;
  for (const component of componentsRaw) {
    if (!isRecord(component)) continue;
    if (typeof component.evidence === 'string')
      encodedBundleUpperBound += Math.floor((component.evidence.length * 3) / 4);
    if (typeof component.endorsements === 'string')
      encodedBundleUpperBound += Math.floor((component.endorsements.length * 3) / 4);
  }
  if (encodedBundleUpperBound > 16 * 1024 * 1024)
    throw new Denial('resource_limit', 'bundle too large');
  const components = componentsRaw.map(validateComponent);
  const edgesRaw = value.bindingEdges;
  if (edgesRaw !== undefined && !Array.isArray(edgesRaw))
    throw new Denial('malformed', 'bindingEdges must be an array');
  if (edgesRaw !== undefined && edgesRaw.length > 64)
    throw new Denial('resource_limit', 'too many binding edges');
  const bundle: EvidenceBundleV1 = {
    protocolVersion: 1,
    challengeId: requireString(value.challengeId, 'challengeId'),
    subject: validateSubject(value.subject),
    components,
    ...(edgesRaw === undefined ? {} : { bindingEdges: edgesRaw.map(validateEdge) }),
  };
  decodeB64Url(bundle.challengeId, 'challengeId', 16);
  validateBundleBytes(bundle);
  return bundle;
}

function validateComponent(value: unknown): EvidenceComponentV1 {
  const required = ['componentId', 'provider', 'mediaType', 'evidence'];
  if (!isRecord(value) || !hasOnlyOptional(value, required, ['endorsements', 'untrustedMetadata']))
    throw new Denial('malformed', 'invalid evidence component');
  const component: EvidenceComponentV1 = {
    componentId: validateString(value.componentId, 'componentId'),
    provider: validateString(value.provider, 'provider'),
    mediaType: validateString(value.mediaType, 'mediaType'),
    evidence: requireString(value.evidence, 'evidence'),
    ...(value.endorsements === undefined
      ? {}
      : { endorsements: requireString(value.endorsements, 'endorsements') }),
    ...(value.untrustedMetadata === undefined
      ? {}
      : { untrustedMetadata: validateMetadata(value.untrustedMetadata) }),
  };
  decodeB64Url(component.evidence, 'evidence', undefined, 2 * 1024 * 1024);
  if (component.endorsements !== undefined)
    decodeB64Url(component.endorsements, 'endorsements', undefined, 4 * 1024 * 1024);
  return component;
}

function validateMetadata(value: unknown): Record<string, string> {
  if (!isRecord(value)) throw new Denial('malformed', 'untrusted metadata must be a record');
  const metadata: Record<string, string> = {};
  for (const [key, item] of Object.entries(value))
    metadata[validateString(key, 'metadata key')] = validateString(item, 'metadata value');
  return metadata;
}

function validateEdge(value: unknown): EvidenceBindingEdgeV1 {
  const required = ['parentComponentId', 'childComponentId', 'relation'];
  if (!isRecord(value) || !hasOnlyOptional(value, required, ['evidence']))
    throw new Denial('malformed', 'invalid binding edge');
  const edge: EvidenceBindingEdgeV1 = {
    parentComponentId: validateString(value.parentComponentId, 'parentComponentId'),
    childComponentId: validateString(value.childComponentId, 'childComponentId'),
    relation: validateString(value.relation, 'relation'),
    ...(value.evidence === undefined
      ? {}
      : { evidence: requireString(value.evidence, 'edge evidence') }),
  };
  if (edge.evidence !== undefined) decodeB64Url(edge.evidence, 'edge evidence');
  return edge;
}

function validateBundleBytes(bundle: EvidenceBundleV1): void {
  let bytes = 0;
  for (const component of bundle.components) {
    bytes += decodeB64Url(component.evidence, 'evidence').byteLength;
    if (component.endorsements)
      bytes += decodeB64Url(component.endorsements, 'endorsements').byteLength;
  }
  if (bytes > 16 * 1024 * 1024) throw new Denial('resource_limit', 'bundle too large');
}

export class VerifierRegistry {
  readonly #providers = new Map<string, EvidenceVerifier>();
  readonly #relations = new Map<string, BindingRelationVerifier>();

  registerProvider(verifier: EvidenceVerifier): this {
    if (this.#providers.has(verifier.provider))
      throw new Denial('malformed', 'duplicate provider verifier');
    this.#providers.set(verifier.provider, verifier);
    return this;
  }

  registerRelation(verifier: BindingRelationVerifier): this {
    if (this.#relations.has(verifier.relation))
      throw new Denial('malformed', 'duplicate relation verifier');
    this.#relations.set(verifier.relation, verifier);
    return this;
  }

  provider(name: string): EvidenceVerifier | undefined {
    return this.#providers.get(name);
  }

  relation(name: string): BindingRelationVerifier | undefined {
    return this.#relations.get(name);
  }
}

/** Verifies component plugins and that every component has a direct or registered-edge path to the BCAP1 digest. */
export async function verifyBundleComponents(input: {
  challenge: AttestationChallengeV1;
  bundle: EvidenceBundleV1;
  registry: VerifierRegistry;
  snapshot: SignedSecuritySnapshotV1;
  nowMs: bigint;
}): Promise<VerifiedComponentV1[]> {
  const { challenge, bundle, registry, snapshot, nowMs } = input;
  const ids = new Set<string>();
  for (const component of bundle.components) {
    if (ids.has(component.componentId)) throw new Denial('malformed', 'duplicate component ID');
    ids.add(component.componentId);
  }
  const expected = bindingDigest(challenge);
  const verified: VerifiedComponentV1[] = [];
  for (const component of bundle.components) {
    const verifier = registry.provider(component.provider);
    if (verifier === undefined)
      throw new Denial('unsupported_provider', `no local verifier for ${component.provider}`);
    const output = await verifier.verify(component, expected, nowMs, snapshot);
    if (output.componentId !== component.componentId || output.provider !== component.provider)
      throw new Denial('malformed', 'verifier output does not match component');
    // A component may bind through a registered, verified composition edge.
    // The graph below decides whether this value reaches a direct binding root.
    decodeB64Url(output.bindingDigest, 'component bindingDigest', 64);
    parseU64(output.validUntilMs, 'component validUntilMs');
    verified.push(output);
  }
  await verifyBindingGraph(bundle, verified, registry, expected, snapshot);
  return verified;
}

async function verifyBindingGraph(
  bundle: EvidenceBundleV1,
  verified: readonly VerifiedComponentV1[],
  registry: VerifierRegistry,
  expected: Uint8Array,
  snapshot: SignedSecuritySnapshotV1,
): Promise<void> {
  const components = new Map(verified.map((component) => [component.componentId, component]));
  const parentOf = new Map<string, string[]>();
  const edgeKeys = new Set<string>();
  for (const edge of bundle.bindingEdges ?? []) {
    const parent = components.get(edge.parentComponentId);
    const child = components.get(edge.childComponentId);
    if (!parent || !child || parent === child)
      throw new Denial('component_unbound', 'dangling or self binding edge');
    const edgeKey = `${edge.parentComponentId}\0${edge.childComponentId}\0${edge.relation}`;
    if (edgeKeys.has(edgeKey)) throw new Denial('malformed', 'duplicate binding edge');
    edgeKeys.add(edgeKey);
    const verifier = registry.relation(edge.relation);
    if (!verifier)
      throw new Denial('unsupported_provider', `no relation verifier for ${edge.relation}`);
    await verifier.verify(parent, child, edge, expected, snapshot);
    parentOf.set(child.componentId, [
      ...(parentOf.get(child.componentId) ?? []),
      parent.componentId,
    ]);
  }
  const direct = new Set(
    verified
      .filter((component) =>
        equalBytes(decodeB64Url(component.bindingDigest, 'component bindingDigest', 64), expected),
      )
      .map((component) => component.componentId),
  );
  const visiting = new Set<string>();
  const memo = new Map<string, boolean>();
  const reachesDirect = (id: string): boolean => {
    const prior = memo.get(id);
    if (prior !== undefined) return prior;
    if (visiting.has(id)) throw new Denial('component_unbound', 'cyclic binding graph');
    visiting.add(id);
    const result = direct.has(id) || (parentOf.get(id) ?? []).some(reachesDirect);
    visiting.delete(id);
    memo.set(id, result);
    return result;
  };
  for (const component of verified)
    if (!reachesDirect(component.componentId)) throw new Denial('component_unbound');
}

export function evidenceDigest(component: EvidenceComponentV1): string {
  return encodeB64Url(sha256Bytes(decodeB64Url(component.evidence, 'evidence')));
}
