import { sha256Bytes } from './crypto.js';
import { bindingDigest } from './transcript.js';
import {
  decodeB64Url,
  encodeB64Url,
  equalBytes,
  hasOnly,
  hasOnlyOptional,
  isRecord,
  MAX_BUNDLE_BYTES,
  MAX_EVIDENCE_BYTES,
  MAX_METADATA_ENTRIES,
  parseU64,
  requireString,
  validateString,
  validateSubject,
  utf8,
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
  const edgesRaw = value.bindingEdges;
  if (edgesRaw !== undefined && !Array.isArray(edgesRaw))
    throw new Denial('malformed', 'bindingEdges must be an array');
  if (edgesRaw !== undefined && edgesRaw.length > 64)
    throw new Denial('resource_limit', 'too many binding edges');
  let encodedBundleUpperBound = 0;
  for (const component of componentsRaw) {
    if (!isRecord(component)) continue;
    if (typeof component.evidence === 'string')
      encodedBundleUpperBound += Math.floor((component.evidence.length * 3) / 4);
    if (typeof component.endorsements === 'string')
      encodedBundleUpperBound += Math.floor((component.endorsements.length * 3) / 4);
    encodedBundleUpperBound += rawMetadataJsonBytes(component.untrustedMetadata);
  }
  for (const edge of edgesRaw ?? []) {
    if (isRecord(edge) && typeof edge.evidence === 'string')
      encodedBundleUpperBound += Math.floor((edge.evidence.length * 3) / 4);
  }
  if (encodedBundleUpperBound > MAX_BUNDLE_BYTES)
    throw new Denial('resource_limit', 'bundle too large');
  const components = componentsRaw.map(validateComponent);
  const componentIds = new Set<string>();
  for (const component of components) {
    if (componentIds.has(component.componentId))
      throw new Denial('malformed', 'duplicate component ID');
    componentIds.add(component.componentId);
  }
  const bindingEdges = edgesRaw?.map(validateEdge);
  const edgeEndpoints = new Set<string>();
  for (const edge of bindingEdges ?? []) {
    if (!componentIds.has(edge.parentComponentId) || !componentIds.has(edge.childComponentId)) {
      throw new Denial('malformed', 'binding edge references an unknown component');
    }
    const endpoints = `${edge.parentComponentId}\0${edge.childComponentId}`;
    if (edgeEndpoints.has(endpoints))
      throw new Denial('malformed', 'duplicate binding edge endpoints');
    edgeEndpoints.add(endpoints);
  }
  const bundle: EvidenceBundleV1 = {
    protocolVersion: 1,
    challengeId: requireString(value.challengeId, 'challengeId'),
    subject: validateSubject(value.subject),
    components,
    ...(bindingEdges === undefined ? {} : { bindingEdges }),
  };
  decodeB64Url(bundle.challengeId, 'challengeId', 16);
  validateBundleBytes(bundle);
  return bundle;
}

function rawMetadataJsonBytes(value: unknown): number {
  if (value === undefined || !isRecord(value)) return 0;
  let bytes = 2;
  let entries = 0;
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    entries += 1;
    if (entries > MAX_METADATA_ENTRIES)
      throw new Denial('resource_limit', 'untrusted metadata has too many entries');
    const item = value[key];
    if (typeof item !== 'string') continue;
    if (entries > 1) bytes += 1;
    bytes += utf8(JSON.stringify(key)).byteLength + 1 + utf8(JSON.stringify(item)).byteLength;
    if (bytes > MAX_BUNDLE_BYTES) return bytes;
  }
  return bytes;
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
  decodeB64Url(component.evidence, 'evidence', undefined, MAX_EVIDENCE_BYTES);
  if (component.endorsements !== undefined)
    decodeB64Url(component.endorsements, 'endorsements', undefined, 4 * 1024 * 1024);
  return component;
}

function validateMetadata(value: unknown): Record<string, string> {
  if (!isRecord(value)) throw new Denial('malformed', 'untrusted metadata must be a record');
  const metadata: Record<string, string> = {};
  let entries = 0;
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    entries += 1;
    if (entries > MAX_METADATA_ENTRIES)
      throw new Denial('resource_limit', 'untrusted metadata has too many entries');
    metadata[validateString(key, 'metadata key')] = validateString(value[key], 'metadata value');
  }
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
  if (edge.evidence !== undefined)
    decodeB64Url(edge.evidence, 'edge evidence', undefined, MAX_EVIDENCE_BYTES);
  return edge;
}

function validateBundleBytes(bundle: EvidenceBundleV1): void {
  let bytes = 0;
  for (const component of bundle.components) {
    bytes += decodeB64Url(component.evidence, 'evidence').byteLength;
    if (component.endorsements)
      bytes += decodeB64Url(component.endorsements, 'endorsements').byteLength;
    if (component.untrustedMetadata) bytes += metadataJsonBytes(component.untrustedMetadata);
    if (bytes > MAX_BUNDLE_BYTES) throw new Denial('resource_limit', 'bundle too large');
  }
  for (const edge of bundle.bindingEdges ?? []) {
    if (edge.evidence) bytes += decodeB64Url(edge.evidence, 'edge evidence').byteLength;
    if (bytes > MAX_BUNDLE_BYTES) throw new Denial('resource_limit', 'bundle too large');
  }
}

function metadataJsonBytes(metadata: Record<string, string>): number {
  let bytes = 2; // opening and closing braces
  let first = true;
  for (const [key, value] of Object.entries(metadata)) {
    if (!first) bytes += 1; // comma
    first = false;
    bytes += utf8(JSON.stringify(key)).byteLength;
    bytes += 1; // colon
    bytes += utf8(JSON.stringify(value)).byteLength;
  }
  return bytes;
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
  const { challenge, registry, snapshot, nowMs } = input;
  // This helper is public and can be reached without AttestationCore. Validate
  // the complete bundle before any provider plugin receives attacker input.
  const bundle = validateEvidenceBundle(input.bundle);
  const expected = bindingDigest(challenge);
  const verified: VerifiedComponentV1[] = [];
  for (const component of bundle.components) {
    const verifier = registry.provider(component.provider);
    if (verifier === undefined)
      throw new Denial('unsupported_provider', `no local verifier for ${component.provider}`);
    const output = validateVerifiedComponent(
      await verifier.verify(component, expected, nowMs, snapshot),
      component,
      nowMs,
    );
    verified.push(output);
  }
  await verifyBindingGraph(bundle, verified, registry, expected, snapshot);
  return verified;
}

function validateVerifiedComponent(
  output: unknown,
  source: EvidenceComponentV1,
  nowMs: bigint,
): VerifiedComponentV1 {
  const keys = [
    'componentId',
    'provider',
    'evidenceDigest',
    'bindingDigest',
    'platform',
    'measurements',
    'tcb',
    'advisories',
    'validUntilMs',
  ];
  if (!isRecord(output) || !hasOnly(output, keys))
    throw new Denial('malformed', 'invalid verified component');
  const component: VerifiedComponentV1 = {
    componentId: validateString(output.componentId, 'verified componentId'),
    provider: validateString(output.provider, 'verified provider'),
    evidenceDigest: requireString(output.evidenceDigest, 'evidenceDigest'),
    bindingDigest: requireString(output.bindingDigest, 'bindingDigest'),
    platform: validateClaimMap(output.platform, 'platform'),
    measurements: validateMeasurements(output.measurements),
    tcb: validateClaimMap(output.tcb, 'tcb'),
    advisories: validateAdvisories(output.advisories),
    validUntilMs: requireString(output.validUntilMs, 'validUntilMs'),
  };
  if (component.componentId !== source.componentId || component.provider !== source.provider)
    throw new Denial('malformed', 'verifier output does not match component');
  const sourceEvidence = decodeB64Url(source.evidence, 'evidence', undefined, MAX_EVIDENCE_BYTES);
  const reportedEvidenceDigest = decodeB64Url(component.evidenceDigest, 'evidenceDigest', 32);
  if (!equalBytes(reportedEvidenceDigest, sha256Bytes(sourceEvidence)))
    throw new Denial('binding_mismatch', 'verifier evidence digest mismatch');
  decodeB64Url(component.bindingDigest, 'component bindingDigest', 64);
  if (parseU64(component.validUntilMs, 'component validUntilMs') <= nowMs)
    throw new Denial('endorsements_stale', 'component is already expired');
  return component;
}

function validateClaimMap(value: unknown, name: string): Record<string, string | number | boolean> {
  if (!isRecord(value)) throw new Denial('malformed', `${name} must be a claim map`);
  const entries = Object.entries(value);
  if (entries.length > 256) throw new Denial('resource_limit', `${name} has too many claims`);
  const result: Record<string, string | number | boolean> = {};
  for (const [key, claim] of entries) {
    const validatedKey = validateString(key, `${name} key`);
    if (typeof claim === 'string') result[validatedKey] = validateString(claim, `${name} value`);
    else if (typeof claim === 'boolean') result[validatedKey] = claim;
    else if (typeof claim === 'number' && Number.isFinite(claim)) result[validatedKey] = claim;
    else throw new Denial('malformed', `${name} has invalid claim value`);
  }
  return result;
}

function validateMeasurements(value: unknown): Record<string, string> {
  const claims = validateClaimMap(value, 'measurements');
  const result: Record<string, string> = {};
  for (const [key, claim] of Object.entries(claims)) {
    if (typeof claim !== 'string') throw new Denial('malformed', 'measurements must be strings');
    result[key] = claim;
  }
  return result;
}

function validateAdvisories(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 256)
    throw new Denial('resource_limit', 'invalid advisories');
  return value.map((advisory) => validateString(advisory, 'advisory'));
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
  return encodeB64Url(
    sha256Bytes(decodeB64Url(component.evidence, 'evidence', undefined, MAX_EVIDENCE_BYTES)),
  );
}
