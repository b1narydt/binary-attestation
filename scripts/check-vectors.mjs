#!/usr/bin/env node
/**
 * Verifies checked-in BCAP1 A0 vectors. This checker is deliberately
 * read-only: vector changes must be reviewed as protocol changes, never
 * regenerated in CI.
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
const vectorsDir = resolve(root, 'vectors');
const specDir = resolve(root, 'spec');
const U64_MAX = 18_446_744_073_709_551_615n;
const B64URL = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3})?$/;

function fail(message) {
  throw new Error(message);
}

function equal(actual, expected, label) {
  if (actual !== expected) fail(`${label} differs from its checked-in value`);
}

async function readJson(directory, name) {
  const bytes = await readFile(resolve(directory, name));
  try {
    return JSON.parse(bytes);
  } catch (error) {
    fail(`${name} is not valid JSON: ${error.message}`);
  }
}

async function verifyDstackCollateralEvidenceVector() {
  const vector = await readJson(vectorsDir, 'bcap1-dstack-collateral-evidence.json');
  equal(vector.format, 'bcap1-dstack-collateral-evidence-v1', 'collateral vector format');
  equal(vector.evidenceComponent.provider, 'dstack-attest-v0', 'collateral provider');
  equal(
    vector.evidenceComponent.mediaType,
    'application/vnd.dstack.attestation.scale-v0',
    'collateral media type',
  );
  equal(vector.evidenceComponent.collateralField, 'endorsements', 'collateral wire field');
  if (Object.hasOwn(vector.policyArtifact, 'collateralJson')) {
    fail('collateralJson must not appear in the dstack policy artifact');
  }
  const floor = u64(vector.policyArtifact.minCollateralIssuedMs, 'minCollateralIssuedMs');
  const collateralBytes = await readFile(resolve(root, vector.collateralFixture));
  equal(hash('sha256', collateralBytes).toString('hex'), vector.collateralSha256, 'collateral SHA-256');
  const collateral = JSON.parse(collateralBytes);
  const tcbInfo = JSON.parse(collateral.tcb_info);
  equal(tcbInfo.fmspc, vector.expected.fmspc, 'collateral FMSPC');
  const issuedMs = BigInt(Date.parse(tcbInfo.issueDate));
  const nextUpdateMs = BigInt(Date.parse(tcbInfo.nextUpdate));
  equal(issuedMs.toString(), vector.expected.tcbInfoIssuedMs, 'TCB-info issue time');
  equal(nextUpdateMs.toString(), vector.expected.tcbInfoNextUpdateMs, 'TCB-info next update');
  if (issuedMs < floor) fail('collateral fixture is older than its policy floor');
  if (!Array.isArray(vector.rejections) || vector.rejections.length !== 5) {
    fail('collateral rejection contract differs from its checked-in value');
  }
}

function hash(algorithm, bytes) {
  return createHash(algorithm).update(bytes).digest();
}

function base64Url(value, label) {
  if (typeof value !== 'string' || !B64URL.test(value)) fail(`${label} is not unpadded base64url`);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) fail(`${label} is not canonical base64url`);
  return bytes;
}

function bytes(value, length, label) {
  const decoded = base64Url(value, label);
  if (decoded.length !== length) fail(`${label} must decode to ${length} bytes`);
  return decoded;
}

function u64(value, label) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/.test(value)) {
    fail(`${label} is not canonical unsigned-u64 decimal`);
  }
  const parsed = BigInt(value);
  if (parsed > U64_MAX) fail(`${label} exceeds unsigned-u64`);
  return parsed;
}

function string(value, label) {
  if (typeof value !== 'string' || value.includes('\0') || value.normalize('NFC') !== value) {
    fail(`${label} is not an NFC non-NUL string`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff)
        fail(`${label} contains an unpaired surrogate`);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail(`${label} contains an unpaired surrogate`);
    }
  }
  if (Buffer.byteLength(value, 'utf8') > 1024) fail(`${label} exceeds 1,024 UTF-8 bytes`);
  return Buffer.from(value, 'utf8');
}

function field(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

function transcriptPreimage(input) {
  const parts = [Buffer.from('BINARY-BCAP1-CHALLENGE\0', 'ascii')];
  const pushField = (value) => parts.push(field(value));
  pushField(bytes(input.challengeId, 16, 'challengeId'));
  pushField(bytes(input.nonce, 32, 'nonce'));
  pushField(string(input.subject.type, 'subject.type'));
  pushField(string(input.subject.value, 'subject.value'));
  pushField(string(input.audience, 'audience'));
  pushField(string(input.context, 'context'));
  pushField(bytes(input.contextDigest, 32, 'contextDigest'));
  pushField(string(input.policyId, 'policyId'));
  pushField(bytes(input.policyDigest, 32, 'policyDigest'));
  for (const [value, label] of [
    [input.securityEpoch, 'securityEpoch'],
    [input.issuedAtMs, 'issuedAtMs'],
    [input.expiresAtMs, 'expiresAtMs'],
  ]) {
    if (label === 'issuedAtMs') pushField(bytes(input.trustDigest, 32, 'trustDigest'));
    const encoded = Buffer.alloc(8);
    encoded.writeBigUInt64BE(u64(value, label));
    parts.push(encoded);
  }
  if (u64(input.issuedAtMs, 'issuedAtMs') >= u64(input.expiresAtMs, 'expiresAtMs')) {
    fail('issuedAtMs must be before expiresAtMs');
  }
  return Buffer.concat(parts);
}

function clone(value) {
  return structuredClone(value);
}

function setPath(object, path, value) {
  const keys = path.split('.');
  let parent = object;
  for (const key of keys.slice(0, -1)) parent = parent[key];
  parent[keys.at(-1)] = value;
}

function rawTranscriptField(input, path) {
  const value = path.split('.').reduce((current, key) => current[key], input);
  if (['challengeId', 'nonce', 'contextDigest', 'policyDigest', 'trustDigest'].includes(path))
    return base64Url(value, path);
  if (['securityEpoch', 'issuedAtMs', 'expiresAtMs'].includes(path)) {
    const result = Buffer.alloc(8);
    result.writeBigUInt64BE(u64(value, path));
    return result;
  }
  return Buffer.from(value, 'utf8');
}

function hammingDistance(left, right) {
  if (left.length !== right.length) return Infinity;
  let distance = 0;
  for (let index = 0; index < left.length; index += 1) {
    let bits = left[index] ^ right[index];
    while (bits !== 0) {
      distance += bits & 1;
      bits >>>= 1;
    }
  }
  return distance;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function sameSubject(left, right) {
  return left.type === right.type && left.value === right.value;
}

function isDstackGpuEventOrder(events) {
  let index = 0;
  if (events[index++] !== 'compose-hash') return false;
  while (events[index] === 'init-script-hash') index += 1;
  for (const name of ['gpu-policy-hash', 'instance-id', 'boot-mr-done']) {
    if (events[index++] !== name) return false;
  }
  if (events[index] === 'os-image-hash') index += 1;
  return (
    events[index++] === 'gpu-attestation' &&
    events[index++] === 'key-provider' &&
    index === events.length
  );
}

function modularPower(base, exponent, modulus) {
  let result = 1n;
  let factor = base % modulus;
  let remaining = exponent;
  while (remaining > 0n) {
    if (remaining & 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    remaining >>= 1n;
  }
  return result;
}

function validBrc100PublicKey(value) {
  if (!/^(?:02|03)[0-9a-f]{64}$/.test(value)) return false;
  const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const x = BigInt(`0x${value.slice(2)}`);
  if (x >= p) return false;
  const ySquared = (x * x * x + 7n) % p;
  return modularPower(ySquared, (p - 1n) / 2n, p) === 1n;
}

function verifyTranscript(vector) {
  equal(vector.format, 'bcap1-transcript-v1', 'transcript vector format');
  const cases = new Map();
  for (const testCase of vector.valid) {
    const preimage = transcriptPreimage(testCase.input);
    equal(preimage.toString('hex'), testCase.preimageHex, `${testCase.id} preimage`);
    equal(
      hash('sha512', preimage).toString('hex'),
      testCase.bindingDigestHex,
      `${testCase.id} binding digest`,
    );
    cases.set(testCase.id, testCase);
  }
  for (const mutation of vector.mutations) {
    const base = cases.get(mutation.base);
    if (!base) fail(`${mutation.id} references an unknown base case`);
    const input = clone(base.input);
    setPath(input, mutation.path, mutation.value);
    const preimage = transcriptPreimage(input);
    equal(preimage.toString('hex'), mutation.preimageHex, `${mutation.id} preimage`);
    equal(
      hash('sha512', preimage).toString('hex'),
      mutation.bindingDigestHex,
      `${mutation.id} binding digest`,
    );
    if (mutation.bindingDigestHex === base.bindingDigestHex)
      fail(`${mutation.id} did not change the digest`);
    if (
      hammingDistance(
        rawTranscriptField(base.input, mutation.path),
        rawTranscriptField(input, mutation.path),
      ) !== 1
    ) {
      fail(`${mutation.id} is not a one-bit field mutation`);
    }
  }
  for (const rejection of vector.rejections) {
    if (!rejection.id || !rejection.reason) fail('transcript rejection lacks an id or reason');
    if (
      rejection.id.startsWith('u64-') &&
      (() => {
        try {
          u64(rejection.value, rejection.id);
          return true;
        } catch {
          return false;
        }
      })()
    ) {
      fail(`${rejection.id} was accepted as u64`);
    }
    if (rejection.id === 'base64-padding' || rejection.id === 'base64-alternate-alphabet') {
      if (B64URL.test(rejection.value)) fail(`${rejection.id} was accepted as base64url`);
    }
    if (
      rejection.id === 'nfc-decomposed-alias' &&
      rejection.value.normalize('NFC') === rejection.value
    ) {
      fail('decomposed NFC alias was accepted');
    }
    if (rejection.id === 'brc100-invalid-compressed-key' && validBrc100PublicKey(rejection.value)) {
      fail('invalid BRC-100 key vector is a valid point');
    }
  }
}

function verifyTransport(vector) {
  equal(vector.format, 'bcap1-transport-v1', 'transport vector format');
  for (const testCase of vector.valid) {
    const message = testCase.message;
    const payload = Buffer.from(testCase.payloadJcsUtf8, 'utf8');
    equal(
      hash('sha256', payload).toString('hex'),
      testCase.payloadDigestHex,
      `${testCase.id} payload digest`,
    );
    equal(
      base64Url(message.payload, `${testCase.id} payload`).toString('utf8'),
      testCase.payloadJcsUtf8,
      `${testCase.id} payload bytes`,
    );
    equal(
      bytes(message.payloadDigest, 32, `${testCase.id} payloadDigest`).toString('hex'),
      testCase.payloadDigestHex,
      `${testCase.id} payloadDigest encoding`,
    );
    equal(
      canonicalJson(JSON.parse(testCase.payloadJcsUtf8)),
      testCase.payloadJcsUtf8,
      `${testCase.id} payload JCS`,
    );
    if (
      !sameSubject(message.sender, testCase.authenticatedPeer) ||
      !sameSubject(message.recipient, testCase.authenticatedLocalSubject)
    ) {
      fail(`${testCase.id} transport direction does not match authenticated provenance`);
    }
    const body = JSON.parse(testCase.payloadJcsUtf8);
    if (testCase.payloadType === 'challenge') {
      if (
        !sameSubject(message.recipient, body.subject) ||
        message.contextDigest !== body.contextDigest
      ) {
        fail('challenge envelope does not target the challenged subject/context');
      }
    } else if (testCase.payloadType === 'evidence' && !sameSubject(message.sender, body.subject)) {
      fail('evidence envelope sender does not match asserted bundle subject');
    }
  }
  for (const rejection of vector.rejections) {
    if (!rejection.id || !rejection.base || !rejection.path || !rejection.reason)
      fail('transport rejection is incomplete');
  }
}

function verifySnapshot(vector) {
  equal(vector.format, 'bcap1-security-snapshot-jcs-v1', 'snapshot vector format');
  for (const testCase of vector.valid) {
    equal(canonicalJson(testCase.body), testCase.bodyJcsUtf8, `${testCase.id} body JCS`);
    const digest = hash('sha256', Buffer.from(testCase.bodyJcsUtf8));
    equal(digest.toString('hex'), testCase.trustDigestHex, `${testCase.id} trust digest`);
    equal(
      bytes(testCase.signedSnapshot.trustDigest, 32, `${testCase.id} trustDigest`).toString('hex'),
      testCase.trustDigestHex,
      `${testCase.id} trustDigest encoding`,
    );
    for (const artifact of testCase.body.providerArtifacts) {
      equal(
        hash('sha256', base64Url(artifact.content, `${testCase.id} artifact content`)).toString(
          'hex',
        ),
        bytes(artifact.digest, 32, `${testCase.id} artifact digest`).toString('hex'),
        `${testCase.id} artifact digest`,
      );
    }
  }
}

function verifyGpuPolicy(vector) {
  equal(vector.format, 'bcap1-dstack-gpu-policy-jcs-v1', 'GPU policy vector format');
  for (const policy of vector.policies) {
    equal(canonicalJson(policy.source), policy.canonicalJcsUtf8, `${policy.id} JCS`);
    const source = Buffer.from(policy.canonicalJcsUtf8);
    equal(hash('sha256', source).toString('hex'), policy.digestHex, `${policy.id} digest`);
    equal(
      base64Url(policy.contentBase64Url, `${policy.id} content`).toString('utf8'),
      policy.canonicalJcsUtf8,
      `${policy.id} content encoding`,
    );
  }
  for (const valid of vector.eventOrder.valid) {
    if (!isDstackGpuEventOrder(valid.events))
      fail(`${valid.id} is not a valid dstack GPU event order`);
  }
  for (const rejected of vector.eventOrder.rejected) {
    if (isDstackGpuEventOrder(rejected.events))
      fail(`${rejected.id} unexpectedly has a valid dstack GPU event order`);
  }
}

function verifyCoreRejections(vector) {
  equal(vector.format, 'bcap1-core-rejections-v1', 'core-rejection vector format');
  for (const testCase of vector.unicode) {
    if (!testCase.id || !testCase.field || !testCase.reason)
      fail('Unicode rejection is incomplete');
    const value = JSON.parse(testCase.valueJson);
    let accepted = true;
    try {
      string(value, testCase.id);
    } catch {
      accepted = false;
    }
    if (accepted) fail(`${testCase.id} was accepted as UTF-8 scalar text`);
  }
  verifyBundleRejections(vector.bundleRejections);
}

function verifyGraphRejections(vector) {
  equal(vector.format, 'bcap1-graph-rejections-v1', 'graph-rejection vector format');
  if (!Array.isArray(vector.bundleRejections) || vector.bundleRejections.length === 0)
    fail('graph rejection vectors are empty');
  verifyBundleRejections(vector.bundleRejections);
}

const PRECEDENCE_DENIALS = new Set(['malformed', 'resource_limit', 'unsupported_version']);

function verifyBundlePrecedence(vector) {
  equal(vector.format, 'bcap1-bundle-precedence-v1', 'bundle-precedence vector format');
  if (!Array.isArray(vector.cases) || vector.cases.length === 0)
    fail('bundle precedence vectors are empty');
  const ids = new Set();
  for (const testCase of vector.cases) {
    if (!testCase.id || ids.has(testCase.id)) fail('bundle precedence case id is missing or reused');
    ids.add(testCase.id);
    if (!PRECEDENCE_DENIALS.has(testCase.denial)) fail(`${testCase.id} has an invalid denial`);
    if (!Array.isArray(testCase.defects) || testCase.defects.length === 0)
      fail(`${testCase.id} does not name its defects`);
    if (!Array.isArray(testCase.componentIds) || !Array.isArray(testCase.edges))
      fail(`${testCase.id} is incomplete`);
  }
}

const DECODE_MUTATIONS = new Set(['set', 'repeat', 'cloneComponents', 'cloneEdges']);

function verifyBundleDecodePrecedence(vector) {
  equal(
    vector.format,
    'bcap1-bundle-decode-precedence-v1',
    'bundle-decode-precedence vector format',
  );
  if (vector.base === null || typeof vector.base !== 'object') fail('decode precedence base missing');
  if (!Array.isArray(vector.cases) || vector.cases.length === 0)
    fail('decode precedence vectors are empty');
  const ids = new Set();
  for (const testCase of vector.cases) {
    if (!testCase.id || ids.has(testCase.id)) fail('decode precedence case id is missing or reused');
    ids.add(testCase.id);
    if (!PRECEDENCE_DENIALS.has(testCase.denial)) fail(`${testCase.id} has an invalid denial`);
    if (!Array.isArray(testCase.defects) || testCase.defects.length === 0)
      fail(`${testCase.id} does not name its defects`);
    if (!Array.isArray(testCase.mutations) || testCase.mutations.length === 0)
      fail(`${testCase.id} has no mutations`);
    for (const mutation of testCase.mutations)
      if (!DECODE_MUTATIONS.has(mutation.op)) fail(`${testCase.id} has an unknown mutation`);
  }
}

function verifyBundleRejections(cases) {
  for (const testCase of cases) {
    if (testCase.denial !== 'malformed' && testCase.denial !== 'resource_limit')
      fail(`${testCase.id} has an invalid denial`);
    const ids = new Set();
    let rejected = false;
    for (const id of testCase.componentIds) {
      if (ids.has(id)) rejected = true;
      ids.add(id);
    }
    const endpoints = new Set();
    const children = new Map();
    for (const edge of testCase.edges) {
      if (!ids.has(edge.parentComponentId) || !ids.has(edge.childComponentId)) rejected = true;
      if (edge.parentComponentId === edge.childComponentId) rejected = true;
      const key = `${edge.parentComponentId}\0${edge.childComponentId}`;
      if (endpoints.has(key)) rejected = true;
      endpoints.add(key);
      children.set(edge.parentComponentId, [
        ...(children.get(edge.parentComponentId) ?? []),
        edge.childComponentId,
      ]);
    }
    const visiting = new Set();
    const done = new Set();
    const cyclic = (node) => {
      if (done.has(node)) return false;
      if (visiting.has(node)) return true;
      visiting.add(node);
      const found = (children.get(node) ?? []).some(cyclic);
      visiting.delete(node);
      done.add(node);
      return found;
    };
    if ([...children.keys()].some(cyclic)) rejected = true;
    if (testCase.metadataEntries > 256) rejected = true;
    if (
      (testCase.evidenceBytesPerComponent ?? 0) * testCase.componentIds.length >=
        16 * 1024 * 1024 &&
      testCase.metadataEntries > 0
    ) {
      rejected = true;
    }
    if (!rejected) fail(`${testCase.id} does not exercise a rejected bundle structure`);
  }
}

function pathParts(path) {
  return [...path.matchAll(/([^.\[\]]+)|\[(\d+)\]/g)].map((match) =>
    match[2] === undefined ? match[1] : Number(match[2]),
  );
}

function mutateFixture(fixture, rejection) {
  const result = clone(fixture);
  const parts = pathParts(rejection.path);
  let parent = result;
  for (const part of parts.slice(0, -1)) parent = parent[part];
  const last = parts.at(-1);
  switch (rejection.operation) {
    case 'delete':
      delete parent[last];
      break;
    case 'set':
      parent[last] = rejection.value;
      break;
    case 'repeat':
      parent[last] = rejection.character.repeat(rejection.count);
      break;
    case 'repeat-array':
      parent[last] = Array.from({ length: rejection.count }, () => clone(parent[last][0]));
      break;
    case 'repeat-map':
      parent[last] = Object.fromEntries(
        Array.from({ length: rejection.count }, (_, index) => [
          `${rejection.keyPrefix}${index}`,
          rejection.value,
        ]),
      );
      break;
    default:
      fail(`${rejection.id} has unknown mutation ${rejection.operation}`);
  }
  return result;
}

function rejectionFixture(rejection, vectors) {
  const [file, fragment] = rejection.fixture.split('#');
  if (file === 'bcap1-transcript.json') {
    const [id] = fragment.split('.');
    return vectors.transcript.valid.find((entry) => entry.id === id)?.input;
  }
  if (file === 'bcap1-transport.json') {
    const [id, ...path] = fragment.split('.');
    const entry = vectors.transport.valid.find((candidate) => candidate.id === id);
    if (!entry) return undefined;
    if (path.join('.').startsWith('message.payload')) {
      return JSON.parse(base64Url(entry.message.payload, `${id} payload`).toString('utf8'));
    }
    return path.reduce((value, key) => value[key], entry);
  }
  if (file === 'bcap1-security-snapshot-jcs.json') {
    const [id, ...path] = fragment.split('.');
    const entry = vectors.snapshot.valid.find((candidate) => candidate.id === id);
    return path.reduce((value, key) => value[key], entry);
  }
  return undefined;
}

function verifySchemas(schemas, vectors, rejections) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addKeyword({ keyword: 'x-bcap1-validation', schemaType: 'array', valid: true });
  for (const schema of schemas.values()) ajv.addSchema(schema);

  for (const rejection of rejections.cases) {
    const schema = schemas.get(rejection.schema);
    const validate = schema && ajv.getSchema(schema.$id);
    const fixture = rejectionFixture(rejection, vectors);
    if (!validate || fixture === undefined)
      fail(`${rejection.id} has an unresolved schema or fixture`);
    if (!validate(fixture)) {
      fail(`${rejection.id} starts from an invalid fixture: ${ajv.errorsText(validate.errors)}`);
    }
    if (validate(mutateFixture(fixture, rejection))) {
      fail(`${rejection.id} was accepted by ${rejection.schema}`);
    }
  }
}

async function main() {
  const schemaNames = [
    'common.schema.json',
    'challenge.schema.json',
    'evidence-bundle.schema.json',
    'transport-message.schema.json',
    'security-snapshot.schema.json',
  ];
  const schemas = new Map(
    await Promise.all(schemaNames.map(async (name) => [name, await readJson(specDir, name)])),
  );
  const transcript = await readJson(vectorsDir, 'bcap1-transcript.json');
  const transport = await readJson(vectorsDir, 'bcap1-transport.json');
  const snapshot = await readJson(vectorsDir, 'bcap1-security-snapshot-jcs.json');
  const gpuPolicy = await readJson(vectorsDir, 'bcap1-dstack-gpu-policy-jcs.json');
  const coreRejections = await readJson(vectorsDir, 'bcap1-core-rejections.json');
  verifyTranscript(transcript);
  verifyTransport(transport);
  verifySnapshot(snapshot);
  verifyGpuPolicy(gpuPolicy);
  await verifyDstackCollateralEvidenceVector();
  verifyCoreRejections(coreRejections);
  verifyGraphRejections(await readJson(vectorsDir, 'bcap1-graph-rejections.json'));
  verifyBundlePrecedence(await readJson(vectorsDir, 'bcap1-bundle-precedence.json'));
  verifyBundleDecodePrecedence(await readJson(vectorsDir, 'bcap1-bundle-decode-precedence.json'));
  const rejections = await readJson(vectorsDir, 'bcap1-validation-rejections.json');
  equal(rejections.format, 'bcap1-schema-rejections-v1', 'schema-rejection vector format');
  if (!Array.isArray(rejections.cases) || rejections.cases.length === 0)
    fail('schema rejection vectors are empty');
  verifySchemas(schemas, { transcript, transport, snapshot }, rejections);
  process.stdout.write('BCAP1 vectors verified.\n');
}

main().catch((error) => {
  process.stderr.write(`BCAP1 vector verification failed: ${error.message}\n`);
  process.exitCode = 1;
});
