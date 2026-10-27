import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PASSWORD_KDF_ITERATIONS,
  SYNC_HANDOFF_SUITE,
  base64UrlEncode,
  canonicalJson,
  completeDeviceHandoffIfCurrent,
  createDeviceHandoff,
  derivePasswordKey,
  openDeviceHandoff,
  parseSyncLaunchFragment,
  p256PublicKeySha256,
  verifyDeviceConfirmationCode
} from '../auth/sync-key-flow.mjs';

const now = Date.parse('2026-01-01T00:00:00.000Z');
const backendOrigin = 'https://uptier.example';
const accountId = '123e4567-e89b-42d3-a456-426614174000';
const requestId = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => index));
const deviceNonceBase64url = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => 255 - index));
const deviceConfirmationHash = 'xI7-rpuzqEwlYlRz-4hUBVroNoe6qostMMmfGZEV9cU';
const expiresAt = '2026-01-01T00:05:00.000Z';
const passwordKdf = Object.freeze({
  schemaVersion: 1,
  name: 'PBKDF2',
  hash: 'SHA-256',
  iterations: PASSWORD_KDF_ITERATIONS,
  saltBase64url: base64UrlEncode(Uint8Array.from({ length: 16 }, (_, index) => 16 + index))
});

const devicePublicJwk = Object.freeze({
  kty: 'EC',
  crv: 'P-256',
  x: 'p49skr4gxS4f9VppFtfC-xuZyvmpjNfgODYhtmU5SgI',
  y: 'JiLfSJJOjXKfDE7804iAHoj9EdpOVTkH7-bZ3xMXBcw'
});
const devicePrivateJwk = Object.freeze({
  ...devicePublicJwk,
  d: 'pBQFJpKDuDzkZX6r2tyoJz-Mb_3quYacbWKHvJQoYAc',
  ext: true,
  key_ops: ['deriveBits']
});
const portalPublicJwk = Object.freeze({
  kty: 'EC',
  crv: 'P-256',
  x: 'e0QL0CxmxcvlpO_dFK11UJUQa6cQ87PeoqFgw3Oty80',
  y: '-KeXSJNvtusOG-oPYX-5T2dDYPd9hIr7DU8tKHhxWCI'
});
const portalPrivateJwk = Object.freeze({
  ...portalPublicJwk,
  d: 'kb32G-UH_XEksJidLELUEN5SoxJJl8oxE7X2dNkwCoI',
  ext: true,
  key_ops: ['deriveBits']
});

function syncContext(overrides = {}) {
  return {
    schemaVersion: 1,
    requestId,
    backendOrigin,
    expiresAt,
    deviceNonceBase64url,
    deviceConfirmationHash,
    devicePublicJwk,
    ...overrides
  };
}

function prepareResponse(overrides = {}) {
  return { requestId, accountId, expiresAt, passwordKdf, ...overrides };
}

async function importPair(publicJwk, privateJwk) {
  return {
    publicKey: await crypto.subtle.importKey(
      'jwk',
      { ...publicJwk, ext: true },
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    ),
    privateKey: await crypto.subtle.importKey(
      'jwk',
      privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    )
  };
}

function fragmentFor(value, canonical = true) {
  const text = canonical ? canonicalJson(value) : JSON.stringify(value);
  return `#sync=${base64UrlEncode(new TextEncoder().encode(text))}`;
}

test('sync launch fragments are canonical, exact, origin-bound, public-only, and short-lived', () => {
  assert.equal(fragmentFor(syncContext()), '#sync=eyJiYWNrZW5kT3JpZ2luIjoiaHR0cHM6Ly91cHRpZXIuZXhhbXBsZSIsImRldmljZUNvbmZpcm1hdGlvbkhhc2giOiJ4STctcnB1enFFd2xZbFJ6LTRoVUJWcm9Ob2U2cW9zdE1NbWZHWkVWOWNVIiwiZGV2aWNlTm9uY2VCYXNlNjR1cmwiOiJfXzc5X1B2Ni1majM5dlgwOF9MeDhPX3U3ZXpyNnVubzUtYmw1T1BpNGVBIiwiZGV2aWNlUHVibGljSndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoicDQ5c2tyNGd4UzRmOVZwcEZ0ZkMteHVaeXZtcGpOZmdPRFlodG1VNVNnSSIsInkiOiJKaUxmU0pKT2pYS2ZERTc4MDRpQUhvajlFZHBPVlRrSDctYlozeE1YQmN3In0sImV4cGlyZXNBdCI6IjIwMjYtMDEtMDFUMDA6MDU6MDAuMDAwWiIsInJlcXVlc3RJZCI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDgiLCJzY2hlbWFWZXJzaW9uIjoxfQ');
  const parsed = parseSyncLaunchFragment(fragmentFor(syncContext()), {
    allowedBackendOrigins: [backendOrigin],
    expectedBackendOrigin: backendOrigin,
    now
  });
  assert.deepEqual(parsed, syncContext());

  assert.throws(() => parseSyncLaunchFragment(fragmentFor({ ...syncContext(), extra: true }), {
    allowedBackendOrigins: [backendOrigin], expectedBackendOrigin: backendOrigin, now
  }), /unsupported format/);
  assert.throws(() => parseSyncLaunchFragment(fragmentFor({ ...syncContext(), devicePublicJwk: { ...devicePublicJwk, d: 'secret' } }), {
    allowedBackendOrigins: [backendOrigin], expectedBackendOrigin: backendOrigin, now
  }), /unsupported format/);
  assert.throws(() => parseSyncLaunchFragment(fragmentFor({ ...syncContext(), backendOrigin: 'https://evil.example' }), {
    allowedBackendOrigins: [backendOrigin], expectedBackendOrigin: backendOrigin, now
  }), /approved UpTier service/);
  assert.throws(() => parseSyncLaunchFragment(fragmentFor(syncContext(), false), {
    allowedBackendOrigins: [backendOrigin], expectedBackendOrigin: backendOrigin, now
  }), /not canonical/);
  assert.throws(() => parseSyncLaunchFragment(fragmentFor({ ...syncContext(), expiresAt: '2025-12-31T23:59:59.000Z' }), {
    allowedBackendOrigins: [backendOrigin], expectedBackendOrigin: backendOrigin, now
  }), /expired/);
  assert.throws(() => parseSyncLaunchFragment(`#sync=${'A'.repeat(4097)}`, {
    allowedBackendOrigins: [backendOrigin], expectedBackendOrigin: backendOrigin, now
  }), /too large/);
});

test('six-digit device confirmation is checked locally without accepting near matches', async () => {
  assert.equal(await verifyDeviceConfirmationCode('123456', syncContext()), true);
  assert.equal(await verifyDeviceConfirmationCode('123457', syncContext()), false);
  assert.equal(await verifyDeviceConfirmationCode('12345', syncContext()), false);
  assert.equal(await verifyDeviceConfirmationCode('123456 ', syncContext()), false);
});

test('password-key derivation is deterministic and bound to backend, account, and salt', async () => {
  const first = await derivePasswordKey('correct horse battery staple', backendOrigin, accountId, passwordKdf);
  const second = await derivePasswordKey('correct horse battery staple', backendOrigin, accountId, passwordKdf);
  assert.equal(first.length, 32);
  assert.deepEqual(first, second);
  assert.notDeepEqual(
    first,
    await derivePasswordKey('correct horse battery staple', 'https://other.example', accountId, passwordKdf)
  );
  assert.notDeepEqual(
    first,
    await derivePasswordKey('correct horse battery staple', backendOrigin, '123e4567-e89b-42d3-a456-426614174001', passwordKdf)
  );
  assert.rejects(() => derivePasswordKey('', backendOrigin, accountId, passwordKdf), /temporary account password/);
  assert.rejects(() => derivePasswordKey('password', backendOrigin, accountId, { ...passwordKdf, iterations: 1 }), /unsupported/);
});

test('fixed P-256/HKDF/AES-GCM vector opens only for the intended device and transcript', async () => {
  const portalKeyPair = await importPair(portalPublicJwk, portalPrivateJwk);
  const deviceKeyPair = await importPair(devicePublicJwk, devicePrivateJwk);
  const handoff = await createDeviceHandoff({
    syncContext: syncContext(),
    prepareResponse: prepareResponse(),
    password: 'correct horse battery staple',
    portalKeyPair,
    ivBytes: Uint8Array.from({ length: 12 }, (_, index) => 32 + index),
    now
  });

  assert.equal(handoff.suite, SYNC_HANDOFF_SUITE);
  assert.equal(handoff.devicePublicKeySha256, await p256PublicKeySha256(devicePublicJwk));
  assert.equal(handoff.portalPublicKeySha256, await p256PublicKeySha256(portalPublicJwk));
  const payload = await openDeviceHandoff({ handoff, devicePrivateKey: deviceKeyPair.privateKey });
  assert.equal(payload.requestId, requestId);
  assert.equal(payload.accountId, accountId);
  assert.equal(payload.deviceConfirmationHash, deviceConfirmationHash);
  assert.deepEqual(payload.passwordKdf, passwordKdf);
  assert.deepEqual(
    payload.passwordKeyBase64url,
    base64UrlEncode(await derivePasswordKey('correct horse battery staple', backendOrigin, accountId, passwordKdf))
  );

  // This exact ciphertext is the cross-runtime release vector. Any intentional
  // protocol change must update both clients and this reviewed value together.
  assert.equal(handoff.ivBase64url, 'ICEiIyQlJicoKSor');
  assert.equal(handoff.ciphertextBase64url, 'mnUXQsIRoUSPph5yjIJorpPT6abN-rjd1ZdkEZFfHvNOgr7_a3fomRrLbvEd0P5NuV5JwP-LYJu4XjPM9jg4oMhuw-7XYxKdOuntf3hD3izraFn9RsI33TEt98Ny0AihAagYzUXm1wocp-cXmxGmVubcsE6nXoyxRwvJxl3lLrZ1ZSAM_X0vw8USishHNu8Eaedruge1kni5QArF33WzYpmxWp7Uc2TsHHL0H7fUpEB3RMc_md70UDBPi3uCjFzn6Q6gTRX_xYKoaI0ZrfXWJ1PDmHZw9GhUG2AXXT-s6Pu-4gYT4gDmB61sOesWJt-hWn4RFIzYkExk4jYvoyxwYYu2kM2QyiQGyZt20bPwtR0AUzfx2QumrK-bZI1FNDTZt9dWIyfQh7ekzSuuCQSGME0PZEVck3uyQJ4RtwbiIeHkcDrENZBR1pTv-Mb0as8yB4pN5dH6Zix-BOxT0dDF-kKiloyQnWO7lz_SI-0_MPPWQT14EaweILoVes4_Dps10GLDQc4-MI5Tpf_mkC37xz1vsGpbU8GCPyRNyNHatSAH_DKjfJPIH76F4GHyGEJSL7TaFRTUDSP3QBGrQwgsSxpoGA37DH0pzRWCFIkOSwx3C-cT3l35AlO_ED9hZt9FIpDRoWgQYsrYRRR0WKEbyS_8FzhGtrAm7dscPx2OZxhgYtTyLKkP8D61B4Jni-7CbrF_RprQXpUM');
});

test('handoff rejects tampering, a different device, and mismatched preparation', async () => {
  const portalKeyPair = await importPair(portalPublicJwk, portalPrivateJwk);
  const deviceKeyPair = await importPair(devicePublicJwk, devicePrivateJwk);
  const otherDeviceKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const handoff = await createDeviceHandoff({
    syncContext: syncContext(), prepareResponse: prepareResponse(), password: 'password-1', portalKeyPair,
    ivBytes: Uint8Array.from({ length: 12 }, (_, index) => index), now
  });
  const tamperedCiphertext = `${handoff.ciphertextBase64url.slice(0, -1)}${handoff.ciphertextBase64url.endsWith('A') ? 'B' : 'A'}`;
  await assert.rejects(() => openDeviceHandoff({
    handoff: { ...handoff, ciphertextBase64url: tamperedCiphertext },
    devicePrivateKey: deviceKeyPair.privateKey
  }), /authenticated/);
  await assert.rejects(() => openDeviceHandoff({
    handoff: { ...handoff, accountId: '123e4567-e89b-42d3-a456-426614174001' },
    devicePrivateKey: deviceKeyPair.privateKey
  }), /authenticated/);
  await assert.rejects(() => openDeviceHandoff({ handoff, devicePrivateKey: otherDeviceKeyPair.privateKey }), /authenticated/);
  await assert.rejects(() => createDeviceHandoff({
    syncContext: syncContext(),
    prepareResponse: prepareResponse({ requestId: base64UrlEncode(new Uint8Array(32).fill(9)) }),
    password: 'password-1', portalKeyPair, now
  }), /different request/);
});

test('expiry or cancellation during delayed handoff crypto never reaches complete or retains a handoff', async (context) => {
  await context.test('expiry while crypto is delayed', async () => {
    let releaseCrypto;
    const cryptoGate = new Promise((resolve) => { releaseCrypto = resolve; });
    let current = true;
    let completeCalls = 0;
    let retainedHandoff;
    const operation = completeDeviceHandoffIfCurrent({
      createHandoff: async () => {
        await cryptoGate;
        return Object.freeze({ ciphertextBase64url: 'sealed' });
      },
      isCurrent: () => current,
      beforeComplete: () => {},
      complete: async (handoff) => {
        completeCalls += 1;
        retainedHandoff = handoff;
      }
    });

    current = false;
    releaseCrypto();
    assert.deepEqual(await operation, { completed: false });
    assert.equal(completeCalls, 0);
    assert.equal(retainedHandoff, undefined);
  });

  await context.test('cancellation at the pre-complete boundary', async () => {
    let current = true;
    let completeCalls = 0;
    let retainedHandoff;
    const result = await completeDeviceHandoffIfCurrent({
      createHandoff: async () => Object.freeze({ ciphertextBase64url: 'sealed' }),
      isCurrent: () => current,
      beforeComplete: () => { current = false; },
      complete: async (handoff) => {
        completeCalls += 1;
        retainedHandoff = handoff;
      }
    });

    assert.deepEqual(result, { completed: false });
    assert.equal(completeCalls, 0);
    assert.equal(retainedHandoff, undefined);
  });
});
