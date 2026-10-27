const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const SYNC_HANDOFF_SCHEMA_VERSION = 1;
export const SYNC_HANDOFF_SUITE = 'P-256-HKDF-SHA256-AES-256-GCM';
export const PASSWORD_KDF_ITERATIONS = 600_000;
export const PASSWORD_KDF_SALT_BYTES = 16;
export const DEVICE_NONCE_BYTES = 32;
export const HANDOFF_IV_BYTES = 12;
export const APP_BOUND_AUTH_KIND = 'ios-app-bound-pkce-v1';
export const APP_BOUND_CALLBACK_URL = 'com.uptier.app.auth://account-sign-in/callback';

const requestIdPattern = /^[A-Za-z0-9_-]{43}$/;
const accountIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const coordinatePattern = /^[A-Za-z0-9_-]{43}$/;
const authorizationCodePrefix = 'uptier_app_auth_';

function cryptoApi() {
  const value = globalThis.crypto;
  if (!value?.subtle || typeof value.getRandomValues !== 'function') {
    throw new Error('This browser does not provide the secure cryptography required for account sync.');
  }
  return value;
}

function plainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype);
}

function requireExactKeys(value, expected, label) {
  if (!plainObject(value)) throw new Error(`${label} is invalid.`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.join('\n') !== wanted.join('\n')) throw new Error(`${label} has an unsupported format.`);
}

function cleanOrigin(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} is invalid.`);
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${label} is invalid.`); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/'
      || parsed.search || parsed.hash || parsed.origin !== value) {
    throw new Error(`${label} is invalid.`);
  }
  return parsed.origin;
}

function cleanExpiry(value, nowMilliseconds) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    throw new Error('The account-sync handoff expiry is invalid.');
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || parsed <= nowMilliseconds || parsed > nowMilliseconds + 10 * 60_000) {
    throw new Error('The account-sync handoff is expired or outside its allowed lifetime.');
  }
  return new Date(parsed).toISOString();
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Canonical JSON does not support non-finite numbers.');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!plainObject(value)) throw new Error('Canonical JSON requires plain data objects.');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function base64UrlEncode(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(bytes.length, offset + 0x8000)));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export function base64UrlDecode(value, expectedBytes, label = 'Encoded value') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error(`${label} is invalid.`);
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  let binary;
  try { binary = atob(padded); } catch { throw new Error(`${label} is invalid.`); }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) throw new Error(`${label} is invalid.`);
  if (base64UrlEncode(bytes) !== value) throw new Error(`${label} is not canonical.`);
  return bytes;
}

export function normalizeP256PublicJwk(value, label = 'Device public key') {
  requireExactKeys(value, ['crv', 'kty', 'x', 'y'], label);
  if (value.kty !== 'EC' || value.crv !== 'P-256'
      || typeof value.x !== 'string' || !coordinatePattern.test(value.x)
      || typeof value.y !== 'string' || !coordinatePattern.test(value.y)) {
    throw new Error(`${label} is invalid.`);
  }
  base64UrlDecode(value.x, 32, `${label} x coordinate`);
  base64UrlDecode(value.y, 32, `${label} y coordinate`);
  return Object.freeze({ crv: 'P-256', kty: 'EC', x: value.x, y: value.y });
}

function parseCanonicalBase64Json(value, label, limits = {}) {
  const { maximumEncodedCharacters, maximumDecodedBytes } = limits;
  if (typeof value !== 'string'
      || (maximumEncodedCharacters !== undefined && value.length > maximumEncodedCharacters)
      || (maximumDecodedBytes !== undefined && Math.floor(value.length * 3 / 4) > maximumDecodedBytes)) {
    throw new Error(`${label} is too large.`);
  }
  const bytes = base64UrlDecode(value, undefined, label);
  if (maximumDecodedBytes !== undefined && bytes.length > maximumDecodedBytes) {
    throw new Error(`${label} is too large.`);
  }
  let text;
  let parsed;
  try {
    text = decoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label} is invalid.`);
  }
  if (canonicalJson(parsed) !== text) throw new Error(`${label} is not canonical.`);
  return parsed;
}

export function parseSyncLaunchFragment(fragment, options) {
  const { allowedBackendOrigins, expectedBackendOrigin, now = Date.now() } = options ?? {};
  if (!fragment) return undefined;
  if (typeof fragment !== 'string' || !fragment.startsWith('#')) throw new Error('The account-sync handoff is invalid.');
  if (fragment.length > 4096) throw new Error('The account-sync handoff is too large.');
  const parameters = new URLSearchParams(fragment.slice(1));
  if ([...parameters.keys()].length !== 1 || !parameters.has('sync')) {
    throw new Error('The account-sync handoff has unsupported fields.');
  }
  const parsed = parseCanonicalBase64Json(parameters.get('sync') ?? '', 'The account-sync handoff', {
    maximumEncodedCharacters: 4096 - '#sync='.length,
    maximumDecodedBytes: 3072
  });
  const appBound = parsed?.schemaVersion === 2;
  requireExactKeys(parsed, appBound ? [
    'schemaVersion',
    'requestId',
    'backendOrigin',
    'expiresAt',
    'deviceNonceBase64url',
    'deviceConfirmationHash',
    'devicePublicJwk',
    'appBoundAuth'
  ] : [
    'schemaVersion',
    'requestId',
    'backendOrigin',
    'expiresAt',
    'deviceNonceBase64url',
    'deviceConfirmationHash',
    'devicePublicJwk'
  ], 'The account-sync handoff');
  if ((!appBound && parsed.schemaVersion !== SYNC_HANDOFF_SCHEMA_VERSION)
      || !requestIdPattern.test(parsed.requestId ?? '')) {
    throw new Error('The account-sync handoff version or request is invalid.');
  }
  const backendOrigin = cleanOrigin(parsed.backendOrigin, 'The account-sync backend');
  if (!Array.isArray(allowedBackendOrigins) || !allowedBackendOrigins.includes(backendOrigin)
      || backendOrigin !== expectedBackendOrigin) {
    throw new Error('The account-sync handoff did not come from the approved UpTier service.');
  }
  const expiresAt = cleanExpiry(parsed.expiresAt, now);
  base64UrlDecode(parsed.deviceNonceBase64url, DEVICE_NONCE_BYTES, 'The account-sync device nonce');
  base64UrlDecode(parsed.deviceConfirmationHash, 32, 'The device confirmation hash');
  const devicePublicJwk = normalizeP256PublicJwk(parsed.devicePublicJwk);
  let appBoundAuth;
  if (appBound) {
    requireExactKeys(parsed.appBoundAuth, [
      'kind', 'callbackUrl', 'state', 'codeChallenge', 'codeChallengeMethod'
    ], 'The app-bound authorization request');
    if (parsed.appBoundAuth.kind !== APP_BOUND_AUTH_KIND
        || parsed.appBoundAuth.callbackUrl !== APP_BOUND_CALLBACK_URL
        || parsed.appBoundAuth.codeChallengeMethod !== 'S256') {
      throw new Error('The app-bound authorization request is unsupported.');
    }
    base64UrlDecode(parsed.appBoundAuth.state, 32, 'The app-bound authorization state');
    base64UrlDecode(parsed.appBoundAuth.codeChallenge, 32, 'The app-bound authorization challenge');
    appBoundAuth = Object.freeze({
      kind: APP_BOUND_AUTH_KIND,
      callbackUrl: APP_BOUND_CALLBACK_URL,
      state: parsed.appBoundAuth.state,
      codeChallenge: parsed.appBoundAuth.codeChallenge,
      codeChallengeMethod: 'S256'
    });
  }
  return Object.freeze({
    schemaVersion: parsed.schemaVersion,
    requestId: parsed.requestId,
    backendOrigin,
    expiresAt,
    deviceNonceBase64url: parsed.deviceNonceBase64url,
    deviceConfirmationHash: parsed.deviceConfirmationHash,
    devicePublicJwk,
    ...(appBoundAuth ? { appBoundAuth } : {})
  });
}

export function normalizeAppBoundAuthorizeResponse(value, syncContext, now = Date.now()) {
  if (!syncContext?.appBoundAuth) throw new Error('The app-bound authorization context is unavailable.');
  requireExactKeys(value, ['authorizationCode', 'requestId', 'expiresAt'], 'The app-bound authorization response');
  if (typeof value.authorizationCode !== 'string' || !value.authorizationCode.startsWith(authorizationCodePrefix)) {
    throw new Error('The app-bound authorization code is invalid.');
  }
  base64UrlDecode(
    value.authorizationCode.slice(authorizationCodePrefix.length),
    32,
    'The app-bound authorization code'
  );
  if (value.requestId !== syncContext.requestId) {
    throw new Error('The app-bound authorization response belongs to a different request.');
  }
  const expiresAt = cleanExpiry(value.expiresAt, now);
  if (Date.parse(expiresAt) > Date.parse(syncContext.expiresAt)) {
    throw new Error('The app-bound authorization response outlives the UpTier request.');
  }
  return Object.freeze({
    authorizationCode: value.authorizationCode,
    requestId: value.requestId,
    expiresAt
  });
}

export function createAppBoundCallbackUrl(syncContext, authorizeResponse, now = Date.now()) {
  const normalized = normalizeAppBoundAuthorizeResponse(authorizeResponse, syncContext, now);
  const appBoundAuth = syncContext.appBoundAuth;
  if (appBoundAuth.callbackUrl !== APP_BOUND_CALLBACK_URL) {
    throw new Error('The app-bound callback is unsupported.');
  }
  const callback = new URL(APP_BOUND_CALLBACK_URL);
  callback.searchParams.set('authorization_code', normalized.authorizationCode);
  callback.searchParams.set('state', appBoundAuth.state);
  return callback.toString();
}

export async function verifyDeviceConfirmationCode(code, syncContext) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  const expected = base64UrlDecode(syncContext?.deviceConfirmationHash, 32, 'The device confirmation hash');
  const actual = await sha256(encoder.encode(
    `UpTier device confirmation v1\0${syncContext.requestId}\0${code}`
  ));
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) difference |= expected[index] ^ actual[index];
  actual.fill(0);
  expected.fill(0);
  return difference === 0;
}

export function normalizePasswordKdf(value) {
  requireExactKeys(value, ['schemaVersion', 'name', 'hash', 'iterations', 'saltBase64url'], 'The password-key settings');
  if (value.schemaVersion !== 1 || value.name !== 'PBKDF2' || value.hash !== 'SHA-256'
      || value.iterations !== PASSWORD_KDF_ITERATIONS) {
    throw new Error('The password-key settings are unsupported.');
  }
  base64UrlDecode(value.saltBase64url, PASSWORD_KDF_SALT_BYTES, 'The password-key salt');
  return Object.freeze({
    schemaVersion: 1,
    name: 'PBKDF2',
    hash: 'SHA-256',
    iterations: PASSWORD_KDF_ITERATIONS,
    saltBase64url: value.saltBase64url
  });
}

export function normalizePrepareResponse(value, syncContext, now = Date.now()) {
  requireExactKeys(value, ['requestId', 'accountId', 'expiresAt', 'passwordKdf'], 'The account-sync preparation response');
  if (!requestIdPattern.test(value.requestId ?? '') || value.requestId !== syncContext.requestId) {
    throw new Error('The account-sync preparation response belongs to a different request.');
  }
  if (!accountIdPattern.test(value.accountId ?? '')) throw new Error('The account-sync account identifier is invalid.');
  const expiresAt = cleanExpiry(value.expiresAt, now);
  if (expiresAt !== syncContext.expiresAt) throw new Error('The account-sync preparation response has a mismatched expiry.');
  return Object.freeze({
    requestId: value.requestId,
    accountId: value.accountId.toLowerCase(),
    expiresAt,
    passwordKdf: normalizePasswordKdf(value.passwordKdf)
  });
}

async function sha256(bytes) {
  return new Uint8Array(await cryptoApi().subtle.digest('SHA-256', bytes));
}

function concatenateBytes(...values) {
  const length = values.reduce((total, value) => total + value.length, 0);
  const combined = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    combined.set(value, offset);
    offset += value.length;
  }
  return combined;
}

export async function p256PublicKeySha256(publicJwk) {
  const normalized = normalizeP256PublicJwk(publicJwk);
  return base64UrlEncode(await sha256(encoder.encode(JSON.stringify({
    kty: normalized.kty,
    crv: normalized.crv,
    x: normalized.x,
    y: normalized.y
  }))));
}

export async function derivePasswordKey(password, backendOrigin, accountId, passwordKdf) {
  if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
    throw new Error('The temporary account password is unavailable. Start one fresh sign-in from UpTier.');
  }
  if (!accountIdPattern.test(accountId ?? '')) throw new Error('The account-sync account identifier is invalid.');
  const normalizedBackendOrigin = cleanOrigin(backendOrigin, 'The account-sync backend');
  const kdf = normalizePasswordKdf(passwordKdf);
  const randomSalt = base64UrlDecode(kdf.saltBase64url, PASSWORD_KDF_SALT_BYTES, 'The password-key salt');
  const effectiveSalt = concatenateBytes(
    encoder.encode('UpTier password key v1\0'),
    encoder.encode(normalizedBackendOrigin),
    Uint8Array.of(0),
    encoder.encode(accountId.toLowerCase()),
    Uint8Array.of(0),
    randomSalt
  );
  const passwordMaterial = encoder.encode(password);
  try {
    const sourceKey = await cryptoApi().subtle.importKey('raw', passwordMaterial, 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await cryptoApi().subtle.deriveBits({
      name: 'PBKDF2',
      hash: kdf.hash,
      iterations: kdf.iterations,
      salt: effectiveSalt
    }, sourceKey, 256));
  } finally {
    passwordMaterial.fill(0);
    effectiveSalt.fill(0);
    randomSalt.fill(0);
  }
}

function handoffContext(value) {
  return {
    schemaVersion: SYNC_HANDOFF_SCHEMA_VERSION,
    suite: SYNC_HANDOFF_SUITE,
    purpose: 'uptier-profile-sync-password-key-handoff',
    requestId: value.requestId,
    accountId: value.accountId,
    backendOrigin: value.backendOrigin,
    expiresAt: value.expiresAt,
    deviceNonceBase64url: value.deviceNonceBase64url,
    deviceConfirmationHash: value.deviceConfirmationHash,
    devicePublicKeySha256: value.devicePublicKeySha256,
    portalPublicKeySha256: value.portalPublicKeySha256
  };
}

export async function createDeviceHandoff({ syncContext, prepareResponse, password, portalKeyPair, ivBytes, now = Date.now() }) {
  const prepared = normalizePrepareResponse(prepareResponse, syncContext, now);
  if (syncContext.backendOrigin !== cleanOrigin(syncContext.backendOrigin, 'The account-sync backend')) {
    throw new Error('The account-sync backend is invalid.');
  }
  const devicePublicJwk = normalizeP256PublicJwk(syncContext.devicePublicJwk);
  const api = cryptoApi();
  const passwordKey = await derivePasswordKey(password, syncContext.backendOrigin, prepared.accountId, prepared.passwordKdf);
  let sharedSecret;
  try {
    const devicePublicKey = await api.subtle.importKey(
      'jwk',
      { ...devicePublicJwk, ext: true },
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const handoffPortalKeyPair = portalKeyPair ?? await api.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    if (!handoffPortalKeyPair?.publicKey || !handoffPortalKeyPair?.privateKey) {
      throw new Error('The portal handoff key is invalid.');
    }
    const exportedPortalJwk = await api.subtle.exportKey('jwk', handoffPortalKeyPair.publicKey);
    const portalPublicJwk = normalizeP256PublicJwk({
      crv: exportedPortalJwk.crv,
      kty: exportedPortalJwk.kty,
      x: exportedPortalJwk.x,
      y: exportedPortalJwk.y
    }, 'The portal public key');
    const devicePublicKeySha256 = await p256PublicKeySha256(devicePublicJwk);
    const portalPublicKeySha256 = await p256PublicKeySha256(portalPublicJwk);
    const publicFields = {
      schemaVersion: SYNC_HANDOFF_SCHEMA_VERSION,
      suite: SYNC_HANDOFF_SUITE,
      requestId: syncContext.requestId,
      accountId: prepared.accountId,
      backendOrigin: syncContext.backendOrigin,
      expiresAt: prepared.expiresAt,
      deviceNonceBase64url: syncContext.deviceNonceBase64url,
      deviceConfirmationHash: syncContext.deviceConfirmationHash,
      devicePublicKeySha256,
      portalPublicJwk,
      portalPublicKeySha256
    };
    const context = handoffContext(publicFields);
    const contextJson = JSON.stringify(context);
    const contextBytes = encoder.encode(contextJson);
    const deviceNonce = base64UrlDecode(syncContext.deviceNonceBase64url, DEVICE_NONCE_BYTES, 'The account-sync device nonce');
    sharedSecret = new Uint8Array(await api.subtle.deriveBits(
      { name: 'ECDH', public: devicePublicKey },
      handoffPortalKeyPair.privateKey,
      256
    ));
    const hkdfSource = await api.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const handoffKey = await api.subtle.deriveKey({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: deviceNonce,
      info: encoder.encode(`UpTier profile sync key handoff v1\0${contextJson}`)
    }, hkdfSource, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const payload = {
      schemaVersion: SYNC_HANDOFF_SCHEMA_VERSION,
      purpose: 'uptier-profile-sync-password-key',
      requestId: syncContext.requestId,
      accountId: prepared.accountId,
      backendOrigin: syncContext.backendOrigin,
      expiresAt: prepared.expiresAt,
      deviceConfirmationHash: syncContext.deviceConfirmationHash,
      passwordKdf: prepared.passwordKdf,
      passwordKeyBase64url: base64UrlEncode(passwordKey)
    };
    const iv = ivBytes === undefined
      ? api.getRandomValues(new Uint8Array(HANDOFF_IV_BYTES))
      : new Uint8Array(ivBytes);
    if (iv.length !== HANDOFF_IV_BYTES) throw new Error('The portal handoff IV is invalid.');
    const ciphertext = await api.subtle.encrypt({
      name: 'AES-GCM',
      iv,
      additionalData: contextBytes,
      tagLength: 128
    }, handoffKey, encoder.encode(canonicalJson(payload)));
    return Object.freeze({
      ...publicFields,
      ivBase64url: base64UrlEncode(iv),
      ciphertextBase64url: base64UrlEncode(new Uint8Array(ciphertext))
    });
  } finally {
    passwordKey.fill(0);
    sharedSecret?.fill(0);
  }
}

export async function completeDeviceHandoffIfCurrent({
  createHandoff,
  isCurrent,
  beforeComplete,
  complete
}) {
  if (typeof createHandoff !== 'function' || typeof isCurrent !== 'function'
      || typeof beforeComplete !== 'function' || typeof complete !== 'function') {
    throw new Error('The device handoff lifecycle is invalid.');
  }
  const deviceHandoff = await createHandoff();
  if (!isCurrent()) return Object.freeze({ completed: false });
  beforeComplete();
  if (!isCurrent()) return Object.freeze({ completed: false });
  return Object.freeze({ completed: true, result: await complete(deviceHandoff) });
}

export function deviceHandoffContext(value) {
  requireExactKeys(value, [
    'schemaVersion', 'suite', 'requestId', 'accountId', 'backendOrigin', 'expiresAt',
    'deviceNonceBase64url', 'deviceConfirmationHash', 'devicePublicKeySha256', 'portalPublicJwk', 'portalPublicKeySha256',
    'ivBase64url', 'ciphertextBase64url'
  ], 'The device handoff');
  return handoffContext(value);
}

// Exported so the native clients and release tests can use the exact same
// transcript rules. The production portal never receives a device private key.
export async function openDeviceHandoff({ handoff, devicePrivateKey }) {
  const context = deviceHandoffContext(handoff);
  if (handoff.schemaVersion !== SYNC_HANDOFF_SCHEMA_VERSION || handoff.suite !== SYNC_HANDOFF_SUITE) {
    throw new Error('The device handoff version or suite is unsupported.');
  }
  if (!requestIdPattern.test(handoff.requestId ?? '') || !accountIdPattern.test(handoff.accountId ?? '')) {
    throw new Error('The device handoff identity is invalid.');
  }
  cleanOrigin(handoff.backendOrigin, 'The device handoff backend');
  base64UrlDecode(handoff.deviceNonceBase64url, DEVICE_NONCE_BYTES, 'The device handoff nonce');
  base64UrlDecode(handoff.deviceConfirmationHash, 32, 'The device confirmation hash');
  base64UrlDecode(handoff.devicePublicKeySha256, 32, 'The device public-key fingerprint');
  base64UrlDecode(handoff.portalPublicKeySha256, 32, 'The portal public-key fingerprint');
  const portalPublicJwk = normalizeP256PublicJwk(handoff.portalPublicJwk, 'The portal public key');
  if (await p256PublicKeySha256(portalPublicJwk) !== handoff.portalPublicKeySha256) {
    throw new Error('The portal public-key fingerprint does not match.');
  }
  const api = cryptoApi();
  const portalPublicKey = await api.subtle.importKey(
    'jwk',
    { ...portalPublicJwk, ext: true },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const contextJson = JSON.stringify(context);
  const contextBytes = encoder.encode(contextJson);
  const nonce = base64UrlDecode(handoff.deviceNonceBase64url, DEVICE_NONCE_BYTES, 'The device handoff nonce');
  const iv = base64UrlDecode(handoff.ivBase64url, HANDOFF_IV_BYTES, 'The device handoff IV');
  const ciphertext = base64UrlDecode(handoff.ciphertextBase64url, undefined, 'The device handoff ciphertext');
  if (ciphertext.length < 17 || ciphertext.length > 4096) throw new Error('The device handoff ciphertext is invalid.');
  const sharedSecret = new Uint8Array(await api.subtle.deriveBits(
    { name: 'ECDH', public: portalPublicKey },
    devicePrivateKey,
    256
  ));
  try {
    const hkdfSource = await api.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const handoffKey = await api.subtle.deriveKey({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: nonce,
      info: encoder.encode(`UpTier profile sync key handoff v1\0${contextJson}`)
    }, hkdfSource, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    let plaintext;
    try {
      plaintext = await api.subtle.decrypt({
        name: 'AES-GCM',
        iv,
        additionalData: contextBytes,
        tagLength: 128
      }, handoffKey, ciphertext);
    } catch {
      throw new Error('The device handoff could not be authenticated.');
    }
    const text = decoder.decode(plaintext);
    const payload = JSON.parse(text);
    if (canonicalJson(payload) !== text) throw new Error('The device handoff payload is not canonical.');
    requireExactKeys(payload, [
      'schemaVersion', 'purpose', 'requestId', 'accountId', 'backendOrigin',
      'expiresAt', 'deviceConfirmationHash', 'passwordKdf', 'passwordKeyBase64url'
    ], 'The device handoff payload');
    if (payload.schemaVersion !== 1 || payload.purpose !== 'uptier-profile-sync-password-key'
        || payload.requestId !== context.requestId || payload.accountId !== context.accountId
        || payload.backendOrigin !== context.backendOrigin || payload.expiresAt !== context.expiresAt
        || payload.deviceConfirmationHash !== context.deviceConfirmationHash) {
      throw new Error('The device handoff payload does not match its authenticated context.');
    }
    normalizePasswordKdf(payload.passwordKdf);
    base64UrlDecode(payload.passwordKeyBase64url, 32, 'The password key');
    return payload;
  } finally {
    sharedSecret.fill(0);
  }
}
