import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FIREBASE_PROJECT_ID,
  FIREBASE_SITE_ID,
  PUBLIC_FILES,
  verifyStagedSite
} from './hosting-files.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..');

function sha256(contents) {
  return createHash('sha256').update(contents).digest('hex');
}

function runGit(repositoryRoot, args) {
  const absoluteRoot = resolve(repositoryRoot);
  const result = spawnSync(
    'git',
    ['-c', `safe.directory=${absoluteRoot.replaceAll('\\', '/')}`, '-C', absoluteRoot, ...args],
    { encoding: 'utf8', windowsHide: true }
  );
  if (result.status !== 0) throw new Error(result.stderr.trim() || `git ${args.join(' ')} failed.`);
  return result.stdout.trim();
}

export function verifyExactSource(repositoryRoot, expectedSourceSha) {
  if (!/^[0-9a-f]{40}$/.test(expectedSourceSha)) {
    throw new Error('--expected-source-sha must be a full lowercase 40-character commit.');
  }
  const sourceCommit = runGit(repositoryRoot, ['rev-parse', 'HEAD']);
  if (sourceCommit !== expectedSourceSha) {
    throw new Error(`Checked-out commit ${sourceCommit} does not match expected source ${expectedSourceSha}.`);
  }
  const changes = runGit(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (changes) throw new Error(`Refusing remote verification from a dirty worktree:\n${changes}`);
  return sourceCommit;
}

export function parseFirebaseChannelList(value, expectedChannel) {
  if (!/^[a-z0-9-]{1,63}$/.test(expectedChannel)) {
    throw new Error('The Firebase Hosting channel ID is invalid.');
  }
  let payload;
  try {
    payload = typeof value === 'string' ? JSON.parse(value) : value;
  } catch {
    throw new Error('Firebase CLI channel output was not valid JSON.');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Firebase CLI channel output must be an object.');
  }
  if (payload.status && payload.status !== 'success') {
    throw new Error('Firebase CLI did not report a successful channel lookup.');
  }
  const channels = payload.result?.channels ?? payload.channels;
  if (!Array.isArray(channels)) throw new Error('Firebase CLI channel output did not contain channels.');
  const expectedChannelName = `projects/${FIREBASE_PROJECT_ID}/sites/${FIREBASE_SITE_ID}/channels/${expectedChannel}`;
  const matches = channels.filter((channel) => channel?.name === expectedChannelName);
  if (matches.length !== 1) {
    throw new Error(`Firebase Hosting channel ${expectedChannel} was not returned exactly once.`);
  }
  const channel = matches[0];
  const versionName = channel.release?.version?.name ?? '';
  const match = new RegExp(
    `^projects/${FIREBASE_PROJECT_ID}/sites/${FIREBASE_SITE_ID}/versions/([A-Za-z0-9_-]{1,128})$`
  ).exec(versionName);
  if (!match) throw new Error(`Firebase Hosting channel ${expectedChannel} has no valid immutable version.`);
  const parsedUrl = new URL(channel.url ?? '');
  if (parsedUrl.protocol !== 'https:' || parsedUrl.pathname !== '/' || parsedUrl.search || parsedUrl.hash) {
    throw new Error(`Firebase Hosting channel ${expectedChannel} returned an invalid URL.`);
  }
  return Object.freeze({
    channelId: expectedChannel,
    versionName,
    versionId: match[1],
    origin: parsedUrl.origin,
    updateTime: typeof channel.updateTime === 'string' ? channel.updateTime : ''
  });
}

export function readFirebaseChannelVersion(repositoryRoot, channelId, options = {}) {
  const firebaseCommand = options.firebaseCommand
    ?? (process.platform === 'win32' ? 'firebase.cmd' : 'firebase');
  const spawnImplementation = options.spawnImplementation ?? spawnSync;
  const result = spawnImplementation(firebaseCommand, [
    'hosting:channel:list',
    '--project', FIREBASE_PROJECT_ID,
    '--site', FIREBASE_SITE_ID,
    '--json',
    '--non-interactive'
  ], {
    cwd: resolve(repositoryRoot),
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 4 * 1_024 * 1_024
  });
  if (result.status !== 0) {
    throw new Error('Firebase CLI could not read the Hosting channel state.');
  }
  return parseFirebaseChannelList(result.stdout, channelId);
}

export function hostedPathForFile(path) {
  if (path === 'index.html') return '/';
  if (path.endsWith('/index.html')) return `/${path.slice(0, -'index.html'.length)}`;
  return `/${path.split('/').map(encodeURIComponent).join('/')}`;
}

function requireHeader(response, key, expected) {
  const actual = response.headers.get(key) ?? '';
  if (actual !== expected) throw new Error(`${response.url} returned ${key}: ${actual || '(missing)'}; expected ${expected}.`);
}

export async function verifyRemoteSite(repositoryRoot, origin, options) {
  const {
    expectedChannel = '',
    expectedSourceSha = '',
    expectedVersionId = '',
    live = false,
    fetchImplementation = fetch,
    channelVersionReader = readFirebaseChannelVersion
  } = options ?? {};
  if (live === Boolean(expectedChannel)) throw new Error('Remote verification requires exactly one of live or expectedChannel.');
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(expectedVersionId)) {
    throw new Error('--expected-version-id must identify one immutable Firebase Hosting version.');
  }
  const sourceCommit = verifyExactSource(repositoryRoot, expectedSourceSha);
  const parsedOrigin = new URL(origin);
  if (parsedOrigin.protocol !== 'https:' || parsedOrigin.port || parsedOrigin.username || parsedOrigin.password
      || parsedOrigin.pathname !== '/' || parsedOrigin.search || parsedOrigin.hash) {
    throw new Error('--origin must be an HTTPS origin with no path, query, or fragment.');
  }
  if (live && parsedOrigin.hostname !== 'uptier-502917.web.app') {
    throw new Error('Live verification is restricted to uptier-502917.web.app.');
  }
  if (expectedChannel) {
    if (!/^[a-z0-9-]{1,63}$/.test(expectedChannel)) throw new Error('The expected preview channel ID is invalid.');
    const prefix = `uptier-502917--${expectedChannel}-`;
    if (!parsedOrigin.hostname.startsWith(prefix) || !parsedOrigin.hostname.endsWith('.web.app')) {
      throw new Error(`Preview origin does not belong to the expected ${expectedChannel} channel.`);
    }
  }
  const channelId = live ? 'live' : expectedChannel;
  const versionBefore = await channelVersionReader(repositoryRoot, channelId);
  if (versionBefore.versionId !== expectedVersionId) {
    throw new Error(`Firebase Hosting channel ${channelId} points to version ${versionBefore.versionId}, not approved version ${expectedVersionId}.`);
  }
  if (versionBefore.origin !== parsedOrigin.origin) {
    throw new Error(`Firebase Hosting channel ${channelId} reports ${versionBefore.origin}, not ${parsedOrigin.origin}.`);
  }
  const staged = verifyStagedSite(repositoryRoot);
  const cacheKey = staged.contentAggregateSha256.slice(0, 16);
  const verified = [];

  for (const path of PUBLIC_FILES) {
    const requestUrl = new URL(hostedPathForFile(path), parsedOrigin);
    requestUrl.searchParams.set('uptier-verify', cacheKey);
    const response = await fetchImplementation(requestUrl, {
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'manual',
      headers: { 'Cache-Control': 'no-cache' }
    });
    if (!response.ok) throw new Error(`${requestUrl} returned HTTP ${response.status}.`);
    const remote = Buffer.from(await response.arrayBuffer());
    const local = readFileSync(join(repositoryRoot, '.firebase-site', ...path.split('/')));
    if (sha256(remote) !== sha256(local)) throw new Error(`Remote bytes differ from the staged artifact: ${path}`);
    verified.push({ path, bytes: remote.length, sha256: sha256(remote) });

    if (path === 'auth/index.html') {
      requireHeader(response, 'Cache-Control', 'private, no-store, max-age=0, must-revalidate');
      requireHeader(response, 'Content-Security-Policy', "base-uri 'self'; frame-ancestors 'none'; object-src 'none'");
      requireHeader(response, 'Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      requireHeader(response, 'Referrer-Policy', 'no-referrer');
      requireHeader(response, 'X-Content-Type-Options', 'nosniff');
      requireHeader(response, 'X-Frame-Options', 'DENY');
    }
  }

  const versionAfter = await channelVersionReader(repositoryRoot, channelId);
  if (versionAfter.versionName !== versionBefore.versionName || versionAfter.versionId !== expectedVersionId) {
    throw new Error(`Firebase Hosting channel ${channelId} changed versions during remote verification.`);
  }
  const stagedAfter = verifyStagedSite(repositoryRoot);
  if (stagedAfter.contentAggregateSha256 !== staged.contentAggregateSha256
      || stagedAfter.stagedArtifactAggregateSha256 !== staged.stagedArtifactAggregateSha256
      || stagedAfter.releaseInputAggregateSha256 !== staged.releaseInputAggregateSha256) {
    throw new Error('The staged Hosting release inputs changed during remote verification.');
  }
  const sourceAfter = verifyExactSource(repositoryRoot, expectedSourceSha);
  if (sourceAfter !== sourceCommit) throw new Error('The checked-out source changed during remote verification.');

  return Object.freeze({
    sourceCommit,
    origin: parsedOrigin.origin,
    channelId,
    versionName: versionBefore.versionName,
    versionId: versionBefore.versionId,
    verifiedContentAggregateSha256: staged.contentAggregateSha256,
    stagedArtifactAggregateSha256: staged.stagedArtifactAggregateSha256,
    releaseInputAggregateSha256: staged.releaseInputAggregateSha256,
    verifiedFileCount: verified.length,
    verified
  });
}

if (resolve(process.argv[1] ?? '') === resolve(scriptPath)) {
  const args = process.argv.slice(2);
  let origin = '';
  let expectedChannel = '';
  let expectedSourceSha = '';
  let expectedVersionId = '';
  let live = false;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--origin') origin = args[++index] ?? '';
    else if (args[index] === '--expected-channel') expectedChannel = args[++index] ?? '';
    else if (args[index] === '--expected-source-sha') expectedSourceSha = args[++index] ?? '';
    else if (args[index] === '--expected-version-id') expectedVersionId = args[++index] ?? '';
    else if (args[index] === '--live') live = true;
    else throw new Error(`Unknown argument: ${args[index]}`);
  }
  if (!origin || !expectedSourceSha || !expectedVersionId) {
    throw new Error('Usage: node scripts/verify-hosting-remote.mjs --origin https://host --expected-source-sha SHA --expected-version-id VERSION --live|--expected-channel CHANNEL');
  }
  const result = await verifyRemoteSite(root, origin, {
    expectedChannel,
    expectedSourceSha,
    expectedVersionId,
    live
  });
  console.log(JSON.stringify(result, null, 2));
}
