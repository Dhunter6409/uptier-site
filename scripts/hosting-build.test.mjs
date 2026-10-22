import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  FIREBASE_AUTH_URL,
  HOSTING_OUTPUT_DIRECTORY,
  PUBLIC_FILES,
  stagePublicSite,
  validateFirebaseConfiguration,
  verifyStagedSite
} from './hosting-files.mjs';
import { backendOriginsForPortalLocation } from '../auth/config.js';
import {
  hostedPathForFile,
  parseFirebaseChannelList,
  readFirebaseChannelVersion,
  verifyRemoteSite
} from './verify-hosting-remote.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function createFixture() {
  const fixture = mkdtempSync(join(root, '.uptier-hosting-test-'));
  try {
    for (const path of [...PUBLIC_FILES, 'firebase.json', '.firebaserc', '.gitignore']) {
      const destination = join(fixture, ...path.split('/'));
      mkdirSync(dirname(destination), { recursive: true });
      cpSync(join(root, ...path.split('/')), destination);
    }
    runGit(fixture, ['init', '--quiet']);
    runGit(fixture, ['config', 'user.name', 'UpTier Hosting Test']);
    runGit(fixture, ['config', 'user.email', 'hosting-test@invalid.example']);
    runGit(fixture, ['add', '--all']);
    runGit(fixture, ['commit', '--quiet', '-m', 'fixture']);
    return fixture;
  } catch (error) {
    rmSync(fixture, { recursive: true, force: true });
    throw error;
  }
}

function runGit(repositoryRoot, args) {
  const result = spawnSync('git', ['-c', `safe.directory=${repositoryRoot.replaceAll('\\', '/')}`, '-C', repositoryRoot, ...args], {
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.status !== 0) throw new Error(result.stderr.trim() || `git ${args.join(' ')} failed.`);
  return result.stdout.trim();
}

function channelState(channelId, versionId, origin) {
  return Object.freeze({
    channelId,
    versionName: `projects/uptier-502917/sites/uptier-502917/versions/${versionId}`,
    versionId,
    origin,
    updateTime: '2026-10-22T12:00:00Z'
  });
}

test('Firebase Hosting stages and verifies the exact reviewed public artifact', () => {
  const fixture = createFixture();
  try {
    validateFirebaseConfiguration(fixture);
    stagePublicSite(fixture);
    const verified = verifyStagedSite(fixture);
    assert.equal(verified.target, FIREBASE_AUTH_URL);
    assert.equal(verified.fileCount, PUBLIC_FILES.length + 1);
    assert.match(verified.contentAggregateSha256, /^[0-9a-f]{64}$/);
    assert.match(verified.stagedArtifactAggregateSha256, /^[0-9a-f]{64}$/);
    assert.match(verified.releaseInputAggregateSha256, /^[0-9a-f]{64}$/);
    for (const file of verified.files.filter(({ path }) => path !== '.nojekyll')) {
      assert.deepEqual(
        readFileSync(join(fixture, HOSTING_OUTPUT_DIRECTORY, ...file.path.split('/'))),
        readFileSync(join(fixture, ...file.path.split('/')))
      );
    }

    writeFileSync(join(fixture, HOSTING_OUTPUT_DIRECTORY, 'unexpected.txt'), 'must fail');
    assert.throws(() => verifyStagedSite(fixture), /Unexpected: unexpected\.txt/);

    stagePublicSite(fixture);
    writeFileSync(join(fixture, HOSTING_OUTPUT_DIRECTORY, 'auth', 'config.js'), 'changed');
    assert.throws(() => verifyStagedSite(fixture), /Staged bytes differ from source: auth\/config\.js/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test('the hosted auth portal cannot send identity tokens to a loopback backend', () => {
  const productionBackend = 'https://uptier-plaid-backend-1076418370349.us-central1.run.app';
  assert.deepEqual(
    backendOriginsForPortalLocation(new URL('https://uptier-502917.web.app/auth/')),
    [productionBackend]
  );
  assert.deepEqual(
    backendOriginsForPortalLocation(new URL('https://example.com/auth/')),
    [productionBackend]
  );
  assert.deepEqual(
    backendOriginsForPortalLocation(new URL('http://127.0.0.1:4173/auth/')),
    [productionBackend, 'http://127.0.0.1:8788']
  );
  assert.deepEqual(
    backendOriginsForPortalLocation(new URL('http://localhost:4173/auth/')),
    [productionBackend, 'http://127.0.0.1:8788']
  );
});

test('remote verification maps directory indexes to their public trailing-slash URLs', () => {
  assert.equal(hostedPathForFile('index.html'), '/');
  assert.equal(hostedPathForFile('auth/index.html'), '/auth/');
  assert.equal(hostedPathForFile('premium/success/index.html'), '/premium/success/');
  assert.equal(hostedPathForFile('auth/app.js'), '/auth/app.js');
});

test('the shared 404 page routes home correctly on GitHub Pages and Firebase Hosting', () => {
  const notFound = readFileSync(join(root, '404.html'), 'utf8');
  assert.doesNotMatch(notFound, /http-equiv="refresh"/i);
  assert.match(notFound, /hostname === 'dhunter6409\.github\.io' \? '\/uptier-site\/' : '\/'/);
  assert.match(notFound, /window\.location\.replace\(window\.upTierPublicHome\)/);
});

test('pre-cutover public metadata remains on the current GitHub origin', () => {
  const expectedOrigin = 'https://dhunter6409.github.io/uptier-site';
  const canonicalPages = [
    ['index.html', '/'],
    ['privacy/index.html', '/privacy/'],
    ['terms/index.html', '/terms/'],
    ['support/index.html', '/support/'],
    ['data-deletion/index.html', '/data-deletion/']
  ];
  for (const [path, publicPath] of canonicalPages) {
    const source = readFileSync(join(root, ...path.split('/')), 'utf8');
    assert.match(source, new RegExp(`rel="canonical" href="${expectedOrigin.replaceAll('.', '\\.')}${publicPath}"`));
  }
  const robots = readFileSync(join(root, 'robots.txt'), 'utf8');
  const sitemap = readFileSync(join(root, 'sitemap.xml'), 'utf8');
  assert.match(robots, /Sitemap: https:\/\/dhunter6409\.github\.io\/uptier-site\/sitemap\.xml/);
  assert.match(sitemap, /<loc>https:\/\/dhunter6409\.github\.io\/uptier-site\/<\/loc>/);
  assert.doesNotMatch(sitemap, /uptier-502917\.web\.app/);
});

test('Firebase configuration rejects unreviewed Hosting behavior', () => {
  const fixture = createFixture();
  try {
    const configPath = join(fixture, 'firebase.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    config.hosting.redirects = [{ source: '/old', destination: '/', type: 302 }];
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    assert.throws(() => validateFirebaseConfiguration(fixture), /Hosting keys must be exactly/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test('remote verification compares all public bytes and required auth headers', async () => {
  const fixture = createFixture();
  try {
    stagePublicSite(fixture);
    const expectedSourceSha = runGit(fixture, ['rev-parse', 'HEAD']);
    const expectedChannel = 'auth-0123456789ab';
    const expectedVersionId = 'version_0123456789ab';
    const previewOrigin = 'https://uptier-502917--auth-0123456789ab-previewhash.web.app';
    const readStablePreview = async (_repositoryRoot, channelId) => {
      assert.equal(channelId, expectedChannel);
      return channelState(expectedChannel, expectedVersionId, previewOrigin);
    };
    const fakeFetch = async (requestUrl, requestOptions) => {
      assert.equal(requestOptions.redirect, 'manual');
      const { pathname } = new URL(requestUrl);
      const path = pathname === '/'
        ? 'index.html'
        : pathname.endsWith('/')
          ? `${pathname.slice(1)}index.html`
          : decodeURIComponent(pathname.slice(1));
      const headers = {
        'Content-Security-Policy': "base-uri 'self'; frame-ancestors 'none'; object-src 'none'",
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      };
      if (path === 'auth/index.html') headers['Cache-Control'] = 'private, no-store, max-age=0, must-revalidate';
      return new Response(readFileSync(join(fixture, HOSTING_OUTPUT_DIRECTORY, ...path.split('/'))), { status: 200, headers });
    };
    const verified = await verifyRemoteSite(
      fixture,
      previewOrigin,
      {
        expectedChannel,
        expectedSourceSha,
        expectedVersionId,
        fetchImplementation: fakeFetch,
        channelVersionReader: readStablePreview
      }
    );
    assert.equal(verified.sourceCommit, expectedSourceSha);
    assert.equal(verified.versionId, expectedVersionId);
    assert.equal(verified.verifiedFileCount, PUBLIC_FILES.length);
    assert.match(verified.verifiedContentAggregateSha256, /^[0-9a-f]{64}$/);
    assert.match(verified.releaseInputAggregateSha256, /^[0-9a-f]{64}$/);
    await assert.rejects(
      verifyRemoteSite(fixture, 'https://example.com', {
        live: true,
        expectedSourceSha,
        expectedVersionId,
        fetchImplementation: fakeFetch,
        channelVersionReader: readStablePreview
      }),
      /restricted to uptier-502917\.web\.app/
    );
    await assert.rejects(
      verifyRemoteSite(
        fixture,
        'https://uptier-502917--another-channel-previewhash.web.app',
        {
          expectedChannel,
          expectedSourceSha,
          expectedVersionId,
          fetchImplementation: fakeFetch,
          channelVersionReader: readStablePreview
        }
      ),
      /does not belong to the expected auth-0123456789ab channel/
    );
    const redirectingFetch = async (_requestUrl, requestOptions) => {
      assert.equal(requestOptions.redirect, 'manual');
      return new Response(null, { status: 302, headers: { Location: 'https://example.com/' } });
    };
    await assert.rejects(
      verifyRemoteSite(
        fixture,
        previewOrigin,
        {
          expectedChannel,
          expectedSourceSha,
          expectedVersionId,
          fetchImplementation: redirectingFetch,
          channelVersionReader: readStablePreview
        }
      ),
      /returned HTTP 302/
    );

    await assert.rejects(
      verifyRemoteSite(fixture, previewOrigin, {
        expectedChannel,
        expectedSourceSha,
        expectedVersionId: 'different_version',
        fetchImplementation: fakeFetch,
        channelVersionReader: readStablePreview
      }),
      /not approved version different_version/
    );

    let readCount = 0;
    await assert.rejects(
      verifyRemoteSite(fixture, previewOrigin, {
        expectedChannel,
        expectedSourceSha,
        expectedVersionId,
        fetchImplementation: fakeFetch,
        channelVersionReader: async () => {
          readCount += 1;
          return channelState(
            expectedChannel,
            readCount === 1 ? expectedVersionId : 'replacement_version',
            previewOrigin
          );
        }
      }),
      /changed versions during remote verification/
    );

    const sourcePath = join(fixture, 'auth', 'config.js');
    const source = readFileSync(sourcePath);
    writeFileSync(sourcePath, `${source.toString('utf8')}\n// dirty\n`);
    await assert.rejects(
      verifyRemoteSite(fixture, previewOrigin, {
        expectedChannel,
        expectedSourceSha,
        expectedVersionId,
        fetchImplementation: fakeFetch,
        channelVersionReader: readStablePreview
      }),
      /dirty worktree/
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test('Firebase channel JSON resolves one immutable version for exact-version promotion', () => {
  const parsed = parseFirebaseChannelList({
    status: 'success',
    result: {
      channels: [
        {
          name: 'projects/uptier-502917/sites/uptier-502917/channels/auth-0123456789ab',
          url: 'https://uptier-502917--auth-0123456789ab-previewhash.web.app',
          updateTime: '2026-10-22T12:00:00Z',
          release: { version: { name: 'projects/uptier-502917/sites/uptier-502917/versions/immutable_123' } }
        }
      ]
    }
  }, 'auth-0123456789ab');
  assert.equal(parsed.versionId, 'immutable_123');
  assert.equal(parsed.versionName, 'projects/uptier-502917/sites/uptier-502917/versions/immutable_123');
  assert.equal(parsed.origin, 'https://uptier-502917--auth-0123456789ab-previewhash.web.app');
  assert.throws(
    () => parseFirebaseChannelList({ status: 'success', result: { channels: [] } }, 'auth-0123456789ab'),
    /was not returned exactly once/
  );
  assert.throws(
    () => parseFirebaseChannelList({
      status: 'success',
      result: {
        channels: [{
          name: 'projects/other-project/sites/uptier-502917/channels/auth-0123456789ab',
          url: 'https://uptier-502917--auth-0123456789ab-previewhash.web.app',
          release: { version: { name: 'projects/other-project/sites/uptier-502917/versions/immutable_123' } }
        }]
      }
    }, 'auth-0123456789ab'),
    /was not returned exactly once/
  );
});

test('Firebase channel lookup is read-only, project-bound, and JSON-only', () => {
  const expectedPayload = JSON.stringify({
    status: 'success',
    result: {
      channels: [{
        name: 'projects/uptier-502917/sites/uptier-502917/channels/live',
        url: 'https://uptier-502917.web.app',
        release: { version: { name: 'projects/uptier-502917/sites/uptier-502917/versions/immutable_live' } }
      }]
    }
  });
  const result = readFirebaseChannelVersion(root, 'live', {
    firebaseCommand: 'firebase-test',
    spawnImplementation(command, args, options) {
      assert.equal(command, 'firebase-test');
      assert.deepEqual(args, [
        'hosting:channel:list',
        '--project', 'uptier-502917',
        '--site', 'uptier-502917',
        '--json',
        '--non-interactive'
      ]);
      assert.equal(options.cwd, root);
      return { status: 0, stdout: expectedPayload, stderr: '' };
    }
  });
  assert.equal(result.versionId, 'immutable_live');
  assert.equal(result.origin, 'https://uptier-502917.web.app');
});

test('preview deployment cannot add a temporary Firebase Authentication domain', () => {
  const runbook = readFileSync(join(root, 'docs', 'FIREBASE_HOSTING.md'), 'utf8');
  const previewDeploy = runbook
    .split(/\r?\n/)
    .find((line) => line.includes('firebase hosting:channel:deploy')) ?? '';
  assert.match(previewDeploy, /--no-authorized-domains(?:\s|$)/);
  assert.match(runbook, /otherwise attempts to add the temporary preview hostname to Firebase Authentication/);
});
