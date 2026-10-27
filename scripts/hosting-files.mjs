import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

export const FIREBASE_PROJECT_ID = 'uptier-502917';
export const FIREBASE_SITE_ID = 'uptier-502917';
export const FIREBASE_AUTH_URL = 'https://uptier-502917.web.app/auth/';
export const HOSTING_OUTPUT_DIRECTORY = '.firebase-site';

// Deliberately exact. A newly added public file is not deployable until a reviewer
// adds it here, which prevents repository-only material from leaking into Hosting.
export const PUBLIC_FILES = Object.freeze([
  '404.html',
  'app-preview/assets/index-CJ222twB.css',
  'app-preview/assets/index-Dr0JVjZc.js',
  'app-preview/assets/pdf.worker.min-BOzUj4Jr.js',
  'app-preview/assets/uptier-logo-BKBlADX1.png',
  'app-preview/index.html',
  'assets/uptier-mark.png',
  'auth/account-flow.mjs',
  'auth/app.js',
  'auth/config.js',
  'auth/index.html',
  'auth/styles.css',
  'auth/sync-key-flow.mjs',
  'data-deletion/index.html',
  'index.html',
  'premium/cancel/index.html',
  'premium/index.html',
  'premium/success/index.html',
  'privacy/index.html',
  'robots.txt',
  'sitemap.xml',
  'styles.css',
  'support/index.html',
  'terms/index.html'
]);

export const GENERATED_FILES = Object.freeze(['.nojekyll']);

const REQUIRED_GLOBAL_HEADERS = Object.freeze({
  'Content-Security-Policy': "base-uri 'self'; frame-ancestors 'none'; object-src 'none'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
});

const REQUIRED_AUTH_HEADERS = Object.freeze({
  'Cache-Control': 'private, no-store, max-age=0, must-revalidate'
});

function toPosix(value) {
  return value.split(sep).join('/');
}

function assertSafeManifestPath(path) {
  if (!path || path.startsWith('/') || path.includes('\\') || path.split('/').includes('..')) {
    throw new Error(`Unsafe public manifest path: ${path}`);
  }
}

function assertInside(parent, child) {
  const fromParent = relative(parent, child);
  if (!fromParent || fromParent.startsWith(`..${sep}`) || fromParent === '..') {
    throw new Error(`Hosting output must be a child of the repository: ${child}`);
  }
}

function assertSourceFile(root, path) {
  assertSafeManifestPath(path);
  const segments = path.split('/');
  let candidate = root;
  for (let index = 0; index < segments.length; index += 1) {
    candidate = join(candidate, segments[index]);
    if (!existsSync(candidate)) throw new Error(`Missing public manifest file: ${path}`);
    const stats = lstatSync(candidate);
    if (stats.isSymbolicLink()) throw new Error(`Public manifest paths may not contain symlinks: ${path}`);
    if (index < segments.length - 1 && !stats.isDirectory()) {
      throw new Error(`Public manifest parent is not a directory: ${path}`);
    }
    if (index === segments.length - 1 && !stats.isFile()) {
      throw new Error(`Public manifest entry is not a regular file: ${path}`);
    }
  }
}

function listFiles(root, directory) {
  if (!existsSync(directory)) return [];
  const discovered = [];
  const visit = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolute = join(current, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Staged Hosting output contains a symlink: ${absolute}`);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) discovered.push(toPosix(relative(root, absolute)));
      else throw new Error(`Staged Hosting output contains a non-file entry: ${absolute}`);
    }
  };
  visit(directory);
  return discovered.sort();
}

function sha256(contents) {
  return createHash('sha256').update(contents).digest('hex');
}

function headerMap(entry) {
  return new Map((entry?.headers ?? []).map(({ key, value }) => [key, value]));
}

function assertHeaders(config, source, required) {
  const candidates = (config.hosting.headers ?? []).filter((entry) => entry.source === source);
  if (candidates.length !== 1) throw new Error(`firebase.json must contain exactly one ${source} header rule.`);
  if (Object.keys(candidates[0]).sort().join(',') !== 'headers,source' || !Array.isArray(candidates[0].headers)
      || candidates[0].headers.length !== Object.keys(required).length) {
    throw new Error(`firebase.json ${source} must contain only its reviewed headers.`);
  }
  if (candidates[0].headers.some((header) => Object.keys(header).sort().join(',') !== 'key,value')) {
    throw new Error(`firebase.json ${source} header entries may contain only key and value.`);
  }
  const configured = headerMap(candidates[0]);
  if (configured.size !== candidates[0].headers.length) throw new Error(`firebase.json ${source} contains duplicate header keys.`);
  for (const [key, value] of Object.entries(required)) {
    if (configured.get(key) !== value) throw new Error(`firebase.json ${source} must set ${key} to ${value}.`);
  }
}

export function validateFirebaseConfiguration(root) {
  const firebasePath = join(root, 'firebase.json');
  const projectPath = join(root, '.firebaserc');
  if (!existsSync(firebasePath) || !existsSync(projectPath)) {
    throw new Error('firebase.json and .firebaserc are both required.');
  }
  const config = JSON.parse(readFileSync(firebasePath, 'utf8'));
  const projects = JSON.parse(readFileSync(projectPath, 'utf8'));
  if (Object.keys(config).join(',') !== 'hosting') {
    throw new Error('firebase.json may contain only the reviewed Hosting configuration.');
  }
  if (Object.keys(projects).join(',') !== 'projects' || Object.keys(projects.projects ?? {}).join(',') !== 'default') {
    throw new Error('.firebaserc may contain only the reviewed default project mapping.');
  }
  if (projects.projects?.default !== FIREBASE_PROJECT_ID) {
    throw new Error(`.firebaserc must select ${FIREBASE_PROJECT_ID}.`);
  }
  const hostingKeys = Object.keys(config.hosting ?? {}).sort();
  const expectedHostingKeys = ['headers', 'ignore', 'public', 'site', 'trailingSlash'];
  if (hostingKeys.join(',') !== expectedHostingKeys.join(',')) {
    throw new Error(`firebase.json Hosting keys must be exactly: ${expectedHostingKeys.join(', ')}.`);
  }
  if (config.hosting?.site !== FIREBASE_SITE_ID) {
    throw new Error(`firebase.json must target Hosting site ${FIREBASE_SITE_ID}.`);
  }
  if (config.hosting?.public !== HOSTING_OUTPUT_DIRECTORY) {
    throw new Error(`firebase.json must publish only ${HOSTING_OUTPUT_DIRECTORY}.`);
  }
  if (config.hosting?.trailingSlash !== true) {
    throw new Error('firebase.json must preserve directory URLs with trailingSlash enabled.');
  }
  const expectedIgnore = ['firebase.json', '**/.*', '**/node_modules/**'];
  if (!Array.isArray(config.hosting.ignore) || config.hosting.ignore.join('\n') !== expectedIgnore.join('\n')) {
    throw new Error('firebase.json must retain the exact reviewed ignore list.');
  }
  if (!Array.isArray(config.hosting.headers) || config.hosting.headers.length !== 2) {
    throw new Error('firebase.json must contain exactly the reviewed global and auth header rules.');
  }
  assertHeaders(config, '**', REQUIRED_GLOBAL_HEADERS);
  assertHeaders(config, '/auth/**', REQUIRED_AUTH_HEADERS);
  return config;
}

export function stagePublicSite(root) {
  const repositoryRoot = resolve(root);
  const output = resolve(repositoryRoot, HOSTING_OUTPUT_DIRECTORY);
  assertInside(repositoryRoot, output);
  if (output !== join(repositoryRoot, HOSTING_OUTPUT_DIRECTORY)) {
    throw new Error(`Refusing to clean an unexpected Hosting output path: ${output}`);
  }

  const uniqueFiles = new Set(PUBLIC_FILES);
  if (uniqueFiles.size !== PUBLIC_FILES.length || [...uniqueFiles].sort().join('\n') !== PUBLIC_FILES.join('\n')) {
    throw new Error('PUBLIC_FILES must be unique and sorted.');
  }

  rmSync(output, { recursive: true, force: true });
  try {
    for (const path of PUBLIC_FILES) {
      assertSourceFile(repositoryRoot, path);
      const destination = join(output, ...path.split('/'));
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(join(repositoryRoot, ...path.split('/')), destination);
    }
    writeFileSync(join(output, '.nojekyll'), '');
  } catch (error) {
    rmSync(output, { recursive: true, force: true });
    throw error;
  }
  return output;
}

export function verifyStagedSite(root) {
  const repositoryRoot = resolve(root);
  const output = resolve(repositoryRoot, HOSTING_OUTPUT_DIRECTORY);
  assertInside(repositoryRoot, output);
  validateFirebaseConfiguration(repositoryRoot);
  if (!existsSync(output)) throw new Error(`Missing staged Hosting output: ${output}`);

  const expectedFiles = [...PUBLIC_FILES, ...GENERATED_FILES].sort();
  const actualFiles = listFiles(output, output);
  if (actualFiles.join('\n') !== expectedFiles.join('\n')) {
    const missing = expectedFiles.filter((path) => !actualFiles.includes(path));
    const unexpected = actualFiles.filter((path) => !expectedFiles.includes(path));
    throw new Error(`Staged file set differs from the exact manifest. Missing: ${missing.join(', ') || 'none'}. Unexpected: ${unexpected.join(', ') || 'none'}.`);
  }

  const files = [];
  for (const path of PUBLIC_FILES) {
    assertSourceFile(repositoryRoot, path);
    const source = readFileSync(join(repositoryRoot, ...path.split('/')));
    const staged = readFileSync(join(output, ...path.split('/')));
    const sourceSha256 = sha256(source);
    const stagedSha256 = sha256(staged);
    if (sourceSha256 !== stagedSha256) throw new Error(`Staged bytes differ from source: ${path}`);
    files.push({ path, bytes: staged.length, sha256: stagedSha256 });
  }
  const noJekyll = readFileSync(join(output, '.nojekyll'));
  if (noJekyll.length !== 0) throw new Error('.nojekyll must be empty.');
  files.push({ path: '.nojekyll', bytes: 0, sha256: sha256(noJekyll) });
  files.sort((left, right) => left.path.localeCompare(right.path));

  const manifestDigest = (manifestFiles) => sha256(Buffer.from(manifestFiles.map(({ path, bytes, sha256: digest }) => `${path}\0${bytes}\0${digest}\n`).join('')));
  const contentFiles = files.filter(({ path }) => !GENERATED_FILES.includes(path));
  const contentAggregateSha256 = manifestDigest(contentFiles);
  const stagedArtifactAggregateSha256 = manifestDigest(files);
  const releaseInputs = [...files];
  for (const path of ['.firebaserc', 'firebase.json']) {
    const contents = readFileSync(join(repositoryRoot, path));
    releaseInputs.push({ path, bytes: contents.length, sha256: sha256(contents) });
  }
  releaseInputs.sort((left, right) => left.path.localeCompare(right.path));
  const releaseInputAggregateSha256 = manifestDigest(releaseInputs);
  return Object.freeze({
    target: FIREBASE_AUTH_URL,
    projectId: FIREBASE_PROJECT_ID,
    siteId: FIREBASE_SITE_ID,
    output: HOSTING_OUTPUT_DIRECTORY,
    fileCount: files.length,
    totalBytes: files.reduce((sum, file) => sum + file.bytes, 0),
    contentAggregateSha256,
    stagedArtifactAggregateSha256,
    releaseInputAggregateSha256,
    files
  });
}
