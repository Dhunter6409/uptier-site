import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { accountCreationOutcome, accountModeForRequest, validateNewPassword } from '../auth/account-flow.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const errors = [];

function walk(directory) {
  return readdirSync(directory)
    .filter((entry) => entry !== '.git' && entry !== '_site')
    .flatMap((entry) => {
      const candidate = join(directory, entry);
      return statSync(candidate).isDirectory() ? walk(candidate) : [candidate];
    });
}

const files = walk(root);
const htmlFiles = files.filter((file) => extname(file) === '.html');

const previewIndexPath = join(root, 'app-preview', 'index.html');
if (!existsSync(previewIndexPath)) {
  errors.push('Missing public mobile preview entry page.');
} else {
  const previewIndex = readFileSync(previewIndexPath, 'utf8');
  if (!/<meta\s[^>]*name="robots"\s[^>]*content="noindex,nofollow"/i.test(previewIndex)) {
    errors.push('Mobile preview must remain excluded from search indexing.');
  }
  if (/@vite\/client|react-refresh/i.test(previewIndex)) {
    errors.push('Mobile preview must use the production renderer, not development startup scripts.');
  }
}

const authConfigPath = join(root, 'auth', 'config.js');
const authPortalPath = join(root, 'auth', 'app.js');
const authPortalMarkupPath = join(root, 'auth', 'index.html');
const premiumReturnPaths = [
  join(root, 'premium', 'index.html'),
  join(root, 'premium', 'success', 'index.html'),
  join(root, 'premium', 'cancel', 'index.html')
];
const productionBackendOrigin = 'https://uptier-plaid-backend-1076418370349.us-central1.run.app';
if (!existsSync(authConfigPath)) {
  errors.push('Missing secure account portal configuration.');
} else {
  const authConfig = readFileSync(authConfigPath, 'utf8');
  if (!authConfig.includes(`'${productionBackendOrigin}'`)) {
    errors.push('Secure account portal must allow the deployed UpTier backend origin.');
  }
}

if (!existsSync(authPortalPath) || !existsSync(authPortalMarkupPath)) {
  errors.push('Missing secure account portal implementation.');
} else {
  const authPortal = readFileSync(authPortalPath, 'utf8');
  const authPortalMarkup = readFileSync(authPortalMarkupPath, 'utf8');
  for (const required of [
    "parameters.get('mode') ?? 'sign-in'",
    "actionParameter !== 'sign-in' && actionParameter !== 'delete-account'",
    "if (accountMode === 'create-account' && !deletionMode)",
    'elements.switchAccountMode.hidden = true',
    'accountCreationOutcome(verificationEmailSent, signedOut)'
  ]) {
    if (!authPortal.includes(required)) errors.push(`Secure account portal is missing invariant: ${required}`);
  }
  for (const required of [
    'id="confirm-password"',
    'autocomplete="current-password"',
    'autocomplete="new-password"',
    'data-password-toggle="password"',
    'id="reset-password"'
  ]) {
    if (!authPortalMarkup.includes(required)) errors.push(`Secure account markup is missing invariant: ${required}`);
  }

  const validPassword = 'correct horse battery staple';
  if (accountModeForRequest('create-account', false) !== 'create-account') {
    errors.push('Secure account portal must honor an explicit account-creation request.');
  }
  if (accountModeForRequest('create-account', true) !== 'sign-in') {
    errors.push('Permanent deletion must remain isolated from account-creation mode.');
  }
  if (!validateNewPassword('too-short', 'too-short') || !validateNewPassword(validPassword, `${validPassword}!`)) {
    errors.push('Secure account creation must reject short or mismatched passwords.');
  }
  if (validateNewPassword(validPassword, validPassword)) {
    errors.push('Secure account creation must accept a matching password within the allowed length.');
  }
  const deliveryFailure = accountCreationOutcome(false, true);
  const signOutFailure = accountCreationOutcome(true, false);
  const creationSuccess = accountCreationOutcome(true, true);
  if (deliveryFailure.tone !== 'error' || !deliveryFailure.message.includes('account was created') || !deliveryFailure.message.includes('Resend verification email')) {
    errors.push('Verification-email failure must preserve the created-account recovery path.');
  }
  if (signOutFailure.tone !== 'error' || !signOutFailure.message.includes('could not finish signing out')) {
    errors.push('Account creation must explain the close-page fallback when browser sign-out fails.');
  }
  if (creationSuccess.tone !== 'success' || !creationSuccess.message.includes('fresh secure request') || /return here/i.test(creationSuccess.message)) {
    errors.push('Successful account creation must direct the user to a fresh secure sign-in request.');
  }
}

for (const premiumReturnPath of premiumReturnPaths) {
  if (!existsSync(premiumReturnPath)) {
    errors.push(`Missing Stripe return page: ${premiumReturnPath}`);
    continue;
  }
  const premiumReturn = readFileSync(premiumReturnPath, 'utf8');
  if (!/name="robots"\s+content="noindex, nofollow"/i.test(premiumReturn)) {
    errors.push(`${premiumReturnPath}: Stripe return pages must remain excluded from search indexing.`);
  }
  if (!premiumReturn.toLowerCase().includes('return to uptier')) {
    errors.push(`${premiumReturnPath}: Stripe return page must direct the user back to UpTier.`);
  }
}

for (const file of htmlFiles) {
  const content = readFileSync(file, 'utf8');
  if (!/^<!doctype html>/i.test(content)) errors.push(`${file}: missing HTML doctype`);
  if (!/<html\s[^>]*lang="en"/i.test(content)) errors.push(`${file}: missing English language declaration`);
  if (!/<meta\s[^>]*name="viewport"/i.test(content)) errors.push(`${file}: missing viewport metadata`);
  if (!/<title>[^<]+<\/title>/i.test(content)) errors.push(`${file}: missing page title`);

  for (const match of content.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const reference = match[1];
    if (/^(?:https?:|mailto:|tel:|#)/i.test(reference)) continue;
    const cleanReference = reference.split(/[?#]/, 1)[0];
    if (!cleanReference) continue;
    let target;
    if (cleanReference.startsWith('/uptier-site/')) {
      target = resolve(root, cleanReference.slice('/uptier-site/'.length));
    } else if (cleanReference === '/uptier-site') {
      target = root;
    } else {
      target = resolve(dirname(file), cleanReference);
    }
    if (cleanReference.endsWith('/') || (existsSync(target) && statSync(target).isDirectory())) target = join(target, 'index.html');
    if (!existsSync(target)) errors.push(`${file}: broken local reference ${reference}`);
  }
}

const publicText = files
  .filter((file) => ['.html', '.md', '.xml', '.txt', '.yml'].includes(extname(file)))
  .map((file) => readFileSync(file, 'utf8'))
  .join('\n');

if (/github\.com\/Dhunter6409\/UpTier(?:\/|\.git|["'\s]|$)/i.test(publicText)) {
  errors.push('Public website must not link to the private application repository.');
}

for (const required of [
  'Sandbox and private Trial under validation',
  'invitation-only real-data Trial',
  'UpTier does not sell personal information',
  'Data Deletion',
  'uptier.support@gmail.com',
  'Email private support'
]) {
  if (!publicText.includes(required)) errors.push(`Missing required public content: ${required}`);
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`Validated ${htmlFiles.length} HTML pages and ${files.length} public repository files.`);
