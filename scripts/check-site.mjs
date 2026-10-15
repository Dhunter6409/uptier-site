import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SETUP_MEMORY_TIMEOUT_MS,
  VERIFICATION_RESEND_COOLDOWN_MS,
  accountCreationOutcome,
  accountModeForRequest,
  validateNewPassword,
  verificationResendWaitSeconds
} from '../auth/account-flow.mjs';

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
    'showVerificationStep(result.user, verificationEmailSent, expectedIdentity)',
    'await reload(user)',
    'await beginAutomaticMfaSignIn(expectedIdentity)',
    "tokenResult.signInSecondFactor !== 'phone'"
  ]) {
    if (!authPortal.includes(required)) errors.push(`Secure account portal is missing invariant: ${required}`);
  }
  for (const required of [
    'id="confirm-password"',
    'autocomplete="current-password"',
    'autocomplete="new-password"',
    'data-password-toggle="password"',
    'id="reset-password"',
    'id="verification-panel"',
    'id="verification-address"',
    'id="check-verification"',
    'id="resend-verification"',
    'id="retry-finish"',
    'Do not create the account or sign in again.'
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
  const deliveryFailure = accountCreationOutcome(false);
  const creationSuccess = accountCreationOutcome(true);
  if (deliveryFailure.tone !== 'error' || !deliveryFailure.message.includes('account was created') || !deliveryFailure.message.includes('Stay on this page')) {
    errors.push('Verification-email failure must preserve the created-account recovery path.');
  }
  if (creationSuccess.tone !== 'success' || !creationSuccess.message.includes('return to this same page') || !creationSuccess.message.includes('without asking for your password again')) {
    errors.push('Successful account creation must keep the user in one continuous browser setup.');
  }
  if (VERIFICATION_RESEND_COOLDOWN_MS !== 60_000
      || verificationResendWaitSeconds(10_000, 10_000) !== 60
      || verificationResendWaitSeconds(10_000, 69_001) !== 1
      || verificationResendWaitSeconds(10_000, 70_000) !== 0) {
    errors.push('Verification-email resend must enforce the one-minute cooldown deterministically.');
  }
  if (SETUP_MEMORY_TIMEOUT_MS >= 10 * 60_000
      || !authPortal.includes('window.setTimeout(expireSetupMemory, SETUP_MEMORY_TIMEOUT_MS)')
      || !/auth = initializeAuth\(firebaseApp, \{ persistence: inMemoryPersistence \}\);\s+armSetupMemoryDeadline\(\);/.test(authPortal)) {
    errors.push('Memory-only setup credentials must expire before the ten-minute browser request.');
  }
  if (/localStorage|sessionStorage|indexedDB/.test(authPortal)) {
    errors.push('The secure account portal must never persist temporary credentials or auth state in browser storage.');
  }

  const primarySignInStart = authPortal.indexOf('async function handlePrimarySignIn');
  const accountCreationStart = authPortal.indexOf('async function handleAccountCreation', primarySignInStart);
  const initializationStart = authPortal.indexOf("let apiOrigin = ''", accountCreationStart);
  const primarySignIn = authPortal.slice(primarySignInStart, accountCreationStart);
  const accountCreation = authPortal.slice(accountCreationStart, initializationStart);
  if (primarySignInStart === -1 || accountCreationStart === -1 || initializationStart === -1) {
    errors.push('Secure account portal is missing the expected sign-in and account-creation boundaries.');
  } else {
    if (/sendEmailVerification/.test(primarySignIn)) errors.push('Unverified sign-in must not automatically send another verification email.');
    if (!/rememberPendingIdentity\(result\.user, password\)[\s\S]*showVerificationStep\(result\.user, false, expectedIdentity\)/.test(primarySignIn)) {
      errors.push('Unverified sign-in must retain the memory-only setup session and show the verification step.');
    }
    const retainedCreation = accountCreation.slice(accountCreation.indexOf('const expectedIdentity = rememberPendingIdentity'));
    if (/signOut\(auth\)/.test(retainedCreation) || !/showVerificationStep\(result\.user, verificationEmailSent, expectedIdentity\)/.test(accountCreation)) {
      errors.push('Account creation must stay signed in and advance to the dedicated verification step.');
    }
  }

  const resendStart = authPortal.indexOf("elements.resendVerification.addEventListener('click'");
  const resendEnd = authPortal.indexOf("elements.useDifferentEmail.addEventListener('click'", resendStart);
  const resendHandler = authPortal.slice(resendStart, resendEnd);
  if (resendStart === -1 || resendEnd === -1 || !/const user = auth\.currentUser/.test(resendHandler) || /signInWithEmailAndPassword/.test(resendHandler)) {
    errors.push('Verification resend must use only the already signed-in user and never replay the password.');
  }
  const verificationEmailSendCount = (authPortal.match(/await sendEmailVerification\(/g) ?? []).length;
  if (verificationEmailSendCount !== 2
      || !accountCreation.includes('await sendEmailVerification(result.user)')
      || !resendHandler.includes('await sendEmailVerification(user)')) {
    errors.push('Verification email may be sent only during account creation or an explicit resend request.');
  }

  const automaticReplayStart = authPortal.indexOf('async function beginAutomaticMfaSignIn');
  const backendExchangeStart = authPortal.indexOf('async function finishBackendExchange', automaticReplayStart);
  const automaticReplay = authPortal.slice(automaticReplayStart, backendExchangeStart);
  const clearPasswordAt = automaticReplay.indexOf("pendingSetupPassword = ''");
  const signOutAt = automaticReplay.indexOf('await signOut(auth)');
  const replayAt = automaticReplay.indexOf('await signInWithEmailAndPassword(auth, email, password)');
  if (automaticReplayStart === -1 || backendExchangeStart === -1
      || clearPasswordAt === -1 || signOutAt === -1 || replayAt === -1
      || !(clearPasswordAt < signOutAt && signOutAt < replayAt)
      || !automaticReplay.includes("error?.code !== 'auth/multi-factor-auth-required'")) {
    errors.push('Automatic post-enrollment sign-in must clear the password first and advance only through Firebase MFA-required.');
  }

  const enrollmentStart = authPortal.indexOf("elements.enrollForm.addEventListener('submit'");
  const codeStart = authPortal.indexOf("elements.codeForm.addEventListener('submit'", enrollmentStart);
  const enrollmentHandler = authPortal.slice(enrollmentStart, codeStart);
  if (enrollmentStart === -1 || codeStart === -1
      || enrollmentHandler.indexOf('await reauthenticateWithCredential(user, credential)') === -1
      || enrollmentHandler.indexOf('await multiFactor(user).getSession()') === -1
      || enrollmentHandler.indexOf('await reauthenticateWithCredential(user, credential)') > enrollmentHandler.indexOf('await multiFactor(user).getSession()')) {
    errors.push('SMS enrollment must reauthenticate the same pending identity before creating the enrollment session.');
  }

  const codeHandler = authPortal.slice(codeStart);
  const enrollAt = codeHandler.indexOf("await multiFactor(user).enroll(assertion, 'UpTier mobile')");
  const committedAt = codeHandler.indexOf('enrollmentCommitted = true', enrollAt);
  const modeAt = codeHandler.indexOf("verificationMode = 'enrolled'", committedAt);
  const verificationClearAt = codeHandler.indexOf("verificationId = ''", modeAt);
  const smsClearAt = codeHandler.indexOf("elements.smsCode.value = ''", verificationClearAt);
  const tokenRefreshAt = codeHandler.indexOf('tokenResult = await user.getIdTokenResult(true)', smsClearAt);
  if (codeStart === -1
      || enrollAt === -1
      || committedAt === -1
      || modeAt === -1
      || verificationClearAt === -1
      || smsClearAt === -1
      || tokenRefreshAt === -1
      || !(enrollAt < committedAt && committedAt < modeAt && modeAt < verificationClearAt
        && verificationClearAt < smsClearAt && smsClearAt < tokenRefreshAt)
      || !/catch \{[\s\S]*await beginAutomaticMfaSignIn\(expectedIdentity\)/.test(codeHandler)
      || !/else if \(enrollmentCommitted\)[\s\S]*showManualSignInRecovery/.test(codeHandler)) {
    errors.push('Committed SMS enrollment must clear the consumed challenge and recover without repeating enrollment.');
  }

  const backendExchangeEnd = authPortal.indexOf('async function handlePrimarySignIn', backendExchangeStart);
  const backendExchange = authPortal.slice(backendExchangeStart, backendExchangeEnd);
  if (backendExchangeStart === -1 || backendExchangeEnd === -1
      || backendExchange.indexOf("tokenResult.signInSecondFactor !== 'phone'") === -1
      || backendExchange.indexOf("tokenResult.signInSecondFactor !== 'phone'") > backendExchange.indexOf("fetch(`${apiOrigin}/v1/auth/browser/complete`")) {
    errors.push('The portal must verify a fresh phone second-factor claim before the backend exchange.');
  }
  if (!authPortal.includes('pendingExchangeUser = user;')
      || !authPortal.includes("elements.retryFinish.addEventListener('click'")) {
    errors.push('An MFA-authenticated session must support retrying a transient backend handoff without another sign-in.');
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
