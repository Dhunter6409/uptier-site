import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NEW_ACCOUNT_PASSWORD_MAX_LENGTH,
  NEW_ACCOUNT_PASSWORD_MIN_LENGTH,
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
    .filter((entry) => !['.firebase', '.firebase-site', '.git', '_site', 'node_modules'].includes(entry))
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
const syncKeyFlowPath = join(root, 'auth', 'sync-key-flow.mjs');
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

if (!existsSync(authPortalPath) || !existsSync(authPortalMarkupPath) || !existsSync(syncKeyFlowPath)) {
  errors.push('Missing secure account portal implementation.');
} else {
  const authPortal = readFileSync(authPortalPath, 'utf8');
  const authPortalMarkup = readFileSync(authPortalMarkupPath, 'utf8');
  const syncKeyFlow = readFileSync(syncKeyFlowPath, 'utf8');
  for (const required of [
    "parameters.get('mode') ?? 'sign-in'",
    "actionParameter !== 'sign-in' && actionParameter !== 'delete-account'",
    "if (accountMode === 'create-account' && !deletionMode)",
    'elements.switchAccountMode.hidden = true',
    'showVerificationStep(result.user, verificationEmailSent, expectedIdentity)',
    'await reload(user)',
    'await beginAutomaticMfaSignIn(expectedIdentity)',
    "tokenResult.signInSecondFactor !== 'phone'",
    "tokenResult.signInProvider !== 'password'",
    'parseSyncLaunchFragment(launchSyncFragment',
    'await verifySyncDeviceConfirmation()',
    '/v1/auth/browser/prepare',
    '/v1/auth/browser/authorize',
    'createAppBoundCallbackUrl(syncLaunchContext, payload)',
    'window.location.replace(callbackUrl)',
    'completeDeviceHandoffIfCurrent({'
  ]) {
    if (!authPortal.includes(required)) errors.push(`Secure account portal is missing invariant: ${required}`);
  }
  for (const required of [
    'id="confirm-password"',
    'autocomplete="current-password"',
    'autocomplete="new-password"',
    'data-password-toggle="password"',
    'id="reset-password"',
    'id="sync-confirmation-code"',
    'id="verification-panel"',
    'id="verification-address"',
    'id="check-verification"',
    'id="resend-verification"',
    'id="retry-finish"',
    'Do not create the account or sign in again.',
    'UpTier support will never ask for this code.'
  ]) {
    if (!authPortalMarkup.includes(required)) errors.push(`Secure account markup is missing invariant: ${required}`);
  }

  const validPassword = 'A1b2C3d4';
  if (accountModeForRequest('create-account', false) !== 'create-account') {
    errors.push('Secure account portal must honor an explicit account-creation request.');
  }
  if (accountModeForRequest('create-account', true) !== 'sign-in') {
    errors.push('Permanent deletion must remain isolated from account-creation mode.');
  }
  if (NEW_ACCOUNT_PASSWORD_MIN_LENGTH !== 8
      || NEW_ACCOUNT_PASSWORD_MAX_LENGTH !== 20
      || !validateNewPassword('A1b2C3d', 'A1b2C3d')
      || !validateNewPassword('A1b2C3d4E5f6G7h8I9j0K', 'A1b2C3d4E5f6G7h8I9j0K')
      || !validateNewPassword(validPassword, `${validPassword}!`)) {
    errors.push('Secure account creation must reject short or mismatched passwords.');
  }
  if (validateNewPassword(validPassword, validPassword)) {
    errors.push('Secure account creation must accept a matching password within the allowed length.');
  }
  const configureAccountModeStart = authPortal.indexOf('function configureAccountMode');
  const resetPasswordVisibilityStart = authPortal.indexOf('function resetPasswordVisibility', configureAccountModeStart);
  const configureAccountMode = authPortal.slice(configureAccountModeStart, resetPasswordVisibilityStart);
  if (!configureAccountMode.includes('elements.password.minLength = creating ? NEW_ACCOUNT_PASSWORD_MIN_LENGTH : 0')
      || !configureAccountMode.includes('elements.password.maxLength = creating ? NEW_ACCOUNT_PASSWORD_MAX_LENGTH : 128')
      || !authPortalMarkup.includes('id="password" name="password" type="password" autocomplete="current-password" maxlength="128"')
      || !authPortalMarkup.includes('id="confirm-password" name="confirm-password" type="password" autocomplete="new-password" minlength="8" maxlength="20"')) {
    errors.push('New-account password fields must enforce 8 to 20 characters without limiting existing-account sign-in below 128.');
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
  for (const required of [
    "'P-256-HKDF-SHA256-AES-256-GCM'",
    "encoder.encode('UpTier password key v1\\0')",
    "encoder.encode(`UpTier profile sync key handoff v1\\0${contextJson}`)",
    "purpose: 'uptier-profile-sync-password-key-handoff'",
    '`UpTier device confirmation v1\\0${syncContext.requestId}\\0${code}`',
    'deviceConfirmationHash: value.deviceConfirmationHash',
    'fragment.length > 4096',
    'maximumDecodedBytes: 3072',
    'iterations: PASSWORD_KDF_ITERATIONS',
    "hash: 'SHA-256'"
  ]) {
    if (!syncKeyFlow.includes(required)) errors.push(`Secure account-sync crypto is missing invariant: ${required}`);
  }
  if (/localStorage|sessionStorage|indexedDB|console\./.test(syncKeyFlow)
      || /password\s*[:,]\s*password/i.test(syncKeyFlow)) {
    errors.push('Account-sync cryptography must not persist or log passwords or key material.');
  }
  if (/JSON\.stringify\([^)]*syncConfirmationCode|body:[\s\S]{0,240}syncConfirmationCode/.test(authPortal)) {
    errors.push('The six-digit device confirmation code must never leave the auth portal.');
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
    if (/validateNewPassword/.test(primarySignIn)
        || !primarySignIn.includes('signInWithEmailAndPassword(auth, email, password)')) {
      errors.push('Existing-account sign-in must accept the prior password range without applying new-account length validation.');
    }
    const newPasswordValidationAt = accountCreation.indexOf('validateNewPassword(password, elements.confirmPassword.value)');
    const createIdentityAt = accountCreation.indexOf('createUserWithEmailAndPassword(auth, email, password)');
    if (newPasswordValidationAt === -1 || createIdentityAt === -1 || newPasswordValidationAt > createIdentityAt) {
      errors.push('Account creation must validate the 8 to 20 character password before creating the identity.');
    }
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
  const signOutAt = automaticReplay.indexOf('await signOut(auth)');
  const replayAt = automaticReplay.indexOf('await signInWithEmailAndPassword(auth, email, password)');
  if (automaticReplayStart === -1 || backendExchangeStart === -1
      || signOutAt === -1 || replayAt === -1 || signOutAt > replayAt
      || automaticReplay.includes("pendingSetupPassword = ''")
      || !automaticReplay.includes("error?.code !== 'auth/multi-factor-auth-required'")) {
    errors.push('Automatic post-enrollment sign-in must retain the password only in memory through the required Firebase MFA challenge.');
  }

  const smsSendStart = authPortal.indexOf('async function sendMfaCode');
  const smsSendEnd = authPortal.indexOf('function showVerificationStep', smsSendStart);
  const smsSend = authPortal.slice(smsSendStart, smsSendEnd);
  if (smsSendStart === -1 || smsSendEnd === -1
      || !smsSend.includes('const provider = new PhoneAuthProvider(auth)')
      || !smsSend.includes('await provider.verifyPhoneNumber(options, recaptchaVerifier)')
      || !smsSend.includes("setStatus('Security code sent. It may take a moment to arrive.', 'success')")
      || !authPortal.includes('enter only the security code sent to your phone. No separate code from the app is required')) {
    errors.push('iPhone sign-in must request a Firebase SMS code and clearly omit the separate UpTier device-code prompt.');
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
  const phoneClaimAt = backendExchange.indexOf("tokenResult.signInSecondFactor !== 'phone'");
  const passwordClaimAt = backendExchange.indexOf("tokenResult.signInProvider !== 'password'");
  const prepareAt = backendExchange.indexOf("fetch(`${apiOrigin}/v1/auth/browser/prepare`");
  const authorizeDefinitionAt = backendExchange.indexOf("fetch(`${apiOrigin}/v1/auth/browser/authorize`");
  const handoffAt = backendExchange.indexOf('createHandoff: () => createDeviceHandoff');
  const clearSyncPasswordAt = backendExchange.indexOf("pendingSetupPassword = ''", handoffAt);
  const retainHandoffAt = backendExchange.indexOf('pendingDeviceHandoff = deviceHandoff', clearSyncPasswordAt);
  const legacyCompleteAt = backendExchange.indexOf(': completeRequest(deviceHandoff)', clearSyncPasswordAt);
  const authorizeAt = backendExchange.indexOf('? authorizeAppBoundRequest(deviceHandoff)', clearSyncPasswordAt);
  const callbackAt = backendExchange.indexOf('createAppBoundCallbackUrl(syncLaunchContext, payload)', authorizeAt);
  const redirectAt = backendExchange.indexOf('window.location.replace(callbackUrl)', callbackAt);
  if (backendExchangeStart === -1 || backendExchangeEnd === -1
      || phoneClaimAt === -1 || passwordClaimAt === -1
      || legacyCompleteAt === -1 || authorizeAt === -1
      || !(phoneClaimAt < legacyCompleteAt && passwordClaimAt < legacyCompleteAt
        && phoneClaimAt < authorizeAt && passwordClaimAt < authorizeAt)) {
    errors.push('The portal must verify fresh password-primary and phone second-factor claims before the backend exchange.');
  }
  if (prepareAt === -1 || authorizeDefinitionAt === -1 || handoffAt === -1
      || clearSyncPasswordAt === -1 || retainHandoffAt === -1
      || !(phoneClaimAt < prepareAt && passwordClaimAt < prepareAt
        && prepareAt < handoffAt && handoffAt < clearSyncPasswordAt
        && clearSyncPasswordAt < retainHandoffAt
        && retainHandoffAt < legacyCompleteAt && retainHandoffAt < authorizeAt)
      || /JSON\.stringify\(\{[^}]*password/i.test(backendExchange)) {
    errors.push('Account sync must derive and encrypt its password key after MFA, clear the temporary password, and never send the password to UpTier.');
  }
  if (authorizeDefinitionAt === -1
      || !backendExchange.includes('pkceChallenge: appBoundSyncLaunch().codeChallenge')
      || !backendExchange.includes('deviceHandoff')
      || callbackAt === -1 || redirectAt === -1 || callbackAt > redirectAt
      || !authPortal.includes('return Boolean(syncLaunchContext && !appBoundSyncLaunch())')
      || !authPortal.includes('if (requiresManualDeviceConfirmation())')
      || !authPortal.includes("document.body.dataset.appBoundAuth = 'true'")
      || !authPortal.includes('elements.syncConfirmationField.hidden = true')
      || !authPortal.includes('elements.syncConfirmationCode.required = false')
      || !syncKeyFlow.includes("export const APP_BOUND_CALLBACK_URL = 'com.uptier.app.auth://account-sign-in/callback'")
      || !syncKeyFlow.includes("parsed.appBoundAuth.codeChallengeMethod !== 'S256'")) {
    errors.push('App-bound iPhone sign-in must retain SMS MFA, bind the encrypted handoff to PKCE, skip only the legacy device-code prompt, and return only through the fixed UpTier callback.');
  }
  if (/console\.|location\.(?:assign|replace)\(syncLaunchContext|callbackUrl\s*=\s*syncLaunchContext\.appBoundAuth\.callbackUrl/.test(backendExchange)) {
    errors.push('App-bound sign-in must not log secrets or navigate to a callback supplied directly by the launch payload.');
  }
  const lifecycleCreateAt = syncKeyFlow.indexOf('const deviceHandoff = await createHandoff()');
  const lifecycleFirstGuardAt = syncKeyFlow.indexOf('if (!isCurrent())', lifecycleCreateAt);
  const lifecycleTransitionAt = syncKeyFlow.indexOf('beforeComplete()', lifecycleFirstGuardAt);
  const lifecycleSecondGuardAt = syncKeyFlow.indexOf('if (!isCurrent())', lifecycleTransitionAt);
  const lifecycleCompleteAt = syncKeyFlow.indexOf('await complete(deviceHandoff)', lifecycleSecondGuardAt);
  if (lifecycleCreateAt === -1 || lifecycleFirstGuardAt === -1 || lifecycleTransitionAt === -1
      || lifecycleSecondGuardAt === -1 || lifecycleCompleteAt === -1
      || !(lifecycleCreateAt < lifecycleFirstGuardAt && lifecycleFirstGuardAt < lifecycleTransitionAt
        && lifecycleTransitionAt < lifecycleSecondGuardAt && lifecycleSecondGuardAt < lifecycleCompleteAt)
      || !backendExchange.includes('auth.currentUser?.uid === originalUserUid')
      || !backendExchange.includes('expectedIdentity === pendingIdentity')) {
    errors.push('Device handoff completion must fail closed after crypto and immediately before complete when setup identity changes.');
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

