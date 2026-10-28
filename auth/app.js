import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.16.0/firebase-app.js';
import {
  EmailAuthProvider,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator,
  RecaptchaVerifier,
  createUserWithEmailAndPassword,
  deleteUser,
  getMultiFactorResolver,
  inMemoryPersistence,
  initializeAuth,
  multiFactor,
  reauthenticateWithCredential,
  reload,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut
} from 'https://www.gstatic.com/firebasejs/12.16.0/firebase-auth.js';
import {
  NEW_ACCOUNT_PASSWORD_MAX_LENGTH,
  NEW_ACCOUNT_PASSWORD_MIN_LENGTH,
  SETUP_MEMORY_TIMEOUT_MS,
  accountCreationOutcome,
  accountModeForRequest,
  validateNewPassword,
  verificationResendWaitSeconds
} from './account-flow.mjs';
import { allowedBackendOrigins, firebaseConfig } from './config.js';
import {
  completeDeviceHandoffIfCurrent,
  createAppBoundCallbackUrl,
  createDeviceHandoff,
  normalizePrepareResponse,
  parseSyncLaunchFragment,
  verifyDeviceConfirmationCode
} from './sync-key-flow.mjs';

const elements = {
  status: document.querySelector('#status'),
  requestState: document.querySelector('#request-state'),
  accountForm: document.querySelector('#account-form'),
  verificationPanel: document.querySelector('#verification-panel'),
  enrollForm: document.querySelector('#enroll-form'),
  codeForm: document.querySelector('#code-form'),
  completePanel: document.querySelector('#complete-panel'),
  email: document.querySelector('#email'),
  password: document.querySelector('#password'),
  confirmPassword: document.querySelector('#confirm-password'),
  confirmPasswordField: document.querySelector('#confirm-password-field'),
  passwordGuidance: document.querySelector('#password-guidance'),
  syncConfirmationField: document.querySelector('#sync-confirmation-field'),
  syncConfirmationCode: document.querySelector('#sync-confirmation-code'),
  phone: document.querySelector('#phone'),
  smsConsent: document.querySelector('#sms-consent'),
  smsCode: document.querySelector('#sms-code'),
  signIn: document.querySelector('#sign-in'),
  createAccount: document.querySelector('#create-account'),
  switchAccountMode: document.querySelector('#switch-account-mode'),
  signInHelp: document.querySelector('#sign-in-help'),
  verificationAddress: document.querySelector('#verification-address'),
  checkVerification: document.querySelector('#check-verification'),
  resendVerification: document.querySelector('#resend-verification'),
  useDifferentEmail: document.querySelector('#use-different-email'),
  resetPassword: document.querySelector('#reset-password'),
  sendEnrollmentCode: document.querySelector('#send-enrollment-code'),
  verifyCode: document.querySelector('#verify-code'),
  codeTitle: document.querySelector('#code-title'),
  codeHelp: document.querySelector('#code-help'),
  introEyebrow: document.querySelector('.auth-intro .eyebrow'),
  introTitle: document.querySelector('#auth-title'),
  introLead: document.querySelector('#auth-lead'),
  deleteWarning: document.querySelector('#delete-warning'),
  formTitle: document.querySelector('#form-title'),
  completeTitle: document.querySelector('#complete-title'),
  completeMessage: document.querySelector('#complete-message'),
  retryFinish: document.querySelector('#retry-finish')
};

const parameters = new URLSearchParams(window.location.search);
const requestToken = parameters.get('request') ?? '';
const apiParameter = parameters.get('api') ?? '';
const actionParameter = parameters.get('action') ?? 'sign-in';
const modeParameter = parameters.get('mode') ?? 'sign-in';
const deletionMode = actionParameter === 'delete-account';
let accountMode = accountModeForRequest(modeParameter, deletionMode);
const launchSyncFragment = window.location.hash;
window.history.replaceState({}, document.title, window.location.pathname);

let auth;
let recaptchaVerifier;
let verificationId = '';
let verificationMode = '';
let signInResolver;
let pendingIdentity;
let pendingSetupPassword = '';
let verificationEmailSentAt = 0;
let resendCooldownTimer;
let verificationRefreshInFlight = false;
let busy = false;
let pendingExchangeUser;
let setupMemoryTimer;
let setupGeneration = 0;
let syncLaunchContext;
let pendingDeviceHandoff;
let deviceConfirmationVerified = false;

function appBoundSyncLaunch() {
  return syncLaunchContext?.appBoundAuth;
}

function requiresManualDeviceConfirmation() {
  return Boolean(syncLaunchContext && !appBoundSyncLaunch());
}

function setStatus(message, tone = 'working') {
  elements.status.textContent = message;
  elements.status.dataset.tone = tone;
}

function showPanel(panel) {
  for (const candidate of [elements.accountForm, elements.verificationPanel, elements.enrollForm, elements.codeForm, elements.completePanel]) {
    candidate.hidden = candidate !== panel;
  }
}

function updateVerificationResendButton() {
  const waitSeconds = verificationResendWaitSeconds(verificationEmailSentAt);
  elements.resendVerification.textContent = waitSeconds > 0
    ? `Resend email in ${waitSeconds}s`
    : 'Resend verification email';
  elements.resendVerification.disabled = busy || waitSeconds > 0;
  if (waitSeconds === 0 && resendCooldownTimer) {
    window.clearInterval(resendCooldownTimer);
    resendCooldownTimer = undefined;
  }
}

function startVerificationResendCooldown() {
  verificationEmailSentAt = Date.now();
  if (resendCooldownTimer) window.clearInterval(resendCooldownTimer);
  resendCooldownTimer = window.setInterval(updateVerificationResendButton, 1_000);
  updateVerificationResendButton();
}

function setBusy(nextBusy) {
  busy = nextBusy;
  for (const button of document.querySelectorAll('button')) button.disabled = nextBusy;
  updateVerificationResendButton();
}

function clearSensitiveSetupState({ clearIdentity = false } = {}) {
  pendingSetupPassword = '';
  pendingDeviceHandoff = undefined;
  deviceConfirmationVerified = false;
  elements.password.value = '';
  elements.confirmPassword.value = '';
  elements.smsCode.value = '';
  elements.syncConfirmationCode.value = '';
  verificationId = '';
  verificationMode = '';
  signInResolver = undefined;
  if (clearIdentity) {
    setupGeneration += 1;
    pendingIdentity = undefined;
    pendingExchangeUser = undefined;
  }
}

async function verifySyncDeviceConfirmation() {
  if (!requiresManualDeviceConfirmation() || deviceConfirmationVerified) return;
  const code = elements.syncConfirmationCode.value;
  elements.syncConfirmationCode.value = '';
  if (!/^\d{6}$/.test(code)) {
    elements.syncConfirmationCode.focus();
    throw new Error('Enter the six-digit code shown in the UpTier app you just opened.');
  }
  if (!await verifyDeviceConfirmationCode(code, syncLaunchContext)) {
    elements.syncConfirmationCode.focus();
    throw new Error('That device confirmation code does not match this UpTier request. Return to the app and use the current code.');
  }
  deviceConfirmationVerified = true;
}

async function expireSetupMemory() {
  setupMemoryTimer = undefined;
  const email = pendingIdentity?.email ?? '';
  clearSensitiveSetupState({ clearIdentity: true });
  try { if (auth.currentUser) await signOut(auth); } catch { /* Closing the page clears the memory-only session. */ }
  configureAccountMode('sign-in', { preserveStatus: true });
  showPanel(elements.accountForm);
  elements.email.value = email;
  setStatus('This secure setup window expired, so the temporary credential was cleared. Return to UpTier and start one fresh sign-in.', 'error');
}

function armSetupMemoryDeadline() {
  if (setupMemoryTimer) window.clearTimeout(setupMemoryTimer);
  setupMemoryTimer = window.setTimeout(expireSetupMemory, SETUP_MEMORY_TIMEOUT_MS);
}

function clearSetupMemoryDeadline() {
  if (setupMemoryTimer) window.clearTimeout(setupMemoryTimer);
  setupMemoryTimer = undefined;
}

function rememberPendingIdentity(user, password) {
  setupGeneration += 1;
  pendingIdentity = {
    uid: user.uid,
    email: (user.email ?? '').trim().toLowerCase(),
    generation: setupGeneration
  };
  pendingSetupPassword = password;
  return pendingIdentity;
}

function requirePendingIdentity(user, expectedIdentity = pendingIdentity) {
  if (!expectedIdentity || expectedIdentity !== pendingIdentity || expectedIdentity.generation !== setupGeneration) {
    throw new Error('This setup step was replaced. Continue only with the currently displayed secure account flow.');
  }
  const email = (user.email ?? '').trim().toLowerCase();
  if (user.uid !== expectedIdentity.uid || email !== expectedIdentity.email) {
    clearSensitiveSetupState({ clearIdentity: true });
    void signOut(auth).catch(() => {});
    throw new Error('The secure browser account changed during setup. Start a fresh secure sign-in from UpTier.');
  }
  return expectedIdentity;
}

function isCurrentSetupGeneration(expectedGeneration) {
  return expectedGeneration === setupGeneration;
}

function isCurrentPendingIdentity(expectedIdentity) {
  return Boolean(expectedIdentity
    && expectedIdentity === pendingIdentity
    && expectedIdentity.generation === setupGeneration);
}

function assertPendingIdentity(user) {
  if (pendingIdentity) requirePendingIdentity(user, pendingIdentity);
}

function configureAccountMode(mode, options = {}) {
  if (deletionMode) return;
  accountMode = mode === 'create-account' ? 'create-account' : 'sign-in';
  const creating = accountMode === 'create-account';
  document.body.dataset.accountMode = accountMode;
  document.title = creating ? 'Create secure account | UpTier' : 'Secure account sign-in | UpTier';
  elements.introEyebrow.textContent = creating ? 'CREATE YOUR UPTIER ACCOUNT' : 'SECURE CONNECTED PORTFOLIO';
  elements.introTitle.textContent = creating
    ? 'Create one secure account for your protected UpTier profile.'
    : 'Sign in without sharing credentials with the desktop app.';
  elements.introLead.textContent = creating
    ? 'Choose your email and a unique password here in the secure browser. After email verification, UpTier adds SMS protection before connecting the account to the app.'
    : appBoundSyncLaunch()
      ? 'Sign in with your UpTier email and password, then enter only the security code sent to your phone. No separate code from the app is required; after SMS verification, this page returns directly to UpTier.'
      : 'Google Identity verifies your email and second factor in this browser. UpTier receives only a short-lived identity proof and exchanges it for its own protected session.';
  elements.formTitle.textContent = creating ? 'Create your account' : 'Sign in to UpTier';
  elements.password.autocomplete = creating ? 'new-password' : 'current-password';
  elements.password.minLength = creating ? NEW_ACCOUNT_PASSWORD_MIN_LENGTH : 0;
  elements.password.maxLength = creating ? NEW_ACCOUNT_PASSWORD_MAX_LENGTH : 128;
  elements.confirmPasswordField.hidden = !creating;
  elements.confirmPassword.required = creating;
  elements.confirmPassword.minLength = creating ? NEW_ACCOUNT_PASSWORD_MIN_LENGTH : 0;
  elements.confirmPassword.maxLength = NEW_ACCOUNT_PASSWORD_MAX_LENGTH;
  elements.confirmPassword.value = '';
  elements.passwordGuidance.hidden = !creating;
  elements.signIn.hidden = creating;
  elements.createAccount.hidden = !creating;
  elements.signInHelp.hidden = creating;
  elements.switchAccountMode.textContent = creating ? 'Already have an account? Sign in instead' : 'New to UpTier? Create an account';
  if (!options.preserveStatus) {
    setStatus(creating
      ? 'Enter your email and create a unique password with 8 to 20 characters.'
      : 'Use your UpTier account email and password to continue.');
  }
}

function resetPasswordVisibility() {
  for (const button of document.querySelectorAll('[data-password-toggle]')) {
    const input = document.querySelector(`#${button.dataset.passwordToggle}`);
    if (!(input instanceof HTMLInputElement)) continue;
    input.type = 'password';
    button.textContent = 'Show';
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', input === elements.confirmPassword ? 'Show confirmed password' : 'Show password');
  }
}

function cleanError(error) {
  const code = typeof error?.code === 'string' ? error.code : '';
  const messages = {
    'auth/api-key-not-valid': 'UpTier secure identity configuration is unavailable. Contact UpTier support.',
    'auth/app-not-authorized': 'This UpTier sign-in page is not authorized to use the secure identity service. Contact UpTier support.',
    'auth/email-already-in-use': 'An account already uses that email. Sign in instead.',
    'auth/billing-not-enabled': 'Google billing is not active for SMS verification yet. Check the UpTier Google Cloud billing status and retry after activation.',
    'auth/captcha-check-failed': 'The reCAPTCHA check was not completed. Retry and finish the visible challenge.',
    'auth/invalid-credential': 'The email or password was not accepted.',
    'auth/invalid-login-credentials': 'The email or password was not accepted.',
    'auth/user-not-found': 'The email or password was not accepted.',
    'auth/wrong-password': 'The email or password was not accepted.',
    'auth/invalid-email': 'Enter a valid email address.',
    'auth/invalid-phone-number': 'Enter a valid mobile number including country code, such as +1.',
    'auth/invalid-verification-code': 'That security code was not accepted. Check it and try again.',
    'auth/missing-verification-code': 'Enter the six-digit security code.',
    'auth/operation-not-allowed': 'SMS verification is not currently enabled for this UpTier project.',
    'auth/internal-error': 'The secure identity service returned an unexpected error. Wait a moment and retry.',
    'auth/network-request-failed': 'The secure identity service could not be reached. Check your connection and retry.',
    'auth/quota-exceeded': 'The SMS security limit was reached. Wait and try again later.',
    'auth/requires-recent-login': 'This secure setup window expired. Return to UpTier and start one fresh sign-in.',
    'auth/too-many-requests': 'Too many attempts were made. Stop retrying for now. If a verification email was already sent, use that link—your account is still waiting safely.',
    'auth/unauthorized-domain': 'This UpTier sign-in address is not authorized. Contact UpTier support.',
    'auth/user-disabled': 'This account is disabled. Contact UpTier support.',
    'auth/weak-password': 'Use a password containing 8 to 20 characters.'
  };
  if (messages[code]) return messages[code];
  const supportCode = code.replace(/^auth\//, '').replace(/[^a-z0-9-]/gi, '').slice(0, 64);
  return supportCode
    ? `Secure sign-in could not be completed. Contact UpTier support with code: ${supportCode}.`
    : 'Secure sign-in could not be completed. Retry or contact UpTier support.';
}

function validateLaunchRequest() {
  if (!firebaseConfig.apiKey || !firebaseConfig.appId) throw new Error('UpTier secure sign-in is awaiting final Google configuration.');
  if (!/^uptier_browser_auth_[A-Za-z0-9_-]{43}$/.test(requestToken)) throw new Error('This sign-in request is invalid or expired. Start again from UpTier.');
  if (actionParameter !== 'sign-in' && actionParameter !== 'delete-account') throw new Error('This secure account action is not supported.');
  if (modeParameter !== 'sign-in' && modeParameter !== 'create-account') throw new Error('This secure account mode is not supported.');
  let api;
  try { api = new URL(apiParameter); } catch { throw new Error('This sign-in request has an invalid UpTier service address.'); }
  if (api.username || api.password || api.search || api.hash || api.pathname !== '/' || !allowedBackendOrigins.includes(api.origin)) {
    throw new Error('This sign-in request did not come from an approved UpTier service.');
  }
  return api.origin;
}

function resetRecaptcha() {
  recaptchaVerifier?.clear();
  recaptchaVerifier = new RecaptchaVerifier(auth, 'recaptcha-container', { size: 'normal' });
}

function normalizePhoneNumber(value) {
  const compact = value.trim().replace(/[().\s-]/g, '');
  if (/^\+\d{8,15}$/.test(compact)) return compact;
  const digits = compact.replace(/\D/g, '');
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith('1')) return `+${digits}`;
  return '';
}

async function sendMfaCode(options, mode, help, expectedGeneration = setupGeneration) {
  if (!isCurrentSetupGeneration(expectedGeneration)) return false;
  resetRecaptcha();
  setStatus('Complete the visible reCAPTCHA check to send the security code.');
  const provider = new PhoneAuthProvider(auth);
  const nextVerificationId = await provider.verifyPhoneNumber(options, recaptchaVerifier);
  if (!isCurrentSetupGeneration(expectedGeneration)) return false;
  verificationId = nextVerificationId;
  verificationMode = mode;
  elements.codeTitle.textContent = mode === 'enroll' ? 'Confirm your mobile number' : 'Complete SMS verification';
  elements.codeHelp.textContent = help;
  elements.smsCode.value = '';
  showPanel(elements.codeForm);
  setStatus('Security code sent. It may take a moment to arrive.', 'success');
  elements.smsCode.focus();
  return true;
}

function showVerificationStep(user, verificationEmailSent, expectedIdentity = pendingIdentity) {
  requirePendingIdentity(user, expectedIdentity);
  elements.verificationAddress.textContent = user.email ?? 'your email address';
  showPanel(elements.verificationPanel);
  if (verificationEmailSent) startVerificationResendCooldown();
  else updateVerificationResendButton();
  const outcome = accountCreationOutcome(verificationEmailSent);
  setStatus(outcome.message, outcome.tone);
  elements.checkVerification.focus();
}

function showEnrollmentStep(user, expectedIdentity = pendingIdentity) {
  requirePendingIdentity(user, expectedIdentity);
  showPanel(elements.enrollForm);
  setStatus('Email verified. Add SMS security now—there is no need to sign in again.', 'success');
  elements.phone.focus();
}

async function prepareMfaChallenge(error, help, expectedGeneration = setupGeneration) {
  if (!isCurrentSetupGeneration(expectedGeneration)) return false;
  signInResolver = getMultiFactorResolver(auth, error);
  const phoneHint = signInResolver.hints.find((hint) => hint.factorId === PhoneMultiFactorGenerator.FACTOR_ID);
  if (!phoneHint) throw new Error('This account has no supported SMS factor. Contact UpTier support.');
  return sendMfaCode(
    { multiFactorHint: phoneHint, session: signInResolver.session },
    'sign-in',
    help ?? `Enter the code sent to ${phoneHint.phoneNumber ?? 'your enrolled mobile number'}.`,
    expectedGeneration
  );
}

async function refreshEmailVerification({ announce = false } = {}) {
  if (busy || verificationRefreshInFlight || elements.verificationPanel.hidden) return;
  const user = auth.currentUser;
  const expectedIdentity = pendingIdentity;
  if (!user || !expectedIdentity) {
    clearSensitiveSetupState({ clearIdentity: true });
    configureAccountMode('sign-in', { preserveStatus: true });
    showPanel(elements.accountForm);
    setStatus('This browser setup session ended. Sign in once to continue with the account you already created.', 'error');
    elements.email.focus();
    return;
  }
  verificationRefreshInFlight = true;
  try {
    requirePendingIdentity(user, expectedIdentity);
    await reload(user);
    if (expectedIdentity !== pendingIdentity
        || expectedIdentity.generation !== setupGeneration
        || elements.verificationPanel.hidden
        || auth.currentUser?.uid !== expectedIdentity.uid) return;
    requirePendingIdentity(user, expectedIdentity);
    if (!user.emailVerified) {
      if (announce) setStatus('Email is not verified yet. Open the link in the email already sent, then return here—do not create the account or sign in again.', 'error');
      return;
    }
    showEnrollmentStep(user, expectedIdentity);
  } catch (error) {
    setStatus(error instanceof Error && !error.code ? error.message : cleanError(error), 'error');
  } finally {
    verificationRefreshInFlight = false;
  }
}

function showManualSignInRecovery(message) {
  const email = pendingIdentity?.email ?? '';
  pendingSetupPassword = '';
  pendingDeviceHandoff = undefined;
  deviceConfirmationVerified = false;
  verificationId = '';
  verificationMode = '';
  signInResolver = undefined;
  elements.smsCode.value = '';
  elements.syncConfirmationCode.value = '';
  configureAccountMode('sign-in', { preserveStatus: true });
  showPanel(elements.accountForm);
  elements.email.value = email;
  elements.password.value = '';
  setStatus(message, 'error');
  (requiresManualDeviceConfirmation() ? elements.syncConfirmationCode : elements.password).focus();
}

function showBackendRetry(error) {
  if (requiresManualDeviceConfirmation() && !pendingDeviceHandoff) {
    deviceConfirmationVerified = false;
    elements.syncConfirmationCode.value = '';
    pendingExchangeUser = undefined;
    void signOut(auth).catch(() => {});
    showManualSignInRecovery('The protected device handoff did not finish. Enter the current code shown in UpTier and complete one fresh sign-in.');
    return;
  }
  elements.completeTitle.textContent = 'Your identity is verified';
  elements.completeMessage.textContent = 'The secure handoff to UpTier did not finish. Keep this page open and retry the handoff—do not sign in again.';
  elements.retryFinish.hidden = false;
  showPanel(elements.completePanel);
  setStatus(error instanceof Error && !error.code ? error.message : cleanError(error), 'error');
  elements.retryFinish.focus();
}

async function beginAutomaticMfaSignIn(expectedIdentity = pendingIdentity) {
  const currentUser = auth.currentUser;
  const expectedGeneration = setupGeneration;
  if (!currentUser || !expectedIdentity || !pendingSetupPassword) {
    showManualSignInRecovery('SMS security is active. This browser no longer has the temporary setup credential, so sign in once to finish.');
    return;
  }
  requirePendingIdentity(currentUser, expectedIdentity);
  const { email } = expectedIdentity;
  const password = pendingSetupPassword;
  try {
    await signOut(auth);
  } catch (error) {
    if (isCurrentPendingIdentity(expectedIdentity)) {
      showManualSignInRecovery(`${cleanError(error)} SMS security is active; sign in once to finish.`);
    }
    return;
  }
  if (!isCurrentPendingIdentity(expectedIdentity) || !isCurrentSetupGeneration(expectedGeneration)) return;
  try {
    await signInWithEmailAndPassword(auth, email, password);
    if (!isCurrentPendingIdentity(expectedIdentity) || !isCurrentSetupGeneration(expectedGeneration)) {
      try { if (auth.currentUser) await signOut(auth); } catch { /* Expiry remains terminal. */ }
      return;
    }
    await signOut(auth);
    if (!isCurrentPendingIdentity(expectedIdentity) || !isCurrentSetupGeneration(expectedGeneration)) return;
    showManualSignInRecovery('SMS security is active, but the final challenge did not start. Wait a moment, then sign in once to finish. UpTier will not continue without the SMS check.');
    return;
  } catch (error) {
    if (!isCurrentPendingIdentity(expectedIdentity) || !isCurrentSetupGeneration(expectedGeneration)) {
      try { if (auth.currentUser) await signOut(auth); } catch { /* Expiry remains terminal. */ }
      return;
    }
    if (error?.code !== 'auth/multi-factor-auth-required') {
      showManualSignInRecovery(`${error instanceof Error && !error.code ? error.message : cleanError(error)} When the temporary limit clears, sign in once to finish.`);
      return;
    }
    try {
      await prepareMfaChallenge(
        error,
        'Enter this final code to confirm the SMS factor for your UpTier session. You do not need to enter your email or password again.',
        expectedGeneration
      );
    } catch (challengeError) {
      if (!isCurrentPendingIdentity(expectedIdentity) || !isCurrentSetupGeneration(expectedGeneration)) return;
      showManualSignInRecovery(`${challengeError instanceof Error && !challengeError.code ? challengeError.message : cleanError(challengeError)} SMS security is active; sign in once when you are ready to finish.`);
    }
  }
}

async function finishBackendExchange(user, apiOrigin, expectedGeneration = setupGeneration, expectedIdentity = pendingIdentity) {
  const originalUserUid = user.uid;
  const isCurrentExchange = () => (expectedGeneration === setupGeneration
    && expectedIdentity === pendingIdentity
    && (!expectedIdentity || expectedIdentity.generation === setupGeneration)
    && auth.currentUser?.uid === originalUserUid);
  if (!isCurrentExchange()) return false;
  if (!user.emailVerified || multiFactor(user).enrolledFactors.length === 0) throw new Error('Verified email and SMS MFA are required.');
  if (expectedIdentity) requirePendingIdentity(user, expectedIdentity);
  const tokenResult = await user.getIdTokenResult(true);
  if (!isCurrentExchange()) return false;
  if (tokenResult.signInSecondFactor !== 'phone') throw new Error('Complete the SMS second-factor challenge before connecting this account to UpTier.');
  if (tokenResult.signInProvider !== 'password') throw new Error('Use the UpTier email and password before completing SMS verification.');
  if (deletionMode) {
    setStatus('Identity verified. Removing UpTier server data and connected Plaid Items…');
    const idToken = tokenResult.token;
    const response = await fetch(`${apiOrigin}/v1/auth/browser/delete/complete`, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestToken, idToken })
    });
    const payload = await response.json().catch(() => ({}));
    if (!isCurrentExchange()) return false;
    if (!response.ok) throw new Error(typeof payload.message === 'string' ? payload.message : 'UpTier could not delete this account.');
    try {
      await deleteUser(user);
    } catch {
      elements.requestState.textContent = 'Server data deleted';
      elements.requestState.dataset.tone = 'error';
      setStatus('UpTier server data and Plaid connections were deleted, but the Google Identity record could not be removed. Contact uptier.support@gmail.com for identity cleanup.', 'error');
      elements.completeTitle.textContent = 'Server data deleted';
      elements.completeMessage.textContent = 'Do not reconnect this identity. Contact private support to finish removing the remaining Google Identity record.';
      showPanel(elements.completePanel);
      return;
    }
    elements.requestState.textContent = 'Deleted';
    elements.requestState.dataset.tone = 'success';
    setStatus('The UpTier cloud account, connected Plaid Items, server data, sessions, and Google Identity record were deleted.', 'success');
    elements.completeTitle.textContent = 'Account deletion complete';
    elements.completeMessage.textContent = 'Return to UpTier. The desktop app will clear its protected session automatically. Local imported records remain until you delete them locally.';
    clearSetupMemoryDeadline();
    clearSensitiveSetupState({ clearIdentity: true });
    showPanel(elements.completePanel);
    return true;
  }
  pendingExchangeUser = user;
  const idToken = tokenResult.token;
  const completeRequest = (deviceHandoff) => fetch(`${apiOrigin}/v1/auth/browser/complete`, {
    method: 'POST',
    mode: 'cors',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      requestToken,
      idToken,
      ...(deviceHandoff ? { deviceHandoff } : {})
    })
  });
  const authorizeAppBoundRequest = (deviceHandoff) => fetch(`${apiOrigin}/v1/auth/browser/authorize`, {
    method: 'POST',
    mode: 'cors',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      requestToken,
      idToken,
      pkceChallenge: appBoundSyncLaunch().codeChallenge,
      deviceHandoff
    })
  });
  const appBoundAuth = appBoundSyncLaunch();
  let response;
  if (syncLaunchContext && !pendingDeviceHandoff) {
    if (requiresManualDeviceConfirmation() && !deviceConfirmationVerified) {
      throw new Error('Confirm this device with the six-digit code shown in UpTier before continuing.');
    }
    if (!pendingSetupPassword) {
      throw new Error('The temporary password key expired. Return to UpTier and start one fresh secure sign-in.');
    }
    setStatus('SMS verified. Protecting account sync for this device…');
    const prepareResponse = await fetch(`${apiOrigin}/v1/auth/browser/prepare`, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestToken, idToken })
    });
    const preparePayload = await prepareResponse.json().catch(() => ({}));
    if (!isCurrentExchange()) return false;
    if (!prepareResponse.ok) {
      throw new Error(typeof preparePayload.message === 'string'
        ? preparePayload.message
        : 'UpTier could not prepare secure account sync.');
    }
    const prepared = normalizePrepareResponse(preparePayload, syncLaunchContext);
    const guardedCompletion = await completeDeviceHandoffIfCurrent({
      createHandoff: () => createDeviceHandoff({
        syncContext: syncLaunchContext,
        prepareResponse: prepared,
        password: pendingSetupPassword
      }),
      isCurrent: isCurrentExchange,
      beforeComplete: () => {
        pendingSetupPassword = '';
        deviceConfirmationVerified = false;
        setStatus(appBoundAuth
          ? 'Account sync protected. Returning securely to UpTier…'
          : 'Account sync protected. Creating the UpTier session…');
      },
      complete: (deviceHandoff) => {
        pendingDeviceHandoff = deviceHandoff;
        return appBoundAuth
          ? authorizeAppBoundRequest(deviceHandoff)
          : completeRequest(deviceHandoff);
      }
    });
    if (!guardedCompletion.completed) return false;
    response = guardedCompletion.result;
  } else {
    setStatus(appBoundAuth
      ? 'Account sync protected. Returning securely to UpTier…'
      : syncLaunchContext
        ? 'Account sync protected. Creating the UpTier session…'
      : 'SMS verified. Creating a protected UpTier session…');
    if (!isCurrentExchange()) return false;
    response = appBoundAuth
      ? await authorizeAppBoundRequest(pendingDeviceHandoff)
      : await completeRequest(pendingDeviceHandoff);
  }
  const payload = await response.json().catch(() => ({}));
  if (!isCurrentExchange()) return false;
  if (!response.ok) throw new Error(typeof payload.message === 'string' ? payload.message : 'UpTier could not complete this sign-in.');
  if (appBoundAuth) {
    const callbackUrl = createAppBoundCallbackUrl(syncLaunchContext, payload);
    await signOut(auth);
    if (!isCurrentSetupGeneration(expectedGeneration)
        || (expectedIdentity && !isCurrentPendingIdentity(expectedIdentity))) return false;
    pendingExchangeUser = undefined;
    clearSetupMemoryDeadline();
    clearSensitiveSetupState({ clearIdentity: true });
    elements.requestState.textContent = 'Verified';
    elements.requestState.dataset.tone = 'success';
    setStatus('SMS verified. Returning securely to the UpTier app…', 'success');
    window.location.replace(callbackUrl);
    return true;
  }
  await signOut(auth);
  if (!isCurrentSetupGeneration(expectedGeneration)
      || (expectedIdentity && !isCurrentPendingIdentity(expectedIdentity))) return false;
  pendingExchangeUser = undefined;
  clearSetupMemoryDeadline();
  clearSensitiveSetupState({ clearIdentity: true });
  elements.requestState.textContent = 'Verified';
  elements.requestState.dataset.tone = 'success';
  elements.completeTitle.textContent = 'Secure sign-in complete';
  elements.completeMessage.textContent = 'Return to UpTier. The app will finish automatically.';
  elements.retryFinish.hidden = true;
  setStatus('Identity verified and exchanged. No Google session remains on this page.', 'success');
  showPanel(elements.completePanel);
  return true;
}

async function handlePrimarySignIn(apiOrigin) {
  const email = elements.email.value.trim().toLowerCase();
  const password = elements.password.value;
  const operationGeneration = setupGeneration;
  try {
    const result = await signInWithEmailAndPassword(auth, email, password);
    if (operationGeneration !== setupGeneration) {
      await signOut(auth);
      return;
    }
    if (!result.user.emailVerified) {
      const expectedIdentity = rememberPendingIdentity(result.user, password);
      elements.password.value = '';
      resetPasswordVisibility();
      showVerificationStep(result.user, false, expectedIdentity);
      setStatus('This account is already created and is waiting for email verification. Use the email already sent, or choose Resend once—do not keep signing in.', 'success');
      return;
    }
    if (multiFactor(result.user).enrolledFactors.length === 0) {
      const expectedIdentity = rememberPendingIdentity(result.user, password);
      elements.password.value = '';
      resetPasswordVisibility();
      showEnrollmentStep(result.user, expectedIdentity);
      return;
    }
    await signOut(auth);
    throw new Error('SMS verification did not start. Return to UpTier and open one fresh secure sign-in request.');
  } catch (error) {
    if (operationGeneration !== setupGeneration) return;
    if (error?.code !== 'auth/multi-factor-auth-required') throw error;
    pendingSetupPassword = syncLaunchContext ? password : '';
    elements.password.value = '';
    resetPasswordVisibility();
    try {
      await prepareMfaChallenge(error, undefined, operationGeneration);
    } catch (challengeError) {
      pendingSetupPassword = '';
      throw challengeError;
    }
  }
}

async function handleAccountCreation() {
  const email = elements.email.value.trim().toLowerCase();
  const password = elements.password.value;
  const validationMessage = validateNewPassword(password, elements.confirmPassword.value);
  if (validationMessage) {
    setStatus(validationMessage, 'error');
    (validationMessage === 'Passwords do not match.' ? elements.confirmPassword : elements.password).focus();
    return;
  }
  const operationGeneration = setupGeneration;
  setStatus('Creating your secure UpTier identity…');
  const result = await createUserWithEmailAndPassword(auth, email, password);
  if (operationGeneration !== setupGeneration) {
    await signOut(auth);
    return;
  }
  const expectedIdentity = rememberPendingIdentity(result.user, password);
  let verificationEmailSent = false;
  let verificationEmailError;
  try {
    await sendEmailVerification(result.user);
    verificationEmailSent = true;
  } catch (error) {
    verificationEmailError = error;
  }
  if (expectedIdentity !== pendingIdentity || expectedIdentity.generation !== setupGeneration) return;
  elements.password.value = '';
  elements.confirmPassword.value = '';
  resetPasswordVisibility();
  if (verificationEmailError?.code === 'auth/too-many-requests') startVerificationResendCooldown();
  showVerificationStep(result.user, verificationEmailSent, expectedIdentity);
}

let apiOrigin = '';
try {
  apiOrigin = validateLaunchRequest();
  if (launchSyncFragment) {
    if (deletionMode) throw new Error('Account-sync handoff is not allowed during account deletion.');
    syncLaunchContext = parseSyncLaunchFragment(launchSyncFragment, {
      allowedBackendOrigins,
      expectedBackendOrigin: apiOrigin
    });
    if (requiresManualDeviceConfirmation()) {
      elements.syncConfirmationField.hidden = false;
      elements.syncConfirmationCode.required = true;
    } else {
      document.body.dataset.appBoundAuth = 'true';
      elements.syncConfirmationField.hidden = true;
      elements.syncConfirmationCode.required = false;
    }
  }
  const firebaseApp = initializeApp(firebaseConfig);
  auth = initializeAuth(firebaseApp, { persistence: inMemoryPersistence });
  armSetupMemoryDeadline();
  if (deletionMode) {
    document.title = 'Delete cloud account | UpTier';
    elements.introEyebrow.textContent = 'VERIFIED ACCOUNT DELETION';
    elements.introTitle.textContent = 'Permanently delete the UpTier cloud account.';
    elements.introLead.textContent = 'Re-enter the account credentials and SMS factor. UpTier will disconnect Plaid, erase server-side account data and sessions, and remove the Google Identity record. Local imported records on this computer remain.';
    elements.deleteWarning.hidden = false;
    elements.formTitle.textContent = 'Verify permanent deletion';
    elements.createAccount.hidden = true;
    elements.switchAccountMode.hidden = true;
    document.body.dataset.accountMode = 'delete-account';
  } else {
    configureAccountMode(accountMode);
  }
  elements.requestState.textContent = 'Request verified';
  elements.requestState.dataset.tone = 'success';
  if (deletionMode) setStatus('Sign in to re-verify permanent account deletion.');
  showPanel(elements.accountForm);
  elements.email.focus();
} catch (error) {
  elements.requestState.textContent = 'Unavailable';
  elements.requestState.dataset.tone = 'error';
  setStatus(error instanceof Error ? error.message : 'Secure sign-in is unavailable.', 'error');
}

elements.accountForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setBusy(true);
  if (accountMode === 'sign-in') setStatus('Checking your account…');
  try {
    await verifySyncDeviceConfirmation();
    if (accountMode === 'create-account' && !deletionMode) await handleAccountCreation();
    else await handlePrimarySignIn(apiOrigin);
  }
  catch (error) {
    if (requiresManualDeviceConfirmation() && !pendingDeviceHandoff) {
      deviceConfirmationVerified = false;
      elements.syncConfirmationCode.value = '';
    }
    setStatus(error instanceof Error && !error.code ? error.message : cleanError(error), 'error');
  }
  finally { setBusy(false); }
});

elements.switchAccountMode.addEventListener('click', async () => {
  try { if (auth.currentUser) await signOut(auth); } catch { /* Memory-only session still clears when this page closes. */ }
  clearSensitiveSetupState({ clearIdentity: true });
  configureAccountMode(accountMode === 'create-account' ? 'sign-in' : 'create-account');
  resetPasswordVisibility();
  elements.password.focus();
});

for (const button of document.querySelectorAll('[data-password-toggle]')) {
  button.addEventListener('click', () => {
    const input = document.querySelector(`#${button.dataset.passwordToggle}`);
    if (!(input instanceof HTMLInputElement)) return;
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    button.textContent = showing ? 'Show' : 'Hide';
    button.setAttribute('aria-pressed', String(!showing));
    button.setAttribute('aria-label', `${showing ? 'Show' : 'Hide'} ${input === elements.confirmPassword ? 'confirmed password' : 'password'}`);
    input.focus();
  });
}

elements.checkVerification.addEventListener('click', () => void refreshEmailVerification({ announce: true }));

window.addEventListener('focus', () => void refreshEmailVerification());
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') void refreshEmailVerification();
});

elements.resendVerification.addEventListener('click', async () => {
  if (verificationResendWaitSeconds(verificationEmailSentAt) > 0) return;
  const user = auth.currentUser;
  const expectedIdentity = pendingIdentity;
  if (!user || !expectedIdentity) {
    showManualSignInRecovery('This browser setup session ended. Sign in once to continue with the account you already created.');
    return;
  }
  setBusy(true);
  setStatus('Preparing one new verification email…');
  try {
    requirePendingIdentity(user, expectedIdentity);
    await reload(user);
    if (!isCurrentPendingIdentity(expectedIdentity)
        || elements.verificationPanel.hidden
        || auth.currentUser?.uid !== expectedIdentity.uid) return;
    requirePendingIdentity(user, expectedIdentity);
    if (user.emailVerified) {
      showEnrollmentStep(user, expectedIdentity);
      return;
    }
    await sendEmailVerification(user);
    if (!isCurrentPendingIdentity(expectedIdentity)
        || elements.verificationPanel.hidden
        || auth.currentUser?.uid !== expectedIdentity.uid) return;
    startVerificationResendCooldown();
    setStatus('Verification email sent. Open the link, then return to this page. Do not sign in or create the account again.', 'success');
  } catch (error) {
    if (error?.code === 'auth/too-many-requests') startVerificationResendCooldown();
    setStatus(cleanError(error), 'error');
  }
  finally { setBusy(false); }
});

elements.useDifferentEmail.addEventListener('click', async () => {
  setBusy(true);
  try { if (auth.currentUser) await signOut(auth); } catch { /* Closing the page clears the memory-only session. */ }
  clearSensitiveSetupState({ clearIdentity: true });
  verificationEmailSentAt = 0;
  configureAccountMode(accountMode, { preserveStatus: true });
  showPanel(elements.accountForm);
  elements.email.value = '';
  setStatus('Enter the different email you want to use.', 'working');
  setBusy(false);
  elements.email.focus();
});

elements.resetPassword.addEventListener('click', async () => {
  const email = elements.email.value.trim().toLowerCase();
  if (!email) return setStatus('Enter your email address first.', 'error');
  const confirmed = window.confirm(
    'Resetting the password cannot unlock an existing encrypted UpTier profile by itself. '
    + 'After the reset, use a device that is already linked or your sync recovery code once. Continue?'
  );
  if (!confirmed) return;
  deviceConfirmationVerified = false;
  elements.syncConfirmationCode.value = '';
  setBusy(true);
  try {
    await sendPasswordResetEmail(auth, email);
    setStatus('If that account exists, a password reset email has been sent. Keep an already linked device or the sync recovery code available to restore the encrypted profile.', 'success');
  } catch (error) { setStatus(cleanError(error), 'error'); }
  finally { setBusy(false); }
});

elements.retryFinish.addEventListener('click', async () => {
  if (!pendingExchangeUser) {
    showManualSignInRecovery('This verified handoff expired. Return to UpTier and start one fresh secure sign-in.');
    return;
  }
  setBusy(true);
  elements.retryFinish.hidden = true;
  const expectedGeneration = setupGeneration;
  const expectedIdentity = pendingIdentity;
  try {
    await finishBackendExchange(pendingExchangeUser, apiOrigin, expectedGeneration, expectedIdentity);
  } catch (error) {
    if (isCurrentSetupGeneration(expectedGeneration)
        && (!expectedIdentity || isCurrentPendingIdentity(expectedIdentity))) showBackendRetry(error);
  } finally {
    setBusy(false);
  }
});

elements.enrollForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!elements.smsConsent.checked) return setStatus('Consent is required before sending a security text.', 'error');
  const user = auth.currentUser;
  const expectedIdentity = pendingIdentity;
  if (!user?.emailVerified) return setStatus('Sign in with a verified email before adding SMS MFA.', 'error');
  if (!expectedIdentity) return showManualSignInRecovery('This browser setup session ended. Sign in once to continue with the account you already created.');
  const phoneNumber = normalizePhoneNumber(elements.phone.value);
  if (!phoneNumber) return setStatus('Enter a valid mobile number with country code, such as +1 555 555 0123.', 'error');
  elements.phone.value = phoneNumber;
  setBusy(true);
  setStatus('Preparing the SMS security check…');
  try {
    requirePendingIdentity(user, expectedIdentity);
    if (pendingSetupPassword) {
      const credential = EmailAuthProvider.credential(expectedIdentity.email, pendingSetupPassword);
      const reauthenticated = await reauthenticateWithCredential(user, credential);
      if (!isCurrentPendingIdentity(expectedIdentity)) return;
      requirePendingIdentity(reauthenticated.user, expectedIdentity);
    }
    const session = await multiFactor(user).getSession();
    if (!isCurrentPendingIdentity(expectedIdentity)) return;
    await sendMfaCode(
      { phoneNumber, session },
      'enroll',
      'Enter the code sent to the mobile number you provided.',
      expectedIdentity.generation
    );
  } catch (error) {
    if (isCurrentPendingIdentity(expectedIdentity)) setStatus(cleanError(error), 'error');
  }
  finally { setBusy(false); }
});

elements.codeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!/^\d{6}$/.test(elements.smsCode.value)) return setStatus('Enter the six-digit security code.', 'error');
  setBusy(true);
  setStatus('Verifying the security code…');
  const operationGeneration = setupGeneration;
  const expectedIdentity = pendingIdentity;
  let enrollmentCommitted = false;
  try {
    const credential = PhoneAuthProvider.credential(verificationId, elements.smsCode.value);
    const assertion = PhoneMultiFactorGenerator.assertion(credential);
    if (verificationMode === 'enroll') {
      const user = auth.currentUser;
      if (!user) throw new Error('Your setup session expired. Sign in again.');
      requirePendingIdentity(user, expectedIdentity);
      await multiFactor(user).enroll(assertion, 'UpTier mobile');
      enrollmentCommitted = true;
      verificationMode = 'enrolled';
      verificationId = '';
      elements.smsCode.value = '';
      if (!isCurrentPendingIdentity(expectedIdentity)
          || !isCurrentSetupGeneration(operationGeneration)) {
        try { if (auth.currentUser) await signOut(auth); } catch { /* Expiry remains terminal. */ }
        return;
      }
      let tokenResult;
      try {
        tokenResult = await user.getIdTokenResult(true);
      } catch {
        if (!isCurrentPendingIdentity(expectedIdentity)
            || !isCurrentSetupGeneration(operationGeneration)) return;
        setStatus('SMS security is active. Finishing setup without asking for your password again…', 'success');
        await beginAutomaticMfaSignIn(expectedIdentity);
        return;
      }
      if (!isCurrentPendingIdentity(expectedIdentity)
          || !isCurrentSetupGeneration(operationGeneration)) return;
      if (tokenResult.signInSecondFactor === 'phone') {
        await finishBackendExchange(user, apiOrigin, operationGeneration, expectedIdentity);
        return;
      }
      setStatus('SMS security is active. Finishing setup without asking for your password again…', 'success');
      await beginAutomaticMfaSignIn(expectedIdentity);
      return;
    }
    if (!signInResolver) throw new Error('Your sign-in session expired. Start again from UpTier.');
    const result = await signInResolver.resolveSignIn(assertion);
    if (!isCurrentSetupGeneration(operationGeneration)) {
      try { if (auth.currentUser) await signOut(auth); } catch { /* Expiry remains terminal. */ }
      return;
    }
    assertPendingIdentity(result.user);
    await finishBackendExchange(result.user, apiOrigin, operationGeneration, expectedIdentity);
  } catch (error) {
    if (!isCurrentSetupGeneration(operationGeneration)
        || (expectedIdentity && !isCurrentPendingIdentity(expectedIdentity))) return;
    if (pendingExchangeUser && !deletionMode) showBackendRetry(error);
    else if (enrollmentCommitted) {
      showManualSignInRecovery('SMS security is active. The automatic handoff did not finish, so sign in once to complete setup. Do not try to enroll the phone again.');
    } else setStatus(error instanceof Error && !error.code ? error.message : cleanError(error), 'error');
  } finally { setBusy(false); }
});
