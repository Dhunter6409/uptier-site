import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.16.0/firebase-app.js';
import {
  PhoneAuthProvider,
  PhoneMultiFactorGenerator,
  RecaptchaVerifier,
  createUserWithEmailAndPassword,
  deleteUser,
  getMultiFactorResolver,
  inMemoryPersistence,
  initializeAuth,
  multiFactor,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut
} from 'https://www.gstatic.com/firebasejs/12.16.0/firebase-auth.js';
import { allowedBackendOrigins, firebaseConfig } from './config.js';

const elements = {
  status: document.querySelector('#status'),
  requestState: document.querySelector('#request-state'),
  accountForm: document.querySelector('#account-form'),
  enrollForm: document.querySelector('#enroll-form'),
  codeForm: document.querySelector('#code-form'),
  completePanel: document.querySelector('#complete-panel'),
  email: document.querySelector('#email'),
  password: document.querySelector('#password'),
  phone: document.querySelector('#phone'),
  smsConsent: document.querySelector('#sms-consent'),
  smsCode: document.querySelector('#sms-code'),
  signIn: document.querySelector('#sign-in'),
  createAccount: document.querySelector('#create-account'),
  resendVerification: document.querySelector('#resend-verification'),
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
  completeMessage: document.querySelector('#complete-message')
};

const parameters = new URLSearchParams(window.location.search);
const requestToken = parameters.get('request') ?? '';
const apiParameter = parameters.get('api') ?? '';
const actionParameter = parameters.get('action') ?? 'sign-in';
const deletionMode = actionParameter === 'delete-account';
window.history.replaceState({}, document.title, window.location.pathname);

let auth;
let recaptchaVerifier;
let verificationId = '';
let verificationMode = '';
let signInResolver;

function setStatus(message, tone = 'working') {
  elements.status.textContent = message;
  elements.status.dataset.tone = tone;
}

function showPanel(panel) {
  for (const candidate of [elements.accountForm, elements.enrollForm, elements.codeForm, elements.completePanel]) {
    candidate.hidden = candidate !== panel;
  }
}

function setBusy(busy) {
  for (const button of document.querySelectorAll('button')) button.disabled = busy;
}

function cleanError(error) {
  const code = typeof error?.code === 'string' ? error.code : '';
  const messages = {
    'auth/email-already-in-use': 'An account already uses that email. Sign in instead.',
    'auth/billing-not-enabled': 'Google billing is not active for SMS verification yet. Check the UpTier Google Cloud billing status and retry after activation.',
    'auth/captcha-check-failed': 'The reCAPTCHA check was not completed. Retry and finish the visible challenge.',
    'auth/invalid-credential': 'The email or password was not accepted.',
    'auth/invalid-email': 'Enter a valid email address.',
    'auth/invalid-phone-number': 'Enter a valid mobile number including country code, such as +1.',
    'auth/invalid-verification-code': 'That security code was not accepted. Check it and try again.',
    'auth/missing-verification-code': 'Enter the six-digit security code.',
    'auth/operation-not-allowed': 'SMS verification is not currently enabled for this UpTier project.',
    'auth/network-request-failed': 'The secure identity service could not be reached. Check your connection and retry.',
    'auth/quota-exceeded': 'The SMS security limit was reached. Wait and try again later.',
    'auth/requires-recent-login': 'For security, sign out and sign in again before changing MFA.',
    'auth/too-many-requests': 'Too many attempts were made. Wait and try again later.',
    'auth/user-disabled': 'This account is disabled. Contact UpTier support.',
    'auth/weak-password': 'Use a stronger password with at least 12 characters.'
  };
  return messages[code] ?? 'Secure sign-in could not be completed. Retry or contact UpTier support.';
}

function validateLaunchRequest() {
  if (!firebaseConfig.apiKey || !firebaseConfig.appId) throw new Error('UpTier secure sign-in is awaiting final Google configuration.');
  if (!/^uptier_browser_auth_[A-Za-z0-9_-]{43}$/.test(requestToken)) throw new Error('This sign-in request is invalid or expired. Start again from UpTier.');
  if (actionParameter !== 'sign-in' && actionParameter !== 'delete-account') throw new Error('This secure account action is not supported.');
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

async function sendMfaCode(options, mode, help) {
  resetRecaptcha();
  setStatus('Complete the visible reCAPTCHA check to send the security code.');
  const provider = new PhoneAuthProvider(auth);
  verificationId = await provider.verifyPhoneNumber(options, recaptchaVerifier);
  verificationMode = mode;
  elements.codeTitle.textContent = mode === 'enroll' ? 'Confirm your mobile number' : 'Complete SMS verification';
  elements.codeHelp.textContent = help;
  elements.smsCode.value = '';
  showPanel(elements.codeForm);
  setStatus('Security code sent. It may take a moment to arrive.', 'success');
  elements.smsCode.focus();
}

async function finishBackendExchange(user, apiOrigin) {
  if (!user.emailVerified || multiFactor(user).enrolledFactors.length === 0) throw new Error('Verified email and SMS MFA are required.');
  if (deletionMode) {
    setStatus('Identity verified. Removing UpTier server data and connected Plaid Items…');
    const idToken = await user.getIdToken(true);
    const response = await fetch(`${apiOrigin}/v1/auth/browser/delete/complete`, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestToken, idToken })
    });
    const payload = await response.json().catch(() => ({}));
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
    showPanel(elements.completePanel);
    return;
  }
  setStatus('SMS verified. Creating a protected UpTier session…');
  const idToken = await user.getIdToken(true);
  const response = await fetch(`${apiOrigin}/v1/auth/browser/complete`, {
    method: 'POST',
    mode: 'cors',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestToken, idToken })
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof payload.message === 'string' ? payload.message : 'UpTier could not complete this sign-in.');
  await signOut(auth);
  elements.requestState.textContent = 'Verified';
  elements.requestState.dataset.tone = 'success';
  setStatus('Identity verified and exchanged. No Google session remains on this page.', 'success');
  showPanel(elements.completePanel);
}

async function handlePrimarySignIn(apiOrigin) {
  const email = elements.email.value.trim().toLowerCase();
  const password = elements.password.value;
  try {
    const result = await signInWithEmailAndPassword(auth, email, password);
    if (!result.user.emailVerified) {
      await sendEmailVerification(result.user);
      await signOut(auth);
      elements.password.value = '';
      throw new Error('Verify the email we just sent, then return here and sign in again.');
    }
    if (multiFactor(result.user).enrolledFactors.length === 0) {
      showPanel(elements.enrollForm);
      setStatus('Email verified. Add SMS multi-factor authentication to continue.', 'success');
      elements.phone.focus();
      return;
    }
    throw new Error('SMS verification is required. Sign in again to receive a security code.');
  } catch (error) {
    if (error?.code !== 'auth/multi-factor-auth-required') throw error;
    signInResolver = getMultiFactorResolver(auth, error);
    const phoneHint = signInResolver.hints.find((hint) => hint.factorId === PhoneMultiFactorGenerator.FACTOR_ID);
    if (!phoneHint) throw new Error('This account has no supported SMS factor. Contact UpTier support.');
    await sendMfaCode(
      { multiFactorHint: phoneHint, session: signInResolver.session },
      'sign-in',
      `Enter the code sent to ${phoneHint.phoneNumber ?? 'your enrolled mobile number'}.`
    );
  }
}

let apiOrigin = '';
try {
  apiOrigin = validateLaunchRequest();
  const firebaseApp = initializeApp(firebaseConfig);
  auth = initializeAuth(firebaseApp, { persistence: inMemoryPersistence });
  if (deletionMode) {
    document.title = 'Delete cloud account | UpTier';
    elements.introEyebrow.textContent = 'VERIFIED ACCOUNT DELETION';
    elements.introTitle.textContent = 'Permanently delete the UpTier cloud account.';
    elements.introLead.textContent = 'Re-enter the account credentials and SMS factor. UpTier will disconnect Plaid, erase server-side account data and sessions, and remove the Google Identity record. Local imported records on this computer remain.';
    elements.deleteWarning.hidden = false;
    elements.formTitle.textContent = 'Verify permanent deletion';
    elements.createAccount.hidden = true;
  }
  elements.requestState.textContent = 'Request verified';
  elements.requestState.dataset.tone = 'success';
  setStatus(deletionMode ? 'Sign in to re-verify permanent account deletion.' : 'Use your UpTier account email and password to continue.');
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
  setStatus('Checking your account…');
  try { await handlePrimarySignIn(apiOrigin); }
  catch (error) { setStatus(error instanceof Error && !error.code ? error.message : cleanError(error), 'error'); }
  finally { setBusy(false); }
});

elements.createAccount.addEventListener('click', async () => {
  setBusy(true);
  setStatus('Creating the private-trial identity…');
  try {
    const result = await createUserWithEmailAndPassword(auth, elements.email.value.trim().toLowerCase(), elements.password.value);
    elements.password.value = '';
    await sendEmailVerification(result.user);
    await signOut(auth);
    setStatus('Account created. Verify the email we sent, then return here and sign in to add SMS MFA.', 'success');
  } catch (error) { setStatus(cleanError(error), 'error'); }
  finally { setBusy(false); }
});

elements.resendVerification.addEventListener('click', async () => {
  const email = elements.email.value.trim().toLowerCase();
  const password = elements.password.value;
  if (!email || !password) return setStatus('Enter your email address and password before requesting another verification email.', 'error');
  setBusy(true);
  setStatus('Checking the account and preparing a new verification email…');
  try {
    const result = await signInWithEmailAndPassword(auth, email, password);
    if (result.user.emailVerified) {
      await signOut(auth);
      elements.password.value = '';
      setStatus('This email is already verified. Start a fresh secure sign-in from UpTier to continue.', 'success');
      return;
    }
    await sendEmailVerification(result.user);
    await signOut(auth);
    elements.password.value = '';
    setStatus('A new verification email was sent. Use only the newest message, then start a fresh secure sign-in from UpTier.', 'success');
  } catch (error) { setStatus(cleanError(error), 'error'); }
  finally { setBusy(false); }
});

elements.resetPassword.addEventListener('click', async () => {
  const email = elements.email.value.trim().toLowerCase();
  if (!email) return setStatus('Enter your email address first.', 'error');
  setBusy(true);
  try {
    await sendPasswordResetEmail(auth, email);
    setStatus('If that account exists, a password reset email has been sent.', 'success');
  } catch (error) { setStatus(cleanError(error), 'error'); }
  finally { setBusy(false); }
});

elements.enrollForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!elements.smsConsent.checked) return setStatus('Consent is required before sending a security text.', 'error');
  const user = auth.currentUser;
  if (!user?.emailVerified) return setStatus('Sign in with a verified email before adding SMS MFA.', 'error');
  const phoneNumber = normalizePhoneNumber(elements.phone.value);
  if (!phoneNumber) return setStatus('Enter a valid mobile number with country code, such as +1 555 555 0123.', 'error');
  elements.phone.value = phoneNumber;
  setBusy(true);
  setStatus('Preparing the SMS security check…');
  try {
    const session = await multiFactor(user).getSession();
    await sendMfaCode({ phoneNumber, session }, 'enroll', 'Enter the code sent to the mobile number you provided.');
  } catch (error) { setStatus(cleanError(error), 'error'); }
  finally { setBusy(false); }
});

elements.codeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!/^\d{6}$/.test(elements.smsCode.value)) return setStatus('Enter the six-digit security code.', 'error');
  setBusy(true);
  setStatus('Verifying the security code…');
  try {
    const credential = PhoneAuthProvider.credential(verificationId, elements.smsCode.value);
    const assertion = PhoneMultiFactorGenerator.assertion(credential);
    if (verificationMode === 'enroll') {
      const user = auth.currentUser;
      if (!user) throw new Error('Your setup session expired. Sign in again.');
      await multiFactor(user).enroll(assertion, 'UpTier mobile');
      await signOut(auth);
      showPanel(elements.accountForm);
      elements.password.value = '';
      setStatus('SMS MFA is active. Sign in once more to verify both factors and return to UpTier.', 'success');
      return;
    }
    if (!signInResolver) throw new Error('Your sign-in session expired. Start again from UpTier.');
    const result = await signInResolver.resolveSignIn(assertion);
    await finishBackendExchange(result.user, apiOrigin);
  } catch (error) {
    setStatus(error instanceof Error && !error.code ? error.message : cleanError(error), 'error');
  } finally { setBusy(false); }
});
