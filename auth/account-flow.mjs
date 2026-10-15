export function accountModeForRequest(modeParameter, deletionMode) {
  return modeParameter === 'create-account' && !deletionMode ? 'create-account' : 'sign-in';
}

export function validateNewPassword(password, confirmation) {
  if (password.length < 12 || password.length > 128) return 'Password must be between 12 and 128 characters.';
  if (password !== confirmation) return 'Passwords do not match.';
  return '';
}

export const VERIFICATION_RESEND_COOLDOWN_MS = 60_000;
export const SETUP_MEMORY_TIMEOUT_MS = 9 * 60_000;

export function verificationResendWaitSeconds(lastSentAt, now = Date.now()) {
  if (!Number.isFinite(lastSentAt) || lastSentAt <= 0) return 0;
  return Math.max(0, Math.ceil((lastSentAt + VERIFICATION_RESEND_COOLDOWN_MS - now) / 1_000));
}

export function accountCreationOutcome(verificationEmailSent) {
  if (!verificationEmailSent) {
    return {
      tone: 'error',
      message: 'Your account was created, but the verification email could not be confirmed as sent. Stay on this page and use Resend verification email once it is available.'
    };
  }
  return {
    tone: 'success',
    message: 'Account created. Open the verification email, then return to this same page. UpTier will continue with SMS security without asking for your password again.'
  };
}
