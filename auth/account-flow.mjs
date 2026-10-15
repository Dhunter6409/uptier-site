export function accountModeForRequest(modeParameter, deletionMode) {
  return modeParameter === 'create-account' && !deletionMode ? 'create-account' : 'sign-in';
}

export function validateNewPassword(password, confirmation) {
  if (password.length < 12 || password.length > 128) return 'Password must be between 12 and 128 characters.';
  if (password !== confirmation) return 'Passwords do not match.';
  return '';
}

export function accountCreationOutcome(verificationEmailSent, signedOut) {
  if (!verificationEmailSent) {
    return {
      tone: 'error',
      message: 'Your account was created, but the verification email could not be confirmed as sent. Re-enter the same password below and choose Resend verification email. If this request expires, return to UpTier and start Sign In again.'
    };
  }
  if (!signedOut) {
    return {
      tone: 'error',
      message: 'Your account was created and the verification email was sent, but this browser could not finish signing out. Close this page, verify your email, then return to UpTier and start Sign In again.'
    };
  }
  return {
    tone: 'success',
    message: 'Account created and verification email sent. Verify your email, then sign in below to add SMS security. If this request expires, return to UpTier and start Sign In with a fresh secure request.'
  };
}
