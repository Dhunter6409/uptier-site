import test from 'node:test';
import assert from 'node:assert/strict';

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

test('account creation remains isolated from sign-in and deletion', () => {
  assert.equal(accountModeForRequest('create-account', false), 'create-account');
  assert.equal(accountModeForRequest('create-account', true), 'sign-in');
  assert.equal(accountModeForRequest('sign-in', false), 'sign-in');
});

test('new passwords must match and remain within the supported length', () => {
  const minimumPassword = 'A1b2C3d4';
  const maximumPassword = 'A1b2C3d4E5f6G7h8I9j0';
  assert.equal(NEW_ACCOUNT_PASSWORD_MIN_LENGTH, 8);
  assert.equal(NEW_ACCOUNT_PASSWORD_MAX_LENGTH, 20);
  assert.match(validateNewPassword('A1b2C3d', 'A1b2C3d'), /between 8 and 20/);
  assert.match(validateNewPassword(`${maximumPassword}K`, `${maximumPassword}K`), /between 8 and 20/);
  assert.match(validateNewPassword(minimumPassword, `${minimumPassword}!`), /do not match/);
  assert.equal(validateNewPassword(minimumPassword, minimumPassword), '');
  assert.equal(validateNewPassword(maximumPassword, maximumPassword), '');
});

test('account creation tells users to remain in the same verification flow', () => {
  const sent = accountCreationOutcome(true);
  const failed = accountCreationOutcome(false);

  assert.equal(sent.tone, 'success');
  assert.match(sent.message, /return to this same page/i);
  assert.match(sent.message, /without asking for your password again/i);
  assert.equal(failed.tone, 'error');
  assert.match(failed.message, /account was created/i);
  assert.match(failed.message, /stay on this page/i);
});

test('verification resend cooldown prevents rapid duplicate requests', () => {
  assert.equal(VERIFICATION_RESEND_COOLDOWN_MS, 60_000);
  assert.equal(verificationResendWaitSeconds(0, 50_000), 0);
  assert.equal(verificationResendWaitSeconds(10_000, 10_000), 60);
  assert.equal(verificationResendWaitSeconds(10_000, 69_001), 1);
  assert.equal(verificationResendWaitSeconds(10_000, 70_000), 0);
});

test('temporary setup credentials expire before the backend browser request', () => {
  assert.equal(SETUP_MEMORY_TIMEOUT_MS, 9 * 60_000);
  assert.ok(SETUP_MEMORY_TIMEOUT_MS < 10 * 60_000);
});
