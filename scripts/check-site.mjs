import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
const authAppPath = join(root, 'auth', 'app.js');
const authIndexPath = join(root, 'auth', 'index.html');
const authStylesPath = join(root, 'auth', 'styles.css');
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

if (!existsSync(authAppPath) || !existsSync(authIndexPath) || !existsSync(authStylesPath)) {
  errors.push('Missing secure account portal completion flow.');
} else {
  const authApp = readFileSync(authAppPath, 'utf8');
  const authIndex = readFileSync(authIndexPath, 'utf8');
  const authStyles = readFileSync(authStylesPath, 'utf8');
  const finishFlowStart = authApp.indexOf('function finishFlow(');
  const finishFlowEnd = authApp.indexOf('\nfunction cleanError', finishFlowStart);
  const finishFlow = finishFlowStart >= 0 && finishFlowEnd > finishFlowStart
    ? authApp.slice(finishFlowStart, finishFlowEnd)
    : '';
  const completionRequirements = [
    ['flowCompleted = true;', 'mark the browser flow complete'],
    ["verificationId = '';", 'clear the SMS verification identifier'],
    ["verificationMode = '';", 'clear the SMS verification mode'],
    ['signInResolver = undefined;', 'clear the Firebase sign-in resolver'],
    ['recaptchaVerifier?.clear();', 'clear the reCAPTCHA verifier'],
    ['recaptchaVerifier = undefined;', 'release the reCAPTCHA verifier'],
    ["elements.email.value = '';", 'clear the email field'],
    ["elements.password.value = '';", 'clear the password field'],
    ["elements.phone.value = '';", 'clear the phone field'],
    ['elements.smsConsent.checked = false;', 'clear SMS consent state'],
    ["elements.smsCode.value = '';", 'clear the SMS code field'],
    ["elements.codeHelp.textContent = '';", 'clear the masked phone hint'],
    ["document.body.classList.add('auth-flow-complete');", 'switch to the completed-flow layout'],
    ['setBusy(true);', 'leave browser actions disabled'],
    ['elements.completePanel.focus();', 'move focus to the completion panel']
  ];
  if (!finishFlow) {
    errors.push('Secure account portal must define one completion-flow lock.');
  } else {
    for (const [fragment, purpose] of completionRequirements) {
      if (!finishFlow.includes(fragment)) errors.push(`Secure account portal completion flow must ${purpose}.`);
    }
  }
  if (!authApp.includes('let flowCompleted = false;')) {
    errors.push('Secure account portal must initialize the completed-flow lock before registering actions.');
  }
  if (!authApp.includes('button.disabled = busy || flowCompleted;')) {
    errors.push('Secure account portal must keep every action disabled after completion.');
  }
  const completionGuardCount = authApp.match(/if\s*\(\s*flowCompleted\s*\)\s*return;/g)?.length ?? 0;
  if (completionGuardCount < 6) {
    errors.push('Secure account portal must guard every account, recovery, enrollment, and verification action after completion.');
  }
  const backendExchangeStart = authApp.indexOf('async function finishBackendExchange(');
  const backendExchangeEnd = authApp.indexOf('\nasync function handlePrimarySignIn', backendExchangeStart);
  const backendExchange = backendExchangeStart >= 0 && backendExchangeEnd > backendExchangeStart
    ? authApp.slice(backendExchangeStart, backendExchangeEnd)
    : '';
  const completionCallCount = backendExchange.match(/\bfinishFlow\(\{/g)?.length ?? 0;
  if (completionCallCount !== 3
      || !backendExchange.includes("title: 'Server data deleted'")
      || !backendExchange.includes("title: 'Account deletion complete'")
      || !backendExchange.includes("title: 'You’re signed in'")
      || !/await signOut\(auth\)\.catch\(\(\) => undefined\);\s*finishFlow\(\{\s*title: 'Server data deleted'/.test(backendExchange)
      || !/await signOut\(auth\);\s*finishFlow\(\{\s*title: 'You’re signed in'/.test(backendExchange)) {
    errors.push('Secure account portal must lock sign-in, completed deletion, and signed-out partial identity-deletion outcomes.');
  }
  if (!authIndex.includes('id="complete-panel" class="auth-complete" tabindex="-1"')
      || !authIndex.includes('class="complete-note"')
      || !authIndex.includes('Return to the UpTier app now.')) {
    errors.push('Secure account portal must provide a focusable, explicit return-to-app completion panel.');
  }
  for (const selector of [
    '.auth-flow-complete .auth-intro',
    '.auth-flow-complete .auth-card-heading',
    '.auth-flow-complete .auth-status',
    '.auth-flow-complete .auth-shell',
    '.auth-flow-complete .auth-complete'
  ]) {
    if (!authStyles.includes(selector)) errors.push(`Secure account portal completed-flow styles must include ${selector}.`);
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
