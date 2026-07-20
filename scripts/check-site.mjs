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
