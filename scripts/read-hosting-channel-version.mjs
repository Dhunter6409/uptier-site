import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFirebaseChannelVersion } from './verify-hosting-remote.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..');
const args = process.argv.slice(2);
let channel = '';

for (let index = 0; index < args.length; index += 1) {
  if (args[index] === '--channel') channel = args[++index] ?? '';
  else throw new Error(`Unknown argument: ${args[index]}`);
}

if (!channel) {
  throw new Error('Usage: node scripts/read-hosting-channel-version.mjs --channel CHANNEL');
}

console.log(JSON.stringify(readFirebaseChannelVersion(root, channel), null, 2));
