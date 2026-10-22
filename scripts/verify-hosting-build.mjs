import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyStagedSite } from './hosting-files.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argumentsToParse = process.argv.slice(2);
let expectedSourceSha = '';
let allowDirty = false;

for (let index = 0; index < argumentsToParse.length; index += 1) {
  const argument = argumentsToParse[index];
  if (argument === '--allow-dirty') allowDirty = true;
  else if (argument === '--expected-source-sha') expectedSourceSha = argumentsToParse[++index] ?? '';
  else throw new Error(`Unknown argument: ${argument}`);
}

if (!allowDirty && !/^[0-9a-f]{40}$/i.test(expectedSourceSha)) {
  throw new Error('Exact deployment verification requires --expected-source-sha <40-character commit>. Use --allow-dirty only for local pre-commit testing.');
}
if (expectedSourceSha && !/^[0-9a-f]{40}$/i.test(expectedSourceSha)) {
  throw new Error('--expected-source-sha must be a full 40-character commit.');
}

function runGit(args) {
  const result = spawnSync('git', ['-c', `safe.directory=${root.replaceAll('\\', '/')}`, '-C', root, ...args], {
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.status !== 0) throw new Error(result.stderr.trim() || `git ${args.join(' ')} failed.`);
  return result.stdout.trim();
}

const sourceCommit = runGit(['rev-parse', 'HEAD']);
if (expectedSourceSha && sourceCommit.toLowerCase() !== expectedSourceSha.toLowerCase()) {
  throw new Error(`Checked-out commit ${sourceCommit} does not match expected source ${expectedSourceSha}.`);
}
const changes = runGit(['status', '--porcelain=v1', '--untracked-files=all']);
if (!allowDirty && changes) throw new Error(`Refusing exact deployment verification from a dirty worktree:\n${changes}`);

const result = verifyStagedSite(root);
console.log(JSON.stringify({ sourceCommit, worktreeClean: !changes, ...result }, null, 2));
