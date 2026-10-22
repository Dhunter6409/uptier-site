import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HOSTING_OUTPUT_DIRECTORY, PUBLIC_FILES, stagePublicSite } from './hosting-files.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
stagePublicSite(root);
console.log(`Staged ${PUBLIC_FILES.length} reviewed public files in ${HOSTING_OUTPUT_DIRECTORY}.`);
