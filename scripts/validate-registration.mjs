import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { validateSignedRegistration } from '../web/registration-core.js';

const path = process.argv[2];
if (!path) {
  console.error('Usage: npm run validate:registration -- /path/to/request.json');
  process.exit(2);
}

let document;
try {
  document = JSON.parse(await readFile(resolve(path), 'utf8'));
} catch (error) {
  console.error(`Registration file could not be read: ${error.message}`);
  process.exit(1);
}

try {
  const result = await validateSignedRegistration(document);
  console.log(JSON.stringify({ ...result, reviewStatus: 'pending-human-approval', cryptographicValidation: 'PASS' }, null, 2));
} catch (error) {
  console.error(`Registration validation failed: ${error.message}`);
  process.exit(1);
}
