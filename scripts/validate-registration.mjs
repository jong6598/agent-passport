import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { validateSignedRegistration } from '../web/registration-core.js';

const path = process.argv[2];
if (!path) {
  console.error('Usage: npm run validate:registration -- /path/to/request.json\n       pbpaste | npm run validate:registration -- -');
  process.exit(2);
}

let document;
try {
  let raw = '';
  if (path === '-') {
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) {
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > 524288) throw new Error('input exceeds 512 KiB');
    }
  } else {
    raw = await readFile(resolve(path), 'utf8');
    if (Buffer.byteLength(raw, 'utf8') > 524288) throw new Error('input exceeds 512 KiB');
  }
  document = JSON.parse(raw);
} catch (error) {
  console.error(`Registration JSON could not be read: ${error.message}`);
  process.exit(1);
}

try {
  const result = await validateSignedRegistration(document);
  console.log(JSON.stringify({ ...result, reviewStatus: 'pending-human-approval', cryptographicValidation: 'PASS' }, null, 2));
} catch (error) {
  console.error(`Registration validation failed: ${error.message}`);
  process.exit(1);
}
