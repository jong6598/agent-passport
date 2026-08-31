import test from 'node:test';
import assert from 'node:assert/strict';

import { configuredValueMatches } from '../worker.js';

test('configuredValueMatches accepts an exact value from a comma-separated allowlist', () => {
  const configured = 'https://flop-agent-passport.pages.dev, https://jong6598.github.io';
  assert.equal(configuredValueMatches('https://flop-agent-passport.pages.dev', configured), true);
  assert.equal(configuredValueMatches('https://jong6598.github.io', configured), true);
});

test('configuredValueMatches rejects missing, prefix, suffix, and empty values', () => {
  const configured = 'https://flop-agent-passport.pages.dev,https://jong6598.github.io';
  assert.equal(configuredValueMatches(null, configured), false);
  assert.equal(configuredValueMatches('', configured), false);
  assert.equal(configuredValueMatches('https://flop-agent-passport.pages.dev.evil.example', configured), false);
  assert.equal(configuredValueMatches('https://flop-agent-passport.pages.dev/', configured), false);
  assert.equal(configuredValueMatches('https://flop-agent-passport.pages.dev', ''), false);
});

test('configuredValueMatches supports exact Turnstile hostname allowlists', () => {
  const configured = 'flop-agent-passport.pages.dev,jong6598.github.io';
  assert.equal(configuredValueMatches('flop-agent-passport.pages.dev', configured), true);
  assert.equal(configuredValueMatches('evil-flop-agent-passport.pages.dev', configured), false);
});
