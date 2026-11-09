import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Browser, Page } from 'playwright-core';
import { Session, redact } from '../../src/core/redact.ts';
import { FillError, fill } from '../../src/executor/fill.ts';
import { launchChrome } from '../../src/executor/launch.ts';
import { j } from '../helpers.ts';

const enabled = process.env.CF_BROWSER === '1';
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CARD = ['4242', '4242', '4242', '4242'].join(' ');
const DIGITS = CARD.replaceAll(' ', '');

describe('executor in a real browser', { skip: enabled ? false : 'set CF_BROWSER=1 (npm run test:browser)' }, () => {
  let browser: Browser;
  let page: Page;
  const logs: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);

  before(async () => {
    browser = await launchChrome();
    page = await browser.newPage();
    page.on('console', (m) => logs.push(m.text()));
    page.on('pageerror', (e) => logs.push(e.message));
    await page.setContent(
      readFileSync(join(root, 'demo', 'page.template.html'), 'utf8').replace('{{CARD}}', CARD).replace('{{SSN}}', 'x').replace('{{KEY}}', 'y'),
    );
  });
  after(async () => {
    await browser?.close();
  });

  it('fills the field from a placeholder; digits never reach stdout, stderr, page logs or errors', async () => {
    const session = new Session();
    const redacted = await redact(await page.locator('body').innerText(), { session });
    assert.ok(redacted.text.includes('[CARD_1]') && !redacted.text.includes(DIGITS));

    const captured: string[] = [];
    process.stdout.write = ((c: string | Uint8Array) => (captured.push(String(c)), true)) as typeof process.stdout.write;
    process.stderr.write = ((c: string | Uint8Array) => (captured.push(String(c)), true)) as typeof process.stderr.write;
    let failure = '';
    try {
      await fill(page, '#card', '[CARD_1]', session.vault);
      await fill(page, '#does-not-exist', '[CARD_1]', session.vault, { timeout: 300 }).catch((e: unknown) => {
        failure = e instanceof FillError ? `${e.message}\n${e.stack}` : 'wrong error type';
      });
    } finally {
      process.stdout.write = realOut;
      process.stderr.write = realErr;
    }

    assert.equal(await page.inputValue('#card'), CARD);
    assert.match(failure, /fill failed for \[CARD_1\]/);
    const loose = new RegExp(DIGITS.split('').join('[ -]?'));
    for (const [name, text] of Object.entries({ stdout_stderr: captured.join(''), page_console: logs.join('\n'), error: failure })) {
      assert.ok(!loose.test(text), `${name} leaks the card digits`);
    }
    // control: the same search does see the digits where they legitimately are
    assert.ok(loose.test(await page.inputValue('#card')));
  });

  it('an unknown placeholder leaves the field untouched', async () => {
    const before = await page.inputValue('#ssn');
    await assert.rejects(fill(page, '#ssn', '[US_SSN_7]', new Session().vault), /unknown token \[US_SSN_7\]/);
    assert.equal(await page.inputValue('#ssn'), before);
  });

  it('a hidden-key placeholder fills a second field', async () => {
    const s = new Session();
    const key = j('sk', '_live_', 'Q7x2LmN9pR4sT6vW8yB1cD3f');
    await redact(`key ${key}`, { session: s });
    await fill(page, '#api-key', '[STRIPE_KEY_1]', s.vault);
    assert.equal(await page.inputValue('#api-key'), key);
  });
});
