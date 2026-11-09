import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Browser, Page } from 'playwright-core';
import { Session, redact } from '../../src/core/redact.ts';
import { FillError, fill } from '../../src/executor/fill.ts';
import { launchChrome } from '../../src/executor/launch.ts';
import { serveHtml } from '../../demo/serve.ts';
import { originOf } from '../../src/core/redact.ts';
import { j } from '../helpers.ts';

const enabled = process.env.CF_BROWSER === '1';
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CARD = ['4242', '4242', '4242', '4242'].join(' ');
const DIGITS = CARD.replaceAll(' ', '');

describe('executor in a real browser', { skip: enabled ? false : 'set CF_BROWSER=1 (npm run test:browser)' }, () => {
  let browser: Browser;
  let page: Page;
  let shop: Awaited<ReturnType<typeof serveHtml>>;
  let evil: Awaited<ReturnType<typeof serveHtml>>;
  const logs: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);

  before(async () => {
    browser = await launchChrome();
    page = await browser.newPage();
    page.on('console', (m) => logs.push(m.text()));
    page.on('pageerror', (e) => logs.push(e.message));
    const html = readFileSync(join(root, 'demo', 'page.template.html'), 'utf8').replace('{{CARD}}', CARD).replace('{{SSN}}', 'x').replace('{{KEY}}', 'y');
    shop = await serveHtml(html);
    evil = await serveHtml(html);
    await page.goto(shop.url);
  });
  after(async () => {
    await browser?.close();
    await shop?.close();
    await evil?.close();
  });

  it('fills the field from a placeholder; digits never reach stdout, stderr, page logs or errors', async () => {
    const session = new Session();
    const redacted = await redact(await page.locator('body').innerText(), { session, origin: originOf(page.url()) });
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
    await redact(`key ${key}`, { session: s, origin: originOf(page.url()) });
    await fill(page, '#api-key', '[STRIPE_KEY_1]', s.vault);
    assert.equal(await page.inputValue('#api-key'), key);
  });

  it('a page on another origin (another port) is refused and stays empty', async () => {
    const s = new Session();
    await redact(`card ${CARD}`, { session: s, origin: originOf(shop.url) });
    const other = await browser.newPage();
    try {
      await other.goto(evil.url);
      await assert.rejects(fill(other, '#card', '[CARD_1]', s.vault), /may not be filled on this page/);
      assert.equal(await other.inputValue('#card'), '');
    } finally {
      await other.close();
    }
  });

  it('a field inside an iframe of another origin is out of reach: frame-crossing selectors are refused, plain CSS stays in the main frame', async () => {
    const host = await serveHtml(`<!doctype html><input id="card"><iframe id="w" src="${evil.url}"></iframe>`);
    const p = await browser.newPage();
    try {
      await p.goto(host.url);
      const frameInput = p.frameLocator('#w').locator('#card');
      await frameInput.waitFor();
      // the placeholder is bound to the top page; the iframe is another origin
      const s2 = new Session();
      await redact(`card ${CARD}`, { session: s2, origin: originOf(host.url) });
      for (const sel of ['#w >> internal:control=enter-frame >> #card', 'iframe >> internal:control=enter-frame >> input']) {
        await assert.rejects(fill(p, sel, '[CARD_1]', s2.vault), /selector not allowed/);
      }
      await fill(p, '#card', '[CARD_1]', s2.vault);
      assert.equal(await p.inputValue('#card'), CARD);
      assert.equal(await frameInput.inputValue(), '');
    } finally {
      await p.close();
      await host.close();
    }
  });

  it('navigation after the owner check: nothing typed on the new page, no value in the error', async () => {
    const s = new Session();
    await redact(`card ${CARD}`, { session: s, origin: originOf(shop.url) });
    const p = await browser.newPage();
    try {
      await p.goto(shop.url);
      const main = p.mainFrame();
      const racing = {
        url: () => p.url(),
        mainFrame: () => ({
          url: () => main.url(),
          async waitForSelector(sel: string, o: { state: 'attached'; timeout: number }) {
            const h = (await main.waitForSelector(sel, o))!;
            return {
              ownerFrame: async () => {
                const f = await h.ownerFrame();
                await p.goto(evil.url); // the page moves away after the check
                return f === main ? racing.mainFrame() : f;
              },
              fill: (v: string, opts?: { timeout?: number }) => h.fill(v, opts),
            };
          },
        }),
      };
      let failure = '';
      await fill(racing as never, '#card', '[CARD_1]', s.vault, { timeout: 1000 }).catch((e: unknown) => {
        failure = e instanceof FillError ? e.message : 'wrong error type';
      });
      assert.ok(failure !== '' && failure !== 'wrong error type', failure);
      assert.ok(!failure.includes(DIGITS));
      assert.equal(await p.inputValue('#card'), '');
    } finally {
      await p.close();
    }
  });

  it('redirect while waiting, to a page that replaces Node.prototype.ownerDocument: refused, field empty', async () => {
    const hostile = await serveHtml(
      `<!doctype html><script>Object.defineProperty(Node.prototype,'ownerDocument',{configurable:true,get(){return {location:{origin:${JSON.stringify(
        originOf(shop.url),
      )}}}}});</script><input id="card">`,
    );
    const start = await serveHtml(`<!doctype html><p>loading</p><script>setTimeout(function(){location.href=${JSON.stringify(hostile.url)}},300)</script>`);
    const s = new Session();
    await redact(`card ${CARD}`, { session: s, origin: originOf(start.url) });
    const p = await browser.newPage();
    try {
      await p.goto(start.url);
      let failure = '';
      await fill(p, '#card', '[CARD_1]', s.vault, { timeout: 3000 }).catch((e: unknown) => {
        failure = e instanceof FillError ? e.message : 'wrong error type';
      });
      // either refusal path is fine (origin check, or the handle detached by the navigation)
      assert.match(failure, /^(token \[CARD_1\] may not be filled|fill failed for \[CARD_1\] on #card)/, failure);
      assert.ok(!failure.includes(DIGITS) && !failure.includes(CARD), 'error carries the value');
      await p.waitForURL(hostile.url);
      assert.equal(await p.inputValue('#card'), '');
      const dom = await p.evaluate(() => document.documentElement.outerHTML);
      assert.ok(!dom.includes(DIGITS) && !dom.includes(CARD), 'value present in the foreign page DOM');
    } finally {
      await p.close();
      await start.close();
      await hostile.close();
    }
  });
});
