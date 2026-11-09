import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Session, redact } from '../src/core/redact.ts';
import { FillError, fill } from '../src/executor/fill.ts';
import * as h from './helpers.ts';
import { fakePage } from './helpers.ts';

const SHOP = 'https://shop.example';

async function sessionWithCard(origin: string | null = SHOP): Promise<Session> {
  const s = new Session();
  await redact(`card ${h.VISA}`, { session: s, origin: origin ?? undefined });
  return s;
}

describe('fill', () => {
  it('types the vault value on the origin it came from', async () => {
    const s = await sessionWithCard();
    const calls: [string, string][] = [];
    await fill(fakePage(`${SHOP}/checkout?x=1`, { onFill: (a, b) => calls.push([a, b]) }), '#card', '[CARD_1]', s.vault);
    assert.deepEqual(calls, [['#card', h.VISA]]);
  });

  it('another origin is refused and the page never sees the value', async () => {
    const s = await sessionWithCard();
    const calls: string[] = [];
    for (const url of ['https://evil.example/checkout', 'http://shop.example/', 'https://shop.example:8443/', 'about:blank', 'not a url']) {
      await assert.rejects(fill(fakePage(url, { onFill: (_a, b) => calls.push(b) }), '#card', '[CARD_1]', s.vault), (e: Error) => {
        assert.ok(e instanceof FillError && !e.message.includes(h.VISA.slice(0, 6)), e.message);
        return true;
      });
    }
    assert.deepEqual(calls, []);
  });

  it('a token with no origin binding is refused', async () => {
    const s = await sessionWithCard(null);
    await assert.rejects(fill(fakePage(SHOP), '#card', '[CARD_1]', s.vault), /no origin binding/);
  });

  it('the same value seen on two origins gets two tokens, each bound to its own', async () => {
    const s = new Session();
    await redact(`card ${h.VISA}`, { session: s, origin: SHOP });
    const r = await redact(`card ${h.VISA}`, { session: s, origin: 'https://other.example' });
    assert.equal(r.text, 'card [CARD_2]');
    assert.equal(s.vault.originOf('[CARD_2]'), 'https://other.example');
  });

  it('unknown or malformed token: error with the token, no call to the page', async () => {
    const s = await sessionWithCard();
    let called = false;
    const page = fakePage(SHOP, { onFill: () => void (called = true) });
    await assert.rejects(fill(page, '#a', '[CARD_9]', s.vault), (e: Error) => e instanceof FillError && e.message === 'unknown token [CARD_9]');
    for (const bad of ['4111', '', '[card_1]', '[CARD_1] ']) await assert.rejects(fill(page, '#a', bad, s.vault), FillError);
    await assert.rejects(fill(page, '', '[CARD_1]', s.vault), FillError);
    assert.equal(called, false);
  });

  it('a page error that echoes the value does not reach the caller', async () => {
    const s = await sessionWithCard();
    const page = fakePage(SHOP, {
      fillError: (v) => new Error(`Timeout while typing ${v}`),
    });
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), (e: Error) => {
      assert.ok(e instanceof FillError);
      assert.equal(e.message, 'fill failed for [CARD_1] on #card');
      assert.ok(!String(e.stack).includes(h.VISA) && e.cause === undefined);
      return true;
    });
  });

  it('plain CSS selectors pass, Playwright engines and frame-crossing forms are refused before any lookup', async () => {
    const s = await sessionWithCard();
    const seen: string[] = [];
    const page = fakePage(SHOP, { selectors: seen });
    for (const ok of ['#card', 'input[name=card]', 'form#checkout input.card-number', 'label > input', '[autocomplete="cc-number"]']) {
      await fill(page, ok, '[CARD_1]', s.vault);
    }
    assert.equal(seen.length, 5);
    seen.length = 0;
    for (const bad of [
      'iframe >> internal:control=enter-frame >> input',
      'iframe >> input',
      'aria-ref=f1e2',
      'internal:role=textbox',
      'xpath=//input',
      '//input',
      'text=Card number',
      'input:has-text("x")',
      'role=textbox[name="Card"]',
      'css=input',
      'id=card',
      'input:visible',
      '',
      '   ',
    ]) {
      await assert.rejects(fill(page, bad, '[CARD_1]', s.vault), (e: Error) => e instanceof FillError && !e.message.includes(h.VISA.slice(0, 6)), bad);
    }
    assert.deepEqual(seen, []);
  });

  it('an element in an iframe is refused, whatever the iframe origin', async () => {
    const s = await sessionWithCard();
    const calls: string[] = [];
    const page = fakePage(SHOP, { iframeUrl: 'https://widget.evil.example/chat', onFill: (_a, b) => calls.push(b) });
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), /may not be filled in this document/);
    const blank = fakePage(SHOP, { iframeUrl: SHOP + '/same-origin-iframe', onFill: (_a, b) => calls.push(b) });
    await assert.rejects(fill(blank, '#card', '[CARD_1]', s.vault), /may not be filled in this document/);
    assert.deepEqual(calls, []);
  });

  it('navigation between the origin check and the fill: refused, nothing typed, no value in the error', async () => {
    const s = await sessionWithCard();
    const typed: string[] = [];
    const page = fakePage(SHOP, { detachAfterOwnerCheck: true, onFill: (_a, b) => typed.push(b) });
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), (e: Error) => {
      assert.ok(e instanceof FillError);
      assert.equal(e.message, 'fill failed for [CARD_1] on #card');
      return true;
    });
    assert.deepEqual(typed, []);
  });

  it('redirect while the lookup waits: the element is found in the new document of another origin and refused', async () => {
    const s = await sessionWithCard();
    const typed: string[] = [];
    const page = fakePage(SHOP, { redirectDuringWait: 'https://evil.example/', onFill: (_a, b) => typed.push(b) });
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), /may not be filled in this document/);
    assert.deepEqual(typed, []);
  });

  it('the main frame moves right after the owner check: the second URL check stops the fill', async () => {
    const s = await sessionWithCard();
    const typed: string[] = [];
    const page = fakePage(SHOP, { redirectAfterOwnerCheck: 'https://evil.example/', onFill: (_a, b) => typed.push(b) });
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), (e: Error) => {
      assert.ok(e instanceof FillError && !e.message.includes(h.VISA.slice(0, 6)));
      return true;
    });
    await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(typed, []);
  });

  it('the lookup uses a short timeout by default', async () => {
    const s = await sessionWithCard();
    let seen = -1;
    const page = {
      url: () => SHOP,
      mainFrame: () => ({
        url: () => SHOP,
        async waitForSelector(_sel: string, o: { timeout: number }) {
          seen = o.timeout;
          return null;
        },
      }),
    };
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), FillError);
    assert.equal(seen, 2000);
  });
});
