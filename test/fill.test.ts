import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Session, redact } from '../src/core/redact.ts';
import { FillError, fill } from '../src/executor/fill.ts';
import * as h from './helpers.ts';

const SHOP = 'https://shop.example';

function fakePage(url: string, onFill: (sel: string, v: string) => void = () => {}) {
  return { url: () => url, fill: async (sel: string, v: string) => void onFill(sel, v) };
}

async function sessionWithCard(origin: string | null = SHOP): Promise<Session> {
  const s = new Session();
  await redact(`card ${h.VISA}`, { session: s, origin: origin ?? undefined });
  return s;
}

describe('fill', () => {
  it('types the vault value on the origin it came from', async () => {
    const s = await sessionWithCard();
    const calls: [string, string][] = [];
    await fill(fakePage(`${SHOP}/checkout?x=1`, (a, b) => calls.push([a, b])), '#card', '[CARD_1]', s.vault);
    assert.deepEqual(calls, [['#card', h.VISA]]);
  });

  it('another origin is refused and the page never sees the value', async () => {
    const s = await sessionWithCard();
    const calls: string[] = [];
    for (const url of ['https://evil.example/checkout', 'http://shop.example/', 'https://shop.example:8443/', 'about:blank', 'not a url']) {
      await assert.rejects(fill(fakePage(url, (_a, b) => calls.push(b)), '#card', '[CARD_1]', s.vault), (e: Error) => {
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
    const page = fakePage(SHOP, () => void (called = true));
    await assert.rejects(fill(page, '#a', '[CARD_9]', s.vault), (e: Error) => e instanceof FillError && e.message === 'unknown token [CARD_9]');
    for (const bad of ['4111', '', '[card_1]', '[CARD_1] ']) await assert.rejects(fill(page, '#a', bad, s.vault), FillError);
    await assert.rejects(fill(page, '', '[CARD_1]', s.vault), FillError);
    assert.equal(called, false);
  });

  it('a page error that echoes the value does not reach the caller', async () => {
    const s = await sessionWithCard();
    const page = {
      url: () => SHOP,
      fill: async (_sel: string, v: string) => {
        throw new Error(`Timeout while typing ${v}`);
      },
    };
    await assert.rejects(fill(page, '#card', '[CARD_1]', s.vault), (e: Error) => {
      assert.ok(e instanceof FillError);
      assert.equal(e.message, 'fill failed for [CARD_1] on #card');
      assert.ok(!String(e.stack).includes(h.VISA) && e.cause === undefined);
      return true;
    });
  });
});
