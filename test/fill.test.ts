import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Session, redact } from '../src/core/redact.ts';
import { FillError, fill } from '../src/executor/fill.ts';
import * as h from './helpers.ts';

describe('fill', () => {
  it('types the vault value through page.fill', async () => {
    const s = new Session();
    await redact(`card ${h.VISA}`, { session: s });
    const calls: [string, string][] = [];
    await fill({ fill: async (sel, v) => void calls.push([sel, v]) }, '#card', '[CARD_1]', s.vault);
    assert.deepEqual(calls, [['#card', h.VISA]]);
  });

  it('unknown or malformed token: error with the token, no call to the page', async () => {
    const s = new Session();
    let called = false;
    const page = { fill: async () => void (called = true) };
    await assert.rejects(fill(page, '#a', '[CARD_9]', s.vault), (e: Error) => e instanceof FillError && e.message === 'unknown token [CARD_9]');
    for (const bad of ['4111', '', '[card_1]', '[CARD_1] ']) await assert.rejects(fill(page, '#a', bad, s.vault), FillError);
    await assert.rejects(fill(page, '', '[CARD_1]', s.vault), FillError);
    assert.equal(called, false);
  });

  it('a page error that echoes the value does not reach the caller', async () => {
    const s = new Session();
    await redact(`card ${h.VISA}`, { session: s });
    const page = {
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
