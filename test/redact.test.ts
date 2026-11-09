import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { describe, it } from 'node:test';
import { NearAiCloud, NotConfigured, RulesOnly } from '../src/core/classifier.ts';
import type { Classifier } from '../src/core/classifier.ts';
import { Session, Vault, redact } from '../src/core/redact.ts';
import * as h from './helpers.ts';

describe('redact', () => {
  it('replaces values with numbered placeholders and keeps the rest', async () => {
    const s = new Session();
    const r = await redact(`Card ${h.VISA}, SSN ${h.SSN}, key ${h.OPENAI}. Thanks.`, { session: s });
    assert.equal(r.text, 'Card [CARD_1], SSN [US_SSN_1], key [OPENAI_KEY_1]. Thanks.');
    assert.deepEqual(r.findings.map((f) => f.token), ['[CARD_1]', '[US_SSN_1]', '[OPENAI_KEY_1]']);
    assert.ok(r.findings.every((f) => f.source === 'rules' && /^[0-9a-f]{64}$/.test(f.span_sha256)));
  });

  it('the same value gets the same placeholder, in other formats too', async () => {
    const s = new Session();
    const a = await redact(`${h.VISA} and ${h.VISA_SPACED} and ${h.MASTERCARD}`, { session: s });
    assert.equal(a.text, '[CARD_1] and [CARD_1] and [CARD_2]');
    const b = await redact(`again ${h.VISA}`, { session: s });
    assert.equal(b.text, 'again [CARD_1]');
  });

  it('findings carry no raw value; hashes are salted per session', async () => {
    const s1 = new Session();
    const s2 = new Session();
    const text = `code is 482913`;
    const a = await redact(text, { session: s1 });
    const b = await redact(text, { session: s2 });
    assert.ok(!JSON.stringify(a).includes('482913'));
    assert.notEqual(a.findings[0]?.span_sha256, b.findings[0]?.span_sha256);
    const again = await redact(text, { session: s1 });
    assert.equal(again.findings[0]?.span_sha256, a.findings[0]?.span_sha256);
  });

  it('vault holds values for the executor, never prints them, and forgets', async () => {
    const s = new Session();
    await redact(`card ${h.VISA}`, { session: s });
    assert.equal(s.vault.get('[CARD_1]'), h.VISA);
    for (const shown of [JSON.stringify(s.vault), inspect(s.vault), inspect(s), JSON.stringify(s)]) {
      assert.ok(!shown.includes(h.VISA.slice(0, 8)), shown);
    }
    s.forget();
    assert.equal(s.vault.get('[CARD_1]'), undefined);
    assert.equal(s.vault.size, 0);
    const r = await redact(`card ${h.MASTERCARD}`, { session: s });
    assert.equal(r.text, 'card [CARD_1]');
    const v = new Vault();
    v.set('[X_1]', 'v');
    v.forget();
    assert.equal(v.get('[X_1]'), undefined);
  });

  it('text with nothing sensitive comes back unchanged', async () => {
    const t = 'Order #1234 shipped on 2026-11-09 to 94107.';
    const r = await redact(t, { session: new Session() });
    assert.equal(r.text, t);
    assert.deepEqual(r.findings, []);
  });

  it('empty input is fine', async () => {
    assert.deepEqual(await redact('', { session: new Session() }), { text: '', findings: [] });
  });

  it('a second classifier adds spans marked tee; bad spans are dropped', async () => {
    const fake: Classifier = {
      name: 'fake-tee',
      async classify(text) {
        const at = text.indexOf('Jane Doe');
        return [
          { start: at, end: at + 8, category: 'KNOWN_SECRET', confidence: 'likely', rule: 'tee' },
          { start: -1, end: 4, category: 'CARD', confidence: 'sure', rule: 'bad' },
          { start: 5, end: 9999, category: 'CARD', confidence: 'sure', rule: 'bad' },
        ];
      },
    };
    const r = await redact(`Jane Doe paid with ${h.VISA}`, { session: new Session(), classifier: fake });
    assert.equal(r.text, '[KNOWN_SECRET_1] paid with [CARD_1]');
    assert.deepEqual(r.findings.map((f) => f.source), ['tee', 'rules']);
  });

  it('a failing classifier fails the call instead of letting text through', async () => {
    await assert.rejects(redact(`card ${h.VISA}`, { session: new Session(), classifier: new NearAiCloud({}) }), NotConfigured);
  });
});

describe('ambiguous card runs', () => {
  it('no digit of the run survives, for every 4-digit prefix before a card on the same line', async () => {
    const card = ['4111', '1111', '1111', '1111'].join(' ');
    const session = new Session();
    let n = 0;
    for (let prefix = 1000; prefix <= 9999; prefix++) {
      const r = await redact(`Ref ${prefix} ${card}`, { session });
      assert.equal(r.text.replace(/\[CARD_\d+\]/, ''), 'Ref ', `prefix ${prefix}`);
      assert.ok(!/\d{4}/.test(r.text.replace(/\[CARD_\d+\]/g, '')), `prefix ${prefix}`);
      assert.equal(r.findings.length, 1);
      assert.equal(r.findings[0]!.ambiguous, true, `prefix ${prefix}`);
      n++;
    }
    assert.equal(n, 9000);
  });
});

describe('classifiers', () => {
  it('RulesOnly runs the detectors', async () => {
    const spans = await new RulesOnly().classify(`card ${h.VISA}`);
    assert.equal(spans[0]?.category, 'CARD');
  });
  it('NearAiCloud throws NotConfigured without a key, and still does with one (no transport yet)', async () => {
    await assert.rejects(new NearAiCloud({}).classify('x'), NotConfigured);
    await assert.rejects(new NearAiCloud({ NEAR_AI_CLOUD_API_KEY: 'present' }).classify('x'), /not implemented/);
  });
});
