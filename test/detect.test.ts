import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { detect, resolveOverlaps, sha256Hex, ibanOk, luhn } from '../src/core/detect.ts';
import type { Category } from '../src/core/detect.ts';
import * as h from './helpers.ts';

const cats = (text: string, opts = {}): Category[] => detect(text, opts).map((s) => s.category);
const only = (text: string, opts = {}) => {
  const f = detect(text, opts);
  assert.equal(f.length, 1, JSON.stringify(f));
  return f[0]!;
};

describe('cards', () => {
  for (const [name, n] of Object.entries({ visa: h.VISA, mastercard: h.MASTERCARD, mc2: h.MC_2SERIES, amex: h.AMEX, discover: h.DISCOVER, jcb: h.JCB, unionpay: h.UNIONPAY })) {
    it(`finds ${name}`, () => {
      const text = `pay with ${n} today`;
      const s = only(text);
      assert.equal(s.category, 'CARD');
      assert.equal(text.slice(s.start, s.end), n);
      assert.equal(s.confidence, 'sure');
    });
  }
  it('finds spaced and dashed forms, span covers the separators', () => {
    for (const n of [h.VISA_SPACED, h.VISA_DASHED]) {
      const s = only(`card: ${n}.`);
      assert.equal(`card: ${n}.`.slice(s.start, s.end), n);
    }
  });
  it('ignores Luhn failures, unknown IIN, short and long digit runs', () => {
    for (const n of [h.LUHN_BAD, h.LUHN_OK_UNKNOWN_IIN, '411111111111', h.VISA + '1234567', '1Z999AA10123456784']) {
      assert.deepEqual(detect(`ref ${n} end`), [], n);
    }
  });
  it('does not take digits that sit inside a longer id', () => {
    assert.deepEqual(detect(`ORD-${h.VISA}`), []);
  });
  it('finds a card that follows other digits in the same group run', () => {
    const text = `2026 ${h.VISA_SPACED}`;
    const s = only(text);
    assert.equal(text.slice(s.start, s.end), h.VISA_SPACED);
  });
});

describe('tax ids and IBAN', () => {
  it('SSN valid, with dashes or spaces', () => {
    assert.equal(only(`SSN ${h.SSN}`).category, 'US_SSN');
    assert.equal(only(`SSN ${h.SSN.replaceAll('-', ' ')}`).category, 'US_SSN');
  });
  it('SSN excluded ranges are not findings', () => {
    for (const bad of ['000-12-3456', '666-12-3456', '123-00-3456', '123-45-0000', '934-12-3456']) {
      assert.ok(!cats(bad).includes('US_SSN'), bad);
    }
  });
  it('nine digits count only after the SSN keyword, as likely', () => {
    const s = only('social security number: 123456789');
    assert.deepEqual([s.category, s.confidence], ['US_SSN', 'likely']);
    assert.deepEqual(detect('invoice 123456789'), []);
  });
  it('ITIN needs 9xx and a valid group', () => {
    assert.equal(only(`ITIN ${h.ITIN}`).category, 'US_ITIN');
    assert.deepEqual(detect('ITIN 912-69-1234'), []);
  });
  it('EIN is sure next to a keyword and likely without one', () => {
    assert.deepEqual([only(`EIN: ${h.EIN}`).confidence, only(`Employer ID ${h.EIN}`).confidence], ['sure', 'sure']);
    assert.equal(only(`Invoice ${h.EIN}`).confidence, 'likely');
    assert.deepEqual(detect('EIN: 07-1234567'), []);
  });
  it('IBAN passes mod-97 only', () => {
    assert.ok(ibanOk(h.IBAN_DE.replaceAll(' ', '')));
    const s = only(`IBAN ${h.IBAN_DE} thanks`);
    assert.equal(s.category, 'IBAN');
    assert.deepEqual(detect('IBAN DE89 3704 0044 0532 0130 01'), []);
  });
  it('IBAN does not swallow trailing capitalised words', () => {
    const text = `${h.IBAN_DE} THANKS`;
    const s = only(text);
    assert.equal(text.slice(s.start, s.end), h.IBAN_DE);
  });
  it('luhn helper', () => {
    assert.ok(luhn(h.VISA));
    assert.ok(!luhn(h.LUHN_BAD));
  });
});

describe('keys', () => {
  const cases: [Category, string][] = [
    ['AWS_KEY', h.AWS_ID],
    ['OPENAI_KEY', h.OPENAI],
    ['OPENAI_KEY', h.j('sk', '-', 'Ab3dEfGh1jKlMnOp2qRsTuVw4xYz')],
    ['ANTHROPIC_KEY', h.ANTHROPIC],
    ['GITHUB_TOKEN', h.GITHUB],
    ['GITHUB_TOKEN', h.j('github_', 'pat_', 'Ab3dEfGh1jKlMnOp2qRsTu_vwXyZ')],
    ['STRIPE_KEY', h.STRIPE],
    ['STRIPE_KEY', h.j('rk', '_live_', 'Ab3dEfGh1jKlMnOp2qRsTuVw')],
    ['SLACK_TOKEN', h.SLACK],
    ['GOOGLE_KEY', h.GOOGLE],
    ['JWT', h.JWT],
  ];
  for (const [category, value] of cases) {
    it(`${category}: ${value.slice(0, 6)}…`, () => {
      const text = `key=${value}\n`;
      const s = only(text);
      assert.equal(s.category, category);
      assert.equal(text.slice(s.start, s.end), value);
    });
  }
  it('Anthropic key is not also an OpenAI key', () => {
    assert.deepEqual(cats(h.ANTHROPIC), ['ANTHROPIC_KEY']);
  });
  it('AWS secret only next to a key id, and not a git SHA', () => {
    const text = `id ${h.AWS_ID}\nsecret ${h.AWS_SECRET}`;
    assert.deepEqual(cats(text), ['AWS_KEY', 'AWS_SECRET']);
    assert.deepEqual(cats(`secret ${h.AWS_SECRET}`), []);
    assert.deepEqual(cats(`id ${h.AWS_ID}\ncommit ${'a1b2c3d4e5'.repeat(4)}`), ['AWS_KEY']);
  });
  it('PEM block is one span, with or without the END line', () => {
    const s = only(`before\n${h.PEM}\nafter`);
    assert.equal(s.category, 'PRIVATE_KEY');
    assert.ok(`before\n${h.PEM}\nafter`.slice(s.start, s.end).endsWith('PRIVATE KEY-----'));
    const truncated = h.PEM.split('\n').slice(0, 3).join('\n') + '\nand then prose.';
    assert.equal(only(truncated).category, 'PRIVATE_KEY');
  });
  it('JWT needs a header that decodes to JSON with alg', () => {
    const noAlg = [Buffer.from('{"typ":"JWT"}').toString('base64url'), 'e30', 'c2ln'].join('.');
    assert.deepEqual(detect(noAlg), []);
    assert.deepEqual(detect('eyJ' + 'zzzz.zzzz.zzzz'), []);
  });
  it('prefix words alone are not findings', () => {
    assert.deepEqual(detect('the task-management-and-scheduling-service-v2 uses sk-learn'), []);
  });
});

describe('OTP', () => {
  it('4 to 8 digits within 40 characters after a keyword, case-insensitive', () => {
    for (const t of ['Your code is 482913', 'OTP: 4829', 'Passcode 48291357', 'VERIFICATION code (valid 10 min): 482913', 'one-time 482913', '2FA 482913']) {
      const s = only(t);
      assert.deepEqual([s.category, s.confidence], ['OTP', 'likely'], t);
    }
  });
  it('too far, too short, too long, dates and postal codes are not findings', () => {
    for (const t of ['code ' + 'x'.repeat(41) + ' 482913', 'code 123', 'code 123456789', 'code 2026-11-09', 'Postal code: 94107', 'ZIP code 94107']) {
      assert.deepEqual(detect(t), [], t);
    }
  });
});

describe('known secrets', () => {
  it('matches tokens by sha256 and nothing else', () => {
    const secret = h.j('pw-', 'hunter-', '4242x');
    const hashes = new Set([sha256Hex(secret)]);
    const text = `the password is ${secret}. Other words stay.`;
    const s = only(text, { knownHashes: hashes });
    assert.equal(s.category, 'KNOWN_SECRET');
    assert.equal(text.slice(s.start, s.end), secret);
    assert.deepEqual(detect(text, { knownHashes: new Set() }), []);
  });
});

describe('overlaps', () => {
  it('sure beats likely even when shorter; then the longer wins', () => {
    const mk = (start: number, end: number, confidence: 'sure' | 'likely', category: Category = 'CARD') => ({ start, end, category, confidence, rule: 'x' });
    assert.deepEqual(resolveOverlaps([mk(0, 20, 'likely'), mk(5, 10, 'sure')]).map((s) => s.start), [5]);
    assert.deepEqual(resolveOverlaps([mk(0, 5, 'sure'), mk(3, 12, 'sure', 'JWT')]).map((s) => s.category), ['JWT']);
    assert.equal(resolveOverlaps([mk(0, 5, 'sure'), mk(5, 9, 'sure')]).length, 2);
  });
  it('an IBAN that looks like card digits stays one IBAN finding', () => {
    assert.deepEqual(resolveOverlaps(detect(`IBAN ${h.IBAN_DE}`)).map((s) => s.category), ['IBAN']);
  });
});
