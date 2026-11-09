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
  it('a card-shaped number with a letter prefix is a card (cc-4111...), a longer digit run is not', () => {
    assert.equal(only(`cc-${h.VISA}`).category, 'CARD');
    assert.deepEqual(detect(h.VISA + '5'), []);
  });
  it('NBSP, thin space, dot separators and fullwidth digits', () => {
    const groups = ['4111', '1111', '1111', '1111'];
    for (const sep of ['\u00a0', '\u2009', '\u202f', '.']) {
      const n = groups.join(sep);
      const text = `card ${n} ok`;
      const s = only(text);
      assert.equal(text.slice(s.start, s.end), n, JSON.stringify(sep));
    }
    const wide = h.VISA.replace(/\d/g, (d) => String.fromCharCode(0xff10 + Number(d)));
    const text = `card ${wide} ok`;
    const s = only(text);
    assert.equal(text.slice(s.start, s.end), wide);
  });
  it('tab, line break, ideographic space, fullwidth hyphen, en dash, underscore and wide gaps', () => {
    const groups = ['4111', '1111', '1111', '1111'];
    for (const sep of ['\t', '\n', '\r\n', '\u3000', '\uFF0D', '\u2013', '_', '    ', '      ']) {
      const n = groups.join(sep);
      const text = `card ${n} ok`;
      const s = only(text);
      assert.equal(text.slice(s.start, s.end), n, JSON.stringify(sep));
    }
    const wide = groups.join('\uFF0D').replace(/\d/g, (d) => String.fromCharCode(0xff10 + Number(d)));
    assert.equal(only(`card ${wide}`).category, 'CARD');
  });
  it('multi-line numbers are not glued into a card unless Luhn and a known IIN say so', () => {
    const texts = [
      'Qty 3\nSKU 20481\nPhone 415 555 0134\nTotal 1249.00\nOrder 88213344',
      '1001\n1002\n1003\n1004\n1005',
      '2026 11 09\n12 30 45\n7788 9900',
      [h.LUHN_BAD.slice(0, 4), h.LUHN_BAD.slice(4, 8), h.LUHN_BAD.slice(8, 12), h.LUHN_BAD.slice(12)].join('\n'),
      h.LUHN_OK_UNKNOWN_IIN.replace(/(.{4})/g, '$1\n'),
      '1234 5678 9012 3456',
      'Row 1: 4111\nRow 2: 1111\nRow 3: 1111\nRow 4: 1111',
      '4111\n\n\n\n\n\n\n1111\n1111\n1111',
    ];
    for (const t of texts) assert.deepEqual(detect(t).filter((x) => x.category === 'CARD'), [], JSON.stringify(t));
    const ok = [h.VISA.slice(0, 4), h.VISA.slice(4, 8), h.VISA.slice(8, 12), h.VISA.slice(12)].join('\n');
    assert.equal(only(ok).category, 'CARD');
  });
  it('a number on the line above is not glued to the card below', () => {
    const text = 'Qty 401\n' + [h.AMEX.slice(0, 4), h.AMEX.slice(4, 10), h.AMEX.slice(10)].join(' ');
    const cards = detect(text).filter((x) => x.category === 'CARD');
    assert.equal(cards.length, 1);
    assert.equal(text.slice(cards[0]!.start, cards[0]!.end), [h.AMEX.slice(0, 4), h.AMEX.slice(4, 10), h.AMEX.slice(10)].join(' '));
    for (const sep of ['\n', '\t', '\r\n', ' ']) {
      const t = `Qty 401${sep}${h.AMEX.slice(0, 4)} ${h.AMEX.slice(4, 10)} ${h.AMEX.slice(10)}`;
      const c = detect(t).filter((x) => x.category === 'CARD');
      assert.equal(c.length, 1, JSON.stringify(sep));
      assert.ok(t.slice(c[0]!.start, c[0]!.end).startsWith('3782'), JSON.stringify(sep));
    }
  });
  it('a column of four 4-digit numbers is a card only when Luhn and IIN say so', () => {
    for (const col of ['1001\n1002\n1003\n1004', '4111\n1111\n1111\n1112', '2024\n0615\n0830\n1999', '4111\n1111\n1111\n1111\n9999']) {
      const c = detect(col).filter((x) => x.category === 'CARD');
      if (col.startsWith('4111\n1111\n1111\n1111\n')) assert.equal(c.length, 1, 'the 4x4 inside a longer column is still found once');
      else assert.deepEqual(c, [], JSON.stringify(col));
    }
    assert.equal(detect('4111\n1111\n1111\n1111').filter((x) => x.category === 'CARD').length, 1);
  });
  it('odd groupings are not cards', () => {
    assert.deepEqual(detect('4111 11 11 1111 1111').filter((x) => x.category === 'CARD'), []);
  });
  it('several cards in one row are all found', () => {
    for (const row of [`${h.VISA} ${h.MASTERCARD}`, `${h.VISA_SPACED} ${h.MASTERCARD}`, `${h.VISA}\n${h.AMEX}`]) {
      assert.equal(detect(row).filter((x) => x.category === 'CARD').length, 2, row);
    }
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
  it('AWS secret in .env and shell forms (no spaces around =)', () => {
    for (const text of [
      `AWS_ACCESS_KEY_ID=${h.AWS_ID}\nAWS_SECRET_ACCESS_KEY=${h.AWS_SECRET}\n`,
      `export AWS_ACCESS_KEY_ID=${h.AWS_ID}\nexport AWS_SECRET_ACCESS_KEY="${h.AWS_SECRET}"`,
      `aws_secret_access_key = ${h.AWS_SECRET}\naws_access_key_id = ${h.AWS_ID}`,
      `{"id":"${h.AWS_ID}","secret":"${h.AWS_SECRET}"}`,
    ]) {
      const secret = detect(text).find((x) => x.category === 'AWS_SECRET');
      assert.ok(secret, text);
      assert.equal(text.slice(secret.start, secret.end), h.AWS_SECRET);
    }
  });
  it('AWS secret by its label alone, far from any key id', () => {
    const far = 'x'.repeat(500);
    for (const text of [
      `AWS_SECRET_ACCESS_KEY=${h.AWS_SECRET}\n`,
      `${far}\nexport AWS_SECRET_ACCESS_KEY="${h.AWS_SECRET}"\n${far}`,
      `{"SecretAccessKey": "${h.AWS_SECRET}"}`,
      `aws_secret_access_key: ${h.AWS_SECRET}`,
    ]) {
      const secret = detect(text).filter((x) => x.category === 'AWS_SECRET');
      assert.equal(secret.length, 1, text.slice(0, 60));
      assert.equal(text.slice(secret[0]!.start, secret[0]!.end), h.AWS_SECRET);
      assert.equal(secret[0]!.confidence, 'sure');
    }
    assert.deepEqual(detect(`AWS_SECRET_ACCESS_KEY=${h.AWS_SECRET.slice(0, 39)}`), []);
    assert.deepEqual(detect(`secret_access_key is rotated monthly ${h.AWS_SECRET}`).filter((x) => x.category === 'AWS_SECRET'), []);
  });
  it('AWS secret by label: spaced words, space separator, Kubernetes name/value, Terraform', () => {
    const far = 'x'.repeat(500);
    const forms = [
      `AWS secret access key: ${h.AWS_SECRET}`,
      `Secret Access Key,${h.AWS_SECRET}`.replace(',', ' '),
      `aws configure set aws_secret_access_key ${h.AWS_SECRET}`,
      `${far}\n- name: AWS_SECRET_ACCESS_KEY\n  value: "${h.AWS_SECRET}"\n${far}`,
      `${far}\nenv:\n  - name: AWS_SECRET_ACCESS_KEY\n    value: ${h.AWS_SECRET}`,
      `provider "aws" {\n  secret_key = "${h.AWS_SECRET}"\n}`,
      `SecretAccessKey ${h.AWS_SECRET}`,
    ];
    for (const text of forms) {
      const found = detect(text).filter((x) => x.category === 'AWS_SECRET');
      assert.equal(found.length, 1, text.slice(-80));
      assert.equal(text.slice(found[0]!.start, found[0]!.end), h.AWS_SECRET, text.slice(-80));
    }
    // a bare secret_key needs a mixed-case value; prose and wrong lengths stay quiet
    assert.deepEqual(detect(`secret_key = "${'a1b2c3d4e5'.repeat(4)}"`), []);
    assert.deepEqual(detect(`secret key rotated monthly ${h.AWS_SECRET}`).filter((x) => x.category === 'AWS_SECRET'), []);
    assert.deepEqual(detect(`aws secret access key ${h.AWS_SECRET.slice(0, 38)}`), []);
  });
  it('AWS secret only next to a key id, and not a git SHA', () => {
    const text = `id ${h.AWS_ID}\nsecret ${h.AWS_SECRET}`;
    assert.deepEqual(cats(text), ['AWS_KEY', 'AWS_SECRET']);
    assert.deepEqual(cats(`secret ${h.AWS_SECRET}`), []);
    assert.deepEqual(cats(`id ${h.AWS_ID}\ncommit ${'a1b2c3d4e5'.repeat(4)}`), ['AWS_KEY']);
  });
  it('PEM: JSON-escaped newlines, legacy encrypted headers and quoted lines are redacted whole', () => {
    const body = ['MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'KgwggSkAgEAAoIBAQC7VJTUt9Us8cKj'];
    const begin = h.j('-----BEGIN ', 'PRIVATE KEY-----');
    const end = h.j('-----END ', 'PRIVATE KEY-----');
    const forms = {
      json: `{"private_key":"${[begin, ...body, end].join('\\n')}\\n","client":"x"}`,
      legacy: [h.j('-----BEGIN RSA ', 'PRIVATE KEY-----'), 'Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,0A1B2C3D', '', ...body, h.j('-----END RSA ', 'PRIVATE KEY-----')].join('\n'),
      quoted: [begin, ...body, end].map((l, i) => (i ? '> ' + l : l)).join('\n'),
    };
    for (const [name, text] of Object.entries(forms)) {
      const spans = resolveOverlaps(detect(text)).filter((x) => x.category === 'PRIVATE_KEY');
      assert.equal(spans.length, 1, name);
      const covered = text.slice(spans[0]!.start, spans[0]!.end);
      for (const line of body) assert.ok(covered.includes(line), `${name}: ${line}`);
      assert.ok(covered.endsWith('PRIVATE KEY-----'), name);
    }
  });
  it('PEM without END: escaped newlines and quoted lines are still covered up to the end of the body', () => {
    const begin = h.j('-----BEGIN ', 'PRIVATE KEY-----');
    const text = `{"k":"${begin}\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\nKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj"}`;
    const s = resolveOverlaps(detect(text)).find((x) => x.category === 'PRIVATE_KEY')!;
    assert.ok(text.slice(s.start, s.end).includes('KgwggSkAgEAAoIBAQC7VJTUt9Us8cKj'));
    assert.ok(!text.slice(s.start, s.end).includes('"}'));
  });
  it('public keys and certificates are not private keys', () => {
    assert.deepEqual(detect(h.j('-----BEGIN ', 'PUBLIC KEY-----\nMIIBIjANBgkq\n-----END ', 'PUBLIC KEY-----')), []);
  });
  it('PEM block is one span, with or without the END line', () => {
    const [s, ...rest] = resolveOverlaps(detect(`before\n${h.PEM}\nafter`));
    assert.ok(s && rest.length === 0);
    assert.equal(s.category, 'PRIVATE_KEY');
    assert.ok(`before\n${h.PEM}\nafter`.slice(s.start, s.end).endsWith('PRIVATE KEY-----'));
    const truncated = h.PEM.split('\n').slice(0, 3).join('\n') + '\nand then prose.';
    assert.equal(resolveOverlaps(detect(truncated))[0]?.category, 'PRIVATE_KEY');
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
