import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CATEGORIES, detect } from '../src/core/detect.ts';
import { evaluate } from '../src/eval/run.ts';
import { GENRES, generate } from '../src/eval/gen.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('corpus generator', () => {
  const a = generate({ seed: 7, count: 300 });

  it('is deterministic for a seed and differs between seeds', () => {
    assert.deepEqual(generate({ seed: 7, count: 30 }).docs.map((d) => d.text), a.docs.slice(0, 30).map((d) => d.text));
    assert.notEqual(generate({ seed: 8, count: 3 }).docs[0]?.text, a.docs[0]?.text);
  });

  it('has 300+ documents of three genres, every category in every document, spans point at the value', () => {
    assert.equal(a.docs.length, 300);
    assert.deepEqual([...new Set(a.docs.map((d) => d.genre))].sort(), [...GENRES].sort());
    for (const d of a.docs) {
      assert.deepEqual([...new Set(d.truth.map((t) => t.category))].sort(), [...CATEGORIES].sort(), d.id);
      for (const t of d.truth) assert.ok(d.text.slice(t.start, t.end).length === t.end - t.start && t.end <= d.text.length);
    }
  });

  it('the generator does not import detector code', () => {
    const src = readFileSync(join(root, 'src/eval/gen.ts'), 'utf8');
    const imports = src.split('\n').filter((l) => /^import /.test(l));
    assert.ok(imports.every((l) => !l.includes('detect.ts') || l.startsWith('import type')), imports.join('\n'));
  });

  it('covers the PEM forms, the AWS env form, odd card separators and hard negatives', () => {
    const all = a.docs.map((d) => d.text).join('\n');
    assert.ok(all.includes('PRIVATE KEY-----\\n'), 'json-escaped pem');
    assert.ok(all.includes('Proc-Type: 4,ENCRYPTED'), 'legacy pem');
    assert.ok(all.includes('> ' + 'MIIE'.slice(0, 0)) && /\n> [A-Za-z0-9+/]{20}/.test(all), 'quoted pem');
    assert.ok(all.includes('AWS_SECRET_ACCESS_KEY='), 'env form');
    assert.ok(all.includes('\u00a0') && /\d\.\d{4}\.\d{4}/.test(all), 'nbsp / dot separators');
    for (const bait of ['IMEI:', 'sk-learn', 'Placeholder: sk-', 'Keys start with AKIA', 'PUBLIC KEY', 'Promo code', 'Account no.', 'Booking ref', 'Part no.']) {
      assert.ok(all.includes(bait), bait);
    }
  });

  it('rejects a bad count', () => {
    assert.throws(() => generate({ seed: 1, count: 0 }), RangeError);
  });

  it('eval numbers stay in a sane range with the hard negatives in', () => {
    const res = evaluate(a, 7, 'test');
    assert.ok(res.categories.CARD!.recall >= 0.7 && res.categories.CARD!.precision >= 0.8);
    assert.ok(res.anyCategoryRecall >= 0.85);
    for (const c of ['US_SSN', 'IBAN', 'JWT', 'PRIVATE_KEY'] as const) assert.ok(res.categories[c]!.recall >= 0.9, c);
  });
});

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    if (n === 'node_modules' || n === '.git' || n === 'demo-out') return [];
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|md|json|html|sh)$/.test(n) && n !== 'package-lock.json' ? [p] : [];
  });
}

describe('no secret-shaped literals in the repository', () => {
  it('the scan can see a planted key (control)', () => {
    const planted = ['sk', '-proj-', 'Ab3dEfGh1jKlMnOp2qRsTuVw4xYz'].join('');
    assert.equal(detect(`k=${planted}`).length, 1);
  });

  it('detectors find nothing sure in our own sources', () => {
    const hits: string[] = [];
    for (const f of files(root)) {
      for (const s of detect(readFileSync(f, 'utf8'), { knownHashes: new Set() })) {
        if (s.confidence === 'sure' && s.category !== 'US_EIN') hits.push(`${f}: ${s.category}`);
      }
    }
    assert.deepEqual(hits, []);
  });
});
