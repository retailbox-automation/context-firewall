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

  it('rejects a bad count', () => {
    assert.throws(() => generate({ seed: 1, count: 0 }), RangeError);
  });

  it('eval numbers: sure categories on clean text are found, decoys do not poison cards', () => {
    const res = evaluate(a, 7, 'test');
    assert.ok(res.categories.CARD!.recall >= 0.9 && res.categories.CARD!.precision === 1);
    assert.ok(res.anyCategoryRecall >= 0.9);
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
