import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { RULES_ONLY, RulesOnly } from './classifier.ts';
import type { Classifier } from './classifier.ts';
import { detect, resolveOverlaps } from './detect.ts';
import type { Category, Confidence, Span } from './detect.ts';

/** token -> raw value, in process memory only. Only the executor reads values back. */
export class Vault {
  #values = new Map<string, string>();
  set(token: string, value: string): void {
    this.#values.set(token, value);
  }
  get(token: string): string | undefined {
    return this.#values.get(token);
  }
  get size(): number {
    return this.#values.size;
  }
  forget(): void {
    this.#values.clear();
  }
  toJSON(): { size: number } {
    return { size: this.#values.size };
  }
  [inspect.custom](): string {
    return `Vault { size: ${this.#values.size} }`;
  }
}

/** One placeholder namespace: same value, same placeholder, until forget(). */
export class Session {
  readonly vault = new Vault();
  #salt = randomBytes(16).toString('hex');
  #counters = new Map<Category, number>();
  #tokens = new Map<string, string>();

  tokenFor(category: Category, value: string): string {
    const key = `${category}\0${canonical(category, value)}`;
    let token = this.#tokens.get(key);
    if (token === undefined) {
      const n = (this.#counters.get(category) ?? 0) + 1;
      this.#counters.set(category, n);
      token = `[${category}_${n}]`;
      this.#tokens.set(key, token);
      this.vault.set(token, value);
    }
    return token;
  }

  digest(category: Category, value: string): string {
    return createHash('sha256').update(`${this.#salt}:${category}:${canonical(category, value)}`).digest('hex');
  }

  forget(): void {
    this.vault.forget();
    this.#counters.clear();
    this.#tokens.clear();
    this.#salt = randomBytes(16).toString('hex');
  }
}

const NUMERIC: ReadonlySet<Category> = new Set(['CARD', 'US_SSN', 'US_ITIN', 'US_EIN', 'IBAN']);

function canonical(category: Category, value: string): string {
  return NUMERIC.has(category) ? value.replace(/[\s-]/g, '') : value;
}

export interface Finding {
  token: string;
  category: Category;
  source: 'rules' | 'tee';
  span_sha256: string;
  confidence: Confidence;
  rule: string;
}

export interface RedactResult {
  text: string;
  findings: Finding[];
}

export interface RedactOptions {
  classifier?: Classifier;
  session?: Session;
}

let defaultSession = new Session();
export function getDefaultSession(): Session {
  return defaultSession;
}
export function resetDefaultSession(): void {
  defaultSession.forget();
  defaultSession = new Session();
}

export async function redact(text: string, opts: RedactOptions = {}): Promise<RedactResult> {
  const session = opts.session ?? defaultSession;
  const cls = opts.classifier ?? new RulesOnly();
  const tagged: (Span & { source: 'rules' | 'tee' })[] = detect(text).map((s) => ({ ...s, source: 'rules' }));
  if (cls.name !== RULES_ONLY) {
    for (const s of await cls.classify(text)) {
      if (Number.isInteger(s.start) && Number.isInteger(s.end) && s.start >= 0 && s.end > s.start && s.end <= text.length) {
        tagged.push({ ...s, source: 'tee' });
      }
    }
  }
  let out = '';
  let cursor = 0;
  const findings: Finding[] = [];
  for (const s of resolveOverlaps(tagged)) {
    const value = text.slice(s.start, s.end);
    const token = session.tokenFor(s.category, value);
    out += text.slice(cursor, s.start) + token;
    cursor = s.end;
    findings.push({
      token,
      category: s.category,
      source: s.source,
      span_sha256: session.digest(s.category, value),
      confidence: s.confidence,
      rule: s.rule,
    });
  }
  return { text: out + text.slice(cursor), findings };
}
