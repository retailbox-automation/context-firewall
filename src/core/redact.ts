import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { RULES_ONLY, RulesOnly } from './classifier.ts';
import type { Classifier } from './classifier.ts';
import { detect, resolveOverlaps } from './detect.ts';
import type { Category, Confidence, Span } from './detect.ts';

/** token -> raw value, in process memory only. Only the executor reads values back. */
export class Vault {
  #values = new Map<string, string>();
  #origins = new Map<string, string>();
  #ambiguous = new Set<string>();
  set(token: string, value: string, origin?: string, ambiguous = false): void {
    this.#values.set(token, value);
    if (ambiguous) this.#ambiguous.add(token);
    if (origin !== undefined) this.#origins.set(token, origin);
  }
  /** the value is a run of digits that may hold a card plus neighbours; never filled */
  isAmbiguous(token: string): boolean {
    return this.#ambiguous.has(token);
  }
  /** the page origin the value was seen on; undefined when the source was not given */
  originOf(token: string): string | undefined {
    return this.#origins.get(token);
  }
  get(token: string): string | undefined {
    return this.#values.get(token);
  }
  get size(): number {
    return this.#values.size;
  }
  forget(): void {
    this.#values.clear();
    this.#origins.clear();
    this.#ambiguous.clear();
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

  tokenFor(category: Category, value: string, origin?: string, ambiguous = false): string {
    const key = `${category}\0${origin ?? ''}\0${ambiguous ? 'run:' : ''}${canonical(category, value)}`;
    let token = this.#tokens.get(key);
    if (token === undefined) {
      const n = (this.#counters.get(category) ?? 0) + 1;
      this.#counters.set(category, n);
      token = `[${category}_${n}]`;
      this.#tokens.set(key, token);
      this.vault.set(token, value, origin, ambiguous);
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
  /** set when the token stands for a longer digit run that contains a card-like number */
  ambiguous?: true;
}

export interface RedactResult {
  text: string;
  findings: Finding[];
}

export interface RedactOptions {
  classifier?: Classifier;
  session?: Session;
  /** origin of the page the text came from; a placeholder can only be filled back on this origin */
  origin?: string;
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
    const token = session.tokenFor(s.category, value, opts.origin, s.ambiguous === true);
    out += text.slice(cursor, s.start) + token;
    cursor = s.end;
    findings.push({
      token,
      category: s.category,
      source: s.source,
      span_sha256: session.digest(s.category, value),
      confidence: s.confidence,
      rule: s.rule,
      ...(s.ambiguous ? { ambiguous: true as const } : {}),
    });
  }
  return { text: out + text.slice(cursor), findings };
}

/** `http://host:port` for an http(s) URL; undefined for anything else (file:, about:blank, garbage). */
export function originOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : undefined;
  } catch {
    return undefined;
  }
}
