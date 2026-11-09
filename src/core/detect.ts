import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

export type Category =
  | 'CARD'
  | 'US_SSN'
  | 'US_ITIN'
  | 'US_EIN'
  | 'IBAN'
  | 'AWS_KEY'
  | 'AWS_SECRET'
  | 'OPENAI_KEY'
  | 'ANTHROPIC_KEY'
  | 'GITHUB_TOKEN'
  | 'STRIPE_KEY'
  | 'SLACK_TOKEN'
  | 'GOOGLE_KEY'
  | 'PRIVATE_KEY'
  | 'JWT'
  | 'OTP'
  | 'KNOWN_SECRET';

export const CATEGORIES: readonly Category[] = [
  'CARD', 'US_SSN', 'US_ITIN', 'US_EIN', 'IBAN', 'AWS_KEY', 'AWS_SECRET', 'OPENAI_KEY', 'ANTHROPIC_KEY',
  'GITHUB_TOKEN', 'STRIPE_KEY', 'SLACK_TOKEN', 'GOOGLE_KEY', 'PRIVATE_KEY', 'JWT', 'OTP', 'KNOWN_SECRET',
];

export type Confidence = 'sure' | 'likely';

export interface Span {
  start: number;
  end: number;
  category: Category;
  confidence: Confidence;
  rule: string;
}

export interface DetectOptions {
  /** sha256 hex of known secrets; default comes from the file named by env CF_KNOWN_HASHES */
  knownHashes?: ReadonlySet<string>;
}

// ---------- validators ----------

export function luhn(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return digits.length > 0 && sum % 10 === 0;
}

export function knownIin(d: string): boolean {
  const n = d.length;
  if (d[0] === '4') return n === 13 || n === 16 || n === 19;
  if (/^3[47]/.test(d)) return n === 15;
  if (n === 16 && (/^5[1-5]/.test(d) || (+d.slice(0, 4) >= 2221 && +d.slice(0, 4) <= 2720))) return true;
  if (n < 16 || n > 19) return false;
  if (/^6011/.test(d) || /^64[4-9]/.test(d) || /^65/.test(d)) return true;
  if (+d.slice(0, 6) >= 622126 && +d.slice(0, 6) <= 622925) return true;
  if (+d.slice(0, 4) >= 3528 && +d.slice(0, 4) <= 3589) return true;
  return /^62/.test(d);
}

export function cardOk(d: string): boolean {
  return d.length >= 13 && d.length <= 19 && luhn(d) && knownIin(d);
}

export function ibanOk(compact: string): boolean {
  if (compact.length < 15 || compact.length > 34 || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= 'A' ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    rem = (v < 10 ? rem * 10 + v : rem * 100 + v) % 97;
  }
  return rem === 1;
}

function ssnOk(area: string, group: string, serial: string): boolean {
  return area !== '000' && area !== '666' && area[0] !== '9' && group !== '00' && serial !== '0000';
}

function itinGroupOk(group: string): boolean {
  const g = +group;
  return (g >= 50 && g <= 65) || (g >= 70 && g <= 88) || (g >= 90 && g <= 92) || (g >= 94 && g <= 99);
}

const BAD_EIN_PREFIX = new Set([0, 7, 8, 9, 17, 18, 19, 28, 29, 49, 69, 70, 78, 79, 89, 96, 97]);

function jwtOk(token: string): boolean {
  const head = token.split('.')[0] ?? '';
  try {
    const parsed: unknown = JSON.parse(Buffer.from(head, 'base64url').toString('utf8'));
    return typeof parsed === 'object' && parsed !== null && 'alg' in parsed;
  } catch {
    return false;
  }
}

// ---------- known-secret hashes ----------

const hashCache = new Map<string, { mtime: number; set: Set<string> }>();

export function loadKnownHashes(path: string | undefined = process.env.CF_KNOWN_HASHES): ReadonlySet<string> {
  if (!path) return new Set();
  const mtime = statSync(path).mtimeMs;
  const hit = hashCache.get(path);
  if (hit && hit.mtime === mtime) return hit.set;
  const set = new Set(
    readFileSync(path, 'utf8')
      .split('\n')
      .map((l) => l.trim().toLowerCase())
      .filter((l) => /^[0-9a-f]{64}$/.test(l)),
  );
  hashCache.set(path, { mtime, set });
  return set;
}

export function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

// ---------- detectors ----------

interface KeyRule {
  category: Category;
  rule: string;
  re: RegExp;
  validate?: (m: string) => boolean;
}

const hasDigit = (s: string): boolean => /\d/.test(s);

const KEY_RULES: KeyRule[] = [
  { category: 'AWS_KEY', rule: 'aws-access-key-id', re: /(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g },
  { category: 'ANTHROPIC_KEY', rule: 'anthropic-sk-ant', re: /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}/g },
  { category: 'OPENAI_KEY', rule: 'openai-sk', re: /(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g, validate: hasDigit },
  { category: 'GITHUB_TOKEN', rule: 'github-gh-prefix', re: /gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])/g },
  { category: 'GITHUB_TOKEN', rule: 'github-fine-grained', re: /github_pat_[A-Za-z0-9_]{22,255}/g },
  { category: 'STRIPE_KEY', rule: 'stripe-live', re: /(?:sk|rk)_live_[A-Za-z0-9]{16,}/g },
  { category: 'SLACK_TOKEN', rule: 'slack-xox', re: /xox[abprs]-[A-Za-z0-9-]{10,}/g },
  { category: 'GOOGLE_KEY', rule: 'google-aiza', re: /AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g },
  // whole block up to the nearest END marker, whatever sits between (escaped newlines, headers, quote prefixes)
  {
    category: 'PRIVATE_KEY',
    rule: 'pem-private-key',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
  },
  // truncated block without END: BEGIN line plus body-like characters, capped
  {
    category: 'PRIVATE_KEY',
    rule: 'pem-private-key-no-end',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:(?!-----END)(?:\\[nr]|[A-Za-z0-9+/=\s>:,.-])){0,8192}/g,
  },
  {
    category: 'JWT',
    rule: 'jwt-three-parts',
    re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    validate: jwtOk,
  },
];

function detectKeys(text: string, out: Span[]): void {
  for (const r of KEY_RULES) {
    for (const m of text.matchAll(r.re)) {
      if (r.validate && !r.validate(m[0])) continue;
      out.push({ start: m.index, end: m.index + m[0].length, category: r.category, confidence: 'sure', rule: r.rule });
    }
  }
}

const AWS_SECRET_RE = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g;
const AWS_WINDOW = 120;

function detectAwsSecret(text: string, out: Span[]): void {
  for (const k of out.filter((s) => s.category === 'AWS_KEY')) {
    const lo = Math.max(0, k.start - AWS_WINDOW);
    const hi = Math.min(text.length, k.end + AWS_WINDOW);
    for (const m of text.slice(lo, hi).matchAll(AWS_SECRET_RE)) {
      const start = lo + m.index;
      const end = start + 40;
      if (start < k.end && end > k.start) continue;
      if (/^[0-9a-fA-F]{40}$/.test(m[0]) || !/\d/.test(m[0]) || !/[a-z]/.test(m[0]) || !/[A-Z]/.test(m[0])) continue;
      out.push({ start, end, category: 'AWS_SECRET', confidence: 'sure', rule: 'aws-secret-near-key-id' });
    }
  }
}

const FULLWIDTH_DIGIT = /[\uFF10-\uFF19]/g;
const SEPARATORS = ' \u00a0\u2009\u202f.-';
const CARD_RUN = new RegExp(`(?<!\\d)(?<!\\d-)\\d(?:[${SEPARATORS}]{0,3}\\d){12,}(?!\\d)`, 'g');

function detectCards(text: string, out: Span[]): void {
  // fullwidth digits become ASCII one for one, so offsets stay valid
  const t = text.replace(FULLWIDTH_DIGIT, (c) => String.fromCharCode(c.charCodeAt(0) - 0xff10 + 48));
  for (const m of t.matchAll(CARD_RUN)) {
    const s = m[0];
    const pos: number[] = [];
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) >= 48 && s.charCodeAt(i) <= 57) pos.push(i);
    // windows that start and end at a separator, longest first; several cards may share one run
    let a = 0;
    while (a + 13 <= pos.length) {
      const first = pos[a] as number;
      let hit = 0;
      if (a === 0 || (pos[a - 1] as number) !== first - 1) {
        for (let len = Math.min(19, pos.length - a); len >= 13 && !hit; len--) {
          const last = pos[a + len - 1] as number;
          if (a + len < pos.length && (pos[a + len] as number) === last + 1) continue;
          if (cardOk(pos.slice(a, a + len).map((p) => s[p]).join(''))) {
            out.push({ start: m.index + first, end: m.index + last + 1, category: 'CARD', confidence: 'sure', rule: 'card-luhn-iin' });
            hit = len;
          }
        }
      }
      a += hit || 1;
    }
  }
}

const EIN_KEYWORD = /\b(?:EIN|FEIN|TIN|Employer\s+ID(?:entification)?(?:\s+Number)?|tax\s+id)\b[^\n]{0,20}$/i;

function detectTaxIds(text: string, out: Span[]): void {
  for (const m of text.matchAll(/(?<![\d-])(\d{3})[- ](\d{2})[- ](\d{4})(?![\w-])/g)) {
    const [, a, g, s] = m as unknown as [string, string, string, string];
    const end = m.index + m[0].length;
    if (ssnOk(a, g, s)) out.push({ start: m.index, end, category: 'US_SSN', confidence: 'sure', rule: 'ssn-format-ranges' });
    else if (a[0] === '9' && itinGroupOk(g)) out.push({ start: m.index, end, category: 'US_ITIN', confidence: 'sure', rule: 'itin-9xx-group' });
  }
  for (const m of text.matchAll(/(?:ssn|social\s+security(?:\s+number)?)\D{0,12}?(?<![\d])(\d{9})(?!\d)/gid)) {
    const [from, to] = (m.indices as unknown as [number, number][])[1] as [number, number];
    const d = m[1] as string;
    if (ssnOk(d.slice(0, 3), d.slice(3, 5), d.slice(5))) {
      out.push({ start: from, end: to, category: 'US_SSN', confidence: 'likely', rule: 'ssn-nine-digits-after-keyword' });
    }
  }
  for (const m of text.matchAll(/(?<![\d-])(\d{2})-(\d{7})(?![\w-])/g)) {
    if (BAD_EIN_PREFIX.has(+(m[1] as string))) continue;
    const before = text.slice(Math.max(0, m.index - 40), m.index);
    const keyword = EIN_KEYWORD.test(before);
    out.push({
      start: m.index,
      end: m.index + m[0].length,
      category: 'US_EIN',
      confidence: keyword ? 'sure' : 'likely',
      rule: keyword ? 'ein-with-keyword' : 'ein-shape-only',
    });
  }
}

function detectIban(text: string, out: Span[]): void {
  // no left boundary: mod-97 is the check, and OCR often glues the label to the value
  const re = /[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])/g;
  for (const m of text.matchAll(re)) {
    const pieces = m[0].split(' ');
    for (let n = pieces.length; n >= 1; n--) {
      const head = pieces.slice(0, n).join(' ');
      if (ibanOk(head.replaceAll(' ', ''))) {
        out.push({ start: m.index, end: m.index + head.length, category: 'IBAN', confidence: 'sure', rule: 'iban-mod97' });
        break;
      }
    }
  }
}

const OTP_WORD = /\b(?:code|otp|passcode|verification|one[- ]time|2fa)\b/gi;
const OTP_NOT_AFTER = /(?:zip|postal|area|country|source|error|status|http|dial)\s*$/i;
const OTP_WINDOW = 40;

function detectOtp(text: string, out: Span[]): void {
  for (const w of text.matchAll(OTP_WORD)) {
    if (OTP_NOT_AFTER.test(text.slice(Math.max(0, w.index - 12), w.index))) continue;
    const from = w.index + w[0].length;
    const re = /(?<![\w-])\d{4,8}(?![\w-])/g;
    re.lastIndex = from;
    const m = re.exec(text);
    if (m && m.index - from <= OTP_WINDOW && !out.some((o) => o.category === 'OTP' && o.start === m.index)) {
      out.push({ start: m.index, end: m.index + m[0].length, category: 'OTP', confidence: 'likely', rule: 'otp-digits-after-keyword' });
    }
  }
}

function detectKnown(text: string, hashes: ReadonlySet<string>, out: Span[]): void {
  if (hashes.size === 0) return;
  for (const m of text.matchAll(/[^\s"'`<>()[\]{},;:]+/g)) {
    const token = m[0].replace(/[.!?]+$/, '');
    if (token.length >= 4 && hashes.has(sha256Hex(token))) {
      out.push({ start: m.index, end: m.index + token.length, category: 'KNOWN_SECRET', confidence: 'sure', rule: 'known-hash' });
    }
  }
}

export function detect(text: string, opts: DetectOptions = {}): Span[] {
  const out: Span[] = [];
  detectKeys(text, out);
  detectAwsSecret(text, out);
  detectCards(text, out);
  detectTaxIds(text, out);
  detectIban(text, out);
  detectOtp(text, out);
  detectKnown(text, opts.knownHashes ?? loadKnownHashes(), out);
  return out.sort((a, b) => a.start - b.start || a.end - b.end);
}

/** sure beats likely, then the longer span, then the earlier one; the result does not overlap and is ordered by start. */
export function resolveOverlaps<T extends Span>(spans: readonly T[]): T[] {
  const rank = [...spans].sort(
    (a, b) =>
      (a.confidence === b.confidence ? 0 : a.confidence === 'sure' ? -1 : 1) ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start,
  );
  const kept: T[] = [];
  for (const s of rank) if (!kept.some((k) => s.start < k.end && s.end > k.start)) kept.push(s);
  return kept.sort((a, b) => a.start - b.start);
}
