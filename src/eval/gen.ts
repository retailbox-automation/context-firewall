// Deterministic synthetic corpus. Every secret-shaped value is assembled at run time from
// parts and random characters; nothing here is a real credential. Card numbers are the
// publicly documented test numbers of the payment networks.
import { CATEGORIES, luhn, sha256Hex } from '../core/detect.ts';
import type { Category } from '../core/detect.ts';

export type Genre = 'payment-page' | 'email' | 'ocr';
export const GENRES: readonly Genre[] = ['payment-page', 'email', 'ocr'];

export interface TruthSpan {
  start: number;
  end: number;
  category: Category;
}

export interface Doc {
  id: string;
  genre: Genre;
  text: string;
  truth: TruthSpan[];
}

export interface Corpus {
  docs: Doc[];
  /** sha256 of the KNOWN_SECRET values used in the corpus (for CF_KNOWN_HASHES) */
  knownHashes: string[];
}

// ---------- seeded random ----------

export class Rng {
  #s: number;
  constructor(seed: number) {
    this.#s = seed >>> 0;
  }
  next(): number {
    this.#s = (this.#s + 0x6d2b79f5) >>> 0;
    let t = this.#s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  int(lo: number, hi: number): number {
    return lo + Math.floor(this.next() * (hi - lo + 1));
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.int(0, xs.length - 1)] as T;
  }
  chance(p: number): boolean {
    return this.next() < p;
  }
  shuffle<T>(xs: readonly T[]): T[] {
    const a = [...xs];
    for (let i = a.length - 1; i > 0; i--) {
      const j = this.int(0, i);
      [a[i], a[j]] = [a[j] as T, a[i] as T];
    }
    return a;
  }
  chars(alphabet: string, n: number): string {
    let s = '';
    for (let i = 0; i < n; i++) s += alphabet[this.int(0, alphabet.length - 1)];
    return s;
  }
  digits(n: number): string {
    return this.chars('0123456789', n);
  }
}

const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOW = 'abcdefghijklmnopqrstuvwxyz';
const NUM = '0123456789';
const ALNUM = UP + LOW + NUM;
const B64URL = ALNUM + '-_';

function mixed(r: Rng, alphabet: string, n: number): string {
  // at least one digit, one upper and one lower case letter
  let s = r.chars(alphabet, n);
  while (!/\d/.test(s) || !/[A-Z]/.test(s) || !/[a-z]/.test(s)) s = r.chars(alphabet, n);
  return s;
}

// ---------- sensitive values ----------

// publicly documented test numbers, split so no 13+ digit literal sits in the source
const TEST_PANS: readonly string[][] = [
  ['4111', '1111', '1111', '1111'],
  ['4012', '8888', '8888', '1881'],
  ['4242', '4242', '4242', '4242'],
  ['5555', '5555', '5555', '4444'],
  ['5105', '1051', '0510', '5100'],
  ['2223', '0031', '2200', '3222'],
  ['3782', '822463', '10005'],
  ['3714', '496353', '98431'],
  ['6011', '1111', '1111', '1117'],
  ['6011', '0009', '9013', '9424'],
  ['3530', '1113', '3330', '0000'],
  ['3566', '0020', '2036', '0505'],
  ['6200', '0000', '0000', '0005'],
];

function cardValue(r: Rng, noisy: boolean): string {
  const groups = r.pick(TEST_PANS);
  const style = r.int(0, 2);
  if (style === 0) return groups.join('');
  const sep = style === 1 ? ' ' : '-';
  return groups.join(noisy && r.chance(0.5) ? sep + sep : sep);
}

function ssnValue(r: Rng): string {
  let area = r.int(1, 899);
  while (area === 666) area = r.int(1, 899);
  const p = (n: number, w: number) => String(n).padStart(w, '0');
  const sep = r.chance(0.7) ? '-' : ' ';
  return [p(area, 3), p(r.int(1, 99), 2), p(r.int(1, 9999), 4)].join(sep);
}

function itinValue(r: Rng): string {
  const group = r.pick([...range(50, 65), ...range(70, 88), ...range(90, 92), ...range(94, 99)]);
  return `9${r.digits(2)}-${group}-${r.digits(4)}`;
}

function range(a: number, b: number): number[] {
  return Array.from({ length: b - a + 1 }, (_, i) => a + i);
}

function einValue(r: Rng): string {
  const bad = new Set([0, 7, 8, 9, 17, 18, 19, 28, 29, 49, 69, 70, 78, 79, 89, 96, 97]);
  let p = r.int(1, 99);
  while (bad.has(p)) p = r.int(1, 99);
  return `${String(p).padStart(2, '0')}-${r.digits(7)}`;
}

function ibanValue(r: Rng): string {
  const country = r.pick([
    ['DE', () => r.digits(18)],
    ['GB', () => r.chars(UP, 4) + r.digits(14)],
    ['FR', () => r.digits(23)],
    ['ES', () => r.digits(20)],
    ['IT', () => r.chars(UP, 1) + r.digits(22)],
    ['NL', () => r.chars(UP, 4) + r.digits(10)],
  ] as const);
  const bban = country[1]();
  const num = (bban + country[0] + '00').replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rem = 0;
  for (const ch of num) rem = (rem * 10 + (ch.charCodeAt(0) - 48)) % 97;
  const iban = country[0] + String(98 - rem).padStart(2, '0') + bban;
  return r.chance(0.6) ? (iban.match(/.{1,4}/g) as string[]).join(' ') : iban;
}

function jwtValue(r: Rng): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = b64({ alg: r.pick(['HS256', 'RS256', 'ES256']), typ: 'JWT' });
  const body = b64({ sub: r.chars(LOW, 8), iat: r.int(1700000000, 1800000000), scope: r.chars(LOW, 5) });
  return `${head}.${body}.${r.chars(B64URL, 43)}`;
}

function pemValue(r: Rng): string {
  const lines = Array.from({ length: r.int(3, 6) }, () => r.chars(ALNUM + '+/', 64));
  return ['-----BEGIN ' + 'PRIVATE KEY-----', ...lines, r.chars(ALNUM, 20) + '==', '-----END ' + 'PRIVATE KEY-----'].join('\n');
}

const KEY_BUILDERS: Record<string, (r: Rng) => string> = {
  AWS_KEY: (r) => r.pick(['AK', 'AS']) + 'IA'.slice(0, 2) + r.chars(UP + NUM, 16),
  OPENAI_KEY: (r) => ['sk', r.chance(0.6) ? '-proj-' : '-'].join('') + mixed(r, ALNUM + '_-', r.int(40, 60)),
  ANTHROPIC_KEY: (r) => ['sk', 'ant', 'api03'].join('-') + '-' + mixed(r, B64URL, 80),
  GITHUB_TOKEN: (r) => 'gh' + r.pick(['p', 'o', 'u', 's', 'r']) + '_' + mixed(r, ALNUM, 36),
  STRIPE_KEY: (r) => r.pick(['sk', 'rk']) + '_' + 'live' + '_' + mixed(r, ALNUM, 24),
  SLACK_TOKEN: (r) => 'xox' + r.pick(['a', 'b', 'p', 'r', 's']) + '-' + r.digits(11) + '-' + r.digits(12) + '-' + mixed(r, ALNUM, 24),
  GOOGLE_KEY: (r) => 'AI' + 'za' + mixed(r, B64URL, 35),
};

// ---------- decoys ----------

function luhnCheckDigit(partial: string): string {
  for (let d = 0; d < 10; d++) if (luhn(partial + d)) return String(d);
  throw new Error('unreachable');
}

function nonLuhn16(r: Rng): string {
  let s: string;
  do s = r.pick(['4', '5', '3', '6']) + r.digits(15);
  while (luhn(s));
  return s;
}

const DECOYS: ((r: Rng) => string)[] = [
  (r) => `Order #${r.digits(8)}`,
  (r) => `Order ${r.chars(UP, 3)}-${r.int(2024, 2026)}-${r.digits(6)}`,
  (r) => `Tracking: 1Z${r.chars(UP + NUM, 16)}`,
  (r) => `Tracking number ${r.pick(['94', '92'])}${r.digits(20)}`,
  (r) => `Reference ${nonLuhn16(r)}`,
  (r) => `Ref ${'9' + r.digits(14)}`.replace(/(\d+)$/, (d) => d + luhnCheckDigit(d)), // Luhn-valid, unknown IIN
  (r) => `Phone: (${r.int(201, 989)}) ${r.int(201, 989)}-${r.digits(4)}`,
  (r) => `Call +1 ${r.int(201, 989)} ${r.int(201, 989)} ${r.digits(4)}`,
  (r) => `Phone ${r.int(201, 989)}-${r.int(201, 989)}-${r.digits(4)}`,
  (r) => `Date: ${r.int(2024, 2026)}-${String(r.int(1, 12)).padStart(2, '0')}-${String(r.int(1, 28)).padStart(2, '0')}`,
  (r) => `Placed on ${r.int(1, 12)}/${r.int(1, 28)}/${r.int(2024, 2026)}`,
  (r) => `Request id ${uuid(r)}`,
  (r) => `commit ${r.chars('0123456789abcdef', 40)}`,
  (r) => `build ${r.chars('0123456789abcdef', 7)}`,
  (r) => `Total: $${r.int(1, 9)},${r.digits(3)}.${r.digits(2)}`,
  (r) => `Subtotal $${r.int(10, 999)}.${r.digits(2)}`,
  (r) => `Postal code: ${r.digits(5)}`,
  (r) => `Invoice ${r.digits(2)}-${r.digits(7)}`.replace(/^Invoice (0\d|1[789]|2[89]|49|69|7[089]|89|9[67])/, 'Invoice 31'),
];

function uuid(r: Rng): string {
  const h = (n: number) => r.chars('0123456789abcdef', n);
  return `${h(8)}-${h(4)}-4${h(3)}-${r.pick(['8', '9', 'a', 'b'])}${h(3)}-${h(12)}`;
}

// ---------- templates ----------
// `{v}` marks the sensitive value; every genre has its own wording.

type Templates = Record<Category, string>;

const PAGE: Templates = {
  CARD: 'Card number: {v}',
  US_SSN: 'SSN: {v}',
  US_ITIN: 'ITIN: {v}',
  US_EIN: 'EIN: {v}',
  IBAN: 'IBAN: {v}',
  AWS_KEY: 'AWS access key id: {v}',
  AWS_SECRET: 'AWS secret access key: {v}',
  OPENAI_KEY: 'OpenAI key: {v}',
  ANTHROPIC_KEY: 'LLM API key: {v}',
  GITHUB_TOKEN: 'GitHub token: {v}',
  STRIPE_KEY: 'Stripe key: {v}',
  SLACK_TOKEN: 'Slack token: {v}',
  GOOGLE_KEY: 'Maps API key: {v}',
  PRIVATE_KEY: 'Deploy key:\n{v}',
  JWT: 'Session token: {v}',
  OTP: 'Enter the verification code {v} to confirm this payment',
  KNOWN_SECRET: 'Account password: {v}',
};

const EMAIL: Templates = {
  CARD: 'You can charge my card, {v}, for the balance.',
  US_SSN: 'My social security number is {v}, for the background check.',
  US_ITIN: 'My ITIN is {v} since I do not have an SSN.',
  US_EIN: 'The company EIN is {v}, same as on the W-9.',
  IBAN: 'Please wire the refund to IBAN {v} on Friday.',
  AWS_KEY: 'The AWS key id is {v}',
  AWS_SECRET: 'and the secret is {v}',
  OPENAI_KEY: 'Use this key for the demo: {v}',
  ANTHROPIC_KEY: 'The model API key: {v}',
  GITHUB_TOKEN: 'Clone with token {v} and tell me if it works.',
  STRIPE_KEY: 'Live Stripe key, do not share: {v}',
  SLACK_TOKEN: 'Bot token for the workspace: {v}',
  GOOGLE_KEY: 'Google key {v} is in the site config.',
  PRIVATE_KEY: 'Here is the private key you asked for:\n{v}\nPlease delete this email afterwards.',
  JWT: 'The staging session looks like {v} if you want to reproduce.',
  OTP: 'Your one-time code is {v}. It expires in 10 minutes.',
  KNOWN_SECRET: 'The wifi password is {v} (same as before).',
};

const OCR: Templates = {
  CARD: 'Card No {v}',
  US_SSN: 'SSN {v}',
  US_ITIN: 'ITIN {v}',
  US_EIN: 'Employer ID {v}',
  IBAN: 'IBAN {v}',
  AWS_KEY: 'access key {v}',
  AWS_SECRET: 'secret {v}',
  OPENAI_KEY: 'key {v}',
  ANTHROPIC_KEY: 'api key {v}',
  GITHUB_TOKEN: 'token {v}',
  STRIPE_KEY: 'stripe {v}',
  SLACK_TOKEN: 'slack {v}',
  GOOGLE_KEY: 'google key {v}',
  PRIVATE_KEY: 'key file\n{v}',
  JWT: 'bearer {v}',
  OTP: 'Your passcode: {v}',
  KNOWN_SECRET: 'password {v}',
};

const TEMPLATES: Record<Genre, Templates> = { 'payment-page': PAGE, email: EMAIL, ocr: OCR };

const FILLER: Record<Genre, string[]> = {
  'payment-page': ['Secure checkout', 'Billing details', 'Review your order', 'Shipping address same as billing', 'Place order', 'Powered by Example Pay'],
  email: ['Hi Sam,', 'Thanks for the quick call yesterday.', 'Let me know if anything is unclear.', 'Best,', 'Sent from my phone'],
  ocr: ['Screenshot 14.32', 'Settings   Billing   Team', 'Save changes', 'Back to dashboard', 'Help & support'],
};

const OCR_SWAPS: Record<string, string> = { l: '1', O: '0', S: '5', e: 'c', i: 'l' };

function ocrNoise(r: Rng, s: string): string {
  let out = '';
  for (const ch of s) {
    if (OCR_SWAPS[ch] && r.chance(0.04)) out += OCR_SWAPS[ch];
    else if (ch === ' ' && r.chance(0.08)) out += '  ';
    else out += ch;
  }
  return out;
}

// ---------- document builder ----------

interface Line {
  text: string; // may contain one {v}
  value?: string;
  category?: Category;
}

function makeValue(r: Rng, cat: Category, genre: Genre, known: string[]): string {
  switch (cat) {
    case 'CARD': return cardValue(r, genre === 'ocr');
    case 'US_SSN': return ssnValue(r);
    case 'US_ITIN': return itinValue(r);
    case 'US_EIN': return einValue(r);
    case 'IBAN': return ibanValue(r);
    case 'AWS_SECRET': return mixed(r, ALNUM + '/+', 40);
    case 'PRIVATE_KEY': return pemValue(r);
    case 'JWT': return jwtValue(r);
    case 'OTP': return r.digits(r.int(4, 8));
    case 'KNOWN_SECRET': {
      const v = ['pw', r.chars(LOW, 5), r.chars(NUM, 3), r.chars(LOW, 4)].join('-');
      known.push(sha256Hex(v));
      return v;
    }
    default: return (KEY_BUILDERS[cat] as (r: Rng) => string)(r);
  }
}

function buildDoc(r: Rng, id: string, genre: Genre, known: string[]): Doc {
  const tpl = TEMPLATES[genre];
  const lines: Line[] = [];
  const groups: Line[][] = [];
  for (const cat of CATEGORIES) {
    if (cat === 'AWS_SECRET') continue; // placed right after its key id
    const mk = (c: Category): Line => ({ category: c, value: makeValue(r, c, genre, known), text: tpl[c] });
    groups.push(cat === 'AWS_KEY' ? [mk('AWS_KEY'), mk('AWS_SECRET')] : [mk(cat)]);
  }
  for (let i = r.int(5, 9); i > 0; i--) groups.push([{ text: (r.pick(DECOYS))(r) }]);
  for (let i = r.int(2, 4); i > 0; i--) groups.push([{ text: r.pick(FILLER[genre]) }]);
  for (const g of r.shuffle(groups)) lines.push(...g);

  let text = '';
  const truth: TruthSpan[] = [];
  const sep = genre === 'email' ? '\n\n' : '\n';
  for (const line of lines) {
    const at = line.text.indexOf('{v}');
    let pre = at < 0 ? line.text : line.text.slice(0, at);
    let post = at < 0 ? '' : line.text.slice(at + 3);
    if (genre === 'ocr') {
      pre = ocrNoise(r, pre);
      post = ocrNoise(r, post);
      if (r.chance(0.15)) pre = pre.replace(/ $/, ''); // label glued to the value
      if (r.chance(0.2)) pre = '| ' + pre;
    }
    text += pre;
    if (line.value !== undefined && line.category !== undefined) {
      truth.push({ start: text.length, end: text.length + line.value.length, category: line.category });
      text += line.value;
    }
    text += post + sep;
  }
  return { id, genre, text, truth };
}

export function generate(opts: { seed: number; count: number }): Corpus {
  if (!Number.isInteger(opts.count) || opts.count < 1) throw new RangeError('count must be a positive integer');
  const r = new Rng(opts.seed);
  const known: string[] = [];
  const docs: Doc[] = [];
  for (let i = 0; i < opts.count; i++) {
    const genre = GENRES[i % GENRES.length] as Genre;
    docs.push(buildDoc(r, `${genre}-${String(i).padStart(4, '0')}`, genre, known));
  }
  return { docs, knownHashes: known };
}
