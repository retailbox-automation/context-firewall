// Deterministic synthetic corpus. Every secret-shaped value is assembled at run time from
// parts and random characters; nothing here is a real credential. Card numbers are the
// publicly documented test numbers of the payment networks.
// Deliberately imports nothing from the detectors except the Category type: decoys and
// values are written here, independently of the detector regexes.
import { createHash } from 'node:crypto';
import type { Category } from '../core/detect.ts';

export const CATEGORIES: readonly Category[] = [
  'CARD', 'US_SSN', 'US_ITIN', 'US_EIN', 'IBAN', 'AWS_KEY', 'AWS_SECRET', 'OPENAI_KEY', 'ANTHROPIC_KEY',
  'GITHUB_TOKEN', 'STRIPE_KEY', 'SLACK_TOKEN', 'GOOGLE_KEY', 'PRIVATE_KEY', 'JWT', 'OTP', 'KNOWN_SECRET',
];

const sha256Hex = (s: string): string => createHash('sha256').update(s).digest('hex');

/** own Luhn check, used only to build decoys */
function luhn(digits: string): boolean {
  let sum = 0;
  digits.split('').reverse().forEach((ch, i) => {
    let d = Number(ch);
    if (i % 2 === 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
    sum += d;
  });
  return sum % 10 === 0;
}

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
  // networks outside the detector's list: Diners (16 and 14 digits) and Maestro; counted as misses
  ['3056', '9300', '0902', '0004'],
  ['3622', '720627', '1667'],
  ['6759', '6498', '2643', '8453'],
];

function cardValue(r: Rng, noisy: boolean): string {
  const groups = r.pick(TEST_PANS);
  const style = r.int(0, 5);
  if (style === 0) return groups.join('');
  const sep = [' ', ' ', '-', '\u00a0', '.'][style - 1] as string;
  const joined = groups.join(noisy && r.chance(0.5) ? sep + sep : sep);
  return noisy && r.chance(0.15) ? joined.replace(/\d/g, (d) => String.fromCharCode(0xff10 + Number(d))) : joined;
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
  lines.push(r.chars(ALNUM, 20) + '==');
  const kind = r.pick(['', 'RSA ', 'EC ']);
  const begin = '-----BEGIN ' + kind + 'PRIVATE KEY-----';
  const end = '-----END ' + kind + 'PRIVATE KEY-----';
  switch (r.int(0, 3)) {
    case 0: // plain
      return [begin, ...lines, end].join('\n');
    case 1: // inside a JSON string (service-account file): literal backslash-n
      return [begin, ...lines, end].join('\\n') + '\\n';
    case 2: // legacy encrypted PEM with headers
      return [begin, 'Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,' + r.chars('0123456789ABCDEF', 32), '', ...lines, end].join('\n');
    default: // quoted in a reply
      return [begin, ...lines, end].map((l, i) => (i === 0 ? l : '> ' + l)).join('\n');
  }
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

function withLuhn(partial: string): string {
  for (let d = 0; d < 10; d++) if (luhn(partial + d)) return partial + d;
  throw new Error('unreachable');
}

/** random digits, no Luhn filter: some of these are valid card-shaped numbers by chance */
const randomRef = (r: Rng, lead: string): string => lead + r.digits(15);

const b64u = (s: string): string => Buffer.from(s).toString('base64url');

// Hard negatives. Several of them WILL trip a detector (documentation placeholders, order
// numbers that happen to pass Luhn, "code" words that are not logins); that is the point.
const DECOYS: ((r: Rng) => string)[] = [
  // numbers
  (r) => 'Order #' + r.digits(8),
  (r) => 'Order ' + r.chars(UP, 3) + '-' + r.int(2024, 2026) + '-' + r.digits(6),
  (r) => 'Tracking: 1Z' + r.chars(UP + NUM, 16),
  (r) => 'Tracking number ' + r.pick(['94', '92']) + r.digits(20),
  (r) => 'Order number ' + randomRef(r, r.pick(['4', '5', '3', '6'])),
  (r) => 'Membership no. ' + randomRef(r, r.pick(['4', '5'])),
  (r) => 'Ref ' + withLuhn(r.pick(['9', '8', '1', '7']) + r.digits(14)),
  (r) => 'IMEI: ' + withLuhn(r.pick(['35', '86', '49', '01']) + r.digits(12)),
  (r) => 'Serial ' + r.digits(16),
  (r) => 'Phone: (' + r.int(201, 989) + ') ' + r.int(201, 989) + '-' + r.digits(4),
  (r) => 'Call +1 ' + r.int(201, 989) + ' ' + r.int(201, 989) + ' ' + r.digits(4),
  (r) => 'Phone ' + r.int(201, 989) + '-' + r.int(201, 989) + '-' + r.digits(4),
  (r) => 'Date: ' + r.int(2024, 2026) + '-' + String(r.int(1, 12)).padStart(2, '0') + '-' + String(r.int(1, 28)).padStart(2, '0'),
  (r) => 'Placed on ' + r.int(1, 12) + '/' + r.int(1, 28) + '/' + r.int(2024, 2026),
  (r) => 'Request id ' + uuid(r),
  (r) => 'commit ' + r.chars('0123456789abcdef', 40),
  (r) => 'build ' + r.chars('0123456789abcdef', 7),
  (r) => 'Digest ' + mixed(r, ALNUM + '/+', 40),
  (r) => 'Total: $' + r.int(1, 9) + ',' + r.digits(3) + '.' + r.digits(2),
  (r) => 'Subtotal $' + r.int(10, 999) + '.' + r.digits(2),
  // look-alikes of tax ids and bank numbers
  (r) => 'Part no. ' + r.int(100, 665) + '-' + r.int(10, 99) + '-' + r.int(1000, 9999),
  (r) => 'Part ' + r.int(900, 999) + '-' + r.int(10, 99) + '-' + r.int(1000, 9999),
  (r) => 'Invoice ' + r.int(31, 48) + '-' + r.digits(7),
  (r) => 'Account no. ' + r.int(31, 48) + '-' + r.digits(7),
  (r) => 'Booking ref ' + r.pick(['DE', 'GB', 'FR', 'ES']) + r.digits(2) + ' ' + r.chars(UP, 4) + ' ' + r.digits(4) + ' ' + r.digits(4) + ' ' + r.digits(4) + ' ' + r.digits(2),
  // words that look like keys or codes
  (r) => 'See sk-learn-' + r.pick(['pipeline', 'compat', 'metrics']) + '-v' + r.int(2, 9) + ' in the docs',
  () => 'Placeholder: sk-' + 'x'.repeat(32),
  (r) => 'Example: sk-your-api-key-goes-here-' + r.digits(12),
  (r) => 'Run task-runner-sk-' + r.digits(20) + ' again',
  () => 'Keys start with AKIA followed by 16 characters',
  () => 'From the docs: AK' + 'IA' + 'IOSFODNN7' + 'EXAM' + 'PLE',
  () => 'Tokens look like ghp_ plus 36 characters, ghost_style_names are fine',
  () => 'Use sk_test_ keys for staging, sk_live_ only in production',
  () => 'Docs placeholder AI' + 'za' + 'X'.repeat(35),
  () => 'Thanks, xoxo and see you soon',
  (r) => 'Token header ' + b64u('{"typ":"JWT"}') + '.' + b64u('{"id":' + r.int(1, 99) + '}') + '.' + r.chars(B64URL, 20),
  (r) => 'Blob ' + b64u(r.chars(LOW, 12)) + '.' + b64u(r.chars(LOW, 12)) + '.' + r.chars(B64URL, 12),
  () => '-----BEGIN ' + 'PUBLIC KEY----- (shared with partners) -----END ' + 'PUBLIC KEY-----',
  () => '-----BEGIN ' + 'CERTIFICATE----- chain follows -----END ' + 'CERTIFICATE-----',
  (r) => 'Product code: ' + r.digits(5),
  (r) => 'Promo code ' + r.digits(6),
  (r) => 'Your order code is ' + r.digits(6),
  (r) => 'Error code ' + r.digits(5) + ' on retry',
  (r) => 'Tracking code ' + r.digits(8),
  (r) => 'Postal code: ' + r.digits(5),
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
    if (cat === 'AWS_KEY') {
      const pair = [mk('AWS_KEY'), mk('AWS_SECRET')];
      if (genre === 'payment-page' && r.chance(0.5)) {
        pair[0]!.text = 'AWS_ACCESS_KEY_ID={v}';
        pair[1]!.text = 'AWS_SECRET_ACCESS_KEY={v}';
      }
      groups.push(pair);
    } else groups.push([mk(cat)]);
  }
  for (let i = r.int(12, 18); i > 0; i--) groups.push([{ text: (r.pick(DECOYS))(r) }]);
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
