// Page text -> redact -> transcript with placeholders only -> executor fills the form
// -> search demo-out/ for the card digits.
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Session, originOf, redact } from '../src/core/redact.ts';
import { fill } from '../src/executor/fill.ts';
import { launchChrome } from '../src/executor/launch.ts';
import { serveHtml } from './serve.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'demo-out');

// synthetic values, assembled at run time (the card is a publicly documented test number)
const CARD = ['4242', '4242', '4242', '4242'].join(' ');
const SSN = ['312', '09', '9999'].join('-');
const KEY = ['sk', '_live_', 'Q7x2LmN9pR4sT6vW8yB1cD3f'].join('');

// which form field takes which kind of placeholder (this is what the agent "decides")
const FIELD: Record<string, string> = { CARD: '#card', US_SSN: '#ssn', STRIPE_KEY: '#api-key' };

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const html = readFileSync(join(root, 'demo', 'page.template.html'), 'utf8')
  .replace('{{CARD}}', CARD)
  .replace('{{SSN}}', SSN)
  .replace('{{KEY}}', KEY);

const site = await serveHtml(html);
const browser = await launchChrome();
let status = 'ok';
try {
  const page = await browser.newPage();
  await page.goto(site.url);
  const panel = (await page.locator('#cf-panel').innerText()).trim();
  const pageText = await page.locator('body').innerText();

  const session = new Session();
  const { text: safeText, findings } = await redact(pageText, { session, origin: originOf(page.url()) });

  const transcript: object[] = [{ role: 'tool', name: 'page_text', mode: 'local', content: safeText }];
  for (const f of findings) {
    const selector = FIELD[f.category];
    if (!selector) continue;
    transcript.push({ role: 'assistant', action: 'fill', selector, token: f.token });
    await fill(page, selector, f.token, session.vault);
  }
  writeFileSync(join(out, 'agent-transcript.jsonl'), transcript.map((t) => JSON.stringify(t)).join('\n') + '\n');

  // the form really holds the values (compared in memory, not printed)
  const filled = {
    card: (await page.inputValue('#card')) === CARD,
    ssn: (await page.inputValue('#ssn')) === SSN,
    key: (await page.inputValue('#api-key')) === KEY,
  };
  if (!filled.card || !filled.ssn || !filled.key) status = `form not filled correctly: ${JSON.stringify(filled)}`;

  console.log(`panel: ${panel}\n`);
  console.log('--- BEFORE: page text as the browser shows it ---');
  console.log(pageText);
  console.log('--- AFTER: what the model sees (demo-out/agent-transcript.jsonl) ---');
  console.log(safeText);
  console.log('--- agent actions ---');
  for (const t of transcript.slice(1)) console.log(JSON.stringify(t));
  console.log(`\nform fields filled by the executor: card=${filled.card} ssn=${filled.ssn} api-key=${filled.key}`);
} finally {
  await browser.close();
  await site.close();
}

const digits = CARD.replaceAll(' ', '');
const loose = new RegExp(digits.split('').join('[ -]?'));
// control: the same search must find the digits in the raw page text
if (!loose.test(html)) throw new Error('control failed: search cannot see the card digits');
let matches = 0;
for (const name of readdirSync(out, { recursive: true }) as string[]) {
  const p = join(out, name);
  try {
    const body = readFileSync(p, 'latin1');
    if (loose.test(body)) matches++;
  } catch {
    // directories
  }
}
if (status !== 'ok') {
  console.error(status);
  process.exitCode = 1;
}
console.log(`card digits in demo-out: ${matches} matches`);
if (matches !== 0) process.exitCode = 1;
