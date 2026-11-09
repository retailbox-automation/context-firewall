# Context Firewall

Keeps card numbers, tax IDs, API keys and one-time codes out of what an AI agent's model sees. The agent works with placeholders like `[CARD_1]`; the real value is typed into the form locally at the moment of the click.

Status: built for the NEAR Hackathon 2026 (Privacy & Private AI track). This version runs in `--local` mode: deterministic rules only. The confidential-compute (TEE) classifier is an interface and a stub, not connected.

Second, independent project by the same team: [Last Server](https://github.com/retailbox-automation/last-server) (Games track).

## Try it

Needs Node 22.18 or newer and an installed Chrome (no browser download). Each step prints what is shown below.

1. `npm ci` installs two packages (MCP SDK, Playwright core).
2. `npm test` runs the unit tests without a browser; it ends with `# fail 0`.
3. `npm run test:browser` opens a private headless Chrome and ends with `# fail 0`. It checks that a placeholder fills a real form field and that the card digits appear in no log, error or output.
4. `npm run eval` builds 300 synthetic documents, prints a recall/precision table per category, and writes `docs/EVAL.md` and `docs/eval.json`.
5. `npm run demo` loads a synthetic checkout page, shows its text before and after redaction, lets an executor fill the form, and ends with `card digits in demo-out: 0 matches`.

Set `CF_CHROME_PATH` to use a specific Chrome binary.

## What it does

```
page text / screenshot text
        |
        v
  detect (rules)  --->  redact  --->  "Card: [CARD_1]"  --->  model / agent
                          |
                          v
                 Vault: token -> value (process memory only)
                          ^
                          |
  agent says: fill #card with [CARD_1]  --->  executor reads the value, page.fill(...)
```

- `src/core/detect.ts`: detectors for cards (Luhn and known IIN), US SSN, ITIN, EIN, IBAN (mod-97), API keys and tokens (AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Google, PEM private keys, JWT), one-time codes after words like "code" or "OTP", and secrets you list by sha256 in a file named by `CF_KNOWN_HASHES`. A match is `sure` or `likely`.
- `src/core/redact.ts`: replaces matches with `[CATEGORY_n]`. The same value gets the same placeholder within a session. Findings carry a salted hash of the value, never the value. `Vault.forget()` drops everything.
- `src/executor/fill.ts`: the only code that reads the vault. Errors name the token, not the value.
- `src/mcp/server.ts`: MCP over stdio with tools `redact`, `fill`, `forget` (`npm run start:mcp`). `fill` needs a Chrome with a CDP endpoint (`cdpUrl` or `CF_CDP_URL`).
- `src/http/server.ts`: `POST /redact` and `GET /health` on 127.0.0.1 only, 1 MB body limit (`npm run start:http`, port from `CF_PORT`, default 8787).
- `src/core/classifier.ts`: `RulesOnly` (this mode) and `NearAiCloud`, a stub that throws `NotConfigured`.

## Limits

- Local mode only. Anything the rules do not describe (names, addresses, free-form secrets) is not caught. The TEE classifier that would cover those is not connected.
- Measured on a synthetic corpus of 300 documents, seed 20261109 (full table and caveats in `docs/EVAL.md`): every structured category is found at 93.7 to 100 percent; the misses are all OCR-style text where the label is glued to the value or a keyword is misread. EIN-shaped numbers without a keyword and OTPs are `likely` matches, so EIN precision is 69 percent. Real pages will score lower than a corpus written by the detector's authors.
- The vault lives in one process. The MCP server and the HTTP server do not share placeholders.
- Redaction is a filter on text. It does not stop a page from showing the value in an image the model reads.

License: MIT.
