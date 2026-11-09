# Context Firewall

Keeps card numbers, tax IDs, API keys and one-time codes out of what an AI agent's model sees. The agent works with placeholders like `[CARD_1]`; the real value is typed into the form locally at the moment of the click.

Status: built for the NEAR Hackathon 2026 (Privacy & Private AI track). **This version runs in `--local` mode only: deterministic rules, nothing leaves the process.** The confidential-compute (TEE) classifier on NEAR AI Cloud is an interface and a stub; it will be connected later and is not part of this version.

Second, independent project by the same team: [Last Server](https://github.com/retailbox-automation/last-server) (Games track).

## Try it

Needs Node 22.18 or newer and an installed Chrome (no browser download). Checked on Node 26.12 on macOS.

1. `npm ci` installs the MCP SDK and Playwright core with their dependencies. Output ends with `found 0 vulnerabilities`.
2. `npm test` runs the unit tests without a browser. Output ends with a summary: `ℹ tests 85`, `ℹ pass 85`, `ℹ fail 0` (the count grows as tests are added; `fail` must be 0).
3. `npm run test:browser` starts a private headless Chrome with a throwaway profile and prints the same summary (`ℹ pass 4`, `ℹ fail 0`). It checks that a placeholder fills a real form field, that a page on another origin is refused, and that the card digits appear in no log, error or output.
4. `npm run eval` builds 300 synthetic documents, prints a recall/precision table per category, and writes `docs/EVAL.md` and `docs/eval.json`.
5. `npm run demo` serves a synthetic checkout page on 127.0.0.1, prints its text before and after redaction, lets the executor fill the form, and ends with `card digits in demo-out: 0 matches`.

Set `CF_CHROME_PATH` to use a specific Chrome binary.

## What it does

```
page text / screenshot text
        |
        v
  detect (rules)  --->  redact  --->  "Card: [CARD_1]"  --->  model / agent
                          |
                          v
        Vault: token -> value + origin of the page (process memory only)
                          ^
                          |
  agent says: fill #card with [CARD_1]  --->  executor checks the tab's origin,
                                              reads the value, page.fill(...)
```

- `src/core/detect.ts`: detectors for cards (Luhn and known IIN), US SSN, ITIN, EIN, IBAN (mod-97), API keys and tokens (AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Google, PEM private keys, JWT), one-time codes after words like "code" or "OTP", and secrets you list by sha256 in a file named by `CF_KNOWN_HASHES`. A match is `sure` or `likely`.
- `src/core/redact.ts`: replaces matches with `[CATEGORY_n]`. The same value gets the same placeholder within a session and origin. Findings carry a salted hash of the value, never the value. `Vault.forget()` drops everything.
- `src/executor/fill.ts`: the only code that reads the vault. A placeholder is bound to the origin it was seen on and can only be filled on a page of that origin. Errors name the token, not the value.
- `src/mcp/server.ts`: MCP over stdio with tools `redact {text, source}`, `fill {selector, token}`, `forget` (`npm run start:mcp`). `source` is the page URL; without it the placeholder cannot be filled. The browser endpoint is not a tool argument: the operator sets `CF_CDP_URL` (loopback only), and `fill` picks the open tab whose origin matches the placeholder.
- `src/http/server.ts`: `POST /redact` and `GET /health` on 127.0.0.1 only, 1 MB body limit (`npm run start:http`, port from `CF_PORT`, default 8787).
- `src/core/classifier.ts`: `RulesOnly` (this mode) and `NearAiCloud`, a stub that throws `NotConfigured`.

## Limits

- Local mode only. Anything the rules do not describe (names, addresses, free-form secrets) is not caught. The TEE classifier that would cover those is not connected yet.
- Numbers come from `docs/EVAL.md` (synthetic corpus, 300 documents, seed 20261109, hard negatives included). Recall is 93 to 100 percent per category, except cards at 83 percent: the card rule knows Visa, Mastercard, Amex, Discover, JCB and UnionPay, and the corpus includes Diners and Maestro test numbers on purpose. Precision is where the shape-based rules pay: SSN 73, EIN 59, OTP 44, OpenAI-style `sk-` 73, Google-style `AIza` 75, AWS key id 77 percent, because documentation placeholders, order and part numbers and "code" words of the same shape are reported. The corpus was written by the same team as the detectors; real pages will score lower.
- The executor binds a placeholder to a page origin, not to a field type. A model that controls the selector can fill a card number into any field of that origin, and a model that also has a browser tool on that origin can read the field back. Origin binding stops the value going to another site; it does not make the same site safe from the model.
- A model that calls `redact` itself can test guesses by comparing which placeholders come back. This is outside the v1 threat model.
- The vault lives in one process. The MCP server and the HTTP server do not share placeholders.
- Redaction is a filter on text. It does not stop a page from showing the value in an image the model reads.

License: MIT.
