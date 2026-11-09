import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { fileURLToPath } from 'node:url';
import { RULES_ONLY } from '../core/classifier.ts';
import { Session, originOf, redact } from '../core/redact.ts';
import { fill } from '../executor/fill.ts';
import type { Fillable } from '../executor/fill.ts';

type Args = Record<string, unknown>;

const TOOLS = [
  {
    name: 'redact',
    description: 'Replace card numbers, tax IDs, API keys and one-time codes with placeholders like [CARD_1]. Real values stay in this process.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string' }, source: { type: 'string', description: 'URL of the page the text came from; placeholders can only be filled back on that origin' } },
      required: ['text'],
      additionalProperties: false,
    },
  },
  {
    name: 'fill',
    description: 'Type the real value behind a placeholder into a form field. Works only on an open tab whose origin matches the page the value was seen on. The browser endpoint is set by the operator. The value is not returned.',
    inputSchema: {
      type: 'object',
      properties: {
        selector: { type: 'string' },
        token: { type: 'string', description: 'placeholder such as [CARD_1]' },
      },
      required: ['selector', 'token'],
      additionalProperties: false,
    },
  },
  {
    name: 'forget',
    description: 'Drop every placeholder and its value from memory.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

export interface Deps {
  /** how `fill` reaches the tab for an origin; tests replace it */
  openPage: (cdpUrl: string, origin: string) => Promise<{ page: Fillable; close: () => Promise<void> }>;
  /** operator-set browser endpoint; default is env CF_CDP_URL. Never taken from tool arguments. */
  cdpUrl?: string;
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

export function checkCdpUrl(raw: string | undefined): string {
  if (!raw) throw new Error('no browser endpoint configured (operator sets CF_CDP_URL)');
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('CF_CDP_URL is not a URL');
  }
  if (!LOOPBACK.has(u.hostname)) throw new Error('CF_CDP_URL must point to this machine');
  return raw;
}

async function openCdpPage(cdpUrl: string, origin: string): Promise<{ page: Fillable; close: () => Promise<void> }> {
  const { chromium } = await import('playwright-core');
  const browser = await chromium.connectOverCDP(cdpUrl);
  const matching = browser.contexts().flatMap((c) => c.pages()).filter((p) => originOf(p.url()) === origin);
  const page = matching.at(-1);
  if (!page) {
    await browser.close();
    throw new Error('no open tab on the origin this value came from');
  }
  return { page, close: () => browser.close() };
}

function str(args: Args, key: string): string {
  const v = args[key];
  if (typeof v !== 'string' || v.length === 0) throw new Error(`"${key}" must be a non-empty string`);
  return v;
}

export function createMcpServer(session: Session = new Session(), deps: Deps = { openPage: openCdpPage }): Server {
  const server = new Server({ name: 'context-firewall', version: '0.1.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Args;
    try {
      switch (req.params.name) {
        case 'redact': {
          const source = typeof args.source === 'string' ? args.source : undefined;
          const out = await redact(str(args, 'text'), { session, origin: originOf(source) });
          const result = { text: out.text, findings: out.findings, receipt: { mode: 'local', classifier: RULES_ONLY, ts: new Date().toISOString() } };
          return { content: [{ type: 'text', text: JSON.stringify(result) }] };
        }
        case 'fill': {
          if ('cdpUrl' in args) throw new Error('cdpUrl is not accepted: the browser endpoint is set by the operator');
          const selector = str(args, 'selector');
          const token = str(args, 'token');
          const origin = session.vault.originOf(token);
          if (session.vault.get(token) === undefined) throw new Error(`unknown token ${token}`);
          if (origin === undefined) throw new Error(`token ${token} has no origin binding (pass source to redact)`);
          const cdpUrl = checkCdpUrl(deps.cdpUrl ?? process.env.CF_CDP_URL);
          const { page, close } = await deps.openPage(cdpUrl, origin);
          try {
            await fill(page, selector, token, session.vault);
          } finally {
            await close();
          }
          return { content: [{ type: 'text', text: JSON.stringify({ filled: token, selector }) }] };
        }
        case 'forget':
          session.forget();
          return { content: [{ type: 'text', text: JSON.stringify({ forgotten: true }) }] };
        default:
          throw new Error(`unknown tool ${req.params.name}`);
      }
    } catch (e) {
      return { isError: true, content: [{ type: 'text', text: e instanceof Error ? e.message : 'error' }] };
    }
  });
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await createMcpServer().connect(new StdioServerTransport());
}
