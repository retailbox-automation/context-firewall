import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { fileURLToPath } from 'node:url';
import { RULES_ONLY } from '../core/classifier.ts';
import { Session, redact } from '../core/redact.ts';
import { fill } from '../executor/fill.ts';
import type { Fillable } from '../executor/fill.ts';

type Args = Record<string, unknown>;

const TOOLS = [
  {
    name: 'redact',
    description: 'Replace card numbers, tax IDs, API keys and one-time codes with placeholders like [CARD_1]. Real values stay in this process.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string' }, source: { type: 'string', description: 'where the text came from (optional)' } },
      required: ['text'],
      additionalProperties: false,
    },
  },
  {
    name: 'fill',
    description: 'Type the real value behind a placeholder into a form field of a Chrome reachable over CDP. The value is not returned.',
    inputSchema: {
      type: 'object',
      properties: {
        selector: { type: 'string' },
        token: { type: 'string', description: 'placeholder such as [CARD_1]' },
        cdpUrl: { type: 'string', description: 'default: env CF_CDP_URL' },
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
  /** how `fill` reaches a page; tests replace it, the default connects over CDP */
  openPage: (cdpUrl: string) => Promise<{ page: Fillable; close: () => Promise<void> }>;
}

async function openCdpPage(cdpUrl: string): Promise<{ page: Fillable; close: () => Promise<void> }> {
  const { chromium } = await import('playwright-core');
  const browser = await chromium.connectOverCDP(cdpUrl);
  const page = browser.contexts()[0]?.pages().at(-1);
  if (!page) {
    await browser.close();
    throw new Error('no open page in the browser');
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
          const out = await redact(str(args, 'text'), { session });
          const result = { text: out.text, findings: out.findings, receipt: { mode: 'local', classifier: RULES_ONLY, ts: new Date().toISOString() } };
          return { content: [{ type: 'text', text: JSON.stringify(result) }] };
        }
        case 'fill': {
          const selector = str(args, 'selector');
          const token = str(args, 'token');
          const cdpUrl = typeof args.cdpUrl === 'string' && args.cdpUrl ? args.cdpUrl : process.env.CF_CDP_URL;
          if (!cdpUrl) throw new Error('cdpUrl is required (or set CF_CDP_URL)');
          const { page, close } = await deps.openPage(cdpUrl);
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
