import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { Server } from 'node:http';
import { MAX_BODY, createHttpServer } from '../src/http/server.ts';
import { Session } from '../src/core/redact.ts';
import { createMcpServer } from '../src/mcp/server.ts';
import * as h from './helpers.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function call(port: number, method: string, path: string, body?: string | Buffer, headers: Record<string, string> = {}): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        resolve({ status: res.statusCode ?? 0, json: raw ? JSON.parse(raw) : null });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

describe('http server', () => {
  let server: Server;
  let port: number;
  before(async () => {
    server = createHttpServer(new Session());
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    port = (server.address() as AddressInfo).port;
  });
  after(() => server.close());

  it('listens on loopback only', () => {
    assert.equal((server.address() as AddressInfo).address, '127.0.0.1');
  });

  it('GET /health', async () => {
    const r = await call(port, 'GET', '/health');
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
  });

  it('POST /redact returns text, findings and a local receipt', async () => {
    const r = await call(port, 'POST', '/redact', JSON.stringify({ text: `card ${h.VISA}`, source: 'page' }));
    assert.equal(r.status, 200);
    assert.equal(r.json.text, 'card [CARD_1]');
    assert.equal(r.json.findings[0].category, 'CARD');
    assert.equal(r.json.receipt.mode, 'local');
    assert.equal(r.json.receipt.classifier, 'rules-only');
    assert.ok(!JSON.stringify(r.json).includes(h.VISA));
  });

  it('garbage gets 400 and the server keeps working', async () => {
    for (const body of ['not json', '{"text": 5}', '[]', 'null', '{"text":"a","source":3}', '']) {
      const r = await call(port, 'POST', '/redact', body);
      assert.equal(r.status, 400, body);
    }
    assert.equal((await call(port, 'POST', '/redact', Buffer.from([0xff, 0xfe, 0x00, 0x7b]))).status, 400);
    assert.equal((await call(port, 'GET', '/health')).status, 200);
  });

  it('wrong method and unknown path', async () => {
    assert.equal((await call(port, 'GET', '/redact')).status, 405);
    assert.equal((await call(port, 'POST', '/health', '{}')).status, 405);
    assert.equal((await call(port, 'GET', '/nope')).status, 404);
  });

  it('body over 1 MB is refused, a body just under is served', async () => {
    const big = JSON.stringify({ text: 'a'.repeat(MAX_BODY) });
    const r = await call(port, 'POST', '/redact', big).catch((e: NodeJS.ErrnoException) => ({ status: -1, json: e.code }));
    assert.ok(r.status === 413 || r.status === -1, String(r.status));
    const ok = await call(port, 'POST', '/redact', JSON.stringify({ text: 'a'.repeat(MAX_BODY - 100) }));
    assert.equal(ok.status, 200);
    assert.equal((await call(port, 'GET', '/health')).status, 200);
  });
});

async function connect(session = new Session(), openPage?: Parameters<typeof createMcpServer>[1]) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createMcpServer(session, openPage).connect(b);
  const client = new Client({ name: 'test', version: '0' });
  await client.connect(a);
  return client;
}
const text = (r: any): string => r.content[0].text;

describe('mcp server (in memory)', () => {
  it('lists redact, fill, forget', async () => {
    const c = await connect();
    assert.deepEqual((await c.listTools()).tools.map((t) => t.name).sort(), ['fill', 'forget', 'redact']);
  });

  it('redact returns text, findings and receipt', async () => {
    const c = await connect();
    const out = JSON.parse(text(await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}`, source: 'x' } })));
    assert.equal(out.text, 'card [CARD_1]');
    assert.equal(out.receipt.mode, 'local');
    assert.ok(!JSON.stringify(out).includes(h.VISA));
  });

  it('bad arguments come back as tool errors', async () => {
    const c = await connect();
    const r: any = await c.callTool({ name: 'redact', arguments: { text: 5 } });
    assert.equal(r.isError, true);
    const u: any = await c.callTool({ name: 'nope', arguments: {} });
    assert.equal(u.isError, true);
  });

  const OPEN = (typed: string[], opened: string[], closed: { n: number }, url: string) => ({
    cdpUrl: 'http://127.0.0.1:9',
    openPage: async (_cdp: string, origin: string) => {
      opened.push(origin);
      return { page: { url: () => url, fill: async (_s: string, v: string) => void typed.push(v) }, close: async () => void closed.n++ };
    },
  });

  it('fill uses the vault of the same session, on the bound origin, and never returns the value; forget empties it', async () => {
    const typed: string[] = [];
    const opened: string[] = [];
    const closed = { n: 0 };
    const c = await connect(new Session(), OPEN(typed, opened, closed, 'https://shop.example/pay'));
    await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}`, source: 'https://shop.example/pay?step=2' } });
    const ok: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]' } });
    assert.ok(!ok.isError && !text(ok).includes(h.VISA));
    assert.deepEqual(typed, [h.VISA]);
    assert.deepEqual(opened, ['https://shop.example']);
    assert.equal(closed.n, 1);
    await c.callTool({ name: 'forget', arguments: {} });
    const gone: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]' } });
    assert.equal(gone.isError, true);
    assert.ok(text(gone).includes('[CARD_1]') && !text(gone).includes(h.VISA));
    assert.equal(typed.length, 1);
  });

  it('a tab on another origin is refused without the value', async () => {
    const typed: string[] = [];
    const c = await connect(new Session(), OPEN(typed, [], { n: 0 }, 'https://evil.example/'));
    await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}`, source: 'https://shop.example/' } });
    const r: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]' } });
    assert.equal(r.isError, true);
    assert.ok(!text(r).includes(h.VISA));
    assert.deepEqual(typed, []);
  });

  it('a token redacted without a source cannot be filled', async () => {
    const opened: string[] = [];
    const c = await connect(new Session(), OPEN([], opened, { n: 0 }, 'https://shop.example/'));
    await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}` } });
    const r: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]' } });
    assert.equal(r.isError, true);
    assert.match(text(r), /no origin binding/);
    assert.deepEqual(opened, []);
  });

  it('cdpUrl in the arguments is rejected and never used; the schema does not offer it', async () => {
    const opened: string[] = [];
    const c = await connect(new Session(), OPEN([], opened, { n: 0 }, 'https://shop.example/'));
    const fillTool = (await c.listTools()).tools.find((t) => t.name === 'fill');
    assert.ok(!('cdpUrl' in (fillTool?.inputSchema.properties ?? {})));
    await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}`, source: 'https://shop.example/' } });
    const r: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]', cdpUrl: 'http://203.0.113.9:9222' } });
    assert.equal(r.isError, true);
    assert.ok(!text(r).includes('203.0.113.9'));
    assert.deepEqual(opened, []);
  });

  it('the operator endpoint must be configured and local', async () => {
    const saved = process.env.CF_CDP_URL;
    try {
      for (const [env, expect] of [[undefined, /no browser endpoint/], ['http://203.0.113.9:9222', /this machine/], ['garbage', /not a URL/]] as const) {
        if (env === undefined) delete process.env.CF_CDP_URL;
        else process.env.CF_CDP_URL = env;
        const opened: string[] = [];
        const c = await connect(new Session(), { openPage: OPEN([], opened, { n: 0 }, 'https://shop.example/').openPage });
        await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}`, source: 'https://shop.example/' } });
        const r: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]' } });
        assert.equal(r.isError, true);
        assert.match(text(r), expect);
        assert.deepEqual(opened, []);
      }
    } finally {
      if (saved !== undefined) process.env.CF_CDP_URL = saved;
      else delete process.env.CF_CDP_URL;
    }
  });
});

describe('mcp server (stdio process)', () => {
  it('serves redact over stdio', async () => {
    const transport = new StdioClientTransport({ command: process.execPath, args: [join(root, 'src/mcp/server.ts')], cwd: root });
    const client = new Client({ name: 'test', version: '0' });
    await client.connect(transport);
    try {
      const out = JSON.parse(text(await client.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}` } })));
      assert.equal(out.text, 'card [CARD_1]');
    } finally {
      await client.close();
    }
  });
});
