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

  it('fill uses the vault of the same session and never returns the value; forget empties it', async () => {
    const typed: string[] = [];
    let closed = 0;
    const c = await connect(new Session(), {
      openPage: async () => ({ page: { fill: async (_s: string, v: string) => void typed.push(v) }, close: async () => void closed++ }),
    });
    await c.callTool({ name: 'redact', arguments: { text: `card ${h.VISA}` } });
    const ok: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]', cdpUrl: 'http://127.0.0.1:1' } });
    assert.ok(!ok.isError && !text(ok).includes(h.VISA));
    assert.deepEqual(typed, [h.VISA]);
    assert.equal(closed, 1);
    await c.callTool({ name: 'forget', arguments: {} });
    const gone: any = await c.callTool({ name: 'fill', arguments: { selector: '#card', token: '[CARD_1]', cdpUrl: 'http://127.0.0.1:1' } });
    assert.equal(gone.isError, true);
    assert.ok(text(gone).includes('[CARD_1]') && !text(gone).includes(h.VISA));
    assert.equal(typed.length, 1);
    assert.equal(closed, 2);
  });

  it('fill without a CDP url is an error', async () => {
    const saved = process.env.CF_CDP_URL;
    delete process.env.CF_CDP_URL;
    try {
      const c = await connect();
      const r: any = await c.callTool({ name: 'fill', arguments: { selector: '#a', token: '[CARD_1]' } });
      assert.equal(r.isError, true);
    } finally {
      if (saved !== undefined) process.env.CF_CDP_URL = saved;
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
