import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';
import { RULES_ONLY } from '../core/classifier.ts';
import { Session, redact } from '../core/redact.ts';

export const MAX_BODY = 1024 * 1024;
export const HOST = '127.0.0.1';

function send(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
  res.end(data);
}

class TooLarge extends Error {}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new TooLarge());
        req.pause();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function createHttpServer(session: Session = new Session()): Server {
  return createServer(async (req, res) => {
    try {
      const path = (req.url ?? '').split('?')[0];
      if (path === '/health') {
        if (req.method !== 'GET') return send(res, 405, { error: 'method not allowed' });
        return send(res, 200, { ok: true, mode: 'local', classifier: RULES_ONLY });
      }
      if (path !== '/redact') return send(res, 404, { error: 'not found' });
      if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      let parsed: unknown;
      try {
        parsed = JSON.parse(await readBody(req));
      } catch (e) {
        if (e instanceof TooLarge) {
          res.setHeader('connection', 'close');
          return send(res, 413, { error: 'body too large' });
        }
        return send(res, 400, { error: 'body must be JSON' });
      }
      const text = typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>).text : undefined;
      if (typeof text !== 'string') return send(res, 400, { error: 'field "text" must be a string' });
      const source = (parsed as Record<string, unknown>).source;
      if (source !== undefined && typeof source !== 'string') return send(res, 400, { error: 'field "source" must be a string' });
      const out = await redact(text, { session });
      return send(res, 200, {
        text: out.text,
        findings: out.findings,
        receipt: { mode: 'local', classifier: RULES_ONLY, ts: new Date().toISOString() },
      });
    } catch {
      if (!res.headersSent) send(res, 500, { error: 'internal error' });
      else res.end();
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.CF_PORT ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new RangeError('CF_PORT must be a port number');
  createHttpServer().listen(port, HOST, () => console.log(`context-firewall http on http://${HOST}:${port} (local rules only)`));
}
