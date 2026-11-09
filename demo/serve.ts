import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';

/** Serves one HTML page on 127.0.0.1 so the page has a real http origin. */
export async function serveHtml(html: string): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/checkout`, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}
