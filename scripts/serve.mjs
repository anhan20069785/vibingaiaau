// Máy chủ tĩnh tối thiểu cho trang. Chrome không nạp module ES qua file://, nên demo cần chạy qua HTTP.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PORT = Number(process.env.PORT ?? 8080);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.rsp': 'text/plain; charset=utf-8',
};

const server = createServer(async (request, response) => {
  const requested = new URL(request.url, `http://localhost:${PORT}`).pathname;
  const relative = requested === '/' ? 'index.html' : decodeURIComponent(requested).replace(/^\/+/, '');
  const resolved = normalize(join(ROOT, relative));
  if (!resolved.startsWith(ROOT.endsWith(sep) ? ROOT : ROOT + sep)) {
    response.writeHead(403).end('Forbidden');
    return;
  }
  console.log('REQ', request.url, request.headers['sec-fetch-dest'] ?? '-');
  try {
    const body = await readFile(resolved);
    console.log('RESP', request.url, body.length);
    response.writeHead(200, { 'content-type': TYPES[extname(resolved)] ?? 'application/octet-stream' });
    response.end(body);
  } catch {
    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('Not found');
  }
});

server.listen(PORT, () => {
  console.log(`http://localhost:${PORT}/`);
});