'use strict';

// 岸站 HTTP 服务：
//   GET  /            静态页面（值班员粘贴根公钥与委托链）
//   GET  /health      健康响应
//   POST /api/verify  逐跳核验（请求体 {rootKey, objects:[...], now?}）
//
// 无任何第三方依赖，便于在受限环境构建运行。

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { verifyChain } from './chain.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_BODY = 512 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
};

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function serveStatic(res, filePath) {
  try {
    const data = await readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'content-type': MIME[ext] || 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(data);
  } catch {
    sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: '资源不存在' } });
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('请求体过大'), { code: 'BODY_TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function createServer() {
  const publicDir = path.join(__dirname, '..', 'public');
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        return sendJson(res, 200, { status: 'ok', service: 'buoy-delegation-gateway', time: Math.floor(Date.now() / 1000) });
      }
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        return serveStatic(res, path.join(publicDir, 'index.html'));
      }
      if (req.method === 'GET' && url.pathname === '/app.js') {
        return serveStatic(res, path.join(publicDir, 'app.js'));
      }
      if (req.method === 'GET' && url.pathname === '/style.css') {
        return serveStatic(res, path.join(publicDir, 'style.css'));
      }
      if (req.method === 'POST' && url.pathname === '/api/verify') {
        const text = await readBody(req);
        let body;
        try {
          body = JSON.parse(text);
        } catch {
          return sendJson(res, 400, {
            ok: false,
            error: { code: 'BAD_REQUEST', hop: -1, field: null, message: '请求体必须是 JSON：{rootKey, objects:[...], now?}' },
          });
        }
        if (typeof body !== 'object' || body === null || Array.isArray(body)) {
          return sendJson(res, 400, {
            ok: false,
            error: { code: 'BAD_REQUEST', hop: -1, field: null, message: '请求体必须是 JSON 对象' },
          });
        }
        const result = verifyChain({
          rootKeyText: body.rootKey,
          objectTexts: body.objects,
          now: body.now,
        });
        return sendJson(res, result.ok ? 200 : 422, result);
      }
      return sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: '资源不存在' } });
    } catch (e) {
      if (e && e.code === 'BODY_TOO_LARGE') {
        return sendJson(res, 413, { ok: false, error: { code: 'BODY_TOO_LARGE', message: '请求体过大' } });
      }
      return sendJson(res, 500, { ok: false, error: { code: 'INTERNAL', message: '服务内部错误' } });
    }
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`buoy-delegation-gateway listening on http://${HOST}:${PORT}`);
  });
}
