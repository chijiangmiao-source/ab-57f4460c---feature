#!/usr/bin/env node
'use strict';

// 页面构建检查（无构建工具链的静态页面）：
//  1. index.html / app.js / style.css 存在；
//  2. HTML 引用的本地资源齐全；
//  3. app.js 通过 JS 语法检查（node --check）；
//  4. index.html 含关键 UI 元素（输入区、证据区、错误区）。

import { readFile, access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pub = path.join(root, 'public');

let failures = 0;
function fail(msg) { console.error(`页面检查失败：${msg}`); failures++; }
function ok(msg) { console.log(`  ✓ ${msg}`); }

async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}

async function main() {
  const htmlPath = path.join(pub, 'index.html');
  const jsPath = path.join(pub, 'app.js');
  const cssPath = path.join(pub, 'style.css');
  for (const [label, p] of [['index.html', htmlPath], ['app.js', jsPath], ['style.css', cssPath]]) {
    if (!await exists(p)) { fail(`缺少 public/${label}`); return 1; }
  }
  ok('静态资源齐全（index.html / app.js / style.css）');

  const html = await readFile(htmlPath, 'utf8');
  const js = await readFile(jsPath, 'utf8');
  const css = await readFile(cssPath, 'utf8');

  // HTML 引用的本地资源
  for (const ref of ['/app.js', '/style.css']) {
    if (!html.includes(`src="${ref}"`) && !html.includes(`href="${ref}"`)) {
      fail(`index.html 未引用 ${ref}`);
    }
  }
  ok('HTML 引用资源声明完整');

  // 关键 UI 元素
  for (const id of ['rootKey', 'objects', 'verifyBtn', 'errorPanel', 'evidencePanel', 'hopTable']) {
    if (!html.includes(`id="${id}"`)) fail(`index.html 缺少元素 #${id}`);
  }
  for (const token of ['fetch(', '/api/verify', 'lastValidEvidence']) {
    if (!js.includes(token)) fail(`app.js 缺少关键逻辑：${token}`);
  }
  if (!css.includes('.panel') || !css.includes('.error')) fail('style.css 缺少关键样式');
  ok('页面关键元素与逻辑齐备（输入 / 错误草稿 / 证据留存）');

  // JS 语法检查（浏览器脚本仅做解析校验，不执行）
  try {
    execFileSync(process.execPath, ['--check', jsPath], { stdio: 'pipe' });
    ok('app.js 通过 node --check 语法检查');
  } catch (e) {
    fail(`app.js 语法错误：${e.stderr ? e.stderr.toString() : e.message}`);
  }

  if (failures) { console.error(`页面构建检查：${failures} 项失败`); return 1; }
  console.log('页面构建检查通过');
  return 0;
}

main().then((code) => process.exit(code)).catch((e) => {
  console.error(e);
  process.exit(1);
});
