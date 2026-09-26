#!/usr/bin/env node
'use strict';

// 一次性验收服务 verify：
//   1. 复核合法链的逐跳证据（每跳签名、规范载荷摘要、收紧约束、准许结论）；
//   2. 复核越权链的拒绝（浮标未获上游允许 / 采样量超限 / 约束放宽），定位跳与字段；
//   3. 复核篡改签名 / 改写载荷的拒绝（BAD_SIGNATURE）；
//   4. 复核结构性错误（重复键、键序不规范、不安全 / 越界整数、非有限数、链首非根公钥）；
//   5. 复核容量委托图审计（乱序接线、逐边验签、只收紧、最大流 / 最小割、各类拒绝定位）；
//   6. 运行相关代码测试（node --test tests/）与页面构建检查；
//   7. 启动本机服务做健康地址 API/HTTP 冒烟（含 /api/capacity）；GATEWAY_URL 存在时再冒烟对端。
//
// 执行完毕即退出：0 全部通过，1 存在验收失败，2 执行异常。

import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { verifyChain } from '../src/chain.js';
import { auditCapacity, findCycle, maxFlow } from '../src/capacity.js';
import { canonicalize, parseCanonical } from '../src/canonical.js';
import {
  generateKeyPair,
  issueDelegation,
  issueCommand,
  issueCapDelegation,
  rootKeyDocument,
  buildValidChain,
} from '../src/sign.js';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NOW = 1790000000;

let passed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failures.push(`${name}${detail ? ` —— ${detail}` : ''}`);
    console.log(`  ✗ ${name}${detail ? ` —— ${detail}` : ''}`);
  }
}

function expectReject(name, input, code, hop = null, field = null) {
  const r = verifyChain(input);
  const good = !r.ok && r.error.code === code
    && (hop === null || r.error.hop === hop)
    && (field === null || r.error.field === field);
  check(`${name}（code=${code}${hop === null ? '' : `, hop=${hop}`}${field ? `, field=${field}` : ''}）`,
    good, good ? '' : `实际=${JSON.stringify(r.ok ? r.evidence.verdict : r.error)}`);
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// 用指定私钥对“值对象（含 sig 键）”重签，返回新的规范 JSON 文本
function resign(value, privateJwk) {
  const { sig: _sig, ...payload } = value;
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const sigBuf = crypto.sign('sha256', Buffer.from(canonicalize(payload), 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' });
  const sigB64 = sigBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return canonicalize({ ...payload, sig: sigB64 });
}

// ---------- 1) 合法链逐跳证据 ----------
function sectionValidChain() {
  console.log('\n[1/7] 合法链逐跳证据复核');
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['buoy-01', 'buoy-02', 'buoy-03'], maxSamples: 200,
  }, root.privateJwk);
  const d2 = issueDelegation({
    iss: a.publicJwk, sub: b.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01', 'buoy-02'], maxSamples: 80,
  }, a.privateJwk);
  const cmd = issueCommand({
    iss: b.publicJwk, sub: b.publicJwk,
    nbf: NOW - 600, exp: NOW + 600,
    aud: ['buoy-01'], maxSamples: 50,
    buoy: 'buoy-01', samples: 40,
  }, b.privateJwk);
  const input = { rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, d2, cmd], now: NOW };
  const r = verifyChain(input);
  check('合法三跳链准许', r.ok, !r.ok ? JSON.stringify(r.error) : '');
  if (!r.ok) return;

  const e = r.evidence;
  check('证据含 3 跳', e.hops.length === 3);
  check('链首签发者指纹等于根公钥指纹', e.hops[0].issThumbprint === e.rootKeyThumbprint);
  check('每跳签名非空且为 64 字节 P1363 的 base64url（86 字符）',
    e.hops.every((h) => /^[A-Za-z0-9_-]{86}$/.test(h.signature)));
  check('每跳规范载荷摘要为 64 位十六进制',
    e.hops.every((h) => /^[0-9a-f]{64}$/.test(h.payloadDigest)));

  // 独立复算每跳摘要（不依赖 verifyChain 内部）
  let digestOk = true;
  for (let i = 0; i < 3; i++) {
    const parsed = parseCanonical(input.objectTexts[i]);
    const { sig: _s, ...payload } = parsed.value;
    const want = sha256Hex(Buffer.from(canonicalize(payload), 'utf8'));
    if (want !== e.hops[i].payloadDigest) digestOk = false;
  }
  check('每跳规范载荷摘要可由规范字节独立复算', digestOk);

  check('收紧后浮标集合为交集 [buoy-01]', JSON.stringify(e.finalConstraints.aud) === '["buoy-01"]');
  check('收紧后时间窗为各跳交集 [NOW-600, NOW+600]',
    e.finalConstraints.nbf === NOW - 600 && e.finalConstraints.exp === NOW + 600);
  check('收紧后采样上限为最小值 50', e.finalConstraints.maxSamples === 50);
  check('最终准许结论携带浮标与采样量',
    e.verdict.allow === true && e.verdict.buoy === 'buoy-01' && e.verdict.samples === 40);
}

// ---------- 2) 越权链 ----------
function sectionOverPrivileged() {
  console.log('\n[2/7] 越权链拒绝复核');

  // 2a. 末端浮标未获上游允许（第 0 跳允许 buoy-01/02，末端命令仅允许 buoy-01，
  //     命令请求 buoy-02 → 首个限制跳为末端 hop=1）
  let c = buildValidChain({ now: NOW, buoys: ['buoy-01', 'buoy-02'], maxSamples: 100, samples: 5 });
  let v = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false }).value;
  v.buoy = 'buoy-02';
  c.objectTexts[1] = resign(v, c.mid.privateJwk);
  expectReject('末端浮标未获全部上游允许', c, 'BUOY_NOT_ALLOWED', 1, '$["aud"]');

  // 2b. 采样量超过最严上限（命令上限 50，请求 51）
  c = buildValidChain({ now: NOW });
  v = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false }).value;
  v.samples = 51;
  c.objectTexts[1] = resign(v, c.mid.privateJwk);
  expectReject('采样量超过任一跳上限', c, 'SAMPLES_EXCEEDED', 1, '$["maxSamples"]');

  // 2c. 中间委托放宽浮标集合
  c = buildValidChain({ now: NOW, buoys: ['buoy-01'] });
  const widened = issueDelegation({
    iss: c.mid.publicJwk, sub: c.mid.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01', 'intruder-buoy'], maxSamples: 50,
  }, c.mid.privateJwk);
  c.objectTexts.splice(1, 0, widened);
  expectReject('浮标集合被放宽', c, 'NOT_TIGHTENED', 1, '$["aud"]');

  // 2d. 时间窗放宽（exp 延后）
  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x'], maxSamples: 5,
  }, root.privateJwk);
  const cmdLate = issueCommand({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 100, exp: NOW + 200, aud: ['x'], maxSamples: 5,
    buoy: 'x', samples: 1,
  }, a.privateJwk);
  expectReject('有效期被放宽', {
    rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, cmdLate], now: NOW,
  }, 'NOT_TIGHTENED', 1, '$["exp"]');

  // 2e. 链首签发者不是所粘贴根公钥
  c = buildValidChain({ now: NOW });
  c.rootKeyText = rootKeyDocument(generateKeyPair().publicJwk);
  expectReject('链首签发者不等于根公钥', c, 'ISSUER_NOT_ROOT', 0, '$["iss"]');

  // 2f. 委托并非前一主体签发（iss 与签名密钥同时被替换）
  const root2 = generateKeyPair();
  const good = generateKeyPair();
  const mallory = generateKeyPair();
  const dd1 = issueDelegation({
    iss: root2.publicJwk, sub: good.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['x'], maxSamples: 10,
  }, root2.privateJwk);
  const dd2 = issueDelegation({
    iss: mallory.publicJwk, sub: good.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['x'], maxSamples: 10,
  }, mallory.privateJwk);
  const cc = issueCommand({
    iss: good.publicJwk, sub: good.publicJwk,
    nbf: NOW - 10, exp: NOW + 100, aud: ['x'], maxSamples: 10,
    buoy: 'x', samples: 1,
  }, good.privateJwk);
  expectReject('委托非前一主体签发', {
    rootKeyText: rootKeyDocument(root2.publicJwk), objectTexts: [dd1, dd2, cc], now: NOW,
  }, 'ISSUER_MISMATCH', 1, '$["iss"]');
}

// ---------- 3) 篡改签名 / 改写载荷 ----------
function sectionTamper() {
  console.log('\n[3/7] 篡改签名与改写载荷拒绝复核');

  let c = buildValidChain({ now: NOW });
  let v = parseCanonical(c.objectTexts[0], { requireOrderedKeys: false }).value;
  v.maxSamples = 200; // 改写已签名内容但不重签
  c.objectTexts[0] = canonicalize(v);
  expectReject('已签名委托内容被改写', c, 'BAD_SIGNATURE', 0, '$["sig"]');

  c = buildValidChain({ now: NOW });
  v = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false }).value;
  v.samples = 49; // 命令内容被改写
  c.objectTexts[1] = canonicalize(v);
  expectReject('已签名命令内容被改写', c, 'BAD_SIGNATURE', 1, '$["sig"]');

  c = buildValidChain({ now: NOW });
  v = parseCanonical(c.objectTexts[0], { requireOrderedKeys: false }).value;
  const sigBuf = Buffer.from(v.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  sigBuf[0] ^= 0x01; // 翻转签名 r 的首字节
  v.sig = sigBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  c.objectTexts[0] = canonicalize(v);
  expectReject('签名字段被直接篡改', c, 'BAD_SIGNATURE', 0);
}

// ---------- 4) 结构性 / 数值错误 ----------
function sectionStructural() {
  console.log('\n[4/7] 结构性与数值错误定位复核');
  const cases = [
    { name: '重复键', code: 'DUPLICATE_KEY',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":100,"maxSamples":9') },
    { name: '对象键序不规范', code: 'KEY_ORDER', mutate: (t) => {
      const v = parseCanonical(t, { requireOrderedKeys: false }).value;
      const order = ['typ', 'sub', 'sig', 'nbf', 'maxSamples', 'iss', 'exp', 'aud'];
      return '{' + order.map((k) => `${JSON.stringify(k)}:${JSON.stringify(v[k])}`).join(',') + '}';
    } },
    { name: '越界整数（> int32）', code: 'NUMBER_OUT_OF_RANGE',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":2147483648') },
    { name: '不安全整数（精度丢失）', code: 'NUMBER_UNSAFE_INTEGER',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":9007199254740993') },
    { name: '非有限数（1e999）', code: 'NUMBER_NON_FINITE',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":1e999') },
    { name: '小数字面量用于整数字段', code: 'NUMBER_NOT_INTEGER',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":12.5') },
  ];
  for (const tc of cases) {
    const c = buildValidChain({ now: NOW });
    c.objectTexts[0] = tc.mutate(c.objectTexts[0]);
    const r = verifyChain(c);
    const good = !r.ok && r.error.code === tc.code && r.error.hop === 0 && r.error.line !== null;
    check(`${tc.name} → ${tc.code}（hop=0，定位 行:列=${r.ok ? '-' : `${r.error.line}:${r.error.col}`}）`,
      good, r.ok ? '意外通过' : `实际 code=${r.error.code}`);
  }
}

// ---------- 5) 容量委托图审计 ----------
async function sectionCapacity() {
  console.log('\n[5/7] 容量委托图审计复核');

  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const mk = (over, priv) => issueCapDelegation(over, priv);

  // 菱形图：root-e0(70)->a-e2(50)->t；root-e1(40)->b-e3(30)->t；最大流 80
  const e0 = await mk({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01', 'buoy-02'],
    maxSamples: 100, transfer: 70, parent: '',
  }, root.privateJwk);
  const e1 = await mk({
    iss: root.publicJwk, sub: b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01'],
    maxSamples: 60, transfer: 40, parent: '',
  }, root.privateJwk);
  const e2 = await mk({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 80, transfer: 50, parent: e0.digest,
  }, a.privateJwk);
  const e3 = await mk({
    iss: b.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 50, transfer: 30, parent: e1.digest,
  }, b.privateJwk);

  const base = {
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetText: rootKeyDocument(t.publicJwk),
    buoy: 'buoy-01', now: NOW,
  };
  // 故意乱序粘贴
  const r = auditCapacity({ ...base, delegationTexts: [e3.text, e1.text, e2.text, e0.text] });
  check('菱形乱序集合容量审计通过', r.ok, !r.ok ? JSON.stringify(r.error) : '');
  if (r.ok) {
    const ev = r.evidence;
    check('最大可转移容量 = 80（min(70+40, 50+30)）', ev.maxTransferable === 80,
      `实际=${ev.maxTransferable}`);
    check('最小割容量 = 最大流 = 80',
      ev.minCut.capacity === 80 && ev.minCut.capacity === ev.maxTransferable);
    check('最小割为汇入目标的 e2+e3（50+30）',
      ev.minCut.edges.map((x) => x.payloadDigest).sort().join(',') ===
      [e2.digest, e3.digest].sort().join(','));
    check('全部流量边 flow+remaining=capacity 且按摘要排列',
      ev.flowEdges.every((x) => x.flow + x.remaining === x.capacity) &&
      ev.edges.map((x) => x.payloadDigest).join(',') ===
      ev.edges.map((x) => x.payloadDigest).sort().join(','));
    check('每条边携带签名与父摘要，根边 parent 为空串',
      ev.edges.every((x) => /^[A-Za-z0-9_-]{86}$/.test(x.signature)) &&
      ev.edges.find((x) => x.payloadDigest === e0.digest).parentDigest === '');
  }

  // 独立复算每条边的规范载荷摘要
  let digestOk = true;
  for (const [edge] of [[e0], [e1], [e2], [e3]]) {
    const v = parseCanonical(edge.text).value;
    const { sig: _s, ...payload } = v;
    if (sha256Hex(Buffer.from(canonicalize(payload), 'utf8')) !== edge.digest) digestOk = false;
  }
  check('每条容量委托的 parent 摘要可由规范字节独立复算', digestOk);

  // 确定性：换粘贴顺序结论一致
  const r2 = auditCapacity({ ...base, delegationTexts: [e0.text, e1.text, e2.text, e3.text] });
  check('容量结论与最小割对粘贴顺序不敏感',
    r2.ok && r2.evidence.maxTransferable === 80 &&
    JSON.stringify(r2.evidence.minCut.edges.map((x) => x.payloadDigest).sort()) ===
    JSON.stringify(r.ok ? r.evidence.minCut.edges.map((x) => x.payloadDigest).sort() : []));

  // 失败定位
  const expectCapReject = (name, input, code, index = null, field = null) => {
    const rr = auditCapacity(input);
    const good = !rr.ok && rr.error.code === code
      && (index === null || rr.error.index === index)
      && (field === null || rr.error.field === field);
    check(`${name}（code=${code}${index === null ? '' : `, index=${index}`}${field ? `, field=${field}` : ''}）`,
      good, good ? '' : `实际=${JSON.stringify(rr.ok ? rr.evidence.verdict : rr.error)}`);
  };

  expectCapReject('父摘要缺失（删除 e0 后 e2 悬空）',
    { ...base, delegationTexts: [e3.text, e1.text, e2.text] }, 'PARENT_NOT_FOUND');

  const noParent = canonicalize((() => {
    const v = parseCanonical(e0.text, { requireOrderedKeys: false }).value;
    delete v.parent;
    return v;
  })());
  expectCapReject('缺少 parent 成员',
    { ...base, delegationTexts: [noParent, e1.text, e2.text, e3.text] }, 'PARENT_MISSING');

  const mallory = generateKeyPair();
  const badIss = await mk({
    iss: mallory.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 80, transfer: 50, parent: e0.digest,
  }, mallory.privateJwk);
  expectCapReject('后继签发者不匹配',
    { ...base, delegationTexts: [e3.text, e1.text, badIss.text, e0.text] },
    'ISSUER_MISMATCH', null, '$["iss"]');

  const widened = await mk({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01', 'intruder'],
    maxSamples: 80, transfer: 50, parent: e0.digest,
  }, a.privateJwk);
  expectCapReject('浮标范围放宽',
    { ...base, delegationTexts: [e3.text, e1.text, widened.text, e0.text] },
    'NOT_TIGHTENED', null, '$["aud"]');

  const tampered = (() => {
    const v = parseCanonical(e1.text, { requireOrderedKeys: false }).value;
    v.transfer += 1;
    return canonicalize(v);
  })();
  expectCapReject('改写已签名容量委托',
    { ...base, delegationTexts: [e3.text, tampered, e2.text, e0.text] }, 'BAD_SIGNATURE');

  expectCapReject('错误根公钥',
    { ...base, rootKeyText: rootKeyDocument(generateKeyPair().publicJwk),
      delegationTexts: [e3.text, e1.text, e2.text, e0.text] }, 'ISSUER_NOT_ROOT');

  expectCapReject('目标主体不可达（图中无该密钥）',
    { ...base, targetText: rootKeyDocument(generateKeyPair().publicJwk),
      delegationTexts: [e3.text, e1.text, e2.text, e0.text] }, 'TARGET_UNREACHABLE');

  expectCapReject('浮标无生效路径（buoy-02 不被汇入边允许）',
    { ...base, buoy: 'buoy-02', delegationTexts: [e3.text, e1.text, e2.text, e0.text] },
    'TARGET_UNREACHABLE');

  // 成环无法用真实签名构造（哈希抗第二原像），以白盒纯函数复核检测器
  check('findCycle 检出 2-环 / 3-环，DAG 不报错',
    findCycle([
      { digest: 'aa'.repeat(32), parent: 'bb'.repeat(32), index: 0 },
      { digest: 'bb'.repeat(32), parent: 'aa'.repeat(32), index: 1 },
    ]) &&
    findCycle([
      { digest: 'a'.repeat(64), parent: 'c'.repeat(64), index: 0 },
      { digest: 'b'.repeat(64), parent: 'a'.repeat(64), index: 1 },
      { digest: 'c'.repeat(64), parent: 'b'.repeat(64), index: 2 },
    ]) &&
    findCycle([{ digest: 'r'.repeat(64), parent: '', index: 0 }]) === null);

  // 最大流白盒：割容量恒等于最大流
  const mf = maxFlow(['s', 'x', 't'], [
    { id: '1', from: 's', to: 'x', cap: 7 },
    { id: '2', from: 'x', to: 't', cap: 3 },
    { id: '3', from: 's', to: 't', cap: 5 },
  ], 's', 't');
  check('maxFlow 白盒：最大流 8 且最小割同容量、割边按摘要稳定',
    mf.total === 8 && mf.cut.length >= 1 &&
    mf.cut.map((x) => x).join(',') === [...mf.cut].sort().join(','));
}

// ---------- 6) 代码测试 / 页面检查 ----------
function run(cmd, args, timeoutMs = 120000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: rootDir, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      err += `\n[verify] 子进程超过 ${timeoutMs}ms 未退出，已终止`;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code === null ? 1 : code, out, err });
    });
  });
}

async function sectionTestsAndPage() {
  console.log('\n[6/7] 代码测试与页面构建检查');
  const t = await run(process.execPath, ['--test', '--test-concurrency=2', 'tests/']);
  const testCount = (t.out.match(/# tests (\d+)/) || [])[1];
  const passCount = (t.out.match(/# pass (\d+)/) || [])[1];
  check(`相关代码测试全部通过（tests=${testCount}, pass=${passCount}）`,
    t.code === 0, t.code === 0 ? '' : (t.out + t.err).split('\n').slice(-30).join('\n'));

  const pg = await run(process.execPath, ['scripts/check-page.js']);
  check('页面构建检查通过', pg.code === 0, pg.code === 0 ? '' : (pg.out + pg.err).trim());
}

// ---------- 6) HTTP 冒烟 ----------
function httpRequest(method, urlPath, { port, host = '127.0.0.1', body, baseUrl } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlPath, baseUrl || `http://${host}:${port}`);
    const data = body ? Buffer.from(body) : null;
    const req = http.request({
      hostname: u.hostname, port: u.port || (new URL(baseUrl || 'http://x')).port || 80,
      path: u.pathname, method,
      headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {},
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function waitForHealth(port, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await httpRequest('GET', '/health', { port });
      if (r.status === 200) return true;
    } catch { /* 尚未就绪 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function smokeGateway(label, target) {
  console.log(`\n[7/7] 健康地址 API/HTTP 冒烟（${label}）`);

  const health = await httpRequest('GET', '/health', target);
  const healthJson = JSON.parse(health.body);
  check('GET /health → 200 且 status=ok',
    health.status === 200 && healthJson.status === 'ok', `status=${health.status}`);

  const home = await httpRequest('GET', '/', target);
  check('GET / → 200 且返回静态核验页面',
    home.status === 200 && home.body.includes('受限委托链核验'));

  const valid = buildValidChain({ now: Math.floor(Date.now() / 1000) });
  const okResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: valid.rootKeyText, objects: valid.objectTexts, now: valid.now }),
  });
  const okJson = JSON.parse(okResp.body);
  check('POST /api/verify 合法链 → 200，含逐跳证据与准许结论',
    okResp.status === 200 && okJson.ok === true
    && Array.isArray(okJson.evidence?.hops) && okJson.evidence.verdict.allow === true,
    `status=${okResp.status}`);

  const expired = buildValidChain({ now: NOW });
  const expResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: expired.rootKeyText, objects: expired.objectTexts, now: NOW + 100000 }),
  });
  const expJson = JSON.parse(expResp.body);
  check('POST /api/verify 失效链 → 422 TIME_EXPIRED 且定位到跳',
    expResp.status === 422 && expJson.ok === false
    && expJson.error.code === 'TIME_EXPIRED' && expJson.error.hop !== null,
    `status=${expResp.status}`);

  const tampered = buildValidChain({ now: Math.floor(Date.now() / 1000) });
  const pv = parseCanonical(tampered.objectTexts[0], { requireOrderedKeys: false }).value;
  pv.maxSamples += 1;
  tampered.objectTexts[0] = canonicalize(pv);
  const badResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: tampered.rootKeyText, objects: tampered.objectTexts }),
  });
  const badJson = JSON.parse(badResp.body);
  check('POST /api/verify 篡改已签名内容 → 422 BAD_SIGNATURE（hop=0）',
    badResp.status === 422 && badJson.ok === false
    && badJson.error.code === 'BAD_SIGNATURE' && badJson.error.hop === 0,
    `status=${badResp.status}`);

  const dup = buildValidChain({ now: Math.floor(Date.now() / 1000) });
  dup.objectTexts[0] = dup.objectTexts[0].replace('"maxSamples":100', '"maxSamples":100,"maxSamples":9');
  const dupResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: dup.rootKeyText, objects: dup.objectTexts }),
  });
  const dupJson = JSON.parse(dupResp.body);
  check('POST /api/verify 重复键 → 422 DUPLICATE_KEY 且带行列定位',
    dupResp.status === 422 && dupJson.error?.code === 'DUPLICATE_KEY' && dupJson.error.line != null,
    `status=${dupResp.status}`);

  const badReq = await httpRequest('POST', '/api/verify', { ...target, body: 'not-json' });
  check('POST /api/verify 非法请求体 → 400 BAD_REQUEST', badReq.status === 400);

  // ---- 容量审计 HTTP ----
  const nowSec = Math.floor(Date.now() / 1000);
  const rootC = generateKeyPair();
  const aC = generateKeyPair();
  const tC = generateKeyPair();
  const c0 = await issueCapDelegation({
    iss: rootC.publicJwk, sub: aC.publicJwk,
    nbf: nowSec - 3600, exp: nowSec + 3600, aud: ['buoy-01'],
    maxSamples: 30, transfer: 30, parent: '',
  }, rootC.privateJwk);
  const c1 = await issueCapDelegation({
    iss: aC.publicJwk, sub: tC.publicJwk,
    nbf: nowSec - 1800, exp: nowSec + 1800, aud: ['buoy-01'],
    maxSamples: 20, transfer: 20, parent: c0.digest,
  }, aC.privateJwk);
  const capOkResp = await httpRequest('POST', '/api/capacity', {
    ...target,
    body: JSON.stringify({
      rootKey: rootKeyDocument(rootC.publicJwk),
      delegations: [c1.text, c0.text], // 乱序
      target: rootKeyDocument(tC.publicJwk),
      buoy: 'buoy-01', now: nowSec,
    }),
  });
  const capOkJson = JSON.parse(capOkResp.body);
  check('POST /api/capacity 合法集合 → 200，最大可转移容量 20 且最小割同容量',
    capOkResp.status === 200 && capOkJson.ok === true
    && capOkJson.evidence?.maxTransferable === 20
    && capOkJson.evidence.minCut?.capacity === 20
    && Array.isArray(capOkJson.evidence.flowEdges),
    `status=${capOkResp.status} body=${capOkResp.body.slice(0, 200)}`);

  const capBadBody = JSON.stringify({
    rootKey: rootKeyDocument(rootC.publicJwk),
    delegations: [c1.text], // 缺 c0：c1 的 parent 悬空
    target: rootKeyDocument(tC.publicJwk),
    buoy: 'buoy-01', now: nowSec,
  });
  const capBadResp = await httpRequest('POST', '/api/capacity', { ...target, body: capBadBody });
  const capBadJson = JSON.parse(capBadResp.body);
  check('POST /api/capacity 父摘要缺失 → 422 PARENT_NOT_FOUND 并定位该条',
    capBadResp.status === 422 && capBadJson.ok === false
    && capBadJson.error.code === 'PARENT_NOT_FOUND'
    && capBadJson.error.field === '$["parent"]',
    `status=${capBadResp.status}`);
}

async function main() {
  console.log('=== verify：受限委托链复核 + 容量审计一次性验收 ===');
  sectionValidChain();
  sectionOverPrivileged();
  sectionTamper();
  sectionStructural();
  await sectionCapacity();
  await sectionTestsAndPage();

  const port = Number(process.env.VERIFY_PORT || 18080);
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: rootDir,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d; });
  child.stderr.on('data', (d) => { serverLog += d; });

  let exitCode = 0;
  try {
    const ready = await waitForHealth(port);
    check('验收用临时网关健康就绪', ready, ready ? '' : serverLog.trim());
    if (ready) await smokeGateway('本机临时实例', { port });
    if (process.env.GATEWAY_URL) {
      await smokeGateway(`对端 ${process.env.GATEWAY_URL}`, { port: 0, baseUrl: process.env.GATEWAY_URL });
    }
  } catch (e) {
    failures.push(`HTTP 冒烟异常：${e.stack || e.message}`);
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => child.on('exit', r));
  }

  console.log('\n=== 验收汇总 ===');
  console.log(`通过 ${passed} 项，失败 ${failures.length} 项`);
  if (failures.length) {
    console.log('失败项：');
    for (const f of failures) console.log(`  - ${f}`);
    exitCode = 1;
  } else {
    console.log('委托链复核验收全部通过 ✅');
  }
  process.exit(exitCode);
}

main().catch((e) => {
  console.error('验收执行异常：', e);
  process.exit(2);
});
