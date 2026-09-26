'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyChain } from '../src/chain.js';
import { canonicalize, parseCanonical } from '../src/canonical.js';
import {
  generateKeyPair,
  issueDelegation,
  issueCommand,
  rootKeyDocument,
  buildValidChain,
} from '../src/sign.js';

const NOW = 1790000000;

function chain3() {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['buoy-01', 'buoy-02'], maxSamples: 100,
  }, root.privateJwk);
  const d2 = issueDelegation({
    iss: a.publicJwk, sub: b.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01'], maxSamples: 60,
  }, a.privateJwk);
  const cmd = issueCommand({
    iss: b.publicJwk, sub: b.publicJwk,
    nbf: NOW - 900, exp: NOW + 900,
    aud: ['buoy-01'], maxSamples: 60,
    buoy: 'buoy-01', samples: 40,
  }, b.privateJwk);
  return {
    root, a, b,
    rootKeyText: rootKeyDocument(root.publicJwk),
    objectTexts: [d1, d2, cmd],
    now: NOW,
  };
}

test('合法三跳链：逐跳证据、收紧约束、准许结论', () => {
  const c = chain3();
  const r = verifyChain(c);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  const { evidence } = r;
  assert.equal(evidence.hops.length, 3);
  assert.equal(evidence.verdict.allow, true);
  assert.equal(evidence.verdict.buoy, 'buoy-01');
  // 收紧汇总
  assert.deepEqual(evidence.finalConstraints.aud, ['buoy-01']);
  assert.equal(evidence.finalConstraints.maxSamples, 60);
  assert.equal(evidence.finalConstraints.nbf, NOW - 900);
  assert.equal(evidence.finalConstraints.exp, NOW + 900);
  // 每跳都有签名与规范载荷摘要（64 位十六进制）
  for (const h of evidence.hops) {
    assert.match(h.payloadDigest, /^[0-9a-f]{64}$/);
    assert.ok(h.signature.length > 0);
  }
  // 链首签发者指纹 == 根公钥指纹
  assert.equal(evidence.hops[0].issThumbprint, evidence.rootKeyThumbprint);
});

test('合法链辅助构造器（默认链）', () => {
  const c = buildValidChain({ now: NOW });
  const r = verifyChain(c);
  assert.equal(r.ok, true, JSON.stringify(r.error));
});

test('链首签发者不等于根公钥：拒绝并定位 hop=0 iss', () => {
  const c = chain3();
  const other = generateKeyPair();
  c.rootKeyText = rootKeyDocument(other.publicJwk); // 粘贴了错误的根公钥
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'ISSUER_NOT_ROOT');
  assert.equal(r.error.hop, 0);
  assert.equal(r.error.field, '$["iss"]');
});

test('委托非前一主体签发：ISSUER_MISMATCH 定位到该跳', () => {
  const c = chain3();
  const mallory = generateKeyPair();
  // 用 mallory 重签第 2 跳（iss 仍声称是 a）
  const d2Tampered = issueDelegation({
    iss: c.a.publicJwk, sub: c.b.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01'], maxSamples: 60,
  }, mallory.privateJwk);
  c.objectTexts[1] = d2Tampered;
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  // 签名先于签发关系核验：用 mallory 签的名无法用 iss(a) 验证
  assert.equal(r.error.code, 'BAD_SIGNATURE');
  assert.equal(r.error.hop, 1);
});

test('iss 与签名密钥都被换成攻击者：先过签名，再被 ISSUER_MISMATCH 拦截', () => {
  const c = chain3();
  const mallory = generateKeyPair();
  const d2Tampered = issueDelegation({
    iss: mallory.publicJwk, sub: c.b.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01'], maxSamples: 60,
  }, mallory.privateJwk);
  c.objectTexts[1] = d2Tampered;
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'ISSUER_MISMATCH');
  assert.equal(r.error.hop, 1);
  assert.equal(r.error.field, '$["iss"]');
});

test('时间窗放宽（exp 延后）：NOT_TIGHTENED 定位 exp', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 100,
    aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  const d2 = issueDelegation({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 200, // 延后
    aud: ['x'], maxSamples: 10,
  }, a.privateJwk);
  const cmd = issueCommand({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 10, exp: NOW + 50,
    aud: ['x'], maxSamples: 10, buoy: 'x', samples: 1,
  }, a.privateJwk);
  const r = verifyChain({ rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, d2, cmd], now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.hop, 1);
  assert.equal(r.error.field, '$["exp"]');
});

test('浮标集合放宽：NOT_TIGHTENED 定位 aud 并指出新增项', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  const d2 = issueDelegation({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['x', 'y'], maxSamples: 10,
  }, a.privateJwk);
  const cmd = issueCommand({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 10, exp: NOW + 3600,
    aud: ['x'], maxSamples: 10, buoy: 'x', samples: 1,
  }, a.privateJwk);
  const r = verifyChain({ rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, d2, cmd], now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.field, '$["aud"]');
  assert.match(r.error.message, /y/);
});

test('采样上限放宽：NOT_TIGHTENED 定位 maxSamples', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  const cmd = issueCommand({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 10, exp: NOW + 3600,
    aud: ['x'], maxSamples: 11, buoy: 'x', samples: 1,
  }, a.privateJwk);
  const r = verifyChain({ rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, cmd], now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.field, '$["maxSamples"]');
});

test('末端浮标未获上游允许：BUOY_NOT_ALLOWED 定位首个限制跳', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['x', 'z'], maxSamples: 10,
  }, root.privateJwk);
  // 命令自身 aud 含 z，但末端 buoy 指向 z——d1 允许 z；
  // 构造真正违规：命令 aud=['x'] 而 buoy='z'（命令自身即首个不允许跳）
  const cmd = issueCommand({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 10, exp: NOW + 3600,
    aud: ['x'], maxSamples: 10, buoy: 'z', samples: 1,
  }, a.privateJwk);
  const r = verifyChain({ rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, cmd], now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BUOY_NOT_ALLOWED');
  assert.equal(r.error.hop, 1);
});

test('采样量超过上游任一跳上限：SAMPLES_EXCEEDED', () => {
  const c = chain3(); // 最终上限 60
  const { b } = c;
  const cmd = issueCommand({
    iss: b.publicJwk, sub: b.publicJwk,
    nbf: NOW - 900, exp: NOW + 900,
    aud: ['buoy-01'], maxSamples: 60,
    buoy: 'buoy-01', samples: 61,
  }, b.privateJwk);
  c.objectTexts[2] = cmd;
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SAMPLES_EXCEEDED');
  assert.match(r.error.message, /61/);
});

test('过期链：TIME_EXPIRED', () => {
  const c = buildValidChain({ now: NOW });
  const r = verifyChain({ ...c, now: NOW + 7200 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TIME_EXPIRED');
});

test('未生效链：TIME_NOT_YET_VALID', () => {
  const c = buildValidChain({ now: NOW });
  const r = verifyChain({ ...c, now: NOW - 7200 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TIME_NOT_YET_VALID');
});

test('已签名内容被改写：BAD_SIGNATURE（规范字节变化）', () => {
  const c = buildValidChain({ now: NOW });
  const parsed = parseCanonical(c.objectTexts[0], { requireOrderedKeys: false });
  parsed.value.maxSamples = 999;
  c.objectTexts[0] = canonicalize(parsed.value);
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
  assert.equal(r.error.hop, 0);
});

test('签名被直接篡改：BAD_SIGNATURE', () => {
  const c = buildValidChain({ now: NOW });
  const parsed = parseCanonical(c.objectTexts[0], { requireOrderedKeys: false });
  // 解码 P1363 签名并翻转 r 的首字节，再按规范 base64url 编码
  const sigBuf = Buffer.from(parsed.value.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  sigBuf[0] ^= 0x01;
  parsed.value.sig = sigBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  c.objectTexts[0] = canonicalize(parsed.value);
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
});

test('输入层异常：重复键 / 键序不规范 / 越界整数 / 不安全整数 均可定位', () => {
  const c = buildValidChain({ now: NOW });
  const cases = [
    { mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":100,"maxSamples":9', 1), code: 'DUPLICATE_KEY' },
    { mutate: (t) => reorderTopKey(t), code: 'KEY_ORDER' },
    { mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":2147483648'), code: 'NUMBER_OUT_OF_RANGE' },
    { mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":9007199254740993'), code: 'NUMBER_UNSAFE_INTEGER' },
  ];
  for (const tc of cases) {
    const cc = buildValidChain({ now: NOW });
    cc.objectTexts[0] = tc.mutate(cc.objectTexts[0]);
    const r = verifyChain(cc);
    assert.equal(r.ok, false, `case ${tc.code} 应被拒绝`);
    assert.equal(r.error.code, tc.code);
    assert.notEqual(r.error.line, null, `${tc.code} 应带行/列定位`);
  }
});

function reorderTopKey(text) {
  // 将首成员 aud 与 exp 交换（破坏 JCS 键序）
  const p = parseCanonical(text, { requireOrderedKeys: false });
  const v = p.value;
  // 手工拼一个乱序文本：取 exp 放最前
  const { aud, ...rest } = v;
  return JSON.stringify({ exp: rest.exp, aud: v.aud, iss: rest.iss, maxSamples: rest.maxSamples,
    nbf: rest.nbf, sig: rest.sig, sub: rest.sub, typ: rest.typ });
}

test('非 P-256 JWK：SCHEMA 定位 crv', () => {
  const c = buildValidChain({ now: NOW });
  const p = parseCanonical(c.rootKeyText, { requireOrderedKeys: false });
  p.value.crv = 'P-384';
  c.rootKeyText = canonicalize(p.value);
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
});

test('空链 / 末端非 command 被拒绝', () => {
  const c = buildValidChain({ now: NOW });
  let r = verifyChain({ rootKeyText: c.rootKeyText, objectTexts: [], now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');

  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  r = verifyChain({ rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1], now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
});

test('验签使用规范字节：键序被重排（且语义不变）同样导致签名失败', () => {
  const c = buildValidChain({ now: NOW });
  // 原文是规范字节；改成 JSON.stringify 默认顺序（插入顺序）打乱
  const p = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false });
  const reordered = JSON.stringify(p.value); // 按枚举顺序，与 JCS 相同——无效用例保护
  // 直接手工构造乱序：sig 提前
  const v = p.value;
  const entries = [['sig', v.sig], ['aud', v.aud], ['buoy', v.buoy], ['exp', v.exp],
    ['iss', v.iss], ['maxSamples', v.maxSamples], ['nbf', v.nbf], ['samples', v.samples],
    ['sub', v.sub], ['typ', v.typ]];
  c.objectTexts[1] = '{' + entries.map(([k, val]) => `${JSON.stringify(k)}:${JSON.stringify(val)}`).join(',') + '}';
  assert.notEqual(c.objectTexts[1], reordered);
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'KEY_ORDER');
});
