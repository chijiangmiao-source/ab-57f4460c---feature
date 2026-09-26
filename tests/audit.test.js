'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { auditCapacity, detectCycle } from '../src/audit.js';
import { canonicalize, parseCanonical } from '../src/canonical.js';
import {
  generateKeyPair,
  issueCapacityDelegation,
  issueDelegation,
  rootKeyDocument,
  rootThumbprint,
} from '../src/sign.js';

const NOW = 1790000000;

function resignCapacity(value, privateJwk) {
  const { sig: _s, ...payload } = value;
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const sigBuf = crypto.sign('sha256', Buffer.from(canonicalize(payload), 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' });
  const sig = sigBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return canonicalize({ ...payload, sig });
}

// root -> a -> t 的基础链（aud b1/b2 收紧为 b1）
function linearGraph() {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const t = generateKeyPair();
  const rp = rootThumbprint(root.publicJwk);
  const d1 = issueCapacityDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1', 'b2'], maxSamples: 100, transfer: 80, parent: rp,
  }, root.privateJwk);
  const d2 = issueCapacityDelegation({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['b1'], maxSamples: 60, transfer: 60, parent: d1,
  }, a.privateJwk);
  return {
    root, a, t, rp, d1, d2,
    input: {
      rootKeyText: rootKeyDocument(root.publicJwk),
      delegationTexts: [d2, d1], // 故意乱序
      targetKeyText: rootKeyDocument(t.publicJwk),
      buoy: 'b1', now: NOW,
    },
  };
}

// 菱形汇聚图：root -60-> a -50-> t；root -40-> b -40-> t
function diamondGraph({ da = 50, db = 40, ea = 60, eb = 40 } = {}) {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const rp = rootThumbprint(root.publicJwk);
  const d1 = issueCapacityDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1'], maxSamples: 100, transfer: ea, parent: rp,
  }, root.privateJwk);
  const d2 = issueCapacityDelegation({
    iss: root.publicJwk, sub: b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1'], maxSamples: 100, transfer: eb, parent: rp,
  }, root.privateJwk);
  const d3 = issueCapacityDelegation({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['b1'], maxSamples: 50, transfer: da, parent: d1,
  }, a.privateJwk);
  const d4 = issueCapacityDelegation({
    iss: b.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['b1'], maxSamples: 40, transfer: db, parent: d2,
  }, b.privateJwk);
  return {
    root, a, b, t, d1, d2, d3, d4,
    input: {
      rootKeyText: rootKeyDocument(root.publicJwk),
      delegationTexts: [d4, d2, d3, d1], // 乱序
      targetKeyText: rootKeyDocument(t.publicJwk),
      buoy: 'b1', now: NOW,
    },
  };
}

test('线性图：乱序输入仍按 parent 接图，最大可转移容量 = 链路最窄值 60', () => {
  const g = linearGraph();
  const r = auditCapacity(g.input);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.audit.verdict.maxTransferable, 60);
  assert.equal(r.audit.minCut.capacity, 60);
  assert.equal(r.audit.delegationCount, 2);
  // 流量边按载荷摘要升序
  const digests = r.audit.flowEdges.map((e) => e.payloadDigest);
  assert.deepEqual(digests, [...digests].sort());
  // 每条边实流守恒且不超 transfer
  for (const e of r.audit.flowEdges) {
    assert.ok(e.flow <= e.transfer);
    assert.equal(e.flow + e.residual, e.transfer);
  }
  // 顶点按摘要排列
  const vd = r.audit.vertices.map((v) => v.payloadDigest);
  assert.deepEqual(vd, [...vd].sort());
  const targetV = r.audit.vertices.find((v) => v.isTarget);
  assert.equal(targetV.inflow, 60);
  assert.equal(targetV.remaining, 0);
});

test('菱形汇聚：两条路径容量相加（50+40=90），最小割为两条入目标边', () => {
  const g = diamondGraph();
  const r = auditCapacity(g.input);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.audit.verdict.maxTransferable, 90);
  assert.equal(r.audit.minCut.capacity, 90);
  assert.equal(r.audit.minCut.edges.length, 2);
  assert.ok(r.audit.minCut.edges.every((e) => e.type === 'delegation'));
});

test('窄收口边：入目标委托 transfer 与 maxSamples 同时收窄到 30 时进最小割', () => {
  // 路径 a：d1 边 transfer=60，d3 边 transfer=30 且 d3.maxSamples=30
  // → a 路径最多 30，b 路径 40，总计 70；割中存在容量 30 的收口边
  const g = diamondGraph();
  const v = parseCanonical(g.d3, { requireOrderedKeys: false }).value;
  v.maxSamples = 30;
  v.transfer = 30;
  const d3t = resignCapacity(v, g.a.privateJwk);
  g.input.delegationTexts = [g.d4, g.d2, d3t, g.d1];
  const r = auditCapacity(g.input);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.audit.verdict.maxTransferable, 70);
  assert.ok(r.audit.minCut.edges.some((e) => e.capacity === 30));
  assert.equal(r.audit.minCut.capacity, 70);
});

test('目标主体自身 maxSamples 为最终收口', () => {
  const g = diamondGraph({ da: 50, db: 40 });
  // 目标 t 同时是两份委托的主体；把两条入目标委托的主体上限都收紧到 20
  for (const [key, priv] of [['d3', g.a.privateJwk], ['d4', g.b.privateJwk]]) {
    const v = parseCanonical(g[key], { requireOrderedKeys: false }).value;
    v.maxSamples = 20;
    v.transfer = Math.min(v.transfer, 20);
    g[key] = resignCapacity(v, priv);
  }
  g.input.delegationTexts = [g.d4, g.d2, g.d3, g.d1];
  const r = auditCapacity(g.input);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.audit.verdict.maxTransferable, 40);
});

test('失效边（时间窗外 / 不含目标浮标）被过滤，另一条路径仍可达', () => {
  const g = diamondGraph();
  // 让 d3（a->t 路径）在 now 已过期：时间窗必须仍是父窗 [NOW-3600,NOW+3600]
  // 的收紧子集，故取 [NOW-3000, NOW-500]。
  const d3expired = issueCapacityDelegation({
    iss: g.a.publicJwk, sub: g.t.publicJwk,
    nbf: NOW - 3000, exp: NOW - 500,
    aud: ['b1'], maxSamples: 50, transfer: 50, parent: g.d1,
  }, g.a.privateJwk);
  g.input.delegationTexts = [g.d4, g.d2, d3expired, g.d1];
  const r = auditCapacity(g.input);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.audit.verdict.maxTransferable, 40); // 仅 b 路径
  const expiredV = r.audit.vertices.find((v) => v.exp === NOW - 500);
  assert.equal(expiredV.status, 'inactive');
  assert.equal(expiredV.remaining, null);
  assert.match(expiredV.inactiveReason, /expired/);
  assert.equal(expiredV.reachable, false);
  // 有效顶点仍守恒：b 路径实流 40
  const live = r.audit.flowEdges.filter((e) => e.flow > 0);
  assert.ok(live.every((e) => e.payloadDigest !== expiredV.payloadDigest));
});

test('所有路径失效：TARGET_UNREACHABLE（不返回容量结论）', () => {
  const g = linearGraph();
  const r = auditCapacity({ ...g.input, now: NOW + 99999 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
  assert.equal(r.error.node, 'target');
});

test('目标浮标不在任何委托 aud 内：TARGET_UNREACHABLE', () => {
  const g = linearGraph();
  const r = auditCapacity({ ...g.input, buoy: 'b3' });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
});

test('目标主体与图完全无关：TARGET_UNREACHABLE', () => {
  const g = linearGraph();
  const stranger = generateKeyPair();
  const r = auditCapacity({
    ...g.input,
    targetKeyText: rootKeyDocument(stranger.publicJwk),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
});

test('父摘要缺失：PARENT_NOT_FOUND 定位到该委托', () => {
  const g = linearGraph();
  const v = parseCanonical(g.d2, { requireOrderedKeys: false }).value;
  v.parent = '0'.repeat(64);
  const d2bad = resignCapacity(v, g.a.privateJwk);
  const r = auditCapacity({ ...g.input, delegationTexts: [d2bad, g.d1] });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'PARENT_NOT_FOUND');
  assert.match(r.error.node, /^[0-9a-f]{64}$/);
  assert.equal(r.error.field, '$["parent"]');
});

test('后继签发者与父委托主体不匹配：SUCCESSOR_ISSUER_MISMATCH', () => {
  const g = linearGraph();
  const mallory = generateKeyPair();
  const d2bad = issueCapacityDelegation({
    iss: mallory.publicJwk, sub: g.t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['b1'], maxSamples: 60, transfer: 60, parent: g.d1,
  }, mallory.privateJwk);
  const r = auditCapacity({ ...g.input, delegationTexts: [d2bad, g.d1] });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SUCCESSOR_ISSUER_MISMATCH');
  assert.equal(r.error.field, '$["iss"]');
});

test('根出边签发者不是根：SUCCESSOR_ISSUER_MISMATCH', () => {
  const g = linearGraph();
  const mallory = generateKeyPair();
  const d1bad = issueCapacityDelegation({
    iss: mallory.publicJwk, sub: g.a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1', 'b2'], maxSamples: 100, transfer: 80, parent: g.rp,
  }, mallory.privateJwk);
  // 仅提交这一条根出边委托，目标主体取其 sub（a），在签发关系核验处被拒
  const r = auditCapacity({
    rootKeyText: rootKeyDocument(g.root.publicJwk),
    delegationTexts: [d1bad],
    targetKeyText: rootKeyDocument(g.a.publicJwk),
    buoy: 'b1', now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SUCCESSOR_ISSUER_MISMATCH');
});

test('范围放宽：时间窗延后 / aud 新增 / maxSamples 增大 均 SCOPE_WIDENED', () => {
  const g = linearGraph();
  const variants = [
    { exp: NOW + 4000 },                 // 时间窗放宽（父 exp=NOW+3600）
    { aud: ['b1', 'b3'] },               // 浮标集合放宽（父 aud=['b1','b2']）
    { maxSamples: 200, transfer: 60 },   // 上限放宽（父 maxSamples=100）
  ];
  for (const patch of variants) {
    const d2bad = issueCapacityDelegation({
      iss: g.a.publicJwk, sub: g.t.publicJwk,
      nbf: NOW - 1800, exp: NOW + 1800,
      aud: ['b1'], maxSamples: 60, transfer: 60, parent: g.d1,
      ...patch,
    }, g.a.privateJwk);
    const r = auditCapacity({ ...g.input, delegationTexts: [d2bad, g.d1] });
    assert.equal(r.ok, false, JSON.stringify(patch));
    assert.equal(r.error.code, 'SCOPE_WIDENED', JSON.stringify(patch));
  }
});

test('篡改签名 / 改写已签名载荷：BAD_SIGNATURE 定位到摘要', () => {
  const g = linearGraph();
  const v = parseCanonical(g.d1, { requireOrderedKeys: false }).value;
  v.maxSamples = 99;
  const d1tampered = canonicalize(v);
  const r = auditCapacity({ ...g.input, delegationTexts: [g.d2, d1tampered] });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
  assert.equal(r.error.field, '$["sig"]');
  assert.match(r.error.node, /^[0-9a-f]{64}$/);
});

test('重复委托（同规范载荷摘要）：DUPLICATE_DELEGATION', () => {
  const g = linearGraph();
  const r = auditCapacity({
    ...g.input,
    delegationTexts: [g.d1, g.d2, g.d1],
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'DUPLICATE_DELEGATION');
});

test('结构错误：非 delegation / 缺 parent / transfer>maxSamples / 键序不规范 均拒绝', () => {
  const g = linearGraph();
  // typ 不是 delegation（用普通委托文本，无 parent/transfer）
  const plain = issueDelegation({
    iss: g.root.publicJwk, sub: g.a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1'], maxSamples: 10,
  }, g.root.privateJwk);
  let r = auditCapacity({ ...g.input, delegationTexts: [plain, g.d2] });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');

  // transfer > maxSamples
  const bad = issueCapacityDelegation({
    iss: g.root.publicJwk, sub: g.a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1'], maxSamples: 10, transfer: 11, parent: g.rp,
  }, g.root.privateJwk);
  r = auditCapacity({ ...g.input, delegationTexts: [bad, g.d2] });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
  assert.equal(r.error.field, '$["transfer"]');

  // 键序不规范
  const parsed = parseCanonical(g.d1, { requireOrderedKeys: false }).value;
  const reordered = '{' + Object.entries(parsed).reverse()
    .map(([k, val]) => `${JSON.stringify(k)}:${JSON.stringify(val)}`).join(',') + '}';
  r = auditCapacity({ ...g.input, delegationTexts: [reordered, g.d2] });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'KEY_ORDER');
});

test('目标主体就是根：TARGET_IS_ROOT', () => {
  const g = linearGraph();
  const r = auditCapacity({
    ...g.input,
    targetKeyText: g.input.rootKeyText,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_IS_ROOT');
});

test('detectCycle：DAG 无环、含环时给出环上一条边', () => {
  const okGraph = detectCycle(3, [{ from: 0, to: 1 }, { from: 1, to: 2 }, { from: 0, to: 2 }]);
  assert.equal(okGraph.acyclic, true);
  assert.deepEqual(okGraph.topo, [0, 1, 2]);

  // 成环无法用真实签名构造（parent 摘要是循环固定点），故直接对纯函数覆盖
  const cycGraph = detectCycle(3, [
    { from: 0, to: 1, node: { digest: 'e01' } },
    { from: 1, to: 2, node: { digest: 'e12' } },
    { from: 2, to: 1, node: { digest: 'e21' } },
  ]);
  assert.equal(cycGraph.acyclic, false);
  assert.ok(['e12', 'e21'].includes(cycGraph.cycleEdge.node.digest));
});

test('同一主体经多条并行边汇聚：容量可叠加但受顶点上限约束', () => {
  // root 对 a 发两条并行委托（不同 parent 同指根、不同摘要），a 对 t 转授
  const root = generateKeyPair();
  const a = generateKeyPair();
  const t = generateKeyPair();
  const rp = rootThumbprint(root.publicJwk);
  const e1 = issueCapacityDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1'], maxSamples: 60, transfer: 60, parent: rp,
  }, root.privateJwk);
  const e2 = issueCapacityDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['b1'], maxSamples: 40, transfer: 40, parent: rp,
  }, root.privateJwk);
  // a 的顶点上限取其【任一】委托的 maxSamples——两个委托顶点是不同节点。
  // 建两条 a->t：分别挂在 e1/e2 之下（a 用各自载荷继续转授）
  const c1 = issueCapacityDelegation({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['b1'], maxSamples: 60, transfer: 60, parent: e1,
  }, a.privateJwk);
  const c2 = issueCapacityDelegation({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['b1'], maxSamples: 40, transfer: 40, parent: e2,
  }, a.privateJwk);
  const r = auditCapacity({
    rootKeyText: rootKeyDocument(root.publicJwk),
    delegationTexts: [c2, e2, c1, e1],
    targetKeyText: rootKeyDocument(t.publicJwk),
    buoy: 'b1', now: NOW,
  });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.audit.verdict.maxTransferable, 100);
});
