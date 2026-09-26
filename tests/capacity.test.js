'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCanonical, canonicalize } from '../src/canonical.js';
import { auditCapacity, findCycle, maxFlow } from '../src/capacity.js';
import {
  generateKeyPair,
  issueCapDelegation,
  rootKeyDocument,
} from '../src/sign.js';

const NOW = 1790000000;

function cap(over, priv) {
  return issueCapDelegation(over, priv);
}

// 菱形图：root -e0(transfer 70)-> a -e2(transfer 50)-> t
//                  \-e1(transfer 40)-> b -e3(transfer 30)->/
// 最大流 = 80。e 为 [e0,e1,e2,e3]。
async function diamond() {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const e0 = await cap({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01', 'buoy-02'],
    maxSamples: 100, transfer: 70, parent: '',
  }, root.privateJwk);
  const e1 = await cap({
    iss: root.publicJwk, sub: b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01'],
    maxSamples: 60, transfer: 40, parent: '',
  }, root.privateJwk);
  const e2 = await cap({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 80, transfer: 50, parent: e0.digest,
  }, a.privateJwk);
  const e3 = await cap({
    iss: b.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 50, transfer: 30, parent: e1.digest,
  }, b.privateJwk);
  return {
    root, a, b, t, e: [e0, e1, e2, e3],
    input: {
      rootKeyText: rootKeyDocument(root.publicJwk),
      delegationTexts: [e3.text, e1.text, e2.text, e0.text], // 故意乱序
      targetText: rootKeyDocument(t.publicJwk),
      buoy: 'buoy-01', now: NOW,
    },
  };
}

// 去掉 sig 后改 payload，再用 canonicalize 重组（键序自动 JCS），签名即失效
function mutatePayload(text, mut) {
  const v = parseCanonical(text, { requireOrderedKeys: false }).value;
  mut(v);
  return canonicalize(v);
}

test('菱形图（乱序输入）：最大可转移容量与最小割精确相等，证据按摘要排列', async () => {
  const g = await diamond();
  const r = auditCapacity(g.input);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  const ev = r.evidence;
  assert.equal(ev.maxTransferable, 80);
  assert.equal(ev.minCut.capacity, 80);

  // 流量守恒：0 <= flow <= capacity，flow + remaining = capacity
  for (const e of ev.flowEdges) {
    assert.ok(e.flow >= 0 && e.flow <= e.capacity);
    assert.equal(e.flow + e.remaining, e.capacity);
  }
  // 瓶颈在汇入目标的两条边：e2(50) + e3(30) 全部饱和
  const byDigest = new Map(ev.flowEdges.map((e) => [e.payloadDigest, e]));
  assert.equal(byDigest.get(g.e[2].digest).flow, 50);
  assert.equal(byDigest.get(g.e[3].digest).flow, 30);
  assert.deepEqual(ev.minCut.edges.map((e) => e.payloadDigest).sort(),
    [g.e[2].digest, g.e[3].digest].sort());

  // 证据列表按规范载荷摘要稳定排列，与粘贴顺序无关
  const digests = ev.edges.map((e) => e.payloadDigest);
  assert.deepEqual(digests, [...digests].sort());
  // 粘贴序号映射正确：乱序输入 [e3,e1,e2,e0]（序号 0..3），
  // 证据按摘要排序后序号顺序应由各边摘要排序结果决定
  const indexByDigest = new Map([g.e[3], g.e[1], g.e[2], g.e[0]]
    .map((edge, i) => [edge.digest, i]));
  const expectedIndices = [...digests].sort()
    .map((d) => indexByDigest.get(d));
  assert.deepEqual(ev.edges.map((e) => e.inputIndex), expectedIndices);
});

test('同一图对不同粘贴顺序给出完全一致的容量结论（确定性）', async () => {
  const g = await diamond();
  const r1 = auditCapacity(g.input);
  const r2 = auditCapacity({
    ...g.input,
    delegationTexts: [g.e[0].text, g.e[1].text, g.e[2].text, g.e[3].text],
  });
  const canon = (ev) => ({
    max: ev.maxTransferable,
    flow: ev.flowEdges.map((e) => [e.payloadDigest, e.flow]).sort(),
    cut: ev.minCut.edges.map((e) => e.payloadDigest).sort(),
  });
  assert.deepEqual(canon(r1.evidence), canon(r2.evidence));
});

test('根侧瓶颈：最小割容量恒等于最大流，割边流量贡献守恒', async () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const e0 = await cap({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['x'],
    maxSamples: 5, transfer: 5, parent: '',
  }, root.privateJwk);
  const e1 = await cap({
    iss: root.publicJwk, sub: b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['x'],
    maxSamples: 100, transfer: 100, parent: '',
  }, root.privateJwk);
  const e2 = await cap({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['x'],
    maxSamples: 5, transfer: 5, parent: e0.digest,
  }, a.privateJwk);
  const e3 = await cap({
    iss: b.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['x'],
    maxSamples: 100, transfer: 100, parent: e1.digest,
  }, b.privateJwk);
  const r = auditCapacity({
    rootKeyText: rootKeyDocument(root.publicJwk),
    delegationTexts: [e0.text, e1.text, e2.text, e3.text],
    targetText: rootKeyDocument(t.publicJwk), buoy: 'x', now: NOW,
  });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.maxTransferable, 105);
  assert.equal(r.evidence.minCut.capacity, 105);
  assert.equal(
    r.evidence.minCut.edges.reduce((s, e) => s + e.transfer, 0), 105);
});

test('父摘要在集合中缺失：PARENT_NOT_FOUND 定位悬空的该条', async () => {
  const g = await diamond();
  const r = auditCapacity({
    ...g.input,
    delegationTexts: g.input.delegationTexts.filter((x) => x !== g.e[0].text), // 去掉 e0
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'PARENT_NOT_FOUND');
  assert.equal(r.error.field, '$["parent"]');
  assert.equal(g.input.delegationTexts[r.error.index], g.e[2].text); // e2.parent=e0 悬空
});

test('缺少 parent 成员：PARENT_MISSING', async () => {
  const g = await diamond();
  const bad = mutatePayload(g.e[0].text, (v) => { delete v.parent; });
  const r = auditCapacity({
    ...g.input,
    delegationTexts: g.input.delegationTexts.map((x) => (x === g.e[0].text ? bad : x)),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'PARENT_MISSING');
});

test('后继签发者不匹配：iss 与签名密钥同时替换 → ISSUER_MISMATCH', async () => {
  const g = await diamond();
  const mallory = generateKeyPair();
  const bad = await cap({
    iss: mallory.publicJwk, sub: g.t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 80, transfer: 50, parent: g.e[0].digest,
  }, mallory.privateJwk);
  const r = auditCapacity({
    ...g.input,
    delegationTexts: g.input.delegationTexts.map((x) => (x === g.e[2].text ? bad.text : x)),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'ISSUER_MISMATCH');
  assert.equal(r.error.field, '$["iss"]');
});

test('iss 仍声称 a 但由他密钥签：先被 BAD_SIGNATURE 拦截', async () => {
  const g = await diamond();
  const mallory = generateKeyPair();
  const bad = await cap({
    iss: g.a.publicJwk, sub: g.t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
    maxSamples: 80, transfer: 50, parent: g.e[0].digest,
  }, mallory.privateJwk);
  const r = auditCapacity({
    ...g.input,
    delegationTexts: g.input.delegationTexts.map((x) => (x === g.e[2].text ? bad.text : x)),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
});

test('根委托签发者不等于根公钥：ISSUER_NOT_ROOT', async () => {
  const g = await diamond();
  const other = generateKeyPair();
  const r = auditCapacity({ ...g.input, rootKeyText: rootKeyDocument(other.publicJwk) });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'ISSUER_NOT_ROOT');
});

test('约束放宽：NOT_TIGHTENED 分别定位 aud / maxSamples / exp', async () => {
  const g = await diamond();
  const replace = async (patch) => {
    const bad = await cap({
      iss: g.a.publicJwk, sub: g.t.publicJwk,
      nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'],
      maxSamples: 80, transfer: 50, parent: g.e[0].digest,
      ...patch,
    }, g.a.privateJwk);
    return auditCapacity({
      ...g.input,
      delegationTexts: g.input.delegationTexts.map((x) => (x === g.e[2].text ? bad.text : x)),
    });
  };

  let r = await replace({ aud: ['buoy-01', 'intruder'] });
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.field, '$["aud"]');
  assert.match(r.error.message, /intruder/);

  r = await replace({ maxSamples: 200 });
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.field, '$["maxSamples"]');

  r = await replace({ exp: NOW + 7200 });
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.field, '$["exp"]');

  r = await replace({ nbf: NOW - 4000 });
  assert.equal(r.error.code, 'NOT_TIGHTENED');
  assert.equal(r.error.field, '$["nbf"]');
});

test('篡改签名字节：BAD_SIGNATURE', async () => {
  const g = await diamond();
  const v = parseCanonical(g.e[0].text, { requireOrderedKeys: false }).value;
  const buf = Buffer.from(v.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  buf[0] ^= 0x01;
  v.sig = buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const tampered = canonicalize(v);
  const r = auditCapacity({
    ...g.input,
    delegationTexts: g.input.delegationTexts.map((x) => (x === g.e[0].text ? tampered : x)),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
});

test('改写已签名载荷：BAD_SIGNATURE（规范字节变化）', async () => {
  const g = await diamond();
  const bad = mutatePayload(g.e[1].text, (v) => { v.transfer = 41; });
  const r = auditCapacity({
    ...g.input,
    delegationTexts: g.input.delegationTexts.map((x) => (x === g.e[1].text ? bad : x)),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
});

test('目标不可达：图中无该主体 / 浮标无生效路径 / 时刻超出时间窗', async () => {
  const g = await diamond();

  const stranger = generateKeyPair();
  let r = auditCapacity({ ...g.input, targetText: rootKeyDocument(stranger.publicJwk) });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');

  r = auditCapacity({ ...g.input, buoy: 'buoy-02' });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');

  r = auditCapacity({ ...g.input, now: NOW + 9999 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
});

test('未生效边被剔除并在证据中标注原因，其余路径照常承载', async () => {
  const g = await diamond();
  // e1 放宽到允许 01/02（由 root 重签），e3 收紧为仅 02；
  // 审计 buoy-01 时 e3 因浮标不匹配失效，只剩 e2(50) 一条路径。
  const e1wide = await cap({
    iss: g.root.publicJwk, sub: g.b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01', 'buoy-02'],
    maxSamples: 60, transfer: 40, parent: '',
  }, g.root.privateJwk);
  const e3b02 = await cap({
    iss: g.b.publicJwk, sub: g.t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-02'],
    maxSamples: 60, transfer: 30, parent: e1wide.digest,
  }, g.b.privateJwk);
  const r = auditCapacity({
    ...g.input,
    delegationTexts: [g.e[0].text, e1wide.text, g.e[2].text, e3b02.text],
    buoy: 'buoy-01', now: NOW,
  });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.maxTransferable, 50);
  const dead = r.evidence.edges.find((e) => e.payloadDigest === e3b02.digest);
  assert.equal(dead.active, false);
  assert.deepEqual(dead.inactiveReasons, ['buoy-not-allowed']);
  assert.equal(dead.flow, null);
  assert.equal(dead.remaining, null);
});

test('findCycle 白盒：2-环 / 3-环 / 无环 DAG', () => {
  const cyc2 = findCycle([
    { digest: 'aa'.repeat(32), parent: 'bb'.repeat(32), index: 0 },
    { digest: 'bb'.repeat(32), parent: 'aa'.repeat(32), index: 1 },
  ]);
  assert.ok(cyc2);

  const cyc3 = findCycle([
    { digest: 'a'.repeat(64), parent: 'c'.repeat(64), index: 0 },
    { digest: 'b'.repeat(64), parent: 'a'.repeat(64), index: 1 },
    { digest: 'c'.repeat(64), parent: 'b'.repeat(64), index: 2 },
  ]);
  assert.ok(cyc3);

  const dag = findCycle([
    { digest: 'r'.repeat(64), parent: '', index: 0 },
    { digest: 's'.repeat(64), parent: 'r'.repeat(64), index: 1 },
    { digest: 't'.repeat(64), parent: 'r'.repeat(64), index: 2 },
  ]);
  assert.equal(dag, null);
});

test('maxFlow 白盒：教科书网络给出确定的最大流与割', () => {
  //   s -> a (10), s -> b (10), a -> b (1), a -> t (4), b -> t (8)
  const nodes = ['s', 'a', 'b', 't'];
  const edges = [
    { id: 'e-sa', from: 's', to: 'a', cap: 10 },
    { id: 'e-sb', from: 's', to: 'b', cap: 10 },
    { id: 'e-ab', from: 'a', to: 'b', cap: 1 },
    { id: 'e-at', from: 'a', to: 't', cap: 4 },
    { id: 'e-bt', from: 'b', to: 't', cap: 8 },
  ];
  const mf = maxFlow(nodes, edges, 's', 't');
  assert.equal(mf.total, 12); // at(4) + bt(8)
  assert.deepEqual(mf.cut, ['e-at', 'e-bt']);
  assert.equal(mf.flow.get('e-at'), 4);
  assert.equal(mf.flow.get('e-bt'), 8);
  assert.equal(mf.flow.get('e-ab'), 0);
});

test('maxFlow 白盒：多个等价最小割时，结论对边输入顺序完全不敏感', () => {
  // 对称菱形：s-a(10), s-b(10), a-t(10), b-t(10)，最大流 20，
  // 根侧切 {sa,sb} 与目标侧切 {at,bt} 容量同为 20——割的选择必须只取决于内容顺序。
  const nodes = ['s', 'a', 'b', 't'];
  const base = [
    { id: 'e-sa', from: 's', to: 'a', cap: 10 },
    { id: 'e-sb', from: 's', to: 'b', cap: 10 },
    { id: 'e-at', from: 'a', to: 't', cap: 10 },
    { id: 'e-bt', from: 'b', to: 't', cap: 10 },
  ];
  const sig = (mf) => JSON.stringify({
    total: mf.total, cut: mf.cut, flow: [...mf.flow.entries()].sort(),
  });
  const expected = sig(maxFlow(nodes, base, 's', 't'));
  for (let i = 0; i < base.length; i++) {
    for (let j = i + 1; j < base.length; j++) {
      const perm = base.map((_, k) => base[k]);
      [perm[i], perm[j]] = [perm[j], perm[i]];
      assert.equal(sig(maxFlow(nodes, perm, 's', 't')), expected);
    }
  }
});

test('端到端：对称图所有粘贴排列给出字节级一致的容量 / 流量 / 割证据', async () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const mk10 = (iss, sub, parent, priv) => cap({
    iss: iss.publicJwk, sub: sub.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['x'],
    maxSamples: 10, transfer: 10, parent,
  }, priv.privateJwk);
  const sa = await mk10(root, a, '', root);
  const sb = await mk10(root, b, '', root);
  const at = await mk10(a, t, sa.digest, a);
  const bt = await mk10(b, t, sb.digest, b);
  const texts = [sa.text, sb.text, at.text, bt.text];
  const common = {
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetText: rootKeyDocument(t.publicJwk), buoy: 'x', now: NOW,
  };
  const sig = (ev) => JSON.stringify({
    max: ev.maxTransferable,
    flow: ev.flowEdges.map((e) => [e.payloadDigest, e.flow, e.remaining]).sort(),
    cut: ev.minCut.edges.map((e) => e.payloadDigest).sort(),
  });
  const baseline = sig(auditCapacity({ ...common, delegationTexts: texts }).evidence);
  const permutations = [
    [sb.text, sa.text, bt.text, at.text],
    [at.text, bt.text, sa.text, sb.text],
    [bt.text, at.text, sb.text, sa.text],
    [sa.text, at.text, sb.text, bt.text],
  ];
  for (const p of permutations) {
    const r = auditCapacity({ ...common, delegationTexts: p });
    assert.equal(r.ok, true, JSON.stringify(r.error));
    assert.equal(sig(r.evidence), baseline);
  }
});

test('transfer > maxSamples：SCHEMA 定位 transfer', async () => {
  const g = await diamond();
  const bad = await cap({
    iss: g.root.publicJwk, sub: g.b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01'],
    maxSamples: 10, transfer: 11, parent: '',
  }, g.root.privateJwk);
  const r = auditCapacity({
    ...g.input,
    delegationTexts: [...g.input.delegationTexts.filter((x) => x !== g.e[1].text), bad.text],
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
  assert.equal(r.error.field, '$["transfer"]');
});

test('请求参数校验：buoy / now / 空集合 / 目标为根本身', async () => {
  const g = await diamond();
  let r = auditCapacity({ ...g.input, buoy: '' });
  assert.equal(r.error.code, 'SCHEMA');
  r = auditCapacity({ ...g.input, now: 2147483648 });
  assert.equal(r.error.code, 'SCHEMA');
  r = auditCapacity({ ...g.input, delegationTexts: [] });
  assert.equal(r.error.code, 'SCHEMA');
  r = auditCapacity({ ...g.input, targetText: g.input.rootKeyText });
  assert.equal(r.error.code, 'SCHEMA');
});

test('重复载荷（同一规范委托粘贴两份）：SCHEMA 拒绝', async () => {
  const g = await diamond();
  const r = auditCapacity({
    ...g.input,
    delegationTexts: [...g.input.delegationTexts, g.e[0].text],
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
});
