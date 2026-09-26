'use strict';

// 容量委托图审计（失联期间“最多还能采多少”）。
//
// 值班员粘贴的是一份【无序】的容量委托集合，每条容量委托沿用委托链的
// P-256 签名与规范 JSON（JCS）字节，除既有字段外声明：
//   parent:   父载荷摘要（父委托“去掉 sig 后规范字节”的 SHA-256 hex）；
//             根委托（由根公钥签发）使用空串 "" 显式锚定根。
//   transfer: 本边可转移容量（int32 区间内非负整数，且 <= 本边 maxSamples）。
// 完整对象（键按 JCS 顺序）：
//   cap-delegation: { aud, exp, iss, maxSamples, nbf, parent, sig, sub, transfer, typ }
//
// 核验流程：
//   A. 逐条解析规范 JSON、模式校验、用本边 iss 公钥逐边验签；
//   B. 按父摘要接成有向图：根边 iss 必须等于根公钥，非根边 iss 必须等于
//      父边 sub（后继签发者不匹配即拒绝），且约束相对父边只允许收紧；
//   C. 父摘要悬空（PARENT_NOT_FOUND）/ 缺失（PARENT_MISSING）/ 成环
//      （GRAPH_CYCLE）一律定位拒绝；
//   D. 在指定浮标与评估时刻筛出“生效边”，求根 → 目标主体的最大可转移
//      容量（边容量 = transfer），并给出按摘要稳定排列的最小割证据。
//
// 与单链核验（chain.js）相互独立：单链按顺序核验的结果与错误草稿行为不变。

import crypto from 'node:crypto';
import {
  parseCanonical,
  canonicalBytes,
  requireBoundedInteger,
  LIMITS,
} from './canonical.js';
import {
  validateJwk,
  validateAud,
  importJwk,
  jwkEquals,
  jwkThumbprint,
  b64urlDecode,
  b64urlEncode,
  sha256Hex,
  MAX_OBJECT_BYTES,
  MAX_BUOY_ID_LEN,
} from './chain.js';

const MAX_DELEGATIONS = 64;

const ROOT_PARENT = ''; // 根边的父摘要：空串显式锚定根

class CapacityError extends Error {
  constructor(code, index, field, message, extra = {}) {
    super(message);
    this.code = code;
    this.index = index; // -1 = 根公钥 / 目标 / 请求参数；否则为粘贴集合中的序号
    this.field = field;
    Object.assign(this, extra);
  }
}

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isDigest(s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}

// 校验单条容量委托的模式与整数边界；返回规范化字段
function validateCapacitySchema(parsed, index) {
  const obj = parsed.value;
  const numbers = parsed.numbers;
  if (!isPlainObject(obj)) {
    throw new CapacityError('SCHEMA', index, '$', `第 ${index} 条容量委托必须是 JSON 对象`);
  }
  if (obj.typ !== 'cap-delegation') {
    throw new CapacityError('SCHEMA', index, '$["typ"]',
      '容量审计仅接受 typ="cap-delegation" 的委托对象');
  }
  const required = ['aud', 'exp', 'iss', 'maxSamples', 'nbf', 'parent', 'sig', 'sub', 'transfer', 'typ'];
  for (const k of required) {
    if (!(k in obj)) {
      throw new CapacityError(
        k === 'parent' ? 'PARENT_MISSING' : 'SCHEMA',
        index, '$', `缺少必需成员 "${k}"`);
    }
  }
  for (const k of Object.keys(obj)) {
    if (!required.includes(k)) {
      throw new CapacityError('SCHEMA', index, `$["${k}"]`,
        `不允许的额外成员 "${k}"（疑似内容被改写）`);
    }
  }

  const iss = validateJwk(obj.iss, index, '$["iss"]');
  const sub = validateJwk(obj.sub, index, '$["sub"]');

  const nbf = requireBoundedInteger(numbers, '$["nbf"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期起 nbf ',
  });
  const exp = requireBoundedInteger(numbers, '$["exp"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期止 exp ',
  });
  if (nbf >= exp) {
    throw new CapacityError('SCHEMA', index, '$["nbf"]',
      `有效期无效：nbf(${nbf}) 必须早于 exp(${exp})`);
  }
  const maxSamples = requireBoundedInteger(numbers, '$["maxSamples"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '采样上限 maxSamples ',
  });
  const transfer = requireBoundedInteger(numbers, '$["transfer"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '可转移容量 transfer ',
  });
  if (transfer > maxSamples) {
    throw new CapacityError('SCHEMA', index, '$["transfer"]',
      `可转移容量 transfer(${transfer}) 不能大于本边采样上限 maxSamples(${maxSamples})`);
  }
  const aud = validateAud(obj.aud, index);

  if (typeof obj.parent !== 'string') {
    throw new CapacityError('SCHEMA', index, '$["parent"]',
      'parent 必须是父载荷摘要字符串（根委托使用空串 ""）');
  }
  if (obj.parent !== ROOT_PARENT && !isDigest(obj.parent)) {
    throw new CapacityError('SCHEMA', index, '$["parent"]',
      'parent 必须是 64 位小写十六进制 SHA-256 摘要，根委托使用空串 ""');
  }

  if (typeof obj.sig !== 'string') {
    throw new CapacityError('SCHEMA', index, '$["sig"]', 'sig 必须是 base64url 字符串');
  }
  const sigRaw = b64urlDecode(obj.sig);
  if (sigRaw === null || sigRaw.length !== 64 || b64urlEncode(sigRaw) !== obj.sig) {
    throw new CapacityError('SCHEMA', index, '$["sig"]',
      'sig 必须是 64 字节 P1363 签名的规范 base64url（无填充）');
  }

  return {
    typ: 'cap-delegation', iss, sub, nbf, exp, aud,
    maxSamples, transfer, parent: obj.parent, sig: obj.sig, sigRaw,
  };
}

// Edmonds–Karp 最大流 / 残量最小割。
// nodes：节点 id（指纹）数组；edges：[{id, from, to, cap}]。
// 邻接按“目标节点指纹 + 边摘要”稳定排序，保证最小割证据可复现。
function maxFlow(nodeIds, edges, source, sink) {
  const flow = new Map(); // edge id -> 流量
  for (const e of edges) flow.set(e.id, 0);

  // 残量网络：每条边一对正/反向残量弧（fwd/rev 互相引用），
  // res[u] 按 (to, edgeId) 排序，消除遍历顺序歧义，保证增广路径与割证据可复现。
  const res = new Map();
  for (const u of nodeIds) res.set(u, []);
  for (const e of edges) {
    const fwd = { to: e.to, edge: e.id, cap: e.cap, dir: 1 };
    const rev = { to: e.from, edge: e.id, cap: 0, dir: -1 };
    fwd.pair = rev; rev.pair = fwd;
    res.get(e.from).push(fwd);
    res.get(e.to).push(rev);
  }
  // 按内容（目标指纹 + 边摘要）排序，使增广路径选择与粘贴顺序无关
  for (const u of nodeIds) {
    res.get(u).sort((a, b) => (a.to < b.to ? -1 : a.to > b.to ? 1 :
      a.edge < b.edge ? -1 : a.edge > b.edge ? 1 : 0));
  }

  let total = 0;
  while (true) {
    // BFS 找增广路（遍历顺序已排序 → 结果确定）
    const prev = new Map();
    const q = [source];
    prev.set(source, null);
    while (q.length) {
      const u = q.shift();
      if (u === sink) break;
      for (const a of res.get(u)) {
        if (a.cap > 0 && !prev.has(a.to)) {
          prev.set(a.to, { from: u, arc: a });
          q.push(a.to);
        }
      }
    }
    if (!prev.has(sink)) break;

    let bottleneck = Infinity;
    for (let v = sink; v !== source; v = prev.get(v).from) {
      bottleneck = Math.min(bottleneck, prev.get(v).arc.cap);
    }
    for (let v = sink; v !== source; v = prev.get(v).from) {
      const a = prev.get(v).arc;
      a.cap -= bottleneck;
      a.pair.cap += bottleneck;
      const f = flow.get(a.edge);
      flow.set(a.edge, f + (a.dir === 1 ? bottleneck : -bottleneck));
    }
    total += bottleneck;
  }

  // 残量可达集合（从 source 沿正残量）
  const reachable = new Set([source]);
  const q = [source];
  while (q.length) {
    const u = q.shift();
    for (const a of res.get(u)) {
      if (a.cap > 0 && !reachable.has(a.to)) {
        reachable.add(a.to);
        q.push(a.to);
      }
    }
  }

  // 最小割：from 可达、to 不可达的生效边
  const cut = edges
    .filter((e) => reachable.has(e.from) && !reachable.has(e.to))
    .sort((a, b) => (a.id < b.id ? -1 : 1))
    .map((e) => e.id);

  return { total, flow, reachable, cut };
}

// 纯结构成环判定：nodes 为 [{digest, parent, index}]，parent='' 锚定虚拟根。
// 每个 digest 至多一个 parent（函数式父链）。沿父链行走并标记：
// 命中“当前行走中”的节点即存在环，返回闭合边（行走路径末端）摘要；无环返回 null。
// 按 index 依次出发，保证闭环边定位稳定可复现。
function findCycle(nodes) {
  const byDigest = new Map(nodes.map((n) => [n.digest, n]));
  const state = new Map(); // 1 = 当前行走中, 2 = 确认无环
  for (const start of [...nodes].sort((a, b) => a.index - b.index)) {
    if (state.get(start.digest) === 2) continue;
    const path = [];
    let cur = start.digest;
    while (cur !== ROOT_PARENT) {
      const s = state.get(cur);
      if (s === 2) break;
      if (s === 1) return path[path.length - 1];
      const node = byDigest.get(cur);
      if (!node) break; // 悬空父摘要由接线阶段（PARENT_NOT_FOUND）拒绝
      state.set(cur, 1);
      path.push(cur);
      cur = node.parent;
    }
    for (const d of path) state.set(d, 2);
  }
  return null;
}

function normalizeError(e, index, field) {
  if (e instanceof CapacityError) return e;
  const code = e.code || 'JSON_SYNTAX';
  const err = new CapacityError(code, index, field || e.field || null, e.message);
  if (e.line !== undefined) err.line = e.line;
  if (e.col !== undefined) err.col = e.col;
  if (e.pos !== undefined) err.pos = e.pos;
  return err;
}

function fail(err) {
  return {
    ok: false,
    error: {
      code: err.code,
      hop: err.index, // 与单链错误信封保持同形（hop 字段）
      index: err.index,
      field: err.field ?? null,
      message: err.message,
      line: err.line ?? null,
      col: err.col ?? null,
    },
  };
}

// 主入口：容量审计。
// input: { rootKeyText, delegationTexts: string[], targetText, buoy, now? }
// 返回 { ok:true, evidence } 或 { ok:false, error:{code,index,hop,field,message,line,col} }
function auditCapacity(input) {
  const now = input.now === undefined ? Math.floor(Date.now() / 1000) : input.now;
  if (!Number.isInteger(now) || now < 0 || now > LIMITS.INT32_MAX) {
    return fail(new CapacityError('SCHEMA', -1, 'now', '评估时刻 now 必须是 int32 区间内的整数秒'));
  }
  if (typeof input.buoy !== 'string' || input.buoy.length === 0 || input.buoy.length > MAX_BUOY_ID_LEN) {
    return fail(new CapacityError('SCHEMA', -1, 'buoy',
      `目标浮标 buoy 必须是 1..${MAX_BUOY_ID_LEN} 字符的非空字符串`));
  }
  const buoy = input.buoy;

  // ---- 根公钥 ----
  let rootKey;
  try {
    if (typeof input.rootKeyText !== 'string' || input.rootKeyText.length === 0) {
      throw new CapacityError('ROOT_KEY_INVALID', -1, 'rootKey', '根公钥不能为空');
    }
    if (Buffer.byteLength(input.rootKeyText, 'utf8') > MAX_OBJECT_BYTES) {
      throw new CapacityError('ROOT_KEY_INVALID', -1, 'rootKey', '根公钥文档过大');
    }
    rootKey = validateJwk(parseCanonical(input.rootKeyText).value, -1, 'rootKey');
  } catch (e) {
    return fail(normalizeError(e, -1, 'rootKey'));
  }

  // ---- 目标主体 ----
  let target;
  try {
    if (typeof input.targetText !== 'string' || input.targetText.length === 0) {
      throw new CapacityError('SCHEMA', -1, 'target', '目标主体公钥不能为空');
    }
    target = validateJwk(parseCanonical(input.targetText).value, -1, 'target');
  } catch (e) {
    return fail(normalizeError(e, -1, 'target'));
  }
  if (jwkEquals(target, rootKey)) {
    return fail(new CapacityError('SCHEMA', -1, 'target', '目标主体不能是根公钥本身'));
  }

  // ---- 容量委托集合 ----
  const texts = input.delegationTexts;
  if (!Array.isArray(texts) || texts.length === 0) {
    return fail(new CapacityError('SCHEMA', -1, 'delegations', '容量委托集合不能为空'));
  }
  if (texts.length > MAX_DELEGATIONS) {
    return fail(new CapacityError('SCHEMA', -1, 'delegations',
      `容量委托过多（>${MAX_DELEGATIONS} 条）`));
  }

  // Pass A：逐条解析、模式校验、逐边验签（粘贴序号即定位 index）
  const items = []; // {index, model, digest, sig, text}
  for (let i = 0; i < texts.length; i++) {
    const text = texts[i];
    if (typeof text !== 'string' || text.length === 0) {
      return fail(new CapacityError('SCHEMA', i, '$', `第 ${i} 条委托不是非空字符串`));
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_OBJECT_BYTES) {
      return fail(new CapacityError('SCHEMA', i, '$', `第 ${i} 条委托文档过大（>${MAX_OBJECT_BYTES} 字节）`));
    }
    let parsed;
    try {
      parsed = parseCanonical(text);
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }
    let model;
    try {
      model = validateCapacitySchema(parsed, i);
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }

    const { sig, ...payload } = parsed.value;
    const payloadBytes = canonicalBytes(payload);
    const payloadDigest = sha256Hex(payloadBytes);

    let sigOk = false;
    try {
      sigOk = crypto.verify('sha256', payloadBytes, {
        key: importJwk(model.iss),
        dsaEncoding: 'ieee-p1363',
      }, model.sigRaw);
    } catch {
      sigOk = false;
    }
    if (!sigOk) {
      return fail(new CapacityError('BAD_SIGNATURE', i, '$["sig"]',
        `第 ${i} 条委托签名验证失败（签名与规范载荷摘要不符，载荷 SHA-256=${payloadDigest}）`));
    }

    items.push({ index: i, model, digest: payloadDigest, sig: model.sig });
  }

  // Pass B：摘要索引（重复载荷即重复边，集合必须无歧义）
  const byDigest = new Map();
  for (const it of items) {
    if (byDigest.has(it.digest)) {
      const prev = byDigest.get(it.digest);
      return fail(new CapacityError('SCHEMA', it.index, '$',
        `委托载荷摘要重复：${it.digest}（第 ${prev.index} 条与第 ${it.index} 条完全相同，集合中不允许重复委托）`));
    }
    byDigest.set(it.digest, it);
  }

  // Pass C：父摘要接线、签发关系、只收紧（按粘贴序号定位）
  for (const it of items) {
    const m = it.model;
    if (m.parent === ROOT_PARENT) {
      if (!jwkEquals(m.iss, rootKey)) {
        return fail(new CapacityError('ISSUER_NOT_ROOT', it.index, '$["iss"]',
          `第 ${it.index} 条根委托签发者不等于根公钥（parent 为空串时 iss 必须等于所粘贴根公钥）`));
      }
      continue;
    }
    const parent = byDigest.get(m.parent);
    if (!parent) {
      return fail(new CapacityError('PARENT_NOT_FOUND', it.index, '$["parent"]',
        `第 ${it.index} 条委托的父摘要 ${m.parent} 在集合中找不到对应委托（父摘要缺失 / 未粘贴）`));
    }
    if (!jwkEquals(m.iss, parent.model.sub)) {
      return fail(new CapacityError('ISSUER_MISMATCH', it.index, '$["iss"]',
        `第 ${it.index} 条委托并非父委托（第 ${parent.index} 条，摘要 ${m.parent}）的主体签发` +
        '（后继签发者不匹配：iss ≠ 父边 sub）'));
    }
    const p = parent.model;
    if (m.nbf < p.nbf) {
      return fail(new CapacityError('NOT_TIGHTENED', it.index, '$["nbf"]',
        `第 ${it.index} 条委托有效期起早于父委托（${m.nbf} < ${p.nbf}），时间窗只允许收紧`));
    }
    if (m.exp > p.exp) {
      return fail(new CapacityError('NOT_TIGHTENED', it.index, '$["exp"]',
        `第 ${it.index} 条委托有效期止晚于父委托（${m.exp} > ${p.exp}），时间窗只允许收紧`));
    }
    const parentAud = new Set(p.aud);
    const extra = m.aud.filter((b) => !parentAud.has(b));
    if (extra.length > 0) {
      return fail(new CapacityError('NOT_TIGHTENED', it.index, '$["aud"]',
        `第 ${it.index} 条委托浮标集合超出父委托允许范围（新增：${extra.join(', ')}），浮标集合只允许收紧`));
    }
    if (m.maxSamples > p.maxSamples) {
      return fail(new CapacityError('NOT_TIGHTENED', it.index, '$["maxSamples"]',
        `第 ${it.index} 条委托采样上限大于父委托（${m.maxSamples} > ${p.maxSamples}），采样上限只允许收紧`));
    }
  }

  // Pass D：成环检测（纯结构判定，便于单元测试直接构造摘要图）。
  // 接线阶段已保证每条非根边的 parent 都能解析到集合内某条边；
  // 在“无悬空父摘要 + 无环”的前提下，沿父链行走必终止于 parent='' 的根边，
  // 即每条边都锚定到根，无需额外孤立子图检查。
  const cycleDigest = findCycle(items.map((it) => ({
    digest: it.digest, parent: it.model.parent, index: it.index,
  })));
  if (cycleDigest) {
    const it = byDigest.get(cycleDigest);
    return fail(new CapacityError('GRAPH_CYCLE', it.index, '$["parent"]',
      `委托图成环：第 ${it.index} 条委托（摘要 ${cycleDigest}）的父摘要指回其祖先，` +
      '容量委托图必须是以根为源头的有向无环图'));
  }

  // ---- 在（浮标, 时刻）上构造生效子图 ----
  const rootThumb = jwkThumbprint(rootKey);
  const targetThumb = jwkThumbprint(target);

  // 节点集合 = 根 + 所有边的 iss/sub 指纹
  const nodeSet = new Set([rootThumb]);
  for (const it of items) {
    nodeSet.add(jwkThumbprint(it.model.iss));
    nodeSet.add(jwkThumbprint(it.model.sub));
  }
  if (!nodeSet.has(targetThumb)) {
    return fail(new CapacityError('TARGET_UNREACHABLE', -1, 'target',
      `目标主体 ${targetThumb} 不是任何委托的接收方（图中不存在该主体），无法从根到达`));
  }

  const edgeInfo = items.map((it) => {
    const m = it.model;
    const inactiveReasons = [];
    if (now < m.nbf) inactiveReasons.push('time-not-yet-valid');
    else if (now > m.exp) inactiveReasons.push('time-expired');
    if (!m.aud.includes(buoy)) inactiveReasons.push('buoy-not-allowed');
    return {
      id: it.digest,
      index: it.index,
      model: m,
      sig: it.sig,
      from: jwkThumbprint(m.iss),
      to: jwkThumbprint(m.sub),
      active: inactiveReasons.length === 0,
      inactiveReasons,
    };
  });

  const activeEdges = edgeInfo.filter((e) => e.active);

  // 根 → 目标 的生效路径（忽略容量为 0 的边也算“签发上可达”，
  // 但容量 0 的边在最大流中自然贡献 0）
  const reachableActive = new Set([rootThumb]);
  {
    const adj = new Map();
    for (const e of activeEdges) {
      if (!adj.has(e.from)) adj.set(e.from, []);
      adj.get(e.from).push(e.to);
    }
    const q = [rootThumb];
    while (q.length) {
      const u = q.shift();
      for (const v of adj.get(u) || []) {
        if (!reachableActive.has(v)) { reachableActive.add(v); q.push(v); }
      }
    }
  }
  if (!reachableActive.has(targetThumb)) {
    return fail(new CapacityError('TARGET_UNREACHABLE', -1, 'target',
      `在浮标 "${buoy}"、评估时刻 ${now} 上不存在根到目标主体 ${targetThumb} 的生效委托路径` +
      '（时间窗不覆盖或该浮标未被沿途委托允许）'));
  }

  // ---- 最大流 / 最小割 ----
  const nodeIds = [...nodeSet].sort();
  const flowEdges = activeEdges.map((e) => ({
    id: e.id, from: e.from, to: e.to, cap: e.model.transfer,
  }));
  const mf = maxFlow(nodeIds, flowEdges, rootThumb, targetThumb);

  // ---- 证据（一切列表按规范载荷摘要稳定排列）----
  const edgeEvidence = edgeInfo
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : a.index - b.index))
    .map((e) => ({
      payloadDigest: e.id,
      inputIndex: e.index,
      signature: e.sig,
      parentDigest: e.model.parent,
      issThumbprint: e.from,
      subThumbprint: e.to,
      nbf: e.model.nbf,
      exp: e.model.exp,
      aud: [...e.model.aud],
      maxSamples: e.model.maxSamples,
      transfer: e.model.transfer,
      active: e.active,
      inactiveReasons: e.inactiveReasons,
      flow: e.active ? mf.flow.get(e.id) : null,
      remaining: e.active ? e.model.transfer - mf.flow.get(e.id) : null,
    }));

  const cutEdgeEvidence = mf.cut.map((d) => {
    const e = edgeInfo.find((x) => x.id === d);
    return {
      payloadDigest: d,
      inputIndex: e.index,
      issThumbprint: e.from,
      subThumbprint: e.to,
      transfer: e.model.transfer,
      flow: mf.flow.get(d),
      remaining: e.model.transfer - mf.flow.get(d),
    };
  });
  const cutCapacity = cutEdgeEvidence.reduce((s, e) => s + e.transfer, 0);

  return {
    ok: true,
    evidence: {
      kind: 'capacity',
      now,
      buoy,
      rootKeyThumbprint: rootThumb,
      targetThumbprint: targetThumb,
      maxTransferable: mf.total,
      edges: edgeEvidence,
      flowEdges: edgeEvidence
        .filter((e) => e.active)
        .map((e) => ({
          payloadDigest: e.payloadDigest,
          fromThumbprint: e.issThumbprint,
          toThumbprint: e.subThumbprint,
          capacity: e.transfer,
          flow: e.flow,
          remaining: e.remaining,
        })),
      minCut: {
        capacity: cutCapacity,
        edges: cutEdgeEvidence,
        reachableThumbprints: [...mf.reachable].sort(),
      },
      verdict: {
        reachable: true,
        maxSamples: mf.total,
        reason: `容量审计通过：失联期间浮标 "${buoy}" 上目标主体最多可获得 ${mf.total} 次可用采样额度` +
          `（评估时刻 ${now}，最小割容量同为 ${cutCapacity}，割去所列委托边即可阻断更多采样）`,
      },
    },
  };
}

export {
  auditCapacity,
  findCycle,
  maxFlow,
  MAX_DELEGATIONS,
};
