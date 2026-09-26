'use strict';

// 容量委托图审计。
//
// 值班员粘贴的不再是“按顺序排列的单条链”，而是一个【无序】的容量委托集合，
// 另附根公钥、目标主体（P-256 JWK）、目标浮标与评估时刻。每条容量委托在既有
// 字段（iss/sub/nbf/exp/aud/maxSamples/sig/typ）之外增加两个成员：
//   - parent:    父载荷摘要（SHA-256 hex，即父委托“去掉 sig 后规范字节”的摘要）；
//   - transfer:  本边可转移容量（int32 区间内的非负整数，<= maxSamples）。
// 服务按 parent 把对象接成以根为起点的有向委托图，逐边验签、确认签发关系与
// 约束只收紧，然后在指定浮标与评估时刻上精确计算“根 → 目标主体”的【最大可
// 转移容量】（DAG 最大流），并给出按规范摘要稳定排列的流量边、顶点剩余容量
// 与能阻断更多采样的最小割证据。
//
// 容量模型（每条委托入度恒为 1 的有根树；同一主体可在多个委托顶点的 sub 处
// 合并为目标汇）：委托边容量 = 该边声明的 transfer；目标委托顶点 -> 超汇的
// 容量 = 该委托的 maxSamples（schema 保证 transfer<=自身 maxSamples，故中转
// 顶点上限不会先于入边收口）。根→目标主体最大流即失联期间最多可获得的可用
// 采样额度；残量网络割即“能阻断更多采样”的最小边集。

import crypto from 'node:crypto';
import {
  parseCanonical,
  canonicalBytes,
  requireBoundedInteger,
  LIMITS,
} from './canonical.js';
import {
  b64urlDecode,
  b64urlEncode,
  jwkThumbprint,
  sha256Hex,
} from './chain.js';

const MAX_GRAPH_NODES = 64;
const MAX_OBJECT_BYTES = 64 * 1024;
const MAX_BUOYS = 256;
const MAX_BUOY_ID_LEN = 128;

class AuditError extends Error {
  constructor(code, node, field, message, extra = {}) {
    super(message);
    this.code = code;
    // node: 稳定定位串。'root'=根公钥；'target'=目标主体；否则为问题对象的
    // 规范载荷摘要（SHA-256 hex）。
    this.node = node;
    this.field = field;
    Object.assign(this, extra);
  }
}

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function validateJwk(value, node, field) {
  if (!isPlainObject(value)) {
    throw new AuditError('SCHEMA', node, field, `${field} 必须是 JWK 对象`);
  }
  const keys = Object.keys(value).sort();
  const want = ['crv', 'kty', 'x', 'y'];
  if (keys.length !== 4 || !want.every((k, i) => keys[i] === k)) {
    throw new AuditError('SCHEMA', node, field,
      `${field} 必须恰好包含成员 crv,kty,x,y（实际：${keys.join(',')}）`);
  }
  if (value.kty !== 'EC') {
    throw new AuditError('SCHEMA', node, `${field}["kty"]`, `${field} 的 kty 必须为 "EC"`);
  }
  if (value.crv !== 'P-256') {
    throw new AuditError('SCHEMA', node, `${field}["crv"]`, `${field} 的 crv 必须为 "P-256"`);
  }
  for (const coord of ['x', 'y']) {
    const v = value[coord];
    if (typeof v !== 'string') {
      throw new AuditError('SCHEMA', node, `${field}["${coord}"]`,
        `${field} 的 ${coord} 必须是 base64url 字符串`);
    }
    const raw = b64urlDecode(v);
    if (raw === null || raw.length !== 32 || b64urlEncode(raw) !== v) {
      throw new AuditError('SCHEMA', node, `${field}["${coord}"]`,
        `${field} 的 ${coord} 必须是 32 字节的规范 base64url（无填充）`);
    }
  }
  return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
}

function jwkEquals(a, b) {
  return a && b && a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

const DIGEST_RE = /^[0-9a-f]{64}$/;

function validateAud(value, node) {
  const field = '$["aud"]';
  if (!Array.isArray(value) || value.length === 0) {
    throw new AuditError('SCHEMA', node, field, 'aud 必须是非空数组（允许浮标集合）');
  }
  if (value.length > MAX_BUOYS) {
    throw new AuditError('SCHEMA', node, field, `aud 元素过多（>${MAX_BUOYS}）`);
  }
  const seen = new Set();
  for (let i = 0; i < value.length; i++) {
    const b = value[i];
    if (typeof b !== 'string' || b.length === 0 || b.length > MAX_BUOY_ID_LEN) {
      throw new AuditError('SCHEMA', node, `$["aud"][${i}]`,
        `浮标标识必须是 1..${MAX_BUOY_ID_LEN} 字符的字符串`);
    }
    if (seen.has(b)) {
      throw new AuditError('SCHEMA', node, `$["aud"][${i}]`,
        `aud 中浮标标识重复："${b}"`);
    }
    seen.add(b);
  }
  return value;
}

// 校验单条容量委托模式；返回规范化字段（payloadDigest 由外层计算后挂回）
function validateDelegationSchema(parsed, node) {
  const obj = parsed.value;
  const numbers = parsed.numbers;
  if (!isPlainObject(obj)) {
    throw new AuditError('SCHEMA', node, '$', '容量委托必须是 JSON 对象');
  }
  const required = ['aud', 'exp', 'iss', 'maxSamples', 'nbf', 'parent', 'sig',
    'sub', 'transfer', 'typ'];
  for (const k of required) {
    if (!(k in obj)) {
      throw new AuditError('SCHEMA', node, '$', `缺少必需成员 "${k}"`);
    }
  }
  for (const k of Object.keys(obj)) {
    if (!required.includes(k)) {
      throw new AuditError('SCHEMA', node, `$["${k}"]`,
        `不允许的额外成员 "${k}"（疑似内容被改写）`);
    }
  }
  if (obj.typ !== 'delegation') {
    throw new AuditError('SCHEMA', node, '$["typ"]',
      '容量审计只接受 typ="delegation" 的容量委托（末端命令请走逐跳核验）');
  }
  if (typeof obj.parent !== 'string' || !DIGEST_RE.test(obj.parent)) {
    throw new AuditError('SCHEMA', node, '$["parent"]',
      'parent 必须是 64 位十六进制 SHA-256 摘要（父载荷摘要）');
  }

  const iss = validateJwk(obj.iss, node, '$["iss"]');
  const sub = validateJwk(obj.sub, node, '$["sub"]');

  const nbf = requireBoundedInteger(numbers, '$["nbf"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期起 nbf ',
  });
  const exp = requireBoundedInteger(numbers, '$["exp"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期止 exp ',
  });
  if (nbf >= exp) {
    throw new AuditError('SCHEMA', node, '$["nbf"]',
      `有效期无效：nbf(${nbf}) 必须早于 exp(${exp})`);
  }
  const maxSamples = requireBoundedInteger(numbers, '$["maxSamples"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '采样上限 maxSamples ',
  });
  const transfer = requireBoundedInteger(numbers, '$["transfer"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '可转移容量 transfer ',
  });
  if (transfer > maxSamples) {
    throw new AuditError('SCHEMA', node, '$["transfer"]',
      `可转移容量 transfer(${transfer}) 不得超过本委托采样上限 maxSamples(${maxSamples})`);
  }
  const aud = validateAud(obj.aud, node);

  if (typeof obj.sig !== 'string') {
    throw new AuditError('SCHEMA', node, '$["sig"]', 'sig 必须是 base64url 字符串');
  }
  const sigRaw = b64urlDecode(obj.sig);
  if (sigRaw === null || sigRaw.length !== 64 || b64urlEncode(sigRaw) !== obj.sig) {
    throw new AuditError('SCHEMA', node, '$["sig"]',
      'sig 必须是 64 字节 P1363 签名的规范 base64url（无填充）');
  }

  return {
    iss, sub, nbf, exp, aud, maxSamples, transfer,
    parent: obj.parent, sig: obj.sig, sigRaw,
  };
}

function importJwk(jwk) {
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk',
  });
}

function fail(err) {
  return {
    ok: false,
    error: {
      code: err.code,
      node: err.node,
      field: err.field ?? null,
      message: err.message,
      line: err.line ?? null,
      col: err.col ?? null,
    },
  };
}

// ---------- 成环检测（Kahn 拓扑排序；纯函数，便于单元覆盖） ----------

// edges: [{from,to,...}]；返回 { acyclic, topo, cycleEdge }
// cycleEdge 取一条两端均残余入度的边（环上必有此类边），用于错误定位。
function detectCycle(vertexCount, edges) {
  const outAdj = Array.from({ length: vertexCount }, () => []);
  const indeg = new Array(vertexCount).fill(0);
  for (const e of edges) {
    outAdj[e.from].push(e.to);
    indeg[e.to]++;
  }
  const queue = [];
  for (let v = 0; v < vertexCount; v++) if (indeg[v] === 0) queue.push(v);
  const topo = [];
  while (queue.length) {
    const u = queue.shift();
    topo.push(u);
    for (const w of outAdj[u]) {
      if (--indeg[w] === 0) queue.push(w);
    }
  }
  if (topo.length === vertexCount) return { acyclic: true, topo, cycleEdge: null };
  const inCycle = new Array(vertexCount).fill(false);
  for (let v = 0; v < vertexCount; v++) if (indeg[v] > 0) inCycle[v] = true;
  return {
    acyclic: false,
    topo: null,
    cycleEdge: edges.find((e) => inCycle[e.from] && inCycle[e.to]) ?? null,
  };
}

// ---------- DAG 最大流（边容量上限 int32，总量用 BigInt 兜底） ----------

// 求 s->t 最大流。edges: [{from,to,capacity,meta}]，capacity 为非负整数。
// 返回 { value:number, flow:Map(edge -> 非负整数), residual:Map(edge -> 余量) }
// 顶点数有界（<= MAX_GRAPH_NODES+1），DAG 上以拓扑序 Edmonds–Karp 即可，
// 这里用通用 BFS 增广，残量网络在增广后仍为有限图。
function maxFlow(vertexCount, edges, s, t) {
  const adj = Array.from({ length: vertexCount }, () => []);
  // 残量弧：{ to, rev, cap(BigInt), edge(正向边索引|null), dir:1|-1 }
  for (let ei = 0; ei < edges.length; ei++) {
    const e = edges[ei];
    const fwd = { to: e.to, rev: adj[e.to].length, cap: BigInt(e.capacity), edge: ei, dir: 1 };
    const bwd = { to: e.from, rev: adj[e.from].length, cap: 0n, edge: ei, dir: -1 };
    adj[e.from].push(fwd);
    adj[e.to].push(bwd);
  }

  let total = 0n;
  for (;;) {
    const prevV = new Array(vertexCount).fill(-1);
    const prevA = new Array(vertexCount).fill(null);
    prevV[s] = s;
    const queue = [s];
    let found = false;
    while (queue.length) {
      const u = queue.shift();
      if (u === t) { found = true; break; }
      for (let k = 0; k < adj[u].length; k++) {
        const a = adj[u][k];
        if (a.cap > 0n && prevV[a.to] === -1) {
          prevV[a.to] = u;
          prevA[a.to] = a;
          queue.push(a.to);
        }
      }
    }
    if (!found) break;
    let aug = null;
    for (let v = t; v !== s; v = prevV[v]) {
      const c = prevA[v].cap;
      aug = aug === null || c < aug ? c : aug;
    }
    for (let v = t; v !== s; v = prevV[v]) {
      const a = prevA[v];
      a.cap -= aug;
      adj[v][a.rev].cap += aug;
    }
    total += aug;
  }

  const flow = new Map();
  const residual = new Map();
  for (let ei = 0; ei < edges.length; ei++) {
    const e = edges[ei];
    // 正向弧 = 建图时 adj[e.from] 中 edge===ei 且 dir===1 的那条
    const fwd = adj[e.from].find((a) => a.edge === ei && a.dir === 1);
    const used = BigInt(e.capacity) - fwd.cap;
    flow.set(ei, Number(used));
    residual.set(ei, Number(fwd.cap));
  }
  return { value: Number(total), flow, residual };
}

// 从残量可达性求 s 侧割（最小割证据）。
// 复用 maxFlow 内部结构不便，故再跑一次并返回 reachable 布尔数组与最小割边。
function minCut(vertexCount, edges, s, t) {
  const adj = Array.from({ length: vertexCount }, () => []);
  for (let ei = 0; ei < edges.length; ei++) {
    const e = edges[ei];
    const fwd = { to: e.to, rev: adj[e.to].length, cap: BigInt(e.capacity), edge: ei };
    const bwd = { to: e.from, rev: adj[e.from].length, cap: 0n, edge: ei };
    adj[e.from].push(fwd);
    adj[e.to].push(bwd);
  }
  // 与 maxFlow 相同的 BFS 增广，保证最终残量网络对应一次最大流
  for (;;) {
    const pv = new Array(vertexCount).fill(-1);
    const pa = new Array(vertexCount).fill(null);
    pv[s] = s;
    const queue = [s];
    let found = false;
    while (queue.length) {
      const u = queue.shift();
      if (u === t) { found = true; break; }
      for (const a of adj[u]) {
        if (a.cap > 0n && pv[a.to] === -1) {
          pv[a.to] = u; pa[a.to] = a; queue.push(a.to);
        }
      }
    }
    if (!found) break;
    let aug = null;
    for (let v = t; v !== s; v = pv[v]) {
      const c = pa[v].cap;
      aug = aug === null || c < aug ? c : aug;
    }
    for (let v = t; v !== s; v = pv[v]) {
      const a = pa[v];
      a.cap -= aug;
      adj[v][a.rev].cap += aug;
    }
  }

  const reachable = new Array(vertexCount).fill(false);
  reachable[s] = true;
  const queue = [s];
  while (queue.length) {
    const u = queue.shift();
    for (const a of adj[u]) {
      if (a.cap > 0n && !reachable[a.to]) {
        reachable[a.to] = true;
        queue.push(a.to);
      }
    }
  }
  const cutEdges = [];
  let cutCapacity = 0;
  for (let ei = 0; ei < edges.length; ei++) {
    const e = edges[ei];
    if (reachable[e.from] && !reachable[e.to]) {
      cutEdges.push(ei);
      cutCapacity += e.capacity;
    }
  }
  return { reachable, cutEdges, cutCapacity };
}

// 主入口：容量审计。
// input: { rootKeyText, delegationTexts:string[], targetKeyText, buoy:string, now? }
// 成功：{ ok:true, audit:{...} }；失败：{ ok:false, error:{code,node,field,message,line,col} }
function auditCapacity(input) {
  const now = input.now === undefined ? Math.floor(Date.now() / 1000) : input.now;
  if (!Number.isInteger(now) || now < 0 || now > LIMITS.INT32_MAX) {
    return fail(new AuditError('SCHEMA', 'root', 'now',
      '评估时刻 now 必须是 int32 区间内的整数秒'));
  }

  // ---- 根公钥 ----
  let rootKey;
  try {
    if (typeof input.rootKeyText !== 'string' || input.rootKeyText.length === 0) {
      throw new AuditError('ROOT_KEY_INVALID', 'root', 'rootKey', '根公钥不能为空');
    }
    if (Buffer.byteLength(input.rootKeyText, 'utf8') > MAX_OBJECT_BYTES) {
      throw new AuditError('ROOT_KEY_INVALID', 'root', 'rootKey', '根公钥文档过大');
    }
    rootKey = validateJwk(parseCanonical(input.rootKeyText).value, 'root', 'rootKey');
  } catch (e) {
    return fail(normalizeError(e, 'root'));
  }

  // ---- 目标主体 ----
  let targetKey;
  try {
    if (typeof input.targetKeyText !== 'string' || input.targetKeyText.length === 0) {
      throw new AuditError('TARGET_KEY_INVALID', 'target', 'targetKey', '目标主体公钥不能为空');
    }
    if (Buffer.byteLength(input.targetKeyText, 'utf8') > MAX_OBJECT_BYTES) {
      throw new AuditError('TARGET_KEY_INVALID', 'target', 'targetKey', '目标主体公钥文档过大');
    }
    targetKey = validateJwk(parseCanonical(input.targetKeyText).value, 'target', 'targetKey');
  } catch (e) {
    return fail(normalizeError(e, 'target'));
  }
  if (jwkEquals(rootKey, targetKey)) {
    return fail(new AuditError('TARGET_IS_ROOT', 'target', 'targetKey',
      '目标主体不能就是根本体（容量审计的目标必须是被委托主体）'));
  }

  // ---- 目标浮标 / 集合 ----
  const buoy = input.buoy;
  if (typeof buoy !== 'string' || buoy.length === 0 || buoy.length > MAX_BUOY_ID_LEN) {
    return fail(new AuditError('SCHEMA', 'target', 'buoy',
      `目标浮标必须是 1..${MAX_BUOY_ID_LEN} 字符的字符串`));
  }
  const texts = input.delegationTexts;
  if (!Array.isArray(texts) || texts.length === 0) {
    return fail(new AuditError('SCHEMA', 'root', 'delegations',
      '容量委托集合不能为空'));
  }
  if (texts.length > MAX_GRAPH_NODES) {
    return fail(new AuditError('SCHEMA', 'root', 'delegations',
      `容量委托过多（>${MAX_GRAPH_NODES} 条）`));
  }

  // ---- 逐条解析 / 模式 / 验签（先全部验完再接图，错误定位到摘要） ----
  const nodes = new Map(); // payloadDigest -> node
  const records = [];
  for (let i = 0; i < texts.length; i++) {
    const text = texts[i];
    if (typeof text !== 'string' || text.length === 0) {
      return fail(new AuditError('SCHEMA', `input[${i}]`, '$', `第 ${i} 条不是非空字符串`));
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_OBJECT_BYTES) {
      return fail(new AuditError('SCHEMA', `input[${i}]`, '$',
        `第 ${i} 条文档过大（>${MAX_OBJECT_BYTES} 字节）`));
    }
    let parsed;
    try {
      parsed = parseCanonical(text);
    } catch (e) {
      const err = normalizeError(e, `input[${i}]`);
      return fail(err);
    }
    // 先用输入序号定位做模式校验（此时尚无合法摘要）
    let model;
    try {
      model = validateDelegationSchema(parsed, `input[${i}]`);
    } catch (e) {
      return fail(normalizeError(e, `input[${i}]`));
    }

    const { sig: _sig, ...payload } = parsed.value;
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
      return fail(new AuditError('BAD_SIGNATURE', payloadDigest, '$["sig"]',
        `委托 ${payloadDigest} 签名验证失败（签名与规范载荷摘要不符）`));
    }

    if (nodes.has(payloadDigest)) {
      return fail(new AuditError('DUPLICATE_DELEGATION', payloadDigest, '$',
        `容量委托集合中存在重复对象（规范载荷摘要 ${payloadDigest} 出现多次）`));
    }
    const node = {
      digest: payloadDigest,
      model,
      issThumbprint: jwkThumbprint(model.iss),
      subThumbprint: jwkThumbprint(model.sub),
      index: i,
    };
    nodes.set(payloadDigest, node);
    records.push(node);
  }

  // ---- 接图：parent 必须指向根公钥摘要或另一条委托摘要 ----
  const rootDigest = jwkThumbprint(rootKey);
  // 顶点：0=ROOT，其余按 payloadDigest 的十六进制序稳定编号
  const digestOrder = [...nodes.keys()].sort();
  const idOf = new Map();
  idOf.set('__ROOT__', 0);
  digestOrder.forEach((d, k) => idOf.set(d, k + 1));

  const edges = []; // {from,to,capacity,node}
  for (const node of records) {
    const m = node.model;
    let fromId;
    if (m.parent === rootDigest) {
      fromId = 0;
    } else if (nodes.has(m.parent)) {
      fromId = idOf.get(m.parent);
    } else {
      return fail(new AuditError('PARENT_NOT_FOUND', node.digest, '$["parent"]',
        `委托 ${node.digest} 声明的父载荷摘要 ${m.parent} 在集合中不存在，且不等于根公钥指纹`));
    }
    const parentNode = m.parent === rootDigest
      ? { model: { sub: rootKey }, digest: rootDigest }
      : nodes.get(m.parent);

    // 签发关系：后继签发者必须等于父委托的主体（根出边的签发者必须是根本身）
    if (!jwkEquals(m.iss, parentNode.model.sub)) {
      return fail(new AuditError('SUCCESSOR_ISSUER_MISMATCH', node.digest, '$["iss"]',
        fromId === 0
          ? `根出边委托 ${node.digest} 的签发者不等于根公钥`
          : `委托 ${node.digest} 的签发者不是父委托（${m.parent}）的主体`));
    }

    // 约束只收紧：相对父委托（根出边没有可收紧的上游约束）。
    // transfer 不在此处逐边比较：中间顶点可汇聚多条父边的容量后整体下转，
    // 其合法性由 schema（transfer<=自身 maxSamples）与最大流网络（节点内部边
    // 容量 maxSamples + 边容量 transfer）共同精确收口。
    if (fromId !== 0) {
      const p = nodes.get(m.parent).model;
      if (m.nbf < p.nbf) {
        return fail(new AuditError('SCOPE_WIDENED', node.digest, '$["nbf"]',
          `委托 ${node.digest} 有效期起早于父委托（${m.nbf} < ${p.nbf}），时间窗只允许收紧`));
      }
      if (m.exp > p.exp) {
        return fail(new AuditError('SCOPE_WIDENED', node.digest, '$["exp"]',
          `委托 ${node.digest} 有效期止晚于父委托（${m.exp} > ${p.exp}），时间窗只允许收紧`));
      }
      const parentAud = new Set(p.aud);
      const extra = m.aud.filter((b) => !parentAud.has(b));
      if (extra.length > 0) {
        return fail(new AuditError('SCOPE_WIDENED', node.digest, '$["aud"]',
          `委托 ${node.digest} 浮标集合超出父委托允许范围（新增：${extra.join(', ')}），浮标集合只允许收紧`));
      }
      if (m.maxSamples > p.maxSamples) {
        return fail(new AuditError('SCOPE_WIDENED', node.digest, '$["maxSamples"]',
          `委托 ${node.digest} 采样上限大于父委托（${m.maxSamples} > ${p.maxSamples}），采样上限只允许收紧`));
      }
    }

    edges.push({ from: fromId, to: idOf.get(node.digest), capacity: -1, node });
  }

  // ---- 成环检测（边按摘要稳定编号，拓扑序另行计算） ----
  const V = idOf.size;
  const cyc = detectCycle(V, edges);
  if (!cyc.acyclic) {
    const node = cyc.cycleEdge ? cyc.cycleEdge.node.digest : null;
    return fail(new AuditError('CYCLE_DETECTED', node, '$["parent"]',
      '容量委托按 parent 拼接后存在环（委托图必须是以根为起点的 DAG）'));
  }
  const topo = cyc.topo;

  // ---- 评估时刻 / 浮标过滤 ----
  // 结构核验（签名、签发关系、收紧、成环）针对整图；而“在指定浮标和时刻上”
  // 表现为删边：头顶点在 now 未生效 / 已过期，或其 aud 不含目标浮标，则该顶点
  // 及其出边不参与本次容量计算（下游仍可经另一条合格父边到达）。时间失效属于
  // 不可用而非整图拒绝——拒绝集合仅为父摘要缺失、成环、后继签发者不匹配、
  // 范围放宽、篡改签名与目标不可达。
  const active = new Array(V).fill(false);
  active[0] = true;
  const inactiveReason = new Map();
  for (const node of records) {
    const m = node.model;
    const id = idOf.get(node.digest);
    if (now < m.nbf) {
      inactiveReason.set(id, `not-before:now=${now}<nbf=${m.nbf}`);
      continue;
    }
    if (now > m.exp) {
      inactiveReason.set(id, `expired:now=${now}>exp=${m.exp}`);
      continue;
    }
    if (!m.aud.includes(buoy)) {
      inactiveReason.set(id, `buoy-not-allowed:"${buoy}"`);
      continue;
    }
    active[id] = true;
  }

  const liveEdges = edges.filter((e) => active[e.from] && active[e.to]);

  // ---- 可达性（按浮标/时刻过滤后的图）----
  const reachable = new Array(V).fill(false);
  reachable[0] = true;
  for (const u of topo) {
    if (!reachable[u]) continue;
    for (const e of liveEdges) {
      if (e.from === u) reachable[e.to] = true;
    }
  }

  // 目标主体匹配：目标可能是多个委托的 sub（同一主体可被多次授予）。
  // 在图上以“目标主体所持有的顶点集合”为汇点 super-target。
  const targetVertexDigests = records
    .filter((n) => jwkEquals(n.model.sub, targetKey) && active[idOf.get(n.digest)])
    .map((n) => n.digest)
    .sort();
  if (targetVertexDigests.length === 0 ||
      !targetVertexDigests.some((d) => reachable[idOf.get(d)])) {
    return fail(new AuditError('TARGET_UNREACHABLE', 'target', 'targetKey',
      `目标主体在浮标 "${buoy}"、评估时刻 ${now} 下从根不可达`
      + `${targetVertexDigests.length === 0 ? '（集合中不存在以目标为主体且允许该浮标的委托）' : '（所有指向目标的路径均已失效）'}`));
  }

  // ---- 建容量网络 ----
  // 结构性质：每条委托恰声明一个 parent，故每个委托顶点入度为 1，整图是以根
  // 为起点的有根树，同一主体只可能在“多个顶点的 sub”处合并（目标汇）。
  // 网络：顶点 = 根 + 委托顶点 + 超汇 T。
  //   委托边 parent -> child：容量 = child.transfer（边声明的可转移容量）；
  //   目标委托顶点 -> T：容量 = 该委托的 maxSamples（目标主体在该授予下
  //     可自用的上限）。
  // schema 已保证 transfer <= 自身 maxSamples，中转顶点的自身上限不会先于
  // 其入边收口，无需显式拆点；最大流值即目标主体在给定浮标/时刻最多可获得
  // 的采样额度，残量网络割即能阻断更多采样的最小边集。
  const T = V;
  const VC = V + 1;
  const netEdges = [];
  for (const e of liveEdges) {
    netEdges.push({
      from: e.from, to: e.to,
      capacity: e.node.model.transfer,
      kind: 'delegation', node: e.node,
    });
  }
  const targetVertexIds = new Set(targetVertexDigests.map((d) => idOf.get(d)));
  for (const d of targetVertexDigests) {
    const n = nodes.get(d);
    netEdges.push({ from: idOf.get(d), to: T, capacity: n.model.maxSamples, kind: 'sink', node: n });
  }

  const mf = maxFlow(VC, netEdges, 0, T);
  const mc = minCut(VC, netEdges, 0, T);

  // 每个委托顶点恰有一条入边；记录 顶点id -> 入边索引
  const incomingEdge = new Map();
  const delegRows = [];
  netEdges.forEach((e, ei) => {
    if (e.kind === 'delegation') {
      incomingEdge.set(e.to, ei);
      delegRows.push({ ei, e });
    }
  });

  // 流量边：委托边按本载荷摘要、父摘要稳定排列
  const flowEdges = delegRows.map(({ ei, e }) => {
    const n = e.node;
    const m = n.model;
    return {
      type: 'delegation',
      parentDigest: m.parent,
      payloadDigest: n.digest,
      issThumbprint: n.issThumbprint,
      subThumbprint: n.subThumbprint,
      transfer: m.transfer,
      flow: mf.flow.get(ei),
      residual: mf.residual.get(ei),
    };
  }).sort((a, b) => {
    if (a.payloadDigest !== b.payloadDigest) {
      return a.payloadDigest < b.payloadDigest ? -1 : 1;
    }
    return a.parentDigest < b.parentDigest ? -1 : a.parentDigest > b.parentDigest ? 1 : 0;
  });

  // 顶点剩余容量：每个委托顶点入度为 1，入边实流即经该顶点流入的额度
  // （继续下转 + 目标自用）；剩余 = maxSamples - 入流。按摘要稳定排列，
  // 含全部顶点（失效/不可达顶点同样列出，标注状态，便于核对过滤结果）。
  const vertices = [];
  for (const d of digestOrder) {
    const id = idOf.get(d);
    const n = nodes.get(d);
    const inEi = incomingEdge.get(id);
    const inflow = active[id] && inEi !== undefined ? mf.flow.get(inEi) : 0;
    vertices.push({
      payloadDigest: d,
      parentDigest: n.model.parent,
      issThumbprint: n.issThumbprint,
      subThumbprint: n.subThumbprint,
      nbf: n.model.nbf,
      exp: n.model.exp,
      aud: [...n.model.aud],
      maxSamples: n.model.maxSamples,
      transfer: n.model.transfer,
      status: active[id] ? 'active' : 'inactive',
      inactiveReason: inactiveReason.get(id) ?? null,
      inflow,
      remaining: active[id] ? Math.max(0, n.model.maxSamples - inflow) : null,
      reachable: reachable[id],
      isTarget: targetVertexIds.has(id),
    });
  }
  vertices.sort((a, b) => (a.payloadDigest < b.payloadDigest ? -1 : 1));

  // 最小割证据：割边只可能是委托边（transfer 收口）或入目标汇边
  // （目标主体某授予的 maxSamples 收口）；按割边载荷摘要稳定排列。
  const cut = mc.cutEdges.map((ei) => {
    const e = netEdges[ei];
    const n = e.node;
    return {
      type: e.kind === 'sink' ? 'target' : 'delegation',
      parentDigest: n.model.parent,
      payloadDigest: n.digest,
      issThumbprint: n.issThumbprint,
      subThumbprint: n.subThumbprint,
      capacity: e.capacity,
    };
  }).sort((a, b) => (a.payloadDigest < b.payloadDigest ? -1 : a.payloadDigest > b.payloadDigest ? 1 : 0));

  // 残量网络中仍自根可达的顶点 = 最小割源侧
  const sourceSideVertices = ['__ROOT__'];
  for (const d of digestOrder) {
    if (mc.reachable[idOf.get(d)]) sourceSideVertices.push(d);
  }


  return {
    ok: true,
    audit: {
      now,
      buoy,
      rootKeyThumbprint: rootDigest,
      targetThumbprint: jwkThumbprint(targetKey),
      delegationCount: records.length,
      vertices,
      flowEdges,
      minCut: {
        edges: cut,
        capacity: mc.cutCapacity,
        sourceSideVertices,
      },
      verdict: {
        reachable: true,
        maxTransferable: mf.value,
        reason: `容量审计通过：在浮标 "${buoy}"、评估时刻 ${now}，根到目标主体的最大可转移采样额度为 ${mf.value} 次`
          + `（最小割容量 ${mc.cutCapacity}，由 ${cut.length} 条边构成）`,
      },
    },
  };
}

function normalizeError(e, fallbackNode) {
  if (e instanceof AuditError) return e;
  const err = new AuditError(e.code || 'JSON_SYNTAX', fallbackNode, e.field || null, e.message);
  if (e.line !== undefined) err.line = e.line;
  if (e.col !== undefined) err.col = e.col;
  if (e.pos !== undefined) err.pos = e.pos;
  return err;
}

export {
  auditCapacity,
  detectCycle,
  MAX_GRAPH_NODES,
};
