'use strict';

// 受限委托链逐跳核验。
//
// 链对象（每份均为规范 JSON，键按 JCS 顺序）：
//   委托  delegation: { aud, exp, iss, maxSamples, nbf, sig, sub, typ }
//   命令  command:    { aud, buoy, exp, iss, maxSamples, nbf, samples, sig, sub, typ }
//   - iss/sub: P-256 JWK { crv:"P-256", kty:"EC", x, y }（base64url，无填充）
//   - nbf/exp: 有效期（unix 秒，int32 区间内的整数）
//   - aud:     允许浮标集合（非空字符串数组，元素唯一）
//   - maxSamples: 采样上限（int32 区间内的整数，>=0）
//   - sig:     对“去掉 sig 成员后的规范 JSON 字节”的 ECDSA P-256/SHA-256
//              签名（IEEE-P1363 r||s，base64url 无填充）
//   末端命令额外字段：buoy（目标浮标）、samples（请求采样量，>=1）
//
// 链规则：
//   1. 链首 iss 必须等于根公钥；其后每跳 iss 必须等于上一跳 sub；
//   2. 每跳仅允许收紧：nbf 不提前、exp 不延后、aud 为上一跳子集、
//      maxSamples 不大于上一跳；
//   3. 每跳在评估时刻必须处于有效期内；
//   4. 末端命令的 buoy 须获全部上游 aud 允许，samples 不超过任一 maxSamples；
//   5. 任一失败即拒绝，并定位首个限制字段或签名失败跳。

import crypto from 'node:crypto';
import {
  parseCanonical,
  canonicalBytes,
  requireBoundedInteger,
  LIMITS,
} from './canonical.js';

const MAX_CHAIN_LEN = 16;
const MAX_OBJECT_BYTES = 64 * 1024;
const MAX_BUOYS = 256;
const MAX_BUOY_ID_LEN = 128;

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  let b = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  return Buffer.from(b, 'base64');
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function jwkThumbprint(jwk) {
  // RFC 7638 所需成员按字典序的规范 JSON
  const canon = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return sha256Hex(Buffer.from(canon, 'utf8'));
}

function jwkEquals(a, b) {
  return a && b && a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

class ChainError extends Error {
  constructor(code, hop, field, message, extra = {}) {
    super(message);
    this.code = code;
    this.hop = hop;
    this.field = field;
    Object.assign(this, extra);
  }
}

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// 校验 P-256 JWK 形状；返回规范化后的 {kty,crv,x,y}
function validateJwk(value, hop, field) {
  if (!isPlainObject(value)) {
    throw new ChainError('SCHEMA', hop, field, `${field} 必须是 JWK 对象`);
  }
  const keys = Object.keys(value).sort();
  const want = ['crv', 'kty', 'x', 'y'];
  if (keys.length !== 4 || !want.every((k, i) => keys[i] === k)) {
    throw new ChainError('SCHEMA', hop, field,
      `${field} 必须恰好包含成员 crv,kty,x,y（实际：${keys.join(',')}）`);
  }
  if (value.kty !== 'EC') {
    throw new ChainError('SCHEMA', hop, `${field}["kty"]`, `${field} 的 kty 必须为 "EC"`);
  }
  if (value.crv !== 'P-256') {
    throw new ChainError('SCHEMA', hop, `${field}["crv"]`, `${field} 的 crv 必须为 "P-256"`);
  }
  for (const coord of ['x', 'y']) {
    const v = value[coord];
    if (typeof v !== 'string') {
      throw new ChainError('SCHEMA', hop, `${field}["${coord}"]`, `${field} 的 ${coord} 必须是 base64url 字符串`);
    }
    const raw = b64urlDecode(v);
    if (raw === null || raw.length !== 32 || b64urlEncode(raw) !== v) {
      throw new ChainError('SCHEMA', hop, `${field}["${coord}"]`,
        `${field} 的 ${coord} 必须是 32 字节的规范 base64url（无填充）`);
    }
  }
  return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
}

function validateAud(value, hop) {
  const field = '$["aud"]';
  if (!Array.isArray(value) || value.length === 0) {
    throw new ChainError('SCHEMA', hop, field, 'aud 必须是非空数组（允许浮标集合）');
  }
  if (value.length > MAX_BUOYS) {
    throw new ChainError('SCHEMA', hop, field, `aud 元素过多（>${MAX_BUOYS}）`);
  }
  const seen = new Set();
  for (let i = 0; i < value.length; i++) {
    const b = value[i];
    if (typeof b !== 'string' || b.length === 0 || b.length > MAX_BUOY_ID_LEN) {
      throw new ChainError('SCHEMA', hop, `$["aud"][${i}]`, `浮标标识必须是 1..${MAX_BUOY_ID_LEN} 字符的字符串`);
    }
    if (seen.has(b)) {
      throw new ChainError('SCHEMA', hop, `$["aud"][${i}]`, `aud 中浮标标识重复："${b}"`);
    }
    seen.add(b);
  }
  return value;
}

// 校验单个链对象的模式与整数边界；返回规范化字段
function validateObjectSchema(parsed, index, total) {
  const hop = index;
  const obj = parsed.value;
  const numbers = parsed.numbers;
  if (!isPlainObject(obj)) {
    throw new ChainError('SCHEMA', hop, '$', `第 ${index} 跳必须是 JSON 对象`);
  }
  const typ = obj.typ;
  if (typ !== 'delegation' && typ !== 'command') {
    throw new ChainError('SCHEMA', hop, '$["typ"]', 'typ 必须是 "delegation" 或 "command"');
  }
  if (typ === 'command' && index !== total - 1) {
    throw new ChainError('SCHEMA', hop, '$["typ"]', 'command 对象只能位于链末端');
  }
  const required = ['aud', 'exp', 'iss', 'maxSamples', 'nbf', 'sig', 'sub', 'typ'];
  if (typ === 'command') required.push('buoy', 'samples');
  for (const k of required) {
    if (!(k in obj)) {
      throw new ChainError('SCHEMA', hop, '$', `缺少必需成员 "${k}"`);
    }
  }
  const allowed = new Set(required);
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) {
      throw new ChainError('SCHEMA', hop, `$["${k}"]`, `不允许的额外成员 "${k}"（疑似内容被改写）`);
    }
  }

  const iss = validateJwk(obj.iss, hop, '$["iss"]');
  const sub = validateJwk(obj.sub, hop, '$["sub"]');

  const nbf = requireBoundedInteger(numbers, '$["nbf"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期起 nbf ',
  });
  const exp = requireBoundedInteger(numbers, '$["exp"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期止 exp ',
  });
  if (nbf >= exp) {
    throw new ChainError('SCHEMA', hop, '$["nbf"]', `有效期无效：nbf(${nbf}) 必须早于 exp(${exp})`);
  }
  const maxSamples = requireBoundedInteger(numbers, '$["maxSamples"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '采样上限 maxSamples ',
  });
  const aud = validateAud(obj.aud, hop);

  if (typeof obj.sig !== 'string') {
    throw new ChainError('SCHEMA', hop, '$["sig"]', 'sig 必须是 base64url 字符串');
  }
  const sigRaw = b64urlDecode(obj.sig);
  if (sigRaw === null || sigRaw.length !== 64 || b64urlEncode(sigRaw) !== obj.sig) {
    throw new ChainError('SCHEMA', hop, '$["sig"]',
      'sig 必须是 64 字节 P1363 签名的规范 base64url（无填充）');
  }

  let buoy;
  let samples;
  if (typ === 'command') {
    if (typeof obj.buoy !== 'string' || obj.buoy.length === 0 || obj.buoy.length > MAX_BUOY_ID_LEN) {
      throw new ChainError('SCHEMA', hop, '$["buoy"]', 'buoy 必须是非空字符串（目标浮标）');
    }
    buoy = obj.buoy;
    samples = requireBoundedInteger(numbers, '$["samples"]', {
      min: 1, max: LIMITS.INT32_MAX, label: '采样量 samples ',
    });
  }

  return { typ, iss, sub, nbf, exp, aud, maxSamples, sig: obj.sig, sigRaw, buoy, samples };
}

function importJwk(jwk) {
  return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
}

// 主入口：核验整条链。
// input: { rootKeyText, objectTexts: string[], now?: number(秒) }
// 返回 { ok:true, evidence } 或 { ok:false, error:{code,hop,field,message,line,col} }
function verifyChain(input) {
  const now = input.now === undefined ? Math.floor(Date.now() / 1000) : input.now;
  if (!Number.isInteger(now) || now < 0 || now > LIMITS.INT32_MAX) {
    return fail(new ChainError('SCHEMA', -1, 'now', '评估时刻 now 必须是 int32 区间内的整数秒'));
  }

  // ---- 根公钥 ----
  let rootKey;
  try {
    if (typeof input.rootKeyText !== 'string' || input.rootKeyText.length === 0) {
      throw new ChainError('ROOT_KEY_INVALID', -1, 'rootKey', '根公钥不能为空');
    }
    if (Buffer.byteLength(input.rootKeyText, 'utf8') > MAX_OBJECT_BYTES) {
      throw new ChainError('ROOT_KEY_INVALID', -1, 'rootKey', '根公钥文档过大');
    }
    const parsed = parseCanonical(input.rootKeyText);
    rootKey = validateJwk(parsed.value, -1, 'rootKey');
  } catch (e) {
    return fail(normalizeError(e, -1, 'rootKey'));
  }

  // ---- 链对象 ----
  const texts = input.objectTexts;
  if (!Array.isArray(texts) || texts.length === 0) {
    return fail(new ChainError('SCHEMA', -1, 'objects', '委托链不能为空（至少一份末端命令）'));
  }
  if (texts.length > MAX_CHAIN_LEN) {
    return fail(new ChainError('SCHEMA', -1, 'objects', `链过长（>${MAX_CHAIN_LEN} 跳）`));
  }

  const hops = [];
  for (let i = 0; i < texts.length; i++) {
    const text = texts[i];
    if (typeof text !== 'string' || text.length === 0) {
      return fail(new ChainError('SCHEMA', i, '$', `第 ${i} 跳不是非空字符串`));
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_OBJECT_BYTES) {
      return fail(new ChainError('SCHEMA', i, '$', `第 ${i} 跳文档过大（>${MAX_OBJECT_BYTES} 字节）`));
    }
    let parsed;
    try {
      parsed = parseCanonical(text);
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }
    let model;
    try {
      model = validateObjectSchema(parsed, i, texts.length);
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }

    // 规范载荷字节 = 去掉 sig 后的 JCS 字节（与签发时同一套字节）
    const { sig, ...payload } = parsed.value;
    const payloadBytes = canonicalBytes(payload);
    const payloadDigest = sha256Hex(payloadBytes);

    // 1) 逐跳验签（用本跳 iss 的公钥）
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
      return fail(new ChainError('BAD_SIGNATURE', i, '$["sig"]',
        `第 ${i} 跳签名验证失败（签名与规范载荷摘要不符，载荷 SHA-256=${payloadDigest}）`));
    }

    // 2) 链式签发关系
    if (i === 0) {
      if (!jwkEquals(model.iss, rootKey)) {
        return fail(new ChainError('ISSUER_NOT_ROOT', 0, '$["iss"]',
          '链首签发者不等于根公钥（iss 与 rootKey 的 JWK 不一致）'));
      }
    } else if (!jwkEquals(model.iss, hops[i - 1].model.sub)) {
      return fail(new ChainError('ISSUER_MISMATCH', i, '$["iss"]',
        `第 ${i} 跳委托并非由前一主体签发（iss ≠ 第 ${i - 1} 跳 sub）`));
    }

    // 3) 收紧检查（仅允许收紧，定位首个违规字段）
    if (i > 0) {
      const prev = hops[i - 1].model;
      if (model.nbf < prev.nbf) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["nbf"]',
          `第 ${i} 跳有效期起早于上一跳（${model.nbf} < ${prev.nbf}），时间窗只允许收紧`));
      }
      if (model.exp > prev.exp) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["exp"]',
          `第 ${i} 跳有效期止晚于上一跳（${model.exp} > ${prev.exp}），时间窗只允许收紧`));
      }
      const prevAud = new Set(prev.aud);
      const extra = model.aud.filter((b) => !prevAud.has(b));
      if (extra.length > 0) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["aud"]',
          `第 ${i} 跳浮标集合超出上一跳允许范围（新增：${extra.join(', ')}），浮标集合只允许收紧`));
      }
      if (model.maxSamples > prev.maxSamples) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["maxSamples"]',
          `第 ${i} 跳采样上限大于上一跳（${model.maxSamples} > ${prev.maxSamples}），采样上限只允许收紧`));
      }
    }

    // 4) 有效期（评估时刻须落在每跳时间窗内）
    if (now < model.nbf) {
      return fail(new ChainError('TIME_NOT_YET_VALID', i, '$["nbf"]',
        `第 ${i} 跳尚未生效（now=${now} < nbf=${model.nbf}）`));
    }
    if (now > model.exp) {
      return fail(new ChainError('TIME_EXPIRED', i, '$["exp"]',
        `第 ${i} 跳已过期（now=${now} > exp=${model.exp}）`));
    }

    hops.push({ model, payloadDigest, sig: model.sig });
  }

  // ---- 末端命令：浮标须获全部上游允许、采样量不超过任一上限 ----
  const last = hops[hops.length - 1].model;
  if (last.typ !== 'command') {
    return fail(new ChainError('SCHEMA', hops.length - 1, '$["typ"]', '链末端必须是 command 对象'));
  }
  for (let j = 0; j < hops.length; j++) {
    if (!hops[j].model.aud.includes(last.buoy)) {
      return fail(new ChainError('BUOY_NOT_ALLOWED', j, '$["aud"]',
        `末端浮标 "${last.buoy}" 未获第 ${j} 跳允许（不在该跳 aud 集合内）`));
    }
  }
  for (let j = 0; j < hops.length; j++) {
    if (last.samples > hops[j].model.maxSamples) {
      return fail(new ChainError('SAMPLES_EXCEEDED', j, '$["maxSamples"]',
        `采样量 ${last.samples} 超过第 ${j} 跳采样上限 ${hops[j].model.maxSamples}`));
    }
  }

  // ---- 汇总证据 ----
  const hopEvidence = [];
  let curAud = null;
  let curNbf = 0;
  let curExp = LIMITS.INT32_MAX;
  let curCap = LIMITS.INT32_MAX;
  for (let i = 0; i < hops.length; i++) {
    const m = hops[i].model;
    curAud = curAud === null ? [...m.aud] : curAud.filter((b) => m.aud.includes(b));
    curNbf = Math.max(curNbf, m.nbf);
    curExp = Math.min(curExp, m.exp);
    curCap = Math.min(curCap, m.maxSamples);
    hopEvidence.push({
      index: i,
      typ: m.typ,
      issThumbprint: jwkThumbprint(m.iss),
      subThumbprint: jwkThumbprint(m.sub),
      signature: hops[i].sig,
      payloadDigest: hops[i].payloadDigest,
      tightened: { nbf: curNbf, exp: curExp, aud: [...curAud], maxSamples: curCap },
    });
  }

  return {
    ok: true,
    evidence: {
      now,
      rootKeyThumbprint: jwkThumbprint(rootKey),
      hops: hopEvidence,
      finalConstraints: { nbf: curNbf, exp: curExp, aud: curAud, maxSamples: curCap },
      verdict: {
        allow: true,
        buoy: last.buoy,
        samples: last.samples,
        reason: `链核验通过：准许浮标 "${last.buoy}" 采样 ${last.samples} 次`,
      },
    },
  };
}

function normalizeError(e, hop, field) {
  if (e instanceof ChainError) return e;
  const code = e.code || 'JSON_SYNTAX';
  const err = new ChainError(code, hop, field || e.field || null, e.message);
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
      hop: err.hop,
      field: err.field ?? null,
      message: err.message,
      line: err.line ?? null,
      col: err.col ?? null,
    },
  };
}

export {
  verifyChain,
  b64urlEncode,
  b64urlDecode,
  jwkThumbprint,
  sha256Hex,
  LIMITS,
  MAX_CHAIN_LEN,
};
