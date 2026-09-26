'use strict';

// 严格规范 JSON (JCS, RFC 8785) 解析与序列化。
//
// 解析阶段拒绝：重复键、非有限数、非法字面量、尾随内容等；
// 数字词法按 JSON 路径记录原文，供领域层判定“不安全整数 / 越界整数”；
// 对象键序要求与 JCS 规范顺序一致（“对象键序不规范”可定位）；
// 序列化阶段按 JCS 排序对象键、数字按最短 round-trip 形式输出，
// 从而保证“同一套规范 JSON 字节”逐跳验签。

const INT32_MIN = -2147483648;
const INT32_MAX = 2147483647;
const INT53_MIN = Number.MIN_SAFE_INTEGER; // -(2^53-1)
const INT53_MAX = Number.MAX_SAFE_INTEGER; //  2^53-1

const T = {
  LBRACE: 0, RBRACE: 1, LBRACKET: 2, RBRACKET: 3,
  COLON: 4, COMMA: 5, STRING: 6, NUMBER: 7,
  TRUE: 8, FALSE: 9, NULL: 10, EOF: 11,
};

function isDigit1to9(c) {
  return c >= 0x31 && c <= 0x39;
}

function hexVal(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

class Parser {
  constructor(text, { requireOrderedKeys = true } = {}) {
    if (typeof text !== 'string') throw new TypeError('输入必须是字符串');
    this.s = text;
    this.n = text.length;
    this.i = 0;
    this.requireOrderedKeys = requireOrderedKeys;
    // JSON 路径 -> 数字词法信息 { raw, start, end }
    this.numbers = new Map();
  }

  locOf(pos) {
    const s = this.s;
    let line = 1;
    let col = 1;
    for (let k = 0; k < pos && k < s.length; k++) {
      if (s.charCodeAt(k) === 0x0a) { line++; col = 1; } else col++;
    }
    return { line, col };
  }

  fmtLoc(pos) {
    const { line, col } = this.locOf(pos >= this.n ? this.n : pos);
    return `${line}:${col}`;
  }

  error(code, pos, message) {
    const { line, col } = this.locOf(pos >= this.n ? this.n : pos);
    const err = new Error(message);
    err.code = code;
    err.pos = pos;
    err.line = line;
    err.col = col;
    return err;
  }

  skipWs() {
    const s = this.s;
    while (this.i < this.n) {
      const c = s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  peekToken() {
    this.skipWs();
    if (this.i >= this.n) return T.EOF;
    const c = this.s.charCodeAt(this.i);
    switch (c) {
      case 0x7b: return T.LBRACE;
      case 0x7d: return T.RBRACE;
      case 0x5b: return T.LBRACKET;
      case 0x5d: return T.RBRACKET;
      case 0x3a: return T.COLON;
      case 0x2c: return T.COMMA;
      case 0x22: return T.STRING;
      case 0x74: return T.TRUE;
      case 0x66: return T.FALSE;
      case 0x6e: return T.NULL;
      default:
        if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return T.NUMBER;
        return -1;
    }
  }

  readStringToken() {
    const s = this.s;
    const start = this.i;
    this.i++; // 开引号
    let value = '';
    while (true) {
      if (this.i >= this.n) throw this.error('JSON_SYNTAX', this.n, '字符串未闭合');
      const c = s.charCodeAt(this.i);
      if (c < 0x20) {
        throw this.error('JSON_SYNTAX', this.i,
          `字符串内含未转义控制字符 U+${c.toString(16).padStart(4, '0')}（位置 ${this.fmtLoc(this.i)}）`);
      }
      if (c === 0x22) { this.i++; break; }
      if (c === 0x5c) {
        this.i++;
        if (this.i >= this.n) throw this.error('JSON_SYNTAX', this.i, '转义序列不完整');
        const e = s.charCodeAt(this.i);
        switch (e) {
          case 0x22: value += '"'; this.i++; break;
          case 0x5c: value += '\\'; this.i++; break;
          case 0x2f: value += '/'; this.i++; break;
          case 0x62: value += '\b'; this.i++; break;
          case 0x66: value += '\f'; this.i++; break;
          case 0x6e: value += '\n'; this.i++; break;
          case 0x72: value += '\r'; this.i++; break;
          case 0x74: value += '\t'; this.i++; break;
          case 0x75: {
            if (this.i + 4 >= this.n) throw this.error('JSON_SYNTAX', this.i, '\\u 转义需要 4 位十六进制');
            let cp = 0;
            for (let k = 1; k <= 4; k++) {
              const h = hexVal(s.charCodeAt(this.i + k));
              if (h < 0) throw this.error('JSON_SYNTAX', this.i, '\\u 转义含非十六进制数字');
              cp = (cp << 4) | h;
            }
            this.i += 5;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
              if (s.charCodeAt(this.i) !== 0x5c || s.charCodeAt(this.i + 1) !== 0x75) {
                throw this.error('JSON_SYNTAX', this.i, '高代理项后必须跟 \\uXXXX 低代理项');
              }
              let lo = 0;
              for (let k = 2; k <= 5; k++) {
                const h = hexVal(s.charCodeAt(this.i + k));
                if (h < 0) throw this.error('JSON_SYNTAX', this.i, '低代理项 \\u 转义含非十六进制数字');
                lo = (lo << 4) | h;
              }
              if (lo < 0xDC00 || lo > 0xDFFF) {
                throw this.error('JSON_SYNTAX', this.i, '非法的 UTF-16 代理对');
              }
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
              this.i += 6;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
              throw this.error('JSON_SYNTAX', this.i, '出现孤立的低代理项');
            }
            value += String.fromCodePoint(cp);
            break;
          }
          default:
            throw this.error('JSON_SYNTAX', this.i, `非法转义字符 \\${s[this.i]}`);
        }
      } else {
        value += s[this.i];
        this.i++;
      }
    }
    return [value, start, this.i];
  }

  // 严格按 JSON 数字文法读取
  readNumberToken() {
    const s = this.s;
    const start = this.i;
    if (s.charCodeAt(this.i) === 0x2d) this.i++;
    if (this.i >= this.n) throw this.error('JSON_SYNTAX', start, '数字不完整');
    const c = s.charCodeAt(this.i);
    if (c === 0x30) {
      this.i++;
    } else if (isDigit1to9(c)) {
      while (this.i < this.n && s.charCodeAt(this.i) >= 0x30 && s.charCodeAt(this.i) <= 0x39) this.i++;
    } else {
      throw this.error('JSON_SYNTAX', this.i, `数字缺少整数部分（位置 ${this.fmtLoc(this.i)}）`);
    }
    if (this.i < this.n && s.charCodeAt(this.i) === 0x2e) {
      this.i++;
      if (this.i >= this.n || s.charCodeAt(this.i) < 0x30 || s.charCodeAt(this.i) > 0x39) {
        throw this.error('JSON_SYNTAX', this.i, `小数点后必须有数字（位置 ${this.fmtLoc(this.i)}）`);
      }
      while (this.i < this.n && s.charCodeAt(this.i) >= 0x30 && s.charCodeAt(this.i) <= 0x39) this.i++;
    }
    if (this.i < this.n && (s.charCodeAt(this.i) === 0x65 || s.charCodeAt(this.i) === 0x45)) {
      this.i++;
      if (this.i < this.n && (s.charCodeAt(this.i) === 0x2b || s.charCodeAt(this.i) === 0x2d)) this.i++;
      if (this.i >= this.n || s.charCodeAt(this.i) < 0x30 || s.charCodeAt(this.i) > 0x39) {
        throw this.error('JSON_SYNTAX', this.i, `指数部分必须有数字（位置 ${this.fmtLoc(this.i)}）`);
      }
      while (this.i < this.n && s.charCodeAt(this.i) >= 0x30 && s.charCodeAt(this.i) <= 0x39) this.i++;
    }
    const raw = s.slice(start, this.i);
    const num = Number(raw);
    if (!Number.isFinite(num)) {
      throw this.error('NUMBER_NON_FINITE', start,
        `非有限数：${raw}（位置 ${this.fmtLoc(start)}），JSON 数字必须有限`);
    }
    return [num, raw, start, this.i];
  }

  readLiteral(expected, value) {
    const s = this.s;
    const start = this.i;
    if (this.i + expected.length > this.n || s.slice(this.i, this.i + expected.length) !== expected) {
      throw this.error('JSON_SYNTAX', this.i, `非法字面量（位置 ${this.fmtLoc(this.i)}，期望 ${expected}）`);
    }
    this.i += expected.length;
    return [value, start, this.i];
  }

  parseValue(path) {
    const tok = this.peekToken();
    const start = this.i;
    switch (tok) {
      case T.LBRACE:
        return this.parseObject(path, start);
      case T.LBRACKET:
        return this.parseArray(path, start);
      case T.STRING: {
        const [v, st, en] = this.readStringToken();
        return { value: v, start: st, end: en };
      }
      case T.NUMBER: {
        const [v, raw, st, en] = this.readNumberToken();
        const { line, col } = this.locOf(st);
        this.numbers.set(path, { raw, start: st, end: en, line, col });
        return { value: v, start: st, end: en };
      }
      case T.TRUE: {
        const [v, st, en] = this.readLiteral('true', true);
        return { value: v, start: st, end: en };
      }
      case T.FALSE: {
        const [v, st, en] = this.readLiteral('false', false);
        return { value: v, start: st, end: en };
      }
      case T.NULL: {
        const [v, st, en] = this.readLiteral('null', null);
        return { value: v, start: st, end: en };
      }
      default:
        throw this.error('JSON_SYNTAX', this.i >= this.n ? this.n : this.i,
          `JSON 语法错误：位置 ${this.fmtLoc(this.i)} 处意外字符`);
    }
  }

  parseObject(path, start) {
    this.i++; // {
    const obj = {};
    const seen = new Map(); // 键 -> 首次出现位置
    const memberOrder = []; // [{ key, pos }]
    this.skipWs();
    if (this.peekToken() === T.RBRACE) {
      this.i++;
      return { value: obj, start, end: this.i };
    }
    while (true) {
      this.skipWs();
      if (this.peekToken() !== T.STRING) {
        throw this.error('JSON_SYNTAX', this.i >= this.n ? this.n : this.i,
          `对象成员名必须是字符串（${path}，位置 ${this.fmtLoc(this.i)}）`);
      }
      const keyStart = this.i;
      const [key] = this.readStringToken();
      const memberPath = path === '$' ? `$["${key}"]` : `${path}["${key}"]`;
      if (seen.has(key)) {
        const prev = seen.get(key);
        throw this.error(
          'DUPLICATE_KEY',
          keyStart,
          `重复键：${memberPath}（首次出现于 ${this.fmtLoc(prev)}，重复于 ${this.fmtLoc(keyStart)}）`,
        );
      }
      seen.set(key, keyStart);
      memberOrder.push({ key, pos: keyStart });
      this.skipWs();
      if (this.peekToken() !== T.COLON) {
        throw this.error('JSON_SYNTAX', this.i, `成员 "${key}" 后缺少冒号（${memberPath}）`);
      }
      this.i++;
      const child = this.parseValue(memberPath);
      obj[key] = child.value;
      this.skipWs();
      const nt = this.peekToken();
      if (nt === T.COMMA) {
        this.i++;
        this.skipWs();
        if (this.peekToken() === T.RBRACE) {
          throw this.error('JSON_SYNTAX', this.i, `对象末尾存在多余逗号（${memberPath}）`);
        }
        continue;
      }
      if (nt === T.RBRACE) { this.i++; break; }
      throw this.error('JSON_SYNTAX', this.i >= this.n ? this.n : this.i,
        `成员之间缺少逗号或对象未闭合（${memberPath}）`);
    }

    if (this.requireOrderedKeys && memberOrder.length > 1) {
      const keys = memberOrder.map((m) => m.key);
      const sorted = [...keys].sort(compareJcsKeys);
      for (let k = 0; k < keys.length; k++) {
        if (keys[k] !== sorted[k]) {
          const bad = memberOrder[k];
          throw this.error(
            'KEY_ORDER',
            bad.pos,
            `对象键序不规范：${path} 中成员 "${bad.key}" 未按 JCS（UTF-8 码点序）排列` +
            `（位置 ${this.fmtLoc(bad.pos)}，规范顺序应为 ${JSON.stringify(sorted)}）`,
          );
        }
      }
    }
    return { value: obj, start, end: this.i };
  }

  parseArray(path, start) {
    this.i++; // [
    const arr = [];
    this.skipWs();
    if (this.peekToken() === T.RBRACKET) {
      this.i++;
      return { value: arr, start, end: this.i };
    }
    let idx = 0;
    while (true) {
      const child = this.parseValue(`${path}[${idx}]`);
      arr.push(child.value);
      idx++;
      this.skipWs();
      const nt = this.peekToken();
      if (nt === T.COMMA) {
        this.i++;
        this.skipWs();
        if (this.peekToken() === T.RBRACKET) {
          throw this.error('JSON_SYNTAX', this.i, `数组末尾存在多余逗号（${path}）`);
        }
        continue;
      }
      if (nt === T.RBRACKET) { this.i++; break; }
      throw this.error('JSON_SYNTAX', this.i >= this.n ? this.n : this.i,
        `数组元素之间缺少逗号或数组未闭合（${path}）`);
    }
    return { value: arr, start, end: this.i };
  }

  parse() {
    const root = this.parseValue('$');
    this.skipWs();
    if (this.i !== this.n) {
      throw this.error('JSON_TRAILING', this.i,
        `文档结尾后存在多余内容（位置 ${this.fmtLoc(this.i)}）`);
    }
    return {
      value: root.value,
      numbers: this.numbers,
      start: root.start,
      end: root.end,
    };
  }
}

// ---------- JCS 序列化 ----------

// JCS 数字序列化：最短 round-trip 十进制。
// ECMAScript Number.prototype.toString(10) 自 ES2018 起给出最短 round-trip，
// 其科学计数法门槛（>=1e21 或 <1e-6）与 JCS (RFC 8785 §3.2.2.3) 一致。
export function serializeNumber(x) {
  if (Number.isNaN(x)) throw new Error('不能序列化 NaN');
  if (!Number.isFinite(x)) throw new Error('不能序列化 Infinity');
  return x.toString(10); // 0 与 -0 均输出 "0"
}

function escapeString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (cp === 0x08) out += '\\b';
    else if (cp === 0x09) out += '\\t';
    else if (cp === 0x0a) out += '\\n';
    else if (cp === 0x0c) out += '\\f';
    else if (cp === 0x0d) out += '\\r';
    else if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, '0')}`;
    else out += ch; // JCS 不转义非 ASCII
  }
  return out + '"';
}

// JCS UTF-8 码点排序
export function compareJcsKeys(a, b) {
  const ua = Buffer.from(a, 'utf8');
  const ub = Buffer.from(b, 'utf8');
  const len = Math.min(ua.length, ub.length);
  for (let i = 0; i < len; i++) {
    if (ua[i] !== ub[i]) return ua[i] - ub[i];
  }
  return ua.length - ub.length;
}

export function canonicalize(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return serializeNumber(value);
  if (t === 'string') return escapeString(value);
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v ?? null)).join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value).sort(compareJcsKeys);
    return '{' + keys.map((k) => `${escapeString(k)}:${canonicalize(value[k])}`).join(',') + '}';
  }
  throw new Error(`不可序列化的值类型：${t}`);
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

// 严格解析。requireOrderedKeys 为 true（默认）时，
// 每个对象的键必须已按 JCS 顺序排列，否则抛出 KEY_ORDER。
export function parseStrict(text, options) {
  const p = new Parser(text, options);
  const r = p.parse();
  return { value: r.value, numbers: r.numbers, start: r.start, end: r.end };
}

export function parseCanonical(text, options) {
  const parsed = parseStrict(text, options);
  return {
    value: parsed.value,
    numbers: parsed.numbers,
    bytes: canonicalBytes(parsed.value),
    start: parsed.start,
    end: parsed.end,
  };
}

// 判定数字词法是否为整数字面量（无小数点、无指数）
function isIntegerLexeme(raw) {
  return !/[.eE]/.test(raw);
}

// 领域层整数校验：结合词法原文识别“不安全整数”（精度丢失）与“越界整数”。
// path 为 JSON 路径（如 $["maxSamples"]）；min/max 默认 int32 范围。
export function requireBoundedInteger(numbers, path, { min = INT32_MIN, max = INT32_MAX, label = '整数' } = {}) {
  const meta = numbers.get(path);
  if (!meta) {
    const e = new Error(`内部错误：路径 ${path} 缺少数字词法信息`);
    e.code = 'INTERNAL';
    throw e;
  }
  const { raw, start, line, col } = meta;
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    const e = new Error(`${label}非有限数（${path}）：${raw}`);
    e.code = 'NUMBER_NON_FINITE';
    e.pos = start; e.line = line; e.col = col;
    throw e;
  }
  if (isIntegerLexeme(raw)) {
    // 用 BigInt 做精确边界判定，捕获 2^53 以上的精度丢失
    const bi = BigInt(raw);
    if (bi < BigInt(INT53_MIN) || bi > BigInt(INT53_MAX)) {
      const e = new Error(
        `不安全整数（${path}）：${raw} 超出安全整数范围 ±(2^53-1)，无法精确保留`,
      );
      e.code = 'NUMBER_UNSAFE_INTEGER';
      e.pos = start; e.line = line; e.col = col;
      throw e;
    }
    if (bi < BigInt(min) || bi > BigInt(max)) {
      const e = new Error(
        `越界整数（${path}）：${raw} 不在允许区间 [${min}, ${max}] 内`,
      );
      e.code = 'NUMBER_OUT_OF_RANGE';
      e.pos = start; e.line = line; e.col = col;
      throw e;
    }
    return Number(bi);
  }
  // 小数 / 指数形式
  if (!Number.isInteger(value)) {
    const e = new Error(`${label}必须是整数（${path}）：${raw}`);
    e.code = 'NUMBER_NOT_INTEGER';
    e.pos = start; e.line = line; e.col = col;
    throw e;
  }
  if (value < min || value > max) {
    const e = new Error(`越界整数（${path}）：${raw} 不在允许区间 [${min}, ${max}] 内`);
    e.code = 'NUMBER_OUT_OF_RANGE';
    e.pos = start; e.line = line; e.col = col;
    throw e;
  }
  return value;
}

export const LIMITS = { INT32_MIN, INT32_MAX, INT53_MIN, INT53_MAX };
