'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseStrict,
  canonicalize,
  canonicalBytes,
  requireBoundedInteger,
  compareJcsKeys,
} from '../src/canonical.js';

test('规范序列化：对象键按 UTF-8 码点序，数字最短 round-trip', () => {
  assert.equal(
    canonicalize({ b: 1, a: [2, { d: true, c: null }] }),
    '{"a":[2,{"c":null,"d":true}],"b":1}',
  );
  assert.equal(canonicalize({ x: 0.0000001 }), '{"x":1e-7}');
  assert.equal(canonicalize({ x: 1e21 }), '{"x":1e+21}');
  assert.equal(canonicalize({ x: 100 }), '{"x":100}');
  assert.equal(canonicalize({ x: -0 }), '{"x":0}');
  assert.equal(canonicalize({ x: 'é' }), '{"x":"é"}');
  // RFC 8785 示例风格：emoji 排序
  const keys = ['€', 'A', '😀'];
  assert.deepEqual([...keys].sort(compareJcsKeys), ['A', '€', '😀']);
});

test('重复键被拒绝并定位', () => {
  const text = '{"a":1,"a":2}';
  assert.throws(() => parseStrict(text), (e) => {
    return e.code === 'DUPLICATE_KEY' && e.pos === 7;
  });
});

test('对象键序不规范被拒绝', () => {
  assert.throws(() => parseStrict('{"b":1,"a":2}'), (e) => e.code === 'KEY_ORDER');
  // 嵌套对象同样检查
  assert.throws(() => parseStrict('{"a":{"z":1,"a":2}}'), (e) => e.code === 'KEY_ORDER');
  // 关闭检查时可解析，且规范序列化输出排序后的字节
  const r = parseStrict('{"b":1,"a":2}', { requireOrderedKeys: false });
  assert.equal(canonicalize(r.value), '{"a":2,"b":1}');
});

test('非有限数词法被拒绝', () => {
  // 1e999 四舍五入为 Infinity；解析器直接拒绝
  assert.throws(() => parseStrict('{"x":1e999}'), (e) => e.code === 'NUMBER_NON_FINITE');
});

test('不安全整数（精度丢失）被拒绝', () => {
  const { numbers } = parseStrict('{"x":9007199254740993}');
  assert.throws(() => requireBoundedInteger(numbers, '$["x"]'), (e) => e.code === 'NUMBER_UNSAFE_INTEGER');
});

test('越界整数被拒绝（超过 int32 业务边界）', () => {
  const { numbers } = parseStrict('{"x":2147483648}');
  assert.throws(() => requireBoundedInteger(numbers, '$["x"]'), (e) => e.code === 'NUMBER_OUT_OF_RANGE');
  const ok = parseStrict('{"x":2147483647}');
  assert.equal(requireBoundedInteger(ok.numbers, '$["x"]'), 2147483647);
});

test('小数字面量用于整数字段被拒绝', () => {
  const { numbers } = parseStrict('{"x":1.5}');
  assert.throws(() => requireBoundedInteger(numbers, '$["x"]'), (e) => e.code === 'NUMBER_NOT_INTEGER');
});

test('语法错误：尾随内容 / 未闭合 / 非法字面量', () => {
  assert.throws(() => parseStrict('{}x'), (e) => e.code === 'JSON_TRAILING');
  assert.throws(() => parseStrict('{"a":'), (e) => e.code === 'JSON_SYNTAX');
  assert.throws(() => parseStrict('[1,]'), (e) => e.code === 'JSON_SYNTAX');
});

test('规范字节稳定性：重新序列化与原文一致（对规范文档）', () => {
  const text = '{"aud":["b1","b2"],"exp":100,"iss":{},"maxSamples":5,"nbf":0,"sub":{},"typ":"delegation"}';
  const r = parseStrict(text);
  assert.deepEqual(canonicalBytes(r.value), Buffer.from(text, 'utf8'));
});
