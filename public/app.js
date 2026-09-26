'use strict';

// 值班员页面逻辑：逐跳核验、证据留存。
// 关键约束：错误草稿不得覆盖上一份有效证据——
// lastValidEvidence 只在收到 ok:true 时更新。

const $ = (id) => document.getElementById(id);

// 上一份有效证据（跨多次核验保留）
let lastValidEvidence = null;

function splitObjects(raw) {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function short(s, n = 26) {
  if (!s) return '';
  return s.length <= n * 2 ? s : `${s.slice(0, n)}…${s.slice(-n)}`;
}

async function runVerify() {
  const rootKey = $('rootKey').value.trim();
  const objects = splitObjects($('objects').value);
  const nowRaw = $('now').value.trim();
  const body = { rootKey, objects };
  if (nowRaw) {
    if (!/^\d+$/.test(nowRaw)) {
      showLocalError({ code: 'BAD_REQUEST', hop: -1, field: 'now', message: '评估时刻必须是非负整数 unix 秒' });
      return;
    }
    body.now = Number(nowRaw);
  }

  $('verifyBtn').disabled = true;
  try {
    const resp = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await resp.json();
    if (result.ok) {
      lastValidEvidence = result.evidence; // 仅此处覆盖
      renderEvidence(result.evidence);
      hideError();
    } else {
      renderError(result.error);
      if (lastValidEvidence) renderEvidence(lastValidEvidence, true);
    }
  } catch (e) {
    showLocalError({ code: 'NETWORK', hop: -1, field: null, message: `请求失败：${e.message}` });
    if (lastValidEvidence) renderEvidence(lastValidEvidence, true);
  } finally {
    $('verifyBtn').disabled = false;
  }
}

function showLocalError(err) {
  renderError(err);
  if (lastValidEvidence) renderEvidence(lastValidEvidence, true);
}

function hideError() {
  $('errorPanel').hidden = true;
}

function renderError(err) {
  const panel = $('errorPanel');
  const body = $('errorBody');
  const hopText = err.hop === -1 || err.hop == null
    ? '根公钥 / 请求'
    : `第 ${err.hop} 跳${err.hop === 0 ? '（链首）' : ''}`;
  const loc = err.line ? `（行 ${err.line}，列 ${err.col}）` : '';
  body.innerHTML = `
    <dl>
      <dt>错误码</dt><dd class="mono">${esc(err.code || 'UNKNOWN')}</dd>
      <dt>定位</dt><dd>${esc(hopText)}${err.field ? ` · 字段 <code>${esc(err.field)}</code>` : ''}${loc}</dd>
      <dt>说明</dt><dd>${esc(err.message || '')}</dd>
    </dl>`;
  panel.hidden = false;
}

function renderConstraints(c) {
  return `nbf=<b>${c.nbf}</b>，exp=<b>${c.exp}</b>，` +
    `浮标=[${esc(c.aud.map((b) => `"${b}"`).join(', '))}]，` +
    `上限=<b>${c.maxSamples}</b>`;
}

function renderEvidence(ev, stale = false) {
  const panel = $('evidencePanel');
  const v = ev.verdict;
  $('verdict').innerHTML = `
    <p class="${v.allow ? 'allow' : 'deny'}">
      ${stale ? '⚠ 当前为<b>上一份有效证据</b>（本次核验被拒绝，证据未被覆盖）<br>' : ''}
      最终结论：${v.allow ? '✅ 准许' : '⛔ 拒绝'} —— ${esc(v.reason)}
    </p>
    <p style="font-size:12.5px;color:#9fb0c3">
      根公钥指纹 <code>${esc(ev.rootKeyThumbprint)}</code> · 评估时刻 ${ev.now}
    </p>`;

  const tbody = $('hopTable').querySelector('tbody');
  tbody.innerHTML = ev.hops.map((h) => `
    <tr>
      <td>${h.index}</td>
      <td><span class="pill ${h.typ === 'command' ? 'cmd' : ''}">${esc(h.typ)}</span></td>
      <td class="mono" title="${esc(h.signature)}">${esc(short(h.signature, 20))}</td>
      <td class="mono">${esc(h.payloadDigest)}</td>
      <td class="mono" title="iss">${esc(h.issThumbprint.slice(0, 16))}…</td>
      <td class="mono" title="sub">${esc(h.subThumbprint.slice(0, 16))}…</td>
      <td style="font-size:12px">${renderConstraints(h.tightened)}</td>
    </tr>`).join('');

  $('finalConstraints').innerHTML =
    `<p style="font-size:13px;margin-top:12px">收紧后的最终约束：${renderConstraints(ev.finalConstraints)}</p>`;
  panel.hidden = false;
}

$('verifyBtn').addEventListener('click', runVerify);
$('clearBtn').addEventListener('click', () => {
  $('rootKey').value = '';
  $('objects').value = '';
  $('now').value = '';
  $('errorPanel').hidden = true;
  $('evidencePanel').hidden = true;
  // 注意：清空操作是值班员显式动作，此时一并清除留存证据
  lastValidEvidence = null;
});

// ===================================================================
// 容量委托图审计（与单链核验分区、独立留存证据）。
// lastValidCapacityEvidence 只在容量审计 ok:true 时更新；
// 新的失败请求不得替换最近一次成功的容量证据。
// ===================================================================

let lastValidCapacityEvidence = null;

function fp(s, n = 16) {
  return s ? `${s.slice(0, n)}…` : '';
}

async function runCapacity() {
  const rootKey = $('capRootKey').value.trim();
  const delegations = splitObjects($('capDelegations').value);
  const target = $('capTarget').value.trim();
  const buoy = $('capBuoy').value.trim();
  const nowRaw = $('capNow').value.trim();

  if (!buoy) {
    renderCapError({ code: 'BAD_REQUEST', index: -1, field: 'buoy', message: '必须填写目标浮标' });
    if (lastValidCapacityEvidence) renderCapacity(lastValidCapacityEvidence, true);
    return;
  }
  const body = { rootKey, delegations, target, buoy };
  if (nowRaw) {
    if (!/^\d+$/.test(nowRaw)) {
      renderCapError({ code: 'BAD_REQUEST', index: -1, field: 'now', message: '评估时刻必须是非负整数 unix 秒' });
      if (lastValidCapacityEvidence) renderCapacity(lastValidCapacityEvidence, true);
      return;
    }
    body.now = Number(nowRaw);
  }

  $('capBtn').disabled = true;
  try {
    const resp = await fetch('/api/capacity', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await resp.json();
    if (result.ok) {
      lastValidCapacityEvidence = result.evidence; // 仅此处覆盖
      renderCapacity(result.evidence);
      $('capErrorPanel').hidden = true;
    } else {
      renderCapError(result.error);
      if (lastValidCapacityEvidence) renderCapacity(lastValidCapacityEvidence, true);
    }
  } catch (e) {
    renderCapError({ code: 'NETWORK', index: -1, field: null, message: `请求失败：${e.message}` });
    if (lastValidCapacityEvidence) renderCapacity(lastValidCapacityEvidence, true);
  } finally {
    $('capBtn').disabled = false;
  }
}

function renderCapError(err) {
  const panel = $('capErrorPanel');
  const body = $('capErrorBody');
  const locText = err.index === -1 || err.index == null
    ? '根公钥 / 目标 / 请求'
    : `集合中第 ${err.index} 条委托`;
  const loc = err.line ? `（行 ${err.line}，列 ${err.col}）` : '';
  body.innerHTML = `
    <dl>
      <dt>错误码</dt><dd class="mono">${esc(err.code || 'UNKNOWN')}</dd>
      <dt>定位</dt><dd>${esc(locText)}${err.field ? ` · 字段 <code>${esc(err.field)}</code>` : ''}${loc}</dd>
      <dt>说明</dt><dd>${esc(err.message || '')}</dd>
    </dl>`;
  panel.hidden = false;
}

function renderCapacity(ev, stale = false) {
  const panel = $('capEvidencePanel');
  $('capVerdict').innerHTML = `
    <p class="allow">
      ${stale ? '⚠ 当前为<b>上一份成功的容量证据</b>（本次审计被拒绝，容量证据未被覆盖）<br>' : ''}
      容量结论：✅ ${esc(ev.verdict.reason)}
    </p>
    <p style="font-size:12.5px;color:#9fb0c3">
      根公钥指纹 <code>${esc(ev.rootKeyThumbprint)}</code> ·
      目标主体指纹 <code>${esc(ev.targetThumbprint)}</code> ·
      浮标 <code>${esc(ev.buoy)}</code> · 评估时刻 ${ev.now} ·
      <b>最大可转移容量 = ${ev.maxTransferable}</b>
    </p>`;

  const flowRows = ev.flowEdges.map((e) => `
    <tr>
      <td class="mono" title="${esc(e.payloadDigest)}">${esc(e.payloadDigest)}</td>
      <td class="mono">${esc(fp(e.fromThumbprint))} → ${esc(fp(e.toThumbprint))}</td>
      <td>${e.capacity}</td>
      <td><b>${e.flow}</b></td>
      <td>${e.remaining}</td>
    </tr>`).join('');
  $('capFlowTable').querySelector('tbody').innerHTML = flowRows ||
    '<tr><td colspan="5">无生效流量边</td></tr>';

  const cut = ev.minCut;
  const cutRows = cut.edges.map((e) => `
    <tr>
      <td class="mono" title="${esc(e.payloadDigest)}">${esc(e.payloadDigest)}</td>
      <td class="mono">${esc(fp(e.issThumbprint))} → ${esc(fp(e.subThumbprint))}</td>
      <td>${e.transfer}</td>
      <td>${e.flow}</td>
      <td>${e.remaining}</td>
    </tr>`).join('');
  $('capCut').innerHTML = `
    <p style="font-size:13px">最小割容量 = <b>${cut.capacity}</b>
      （与最大可转移容量 ${ev.maxTransferable} 相等，共 ${cut.edges.length} 条边）</p>
    <table>
      <thead><tr><th>割边载荷摘要</th><th>签发者 → 主体</th><th>transfer</th><th>当前流量</th><th>剩余</th></tr></thead>
      <tbody>${cutRows || '<tr><td colspan="5">割集为空（目标即为源或无边可割）</td></tr>'}</tbody>
    </table>`;

  const allRows = ev.edges.map((e) => `
    <tr class="${e.active ? '' : 'inactive'}">
      <td class="mono">${esc(e.payloadDigest)}</td>
      <td>${e.inputIndex}</td>
      <td class="mono">${esc(fp(e.issThumbprint))} → ${esc(fp(e.subThumbprint))}</td>
      <td class="mono" title="${esc(e.parentDigest || '（根委托）')}">${esc(e.parentDigest ? fp(e.parentDigest, 12) : '（根委托）')}</td>
      <td>${e.transfer} / ${e.maxSamples}</td>
      <td class="mono">${e.nbf} … ${e.exp}</td>
      <td>${e.active
        ? `生效 · 流量 ${e.flow} · 剩余 ${e.remaining}`
        : `<span class="deny">未生效：${esc(e.inactiveReasons.join(', '))}</span>`}</td>
    </tr>`).join('');
  $('capAllTable').querySelector('tbody').innerHTML = allRows;

  panel.hidden = false;
}

$('capBtn').addEventListener('click', runCapacity);
$('capClearBtn').addEventListener('click', () => {
  $('capRootKey').value = '';
  $('capDelegations').value = '';
  $('capTarget').value = '';
  $('capBuoy').value = '';
  $('capNow').value = '';
  $('capErrorPanel').hidden = true;
  $('capEvidencePanel').hidden = true;
  lastValidCapacityEvidence = null;
});
