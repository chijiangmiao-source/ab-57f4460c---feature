'use strict';

// 值班员页面逻辑：单链逐跳核验 + 容量审计，两套证据分区、各自留存。
// 关键约束：错误草稿不得覆盖上一份有效证据——
// lastValidEvidence / lastValidAudit 只在收到 ok:true 时更新。

const $ = (id) => document.getElementById(id);

// 上一份有效证据（跨多次请求保留）：单链与容量审计互不覆盖
let lastValidEvidence = null;
let lastValidAudit = null;

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

// ==================== 一、单链逐跳核验（行为保持不变） ====================

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

// ==================== 二、容量审计 ====================

async function runAudit() {
  const rootKey = $('auditRoot').value.trim();
  const targetKey = $('auditTarget').value.trim();
  const buoy = $('auditBuoy').value.trim();
  const delegations = splitObjects($('auditDelegations').value);
  const nowRaw = $('auditNow').value.trim();
  const body = { rootKey, targetKey, buoy, delegations };
  if (nowRaw) {
    if (!/^\d+$/.test(nowRaw)) {
      showAuditLocalError({ code: 'BAD_REQUEST', node: 'root', field: 'now', message: '评估时刻必须是非负整数 unix 秒' });
      return;
    }
    body.now = Number(nowRaw);
  }

  $('auditBtn').disabled = true;
  try {
    const resp = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await resp.json();
    if (result.ok) {
      lastValidAudit = result.audit; // 容量证据仅在此处覆盖，不被单链结果影响
      renderAudit(result.audit);
      $('auditErrorPanel').hidden = true;
    } else {
      renderAuditError(result.error);
      if (lastValidAudit) renderAudit(lastValidAudit, true);
    }
  } catch (e) {
    showAuditLocalError({ code: 'NETWORK', node: 'root', field: null, message: `请求失败：${e.message}` });
    if (lastValidAudit) renderAudit(lastValidAudit, true);
  } finally {
    $('auditBtn').disabled = false;
  }
}

function showAuditLocalError(err) {
  renderAuditError(err);
  if (lastValidAudit) renderAudit(lastValidAudit, true);
}

function nodeText(node) {
  if (node === 'root') return '根公钥';
  if (node === 'target') return '目标主体';
  if (typeof node === 'string' && node.startsWith('input[')) return `集合中第 ${node.slice(6, -1)} 条`;
  return `委托 ${short(node, 14)}`;
}

function renderAuditError(err) {
  const panel = $('auditErrorPanel');
  const loc = err.line ? `（行 ${err.line}，列 ${err.col}）` : '';
  $('auditErrorBody').innerHTML = `
    <dl>
      <dt>错误码</dt><dd class="mono">${esc(err.code || 'UNKNOWN')}</dd>
      <dt>定位</dt><dd>${esc(nodeText(err.node))}${err.field ? ` · 字段 <code>${esc(err.field)}</code>` : ''}${loc}</dd>
      <dt>说明</dt><dd>${esc(err.message || '')}</dd>
    </dl>`;
  panel.hidden = false;
}

function renderAudit(a, stale = false) {
  const panel = $('auditPanel');
  const v = a.verdict;
  $('auditVerdict').innerHTML = `
    <p class="allow">
      ${stale ? '⚠ 当前为<b>上一份成功的容量证据</b>（本次审计失败，容量证据未被覆盖）<br>' : ''}
      容量结论：✅ ${esc(v.reason)}
    </p>
    <p style="font-size:12.5px;color:#9fb0c3">
      根公钥指纹 <code>${esc(a.rootKeyThumbprint)}</code> ·
      目标主体指纹 <code>${esc(a.targetThumbprint)}</code> ·
      浮标 <code>${esc(a.buoy)}</code> · 评估时刻 ${a.now} ·
      入图委托 ${a.delegationCount} 条 ·
      最大可转移采样额度 <b class="big-num">${v.maxTransferable}</b>
    </p>`;

  $('flowTable').querySelector('tbody').innerHTML = a.flowEdges.map((e) => `
    <tr>
      <td><span class="pill">委托边</span></td>
      <td class="mono">${esc(short(e.parentDigest, 14))}</td>
      <td class="mono">${esc(e.payloadDigest)}</td>
      <td class="mono">${esc(e.issThumbprint.slice(0, 12))}…</td>
      <td class="mono">${esc(e.subThumbprint.slice(0, 12))}…</td>
      <td>${e.transfer}</td>
      <td><b>${e.flow}</b></td>
      <td>${e.residual}</td>
    </tr>`).join('');

  $('vertexTable').querySelector('tbody').innerHTML = a.vertices.map((u) => `
    <tr class="${u.status === 'inactive' ? 'row-inactive' : ''} ${u.isTarget ? 'row-target' : ''}">
      <td class="mono">${esc(u.payloadDigest)}</td>
      <td class="mono" title="parent=${esc(u.parentDigest)}">${esc(u.subThumbprint.slice(0, 12))}…</td>
      <td>${u.status === 'active'
        ? '<span class="pill">有效</span>'
        : `<span class="pill cmd" title="${esc(u.inactiveReason || '')}">本次失效</span>`}</td>
      <td class="mono">${u.nbf} ~ ${u.exp}</td>
      <td style="font-size:11.5px">${esc(u.aud.map((b) => `"${b}"`).join(', '))}</td>
      <td>${u.maxSamples}</td>
      <td>${u.transfer}</td>
      <td>${u.inflow}</td>
      <td><b>${u.remaining === null ? '—' : u.remaining}</b></td>
      <td>${u.reachable ? '是' : '否'}</td>
      <td>${u.isTarget ? '🎯' : ''}</td>
    </tr>`).join('');

  const cut = a.minCut;
  if (cut.edges.length === 0) {
    $('minCutBody').innerHTML = '<p style="font-size:12.5px;color:#9fb0c3">最小割为空（目标容量为 0）。</p>';
  } else {
    $('minCutBody').innerHTML = `
      <p style="font-size:13px">
        共 <b>${cut.edges.length}</b> 条割边，割容量 = <b class="big-num">${cut.capacity}</b>
        （与最大可转移容量相等）；切断以下边即可阻断目标主体获得更多采样额度：
      </p>
      <table>
        <thead><tr><th>收口类型</th><th>父载荷摘要</th><th>割边/顶点摘要</th><th>主体指纹</th><th>割容量</th></tr></thead>
        <tbody>
          ${cut.edges.map((e) => `
            <tr>
              <td><span class="pill ${e.type === 'target' ? 'cmd' : ''}">${e.type === 'target' ? '目标上限' : '委托转移'}</span></td>
              <td class="mono">${esc(short(e.parentDigest, 14))}</td>
              <td class="mono">${esc(e.payloadDigest)}</td>
              <td class="mono">${esc(e.subThumbprint.slice(0, 12))}…</td>
              <td><b>${e.capacity}</b></td>
            </tr>`).join('')}
        </tbody>
      </table>
      <p style="font-size:12px;color:#9fb0c3;margin-top:8px">
        最小割源侧顶点（残量网络自根可达）：${cut.sourceSideVertices.map((d) =>
          `<code>${d === '__ROOT__' ? 'ROOT' : esc(short(d, 10))}</code>`).join(' ')}
      </p>`;
  }
  panel.hidden = false;
}

// ==================== 事件绑定 ====================

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

$('auditBtn').addEventListener('click', runAudit);
$('auditClearBtn').addEventListener('click', () => {
  $('auditRoot').value = '';
  $('auditDelegations').value = '';
  $('auditTarget').value = '';
  $('auditBuoy').value = '';
  $('auditNow').value = '';
  $('auditErrorPanel').hidden = true;
  $('auditPanel').hidden = true;
  lastValidAudit = null; // 仅清除容量证据，不影响单链证据
});
