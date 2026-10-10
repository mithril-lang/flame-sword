const $ = id => document.getElementById(id);
let worker, sequence = 0, result, signedIn = false, busyAI = false;
const pending = new Map();
function clearWorker() {
  worker?.terminate(); worker = null;
  for (const {reject, timer} of pending.values()) { clearTimeout(timer); reject(new Error('Python analysis cancelled.')); }
  pending.clear();
}
function python(type, raw) {
  if (!worker) {
    worker = new Worker('/python-worker.js');
    worker.onmessage = ({data}) => {
      const task = pending.get(data.id); if (!task) return;
      clearTimeout(task.timer); pending.delete(data.id);
      data.error ? task.reject(new Error(data.error)) : task.resolve(data);
    };
    worker.onerror = () => clearWorker();
  }
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => clearWorker(), 90000);
    pending.set(id, {resolve, reject, timer}); worker.postMessage({id, type, raw});
  });
}
async function api(path, options = {}) {
  const response = await fetch('/api/' + path, {credentials: 'same-origin', cache: 'no-store', ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Mithril HTTP ${response.status}`);
  return data;
}
function availability() { $('ai').disabled = !result || !signedIn || !$('consent').checked || !$('model').value || busyAI; }
async function account() {
  try { await api('session'); signedIn = true; $('account').textContent = 'Signed in with Mithril'; $('signIn').textContent = 'Mithril account ↗'; }
  catch (error) { signedIn = false; $('account').textContent = error.message; }
  availability();
}
function invalidate() {
  result = null; $('results').hidden = true; $('empty').hidden = false;
  $('preview').value = ''; $('consent').checked = false; $('export').disabled = true;
  $('aiOutput').hidden = true; $('aiOutput').textContent = ''; $('aiStatus').textContent = ''; availability();
}
$('input').addEventListener('input', invalidate);
$('sample').addEventListener('click', () => {
  invalidate(); $('input').value = JSON.stringify({domain: 'example.com', subdomains: [
    {subdomain: 'www.example.com', http_status: 301, https_status: 200},
    {subdomain: 'admin.example.com', https_status: 403},
    {subdomain: 'staging.example.com', http_status: 200},
  ]}, null, 2); $('status').textContent = 'Synthetic example loaded. No network scan has been performed.';
});
$('file').addEventListener('change', async () => {
  invalidate(); const file = $('file').files[0]; if (!file) return;
  if (file.size > 1048576) { $('status').textContent = 'Import must be smaller than 1 MiB.'; return; }
  $('input').value = await file.text(); $('status').textContent = 'Report loaded locally.';
});
$('analyze').addEventListener('click', async () => {
  invalidate(); const raw = $('input').value;
  if (new TextEncoder().encode(raw).byteLength > 1048576) { $('status').textContent = 'Import must be smaller than 1 MiB.'; return; }
  $('analyze').disabled = true; $('cancel').hidden = false; $('runtime').textContent = 'Loading browser Python…';
  $('status').textContent = 'Running Flame Sword in this browser. First load may take a moment.';
  try {
    const task = await python('analyze', raw);
    // Editing the report while Python loads invalidates that pending analysis.
    if ($('input').value !== raw) { $('status').textContent = 'Input changed. Analyze the updated report.'; return; }
    result = task.result; $('runtime').textContent = 'Pyodide · browser Python ready';
    const summary = result.security_analysis.summary;
    $('total').textContent = summary.total_subdomains; $('active').textContent = summary.active_subdomains; $('https').textContent = summary.https_enabled;
    $('output').textContent = JSON.stringify(result.security_analysis, null, 2); $('results').hidden = false; $('empty').hidden = true; $('export').disabled = false;
    $('preview').value = JSON.stringify({domain: result.domain, evidence: result.evidence, limitations: result.limitations, subdomains: result.subdomains.slice(0, 50)}, null, 2);
    $('status').textContent = 'Local Python analysis complete. No observations were sent to Mithril AI.'; availability();
  } catch (error) { $('status').textContent = error.message; $('runtime').textContent = 'Python analysis unavailable'; }
  finally { $('analyze').disabled = false; $('cancel').hidden = true; }
});
$('cancel').addEventListener('click', clearWorker);
$('export').addEventListener('click', () => {
  if (!result) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], {type: 'application/json'}));
  const a = document.createElement('a'); a.href = url; a.download = 'flame-sword-analysis.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('refresh').addEventListener('click', account); window.addEventListener('focus', account);
$('models').addEventListener('click', async () => {
  $('models').disabled = true;
  try {
    const {models} = await api('models'); $('model').replaceChildren();
    for (const model of models) { const option = document.createElement('option'); option.value = model; option.textContent = model; $('model').append(option); }
    if (models.includes('qwen/qwen3.8-27b')) $('model').value = 'qwen/qwen3.8-27b';
    $('aiStatus').textContent = models.length ? 'Live Mithril model catalog loaded. Inference has not run.' : 'No models are currently available.';
  } catch (error) { $('aiStatus').textContent = error.message; }
  finally { $('models').disabled = false; availability(); }
});
$('consent').addEventListener('change', availability); $('model').addEventListener('change', () => { $('consent').checked = false; availability(); });
$('ai').addEventListener('click', async () => {
  if ($('ai').disabled) return;
  busyAI = true; availability(); $('aiStatus').textContent = 'Mithril AI is reviewing the approved preview…'; $('aiOutput').hidden = true;
  try {
    const data = await api('analyze', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({report: $('preview').value, model: $('model').value, consent: true})});
    $('aiOutput').textContent = data.content; $('aiOutput').hidden = false; $('aiStatus').textContent = 'Mithril AI review received · ' + data.model;
  } catch (error) { $('aiStatus').textContent = error.message; }
  finally { busyAI = false; $('consent').checked = false; availability(); }
});
account();
