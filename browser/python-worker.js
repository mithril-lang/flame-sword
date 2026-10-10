/* Python and observations stay in this dedicated worker. No credentials enter it. */
importScripts('/runtime/pyodide.js');
let ready;
async function initialize() {
  const py = await loadPyodide({indexURL: '/runtime/'});
  for (const file of ['FastAnalyst.py', 'analysis.py']) {
    const response = await fetch('/python/' + file);
    if (!response.ok) throw new Error('Python module could not be loaded.');
    py.FS.writeFile('/home/pyodide/' + file, await response.text());
  }
  py.runPython('from analysis import analyze_json');
  return py;
}
self.onmessage = async ({data}) => {
  try {
    const py = await (ready ??= initialize());
    if (data.type === 'init') { self.postMessage({id: data.id, ready: true}); return; }
    py.globals.set('report_json', data.raw);
    try {
      const result = await py.runPythonAsync('analyze_json(report_json)');
      self.postMessage({id: data.id, result: JSON.parse(result)});
    } finally {
      py.globals.delete('report_json');
    }
  } catch (error) {
    self.postMessage({id: data.id, error: String(error.message || error)});
  }
};
