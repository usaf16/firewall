/* 背景執行緒：把大量 log 的解析與比對移出主畫面，避免畫面卡住 */
importScripts('core.js');

self.onmessage = function (e) {
  var d = e.data;
  try {
    var result = self.FWCore.computeMap(d.rulesText, d.logsText, d.def);
    self.postMessage({ id: d.id, ok: true, result: result });
  } catch (err) {
    self.postMessage({ id: d.id, ok: false, error: String(err) });
  }
};
