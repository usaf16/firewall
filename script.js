(function () {
  'use strict';

  var SAMPLE_OLD = [
    '# 舊版規則（虛構示範）',
    '允許 TCP 任意 -> 192.168.1.10 80',
    '允許 TCP 任意 -> 192.168.1.10 443',
    '允許 TCP 10.0.0.0/24 -> 192.168.1.20 22',
    '允許 UDP 10.0.0.0/24 -> 192.168.1.53 53',
    '允許 ICMP 任意 -> 任意 任意',
    '拒絕 TCP 任意 -> 任意 23'
  ].join('\n');

  var SAMPLE_NEW = [
    '# 新版規則（虛構示範）',
    '允許 TCP 任意 -> 192.168.1.10 443',
    '拒絕 TCP 10.0.0.0/24 -> 192.168.1.20 22',
    '允許 UDP 10.0.0.0/24 -> 192.168.1.53 53',
    '允許 ICMP 任意 -> 任意 任意',
    '拒絕 TCP 任意 -> 任意 23',
    '允許 TCP 10.0.1.0/24 -> 192.168.1.30 8080-8090'
  ].join('\n');

  var $ = function (id) { return document.getElementById(id); };
  var ANY = '任意';

  function parseIp(text) {
    if (text === ANY) { return { ok: true, norm: ANY }; }
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(text);
    if (!m) { return { ok: false }; }
    for (var i = 1; i <= 4; i++) { if (Number(m[i]) > 255) { return { ok: false }; } }
    var mask = m[5] === undefined ? 32 : Number(m[5]);
    if (mask > 32) { return { ok: false }; }
    var addr = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])].join('.');
    // 0.0.0.0/0 與「任意」意思相同
    if (addr === '0.0.0.0' && mask === 0) { return { ok: true, norm: ANY }; }
    return { ok: true, norm: addr + '/' + mask };
  }

  function parsePort(text) {
    if (text === ANY) { return { ok: true, norm: ANY }; }
    var m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(text);
    if (!m) { return { ok: false }; }
    var a = Number(m[1]);
    var b = m[2] === undefined ? a : Number(m[2]);
    if (a < 1 || b > 65535 || a > b) { return { ok: false }; }
    return { ok: true, norm: a === b ? String(a) : a + '-' + b };
  }

  // 回傳 { rule } 或 { error }
  function parseLine(line) {
    var parts = line.split(/\s+/);
    if (parts.length !== 6) {
      return { error: '欄位數量不對，應該是「動作 協定 來源 -> 目的 埠號」共 6 個部分（目前 ' + parts.length + ' 個）。' };
    }
    var action = parts[0];
    if (action !== '允許' && action !== '拒絕') {
      return { error: '動作必須是「允許」或「拒絕」，目前是「' + action + '」。' };
    }
    var proto = parts[1].toUpperCase();
    if (parts[1] === ANY) { proto = ANY; }
    if (['TCP', 'UDP', 'ICMP', ANY].indexOf(proto) < 0) {
      return { error: '協定必須是 TCP、UDP、ICMP 或「任意」，目前是「' + parts[1] + '」。' };
    }
    var src = parseIp(parts[2]);
    if (!src.ok) { return { error: '來源位址格式不對：「' + parts[2] + '」。請寫成 10.0.0.5、10.0.0.0/24 或「任意」。' }; }
    if (parts[3] !== '->') { return { error: '來源與目的之間要用「->」連接，目前是「' + parts[3] + '」。' }; }
    var dst = parseIp(parts[4]);
    if (!dst.ok) { return { error: '目的位址格式不對：「' + parts[4] + '」。請寫成 10.0.0.5、10.0.0.0/24 或「任意」。' }; }
    var port = parsePort(parts[5]);
    if (!port.ok) { return { error: '埠號格式不對：「' + parts[5] + '」。請寫成 443、8080-8090 或「任意」（範圍 1 到 65535）。' }; }
    if (proto === 'ICMP' && port.norm !== ANY) {
      return { error: 'ICMP 沒有埠號，埠號請寫「任意」。' };
    }
    return {
      rule: {
        action: action,
        proto: proto,
        src: src.norm,
        dst: dst.norm,
        port: port.norm,
        key: [proto, src.norm, dst.norm, port.norm].join('|')
      }
    };
  }

  function parseAll(text) {
    var rules = [], errors = [], dups = [], seen = {};
    text.split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') { return; }
      var r = parseLine(line);
      if (r.error) { errors.push({ n: i + 1, text: line, msg: r.error }); return; }
      if (seen[r.rule.key]) { dups.push({ n: i + 1, text: line }); return; }
      seen[r.rule.key] = true;
      rules.push(r.rule);
    });
    return { rules: rules, errors: errors, dups: dups };
  }

  function show(r) {
    return r.action + ' ' + r.proto + ' ' + r.src + ' -> ' + r.dst + ' ' + r.port;
  }

  function plain(r) {
    var where = function (v) { return v === ANY ? '任意位置' : v; };
    var portText = r.proto === 'ICMP' ? '' : (r.port === ANY ? '，任意埠號' : '，埠號 ' + r.port);
    var protoText = r.proto === ANY ? '任何協定' : r.proto;
    return r.action + '：' + protoText + ' 從 ' + where(r.src) + ' 連到 ' + where(r.dst) + portText;
  }

  function diff(oldRules, newRules) {
    var oldMap = {}, newMap = {};
    oldRules.forEach(function (r) { oldMap[r.key] = r; });
    newRules.forEach(function (r) { newMap[r.key] = r; });
    var out = { added: [], removed: [], changed: [], same: [] };
    oldRules.forEach(function (o) {
      var n = newMap[o.key];
      if (!n) { out.removed.push({ rule: o }); }
      else if (n.action !== o.action) { out.changed.push({ before: o, after: n }); }
      else { out.same.push({ rule: o }); }
    });
    newRules.forEach(function (n) { if (!oldMap[n.key]) { out.added.push({ rule: n }); } });
    return out;
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined) { e.textContent = text; }
    return e;
  }

  // 把一條規則拆成有顏色的小標籤：動作、協定、來源、箭頭、目的、埠號
  function ruleNode(r, label) {
    var d = el('div', 'rule');
    if (label) { d.appendChild(el('em', 'lab', label)); d.lastChild.style.fontStyle = 'normal'; }
    d.appendChild(el('span', 'act ' + (r.action === '允許' ? 'allow' : 'deny'), r.action));
    d.appendChild(el('span', 'pro', r.proto));
    d.appendChild(el('span', '', r.src));
    d.appendChild(el('span', 'arrow', '→'));
    d.appendChild(el('span', '', r.dst));
    d.appendChild(el('span', '', r.port === ANY ? '任意埠' : '埠 ' + r.port));
    return d;
  }

  function ruleItem(rule, say) {
    var li = el('li');
    var body = el('div', 'li-body');
    body.appendChild(ruleNode(rule));
    if (say) { body.appendChild(el('p', 'say', say)); }
    li.appendChild(body);
    return li;
  }

  function group(title, cls, tagText, items, emptyText) {
    var sec = el('section', 'panel group g-' + cls);
    var h = el('h2');
    h.appendChild(el('span', 'tag ' + cls, tagText));
    h.appendChild(document.createTextNode(title + '（' + items.length + '）'));
    sec.appendChild(h);
    if (!items.length) { sec.appendChild(el('p', 'empty', emptyText)); return sec; }
    var ul = el('ul');
    items.forEach(function (li) { ul.appendChild(li); });
    sec.appendChild(ul);
    return sec;
  }

  function problemPanel(title, list, side, showMsg) {
    var sec = el('section', 'panel errors');
    sec.appendChild(el('h2', '', side + title + '（' + list.length + '）'));
    var ul = el('ul'); ul.className = 'plainlist';
    ul.style.listStyle = 'none'; ul.style.margin = '0'; ul.style.padding = '0';
    list.forEach(function (e) {
      var li = el('li');
      li.style.marginBottom = '8px';
      li.appendChild(el('div', 'rule', '第 ' + e.n + ' 行：' + e.text));
      li.appendChild(el('p', 'say', showMsg ? e.msg : '與前面的規則比對條件相同，已略過這一行。'));
      ul.appendChild(li);
    });
    sec.appendChild(ul);
    return sec;
  }

  function render() {
    var box = $('result');
    box.textContent = '';
    var o = parseAll($('oldRules').value);
    var n = parseAll($('newRules').value);

    if (!o.rules.length && !n.rules.length && !o.errors.length && !n.errors.length) {
      box.appendChild(el('p', 'panel empty', '兩邊都沒有規則。請貼上規則，或按「載入示範資料」。'));
      return;
    }

    var d = diff(o.rules, n.rules);

    var counts = el('div', 'counts');
    [['新增', d.added.length, 'add'], ['刪除', d.removed.length, 'del'], ['修改', d.changed.length, 'mod'], ['不變', d.same.length, 'same']].forEach(function (c) {
      var box1 = el('div', 'count ' + c[2]);
      box1.appendChild(el('b', '', String(c[1])));
      box1.appendChild(el('span', '', c[0] + ' 條'));
      counts.appendChild(box1);
    });
    box.appendChild(counts);

    if (o.errors.length) { box.appendChild(problemPanel('格式有誤的行', o.errors, '舊版：', true)); }
    if (n.errors.length) { box.appendChild(problemPanel('格式有誤的行', n.errors, '新版：', true)); }
    if (o.dups.length) { box.appendChild(problemPanel('重複的規則', o.dups, '舊版：', false)); }
    if (n.dups.length) { box.appendChild(problemPanel('重複的規則', n.dups, '新版：', false)); }
    if (o.errors.length || n.errors.length) {
      box.appendChild(el('p', 'say', '有格式錯誤的行沒有參與比對，請修正後再按一次「比對」。'));
    }

    box.appendChild(group('新增的規則', 'add', '新增', d.added.map(function (x) {
      return ruleItem(x.rule, '新版多了這一條。' + plain(x.rule) + '。');
    }), '沒有新增的規則。'));

    box.appendChild(group('刪除的規則', 'del', '刪除', d.removed.map(function (x) {
      return ruleItem(x.rule, '舊版有，新版沒有。' + plain(x.rule) + '。');
    }), '沒有刪除的規則。'));

    box.appendChild(group('修改的規則', 'mod', '修改', d.changed.map(function (x) {
      var li = el('li');
      var body = el('div', 'li-body');
      body.appendChild(ruleNode(x.before, '舊'));
      body.appendChild(ruleNode(x.after, '新'));
      body.appendChild(el('p', 'say', '連線條件相同，但動作從「' + x.before.action + '」改成「' + x.after.action + '」。'));
      li.appendChild(body);
      return li;
    }), '沒有修改的規則。'));

    box.appendChild(group('不變的規則', 'same', '不變', d.same.map(function (x) {
      return ruleItem(x.rule, '');
    }), '沒有不變的規則。'));
  }

  $('compareBtn').addEventListener('click', render);
  $('sampleBtn').addEventListener('click', function () {
    $('oldRules').value = SAMPLE_OLD;
    $('newRules').value = SAMPLE_NEW;
    render();
  });
  $('clearBtn').addEventListener('click', function () {
    $('oldRules').value = '';
    $('newRules').value = '';
    $('result').textContent = '';
  });

  /* ---------- 分頁切換 ---------- */
  function showTab(which) {
    var isDiff = which === 'diff';
    $('viewDiff').hidden = !isDiff;
    $('viewLog').hidden = isDiff;
    $('tabDiff').setAttribute('aria-selected', isDiff ? 'true' : 'false');
    $('tabLog').setAttribute('aria-selected', isDiff ? 'false' : 'true');
  }
  $('tabDiff').addEventListener('click', function () { showTab('diff'); });
  $('tabLog').addEventListener('click', function () { showTab('log'); });

  /* ---------- 規則與 log 對應 ---------- */
  var MAP_RULES = [
    '# 規則由上到下比對（虛構示範）',
    '允許 TCP 任意 -> 192.168.1.10 443',
    '拒絕 TCP 10.0.0.0/24 -> 192.168.1.20 22',
    '允許 UDP 10.0.0.0/24 -> 192.168.1.53 53',
    '允許 ICMP 任意 -> 任意 任意',
    '拒絕 TCP 任意 -> 任意 23',
    '允許 TCP 10.0.1.0/24 -> 192.168.1.30 8080-8090'
  ].join('\n');

  var MAP_LOGS = [
    '# 連線紀錄（虛構示範，203.0.113.x 與 198.51.100.x 為文件保留網段）',
    '2026-10-08 09:15:02 TCP 203.0.113.7 -> 192.168.1.10 443 允許',
    '2026-10-08 09:15:40 TCP 10.0.0.8 -> 192.168.1.20 22 拒絕',
    '2026-10-08 09:16:11 UDP 10.0.0.9 -> 192.168.1.53 53 允許',
    '2026-10-08 09:17:03 ICMP 198.51.100.4 -> 192.168.1.1 任意 允許',
    '2026-10-08 09:18:30 TCP 198.51.100.9 -> 192.168.1.40 23 拒絕',
    '2026-10-08 09:19:55 TCP 10.0.1.15 -> 192.168.1.30 8085 允許',
    '2026-10-08 09:21:12 TCP 203.0.113.50 -> 192.168.1.10 80 拒絕'
  ].join('\n');

  // 規則順序有意義，所以這裡保留重複與全部順序，不像比對頁會去除重複
  function parseOrdered(text) {
    var rules = [], errors = [];
    text.split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') { return; }
      var r = parseLine(line);
      if (r.error) { errors.push({ n: i + 1, text: line, msg: r.error }); return; }
      r.rule.no = rules.length + 1;
      rules.push(r.rule);
    });
    return { rules: rules, errors: errors };
  }

  function parseLogLine(line) {
    var p = line.split(/\s+/);
    if (p.length !== 7 && p.length !== 8) {
      return { error: '欄位數量不對，應該是「日期 時間 協定 來源 -> 目的 埠號 [動作]」（目前 ' + p.length + ' 個）。' };
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(p[0])) { return { error: '日期格式不對：「' + p[0] + '」，請寫成 2026-10-08。' }; }
    if (!/^\d{2}:\d{2}:\d{2}$/.test(p[1])) { return { error: '時間格式不對：「' + p[1] + '」，請寫成 09:15:02。' }; }
    var proto = p[2].toUpperCase();
    if (['TCP', 'UDP', 'ICMP'].indexOf(proto) < 0) { return { error: 'log 的協定必須是 TCP、UDP 或 ICMP，目前是「' + p[2] + '」。' }; }
    var src = parseIp(p[3]), dst = parseIp(p[5]);
    if (!src.ok || src.norm === ANY || !/\/32$/.test(src.norm)) { return { error: '來源必須是單一 IPv4 位址，目前是「' + p[3] + '」。' }; }
    if (p[4] !== '->') { return { error: '來源與目的之間要用「->」連接，目前是「' + p[4] + '」。' }; }
    if (!dst.ok || dst.norm === ANY || !/\/32$/.test(dst.norm)) { return { error: '目的必須是單一 IPv4 位址，目前是「' + p[5] + '」。' }; }
    var port;
    if (proto === 'ICMP') {
      if (p[6] !== ANY && p[6] !== '-') { return { error: 'ICMP 沒有埠號，埠號請寫「任意」。' }; }
      port = ANY;
    } else {
      if (!/^\d{1,5}$/.test(p[6]) || Number(p[6]) < 1 || Number(p[6]) > 65535) {
        return { error: '埠號必須是 1 到 65535 的單一數字，目前是「' + p[6] + '」。' };
      }
      port = String(Number(p[6]));
    }
    var action = p.length === 8 ? p[7] : '';
    if (action && action !== '允許' && action !== '拒絕') { return { error: '動作必須是「允許」或「拒絕」，目前是「' + action + '」。' }; }
    return { log: { date: p[0], time: p[1], proto: proto, src: src.norm.replace(/\/32$/, ''), dst: dst.norm.replace(/\/32$/, ''), port: port, action: action } };
  }

  function ipToInt(s) {
    var q = s.split('.');
    return (((Number(q[0]) * 256 + Number(q[1])) * 256 + Number(q[2])) * 256 + Number(q[3])) >>> 0;
  }
  function ipMatch(spec, ip) {
    if (spec === ANY) { return true; }
    var parts = spec.split('/'), mask = Number(parts[1]);
    if (mask === 0) { return true; }
    var m = (0xFFFFFFFF << (32 - mask)) >>> 0;
    return ((ipToInt(parts[0]) & m) >>> 0) === ((ipToInt(ip) & m) >>> 0);
  }
  function portMatch(spec, port) {
    if (spec === ANY) { return true; }
    if (port === ANY) { return false; }
    var r = spec.split('-'), a = Number(r[0]), b = Number(r[r.length - 1]), v = Number(port);
    return v >= a && v <= b;
  }
  function ruleHits(rule, log) {
    return (rule.proto === ANY || rule.proto === log.proto) &&
      ipMatch(rule.src, log.src) && ipMatch(rule.dst, log.dst) && portMatch(rule.port, log.port);
  }

  function renderMap() {
    var box = $('mapResult');
    box.textContent = '';
    var rp = parseOrdered($('mapRules').value);
    var logs = [], logErrors = [];
    $('mapLogs').value.split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') { return; }
      var r = parseLogLine(line);
      if (r.error) { logErrors.push({ n: i + 1, text: line, msg: r.error }); return; }
      r.log.n = i + 1;
      logs.push(r.log);
    });

    if (!rp.rules.length && !logs.length && !rp.errors.length && !logErrors.length) {
      box.appendChild(el('p', 'panel empty', '規則和 log 都是空的。請貼上內容，或按「載入示範資料」。'));
      return;
    }

    var hits = [], misses = [];
    logs.forEach(function (lg) {
      var found = null;
      for (var i = 0; i < rp.rules.length; i++) {
        if (ruleHits(rp.rules[i], lg)) { found = rp.rules[i]; break; }
      }
      (found ? hits : misses).push({ log: lg, rule: found });
    });

    var counts = el('div', 'counts');
    [['log 總筆數', logs.length, 'same'], ['命中規則', hits.length, 'add'], ['沒有規則符合', misses.length, 'del'], ['規則條數', rp.rules.length, 'mod']].forEach(function (c) {
      var b = el('div', 'count ' + c[2]);
      b.appendChild(el('b', '', String(c[1])));
      b.appendChild(el('span', '', c[0]));
      counts.appendChild(b);
    });
    box.appendChild(counts);

    if (rp.errors.length) { box.appendChild(problemPanel('格式有誤的行', rp.errors, '規則：', true)); }
    if (logErrors.length) { box.appendChild(problemPanel('格式有誤的行', logErrors, 'Log：', true)); }
    if (rp.errors.length || logErrors.length) {
      box.appendChild(el('p', 'say', '有格式錯誤的行沒有參與對應，請修正後再按一次「對應」。注意：規則被略過會讓後面的規則編號往前移。'));
    }

    function logText(lg) {
      var tail = lg.proto === 'ICMP' ? '' : ':' + lg.port;
      return lg.date + ' ' + lg.time + '　' + lg.proto + ' ' + lg.src + ' → ' + lg.dst + tail + (lg.action ? '　（log 記錄：' + lg.action + '）' : '');
    }

    // 檔案很大時只畫前 1000 筆，統計數字仍包含全部
    var CAP = 1000;
    if (hits.length > CAP || misses.length > CAP) {
      box.appendChild(el('p', 'say', '為了讓頁面順暢，每一組最多顯示前 ' + CAP + ' 筆；上方統計數字包含全部。'));
      hits = hits.slice(0, CAP);
      misses = misses.slice(0, CAP);
    }

    box.appendChild(group('有命中規則的 log', 'hit', '命中', hits.map(function (x) {
      var li = el('li'), body = el('div', 'li-body');
      body.appendChild(el('div', 'logline', '第 ' + x.log.n + ' 行　' + logText(x.log)));
      body.appendChild(el('p', 'say', '命中第 ' + x.rule.no + ' 條規則：'));
      body.appendChild(ruleNode(x.rule));
      li.appendChild(body);
      return li;
    }), '沒有命中規則的 log。'));

    box.appendChild(group('沒有任何規則符合的 log', 'miss', '未命中', misses.map(function (x) {
      var li = el('li'), body = el('div', 'li-body');
      body.appendChild(el('div', 'logline', '第 ' + x.log.n + ' 行　' + logText(x.log)));
      body.appendChild(el('p', 'say', '貼上的規則裡沒有任何一條符合這筆連線。實際設備通常還有預設政策，本工具不模擬。'));
      li.appendChild(body);
      return li;
    }), '每筆 log 都有對應的規則。'));
  }

  /* ---------- 匯入 log 檔 ---------- */
  var MAX_BYTES = 2 * 1024 * 1024;

  function say(msg, bad) {
    var m = $('importMsg');
    m.hidden = false;
    m.textContent = msg;
    m.style.color = bad ? 'var(--del)' : 'var(--muted)';
  }

  // CSV：逗號換成空白，沒有「->」欄就補上，第一列若是標題（不是以數字開頭）就略過
  function csvToLogText(text) {
    var out = [], skipped = 0;
    text.replace(/^﻿/, '').split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line) { return; }
      var cells = line.split(',').map(function (c) { return c.trim().replace(/^"|"$/g, ''); });
      if (i === 0 && !/^\d/.test(cells[0])) { skipped = 1; return; }
      if (cells.length >= 6 && cells[4] !== '->' && cells.indexOf('->') < 0) { cells.splice(4, 0, '->'); }
      out.push(cells.join(' '));
    });
    return { text: out.join('\n'), skipped: skipped };
  }

  function importLogFile(file) {
    if (!file) { return; }
    if (file.size > MAX_BYTES) { say('檔案太大（' + Math.round(file.size / 1024) + ' KB），請拆成 2 MB 以內再匯入。', true); return; }
    if (!/\.(txt|log|csv)$/i.test(file.name) && file.type.indexOf('text/') !== 0) {
      say('只支援文字檔（.txt、.log、.csv），「' + file.name + '」不是。', true); return;
    }
    var reader = new FileReader();
    reader.onerror = function () { say('讀取「' + file.name + '」失敗，請再試一次。', true); };
    reader.onload = function () {
      var text = String(reader.result), note = '';
      if (/\.csv$/i.test(file.name)) {
        var c = csvToLogText(text);
        text = c.text;
        if (c.skipped) { note = '，已略過標題列'; }
      }
      $('mapLogs').value = text;
      var n = text.split(/\r?\n/).filter(function (l) { var t = l.trim(); return t && t.charAt(0) !== '#'; }).length;
      say('已匯入「' + file.name + '」，共 ' + n + ' 行' + note + '。內容只在你的瀏覽器內處理，沒有上傳。', false);
      renderMap();
    };
    reader.readAsText(file);
  }

  $('importBtn').addEventListener('click', function () { $('logFile').click(); });
  $('logFile').addEventListener('change', function () {
    importLogFile(this.files && this.files[0]);
    this.value = '';
  });
  $('mapLogs').addEventListener('dragover', function (e) { e.preventDefault(); });
  $('mapLogs').addEventListener('drop', function (e) {
    e.preventDefault();
    importLogFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
  });

  $('mapBtn').addEventListener('click', renderMap);
  $('mapSampleBtn').addEventListener('click', function () {
    $('mapRules').value = MAP_RULES;
    $('mapLogs').value = MAP_LOGS;
    renderMap();
  });
  $('useNewBtn').addEventListener('click', function () {
    $('mapRules').value = $('newRules').value;
    renderMap();
  });
  $('mapClearBtn').addEventListener('click', function () {
    $('mapRules').value = '';
    $('mapLogs').value = '';
    $('mapResult').textContent = '';
    $('importMsg').hidden = true;
  });

  $('mapRules').value = MAP_RULES;
  $('mapLogs').value = MAP_LOGS;
  renderMap();

  // 開啟頁面時先載入示範資料，讓畫面不是空的
  $('oldRules').value = SAMPLE_OLD;
  $('newRules').value = SAMPLE_NEW;
  render();
})();
