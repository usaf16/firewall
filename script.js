(function () {
  'use strict';

  var ANY = '任意';
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined) { e.textContent = text; }
    return e;
  }

  /* =========================================================
     一、關鍵字對照（英文與設備別名）
     ========================================================= */
  var ACTIONS = {
    '允許': '允許', 'ALLOW': '允許', 'PERMIT': '允許', 'ACCEPT': '允許', 'PASS': '允許',
    '拒絕': '拒絕', 'DENY': '拒絕', 'DROP': '拒絕', 'BLOCK': '拒絕', 'REJECT': '拒絕'
  };
  var SERVICES = { HTTP: 80, HTTPS: 443, SSH: 22, DNS: 53, FTP: 21, TELNET: 23, SMTP: 25, NTP: 123, SMB: 445, RDP: 3389, MYSQL: 3306 };
  var PROTOS = ['TCP', 'UDP', 'ICMP'];

  function has(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
  function isAny(t) { var u = t.toUpperCase(); return t === ANY || u === 'ANY' || u === 'ALL' || t === '*'; }
  function arrowProblem(t) {
    if (t === '->' || t === '→') { return ''; }
    if (/^[-=]*>+$|^→+$/.test(t)) { return '箭頭請寫成 ->，目前是「' + t + '」。'; }
    return '來源與目的之間要用「->」連接，目前是「' + t + '」。';
  }

  /* =========================================================
     二、位址、埠號、規則解析
     ========================================================= */
  function ipToInt(s) {
    var q = s.split('.');
    return (((Number(q[0]) * 256 + Number(q[1])) * 256 + Number(q[2])) * 256 + Number(q[3])) >>> 0;
  }
  function intToIp(n) { return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  function maskOf(m) { return m === 0 ? 0 : (0xFFFFFFFF << (32 - m)) >>> 0; }

  function parseIp(t) {
    if (isAny(t)) { return { ok: true, norm: ANY }; }
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d+))?$/.exec(t);
    if (!m) { return { ok: false, msg: '位址格式不對：「' + t + '」。請寫成 10.0.0.5、10.0.0.0/24 或「任意」。' }; }
    for (var i = 1; i <= 4; i++) {
      if (Number(m[i]) > 255) { return { ok: false, msg: 'IP 位址每一段必須是 0 到 255：「' + t + '」。' }; }
    }
    var mask = m[5] === undefined ? 32 : Number(m[5]);
    if (mask > 32) { return { ok: false, msg: '不合法的 CIDR 遮罩格式 (' + t + ')，遮罩必須是 0 到 32。' }; }
    if (mask === 0) { return { ok: true, norm: ANY }; }
    var addr = m[1] + '.' + m[2] + '.' + m[3] + '.' + m[4];
    return { ok: true, norm: intToIp((ipToInt(addr) & maskOf(mask)) >>> 0) + '/' + mask };
  }

  function parsePort(t) {
    if (isAny(t)) { return { ok: true, norm: ANY }; }
    var u = t.toUpperCase();
    if (has(SERVICES, u)) { return { ok: true, norm: String(SERVICES[u]) }; }
    var m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(t);
    if (!m) { return { ok: false, msg: '埠號格式不對：「' + t + '」。請寫成 443、8080-8090、服務名稱（如 HTTPS）或「任意」。' }; }
    var a = Number(m[1]), b = m[2] === undefined ? a : Number(m[2]);
    if (a < 1 || a > 65535 || b < 1 || b > 65535) { return { ok: false, msg: '埠號必須在 1 到 65535 之間：「' + t + '」。' }; }
    if (a > b) { return { ok: false, msg: '埠號範圍的起點不能大於終點：「' + t + '」。' }; }
    return { ok: true, norm: a === b ? String(a) : a + '-' + b };
  }

  function parseRuleLine(line) {
    var p = line.split(/\s+/);
    if (p.length !== 6) {
      return { error: '欄位數量不對，應該是「動作 協定 來源 -> 目的 埠號」共 6 個部分（目前 ' + p.length + ' 個）。' };
    }
    var action = ACTIONS[p[0].toUpperCase()];
    if (!action || !has(ACTIONS, p[0].toUpperCase())) {
      return { error: '動作必須是「允許」或「拒絕」（也可寫 allow、permit、deny、drop 等），目前是「' + p[0] + '」。' };
    }
    var proto = isAny(p[1]) ? ANY : p[1].toUpperCase();
    if (proto !== ANY && PROTOS.indexOf(proto) < 0) {
      return { error: '協定必須是 TCP、UDP、ICMP 或「任意」，目前是「' + p[1] + '」。' };
    }
    var src = parseIp(p[2]);
    if (!src.ok) { return { error: '來源：' + src.msg }; }
    var ap = arrowProblem(p[3]);
    if (ap) { return { error: ap }; }
    var dst = parseIp(p[4]);
    if (!dst.ok) { return { error: '目的：' + dst.msg }; }
    var port = parsePort(p[5]);
    if (!port.ok) { return { error: port.msg }; }
    if (proto === 'ICMP' && port.norm !== ANY) { return { error: 'ICMP 沒有埠號，埠號請寫「任意」。' }; }
    return { rule: { action: action, proto: proto, src: src.norm, dst: dst.norm, port: port.norm, key: [proto, src.norm, dst.norm, port.norm].join('|') } };
  }

  // 規則順序有意義：保留全部有效規則，no = 第幾條有效規則，line = 原始行號
  function parseRules(text) {
    var rules = [], errors = [];
    text.split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') { return; }
      var r = parseRuleLine(line);
      if (r.error) { errors.push({ n: i + 1, text: line, msg: r.error }); return; }
      r.rule.line = i + 1;
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
    if (PROTOS.indexOf(proto) < 0) { return { error: 'log 的協定必須是 TCP、UDP 或 ICMP，目前是「' + p[2] + '」。' }; }
    var src = parseIp(p[3]);
    if (!src.ok) { return { error: '來源：' + src.msg }; }
    if (src.norm === ANY || !/\/32$/.test(src.norm)) { return { error: '來源必須是單一 IPv4 位址，目前是「' + p[3] + '」。' }; }
    var ap = arrowProblem(p[4]);
    if (ap) { return { error: ap }; }
    var dst = parseIp(p[5]);
    if (!dst.ok) { return { error: '目的：' + dst.msg }; }
    if (dst.norm === ANY || !/\/32$/.test(dst.norm)) { return { error: '目的必須是單一 IPv4 位址，目前是「' + p[5] + '」。' }; }
    var port;
    if (proto === 'ICMP') {
      if (!isAny(p[6]) && p[6] !== '-') { return { error: 'ICMP 沒有埠號，埠號請寫「任意」。' }; }
      port = ANY;
    } else {
      var pp = parsePort(p[6]);
      if (!pp.ok || pp.norm === ANY || pp.norm.indexOf('-') >= 0) { return { error: 'log 的埠號必須是單一數字或服務名稱，目前是「' + p[6] + '」。' }; }
      port = pp.norm;
    }
    var action = '';
    if (p.length === 8) {
      action = has(ACTIONS, p[7].toUpperCase()) ? ACTIONS[p[7].toUpperCase()] : '';
      if (!action) { return { error: '動作必須是「允許」或「拒絕」，目前是「' + p[7] + '」。' }; }
    }
    return { log: { date: p[0], time: p[1], proto: proto, src: src.norm.replace(/\/32$/, ''), dst: dst.norm.replace(/\/32$/, ''), port: port, action: action } };
  }

  function parseLogs(text) {
    var logs = [], errors = [];
    text.split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') { return; }
      var r = parseLogLine(line);
      if (r.error) { errors.push({ n: i + 1, text: line, msg: r.error }); return; }
      r.log.n = i + 1;
      logs.push(r.log);
    });
    return { logs: logs, errors: errors };
  }

  /* =========================================================
     三、比對、遮蔽與冗餘分析
     ========================================================= */
  function ipCover(a, b) {
    if (a === ANY) { return true; }
    if (b === ANY) { return false; }
    var x = a.split('/'), y = b.split('/');
    var am = Number(x[1]), bm = Number(y[1]);
    return am <= bm && ((ipToInt(y[0]) & maskOf(am)) >>> 0) === ipToInt(x[0]);
  }
  function portRange(s) { var r = s.split('-'); return [Number(r[0]), Number(r[r.length - 1])]; }
  function portCover(a, b) {
    if (a === ANY) { return true; }
    if (b === ANY) { return false; }
    var x = portRange(a), y = portRange(b);
    return x[0] <= y[0] && y[1] <= x[1];
  }
  function covers(a, b) {
    return (a.proto === ANY || a.proto === b.proto) && ipCover(a.src, b.src) && ipCover(a.dst, b.dst) && portCover(a.port, b.port);
  }

  // 後面的規則若完全被前面某一條涵蓋：動作不同 = 遮蔽，動作相同 = 冗餘
  function analyze(rules) {
    var out = [];
    for (var j = 1; j < rules.length; j++) {
      for (var i = 0; i < j; i++) {
        if (covers(rules[i], rules[j])) {
          out.push({ kind: rules[i].action === rules[j].action ? 'redundant' : 'shadow', j: rules[j], i: rules[i] });
          break;
        }
      }
    }
    return out;
  }
  function warnText(w) {
    if (w.kind === 'shadow') {
      return '第 ' + w.j.no + ' 條（第 ' + w.j.line + ' 行）已被第 ' + w.i.no + ' 條覆蓋，這條' + (w.j.action === '拒絕' ? '阻擋' : '放行') + '規則將永遠不會被觸發。';
    }
    return '第 ' + w.j.no + ' 條（第 ' + w.j.line + ' 行）與第 ' + w.i.no + ' 條動作相同且範圍已被涵蓋，建議合併或刪除。';
  }

  function ipMatch(spec, ip) {
    if (spec === ANY) { return true; }
    var parts = spec.split('/');
    var m = maskOf(Number(parts[1]));
    return ((ipToInt(parts[0]) & m) >>> 0) === ((ipToInt(ip) & m) >>> 0);
  }
  function portMatch(spec, port) {
    if (spec === ANY) { return true; }
    if (port === ANY) { return false; }
    var r = portRange(spec), v = Number(port);
    return v >= r[0] && v <= r[1];
  }
  function ruleHits(rule, log) {
    return (rule.proto === ANY || rule.proto === log.proto) && ipMatch(rule.src, log.src) && ipMatch(rule.dst, log.dst) && portMatch(rule.port, log.port);
  }

  // 最長遞增子序列，回傳「保持原相對順序」的位置集合
  function lisSet(arr) {
    var tails = [], tailIdx = [], prev = [];
    for (var k = 0; k < arr.length; k++) {
      var lo = 0, hi = tails.length;
      while (lo < hi) {
        var mid = (lo + hi) >> 1;
        if (tails[mid] < arr[k]) { lo = mid + 1; } else { hi = mid; }
      }
      tails[lo] = arr[k];
      tailIdx[lo] = k;
      prev[k] = lo > 0 ? tailIdx[lo - 1] : -1;
    }
    var set = {}, cur = tails.length ? tailIdx[tails.length - 1] : -1;
    while (cur >= 0) { set[cur] = true; cur = prev[cur]; }
    return set;
  }

  function buildDiff(oldRules, newRules) {
    var oldMap = {}, newMap = {}, oldFirst = [], newFirst = [], dups = { old: [], neu: [] };
    oldRules.forEach(function (r) { if (oldMap[r.key]) { dups.old.push(r); } else { oldMap[r.key] = r; oldFirst.push(r); } });
    newRules.forEach(function (r) { if (newMap[r.key]) { dups.neu.push(r); } else { newMap[r.key] = r; newFirst.push(r); } });

    var identNew = [], newIdx = {};
    newFirst.forEach(function (n) { var o = oldMap[n.key]; if (o && o.action === n.action) { newIdx[n.key] = identNew.length; identNew.push(n); } });
    var oldIdent = oldFirst.filter(function (o) { return newMap[o.key] && newMap[o.key].action === o.action; });
    var stable = lisSet(oldIdent.map(function (o) { return newIdx[o.key]; }));
    var movedKeys = {};
    oldIdent.forEach(function (o, i) { if (!stable[i]) { movedKeys[o.key] = true; } });

    var removed = oldFirst.filter(function (o) { return !newMap[o.key]; });
    var ri = 0, entries = [];
    newFirst.forEach(function (n) {
      var o = oldMap[n.key];
      if (o) { while (ri < removed.length && removed[ri].no < o.no) { entries.push({ type: 'del', before: removed[ri++] }); } }
      if (!o) { entries.push({ type: 'add', after: n }); }
      else if (o.action !== n.action) { entries.push({ type: 'mod', before: o, after: n }); }
      else { entries.push({ type: movedKeys[n.key] ? 'moved' : 'same', before: o, after: n }); }
    });
    while (ri < removed.length) { entries.push({ type: 'del', before: removed[ri++] }); }

    var counts = { add: 0, del: 0, mod: 0, moved: 0, same: 0 };
    entries.forEach(function (e) { counts[e.type]++; });
    return { entries: entries, counts: counts, dups: dups };
  }

  /* =========================================================
     四、畫面小元件
     ========================================================= */
  function disp(s) { return s.replace(/\/32$/, ''); }
  function ruleText(r) { return r.action + ' ' + r.proto + ' ' + disp(r.src) + ' -> ' + disp(r.dst) + ' ' + r.port; }
  function plain(r) {
    var where = function (v) { return v === ANY ? '任意位置' : disp(v); };
    var portText = r.proto === 'ICMP' ? '' : (r.port === ANY ? '，任意埠號' : '，埠號 ' + r.port);
    return r.action + '：' + (r.proto === ANY ? '任何協定' : r.proto) + ' 從 ' + where(r.src) + ' 連到 ' + where(r.dst) + portText;
  }

  function ruleNode(r, label) {
    var d = el('div', 'rule');
    if (label) { d.appendChild(el('em', 'lab', label)); }
    d.appendChild(el('span', 'act ' + (r.action === '允許' ? 'allow' : 'deny'), r.action));
    d.appendChild(el('span', 'pro', r.proto));
    d.appendChild(el('span', '', disp(r.src)));
    d.appendChild(el('span', 'arrow', '→'));
    d.appendChild(el('span', '', disp(r.dst)));
    d.appendChild(el('span', '', r.port === ANY ? '任意埠' : '埠 ' + r.port));
    return d;
  }

  function problemPanel(title, list, showMsg) {
    var sec = el('section', 'panel errors');
    sec.appendChild(el('h2', '', title + '（' + list.length + '）'));
    var ul = el('ul', 'plain');
    list.forEach(function (e) {
      var li = el('li');
      li.appendChild(el('div', 'rule', '第 ' + e.n + ' 行：' + e.text));
      li.appendChild(el('p', 'say', showMsg ? e.msg : '與前面的規則比對條件相同，已略過這一行。'));
      ul.appendChild(li);
    });
    sec.appendChild(ul);
    return sec;
  }

  function warnPanel(title, warns) {
    var sec = el('section', 'panel warnpanel');
    sec.appendChild(el('h2', '', title + '（' + warns.length + '）'));
    var ul = el('ul', 'plain');
    warns.forEach(function (w) {
      var li = el('li');
      li.appendChild(el('span', 'tagw ' + (w.kind === 'shadow' ? 'shadow' : 'redundant'), w.kind === 'shadow' ? '遮蔽' : '冗餘'));
      li.appendChild(document.createTextNode(' ' + warnText(w)));
      ul.appendChild(li);
    });
    sec.appendChild(ul);
    return sec;
  }

  function countTile(label, n, cls) {
    var b = el('div', 'count ' + cls);
    b.appendChild(el('b', '', String(n)));
    b.appendChild(el('span', '', label));
    return b;
  }

  /* =========================================================
     五、CSV 匯出
     ========================================================= */
  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function downloadCsv(name, rows) {
    var text = '﻿' + rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n');
    var blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function stamp() {
    var d = new Date(), z = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + z(d.getMonth() + 1) + z(d.getDate()) + '-' + z(d.getHours()) + z(d.getMinutes());
  }

  /* =========================================================
     六、輸入框：行號、錯誤行反白、即時語法檢查
     ========================================================= */
  var ED = {};
  function makeEditor(id, kind) {
    var ta = $(id), gut = $(id + 'Gut'), hl = $(id + 'Hl'), lint = $(id + 'Lint'), timer = 0;

    function refresh() {
      var text = ta.value;
      var L = text.split('\n').length;
      var errs = [], warns = [], count = 0;
      if (kind === 'rules') {
        var pr = parseRules(text);
        errs = pr.errors; count = pr.rules.length;
        warns = analyze(pr.rules);
      } else {
        var pl = parseLogs(text);
        errs = pl.errors; count = pl.logs.length;
      }
      var bad = {}, wn = {};
      errs.forEach(function (e) { bad[e.n] = true; });
      warns.forEach(function (w) { wn[w.j.line] = true; });

      gut.textContent = ''; hl.textContent = '';
      if (L <= 3000) {
        var fg = document.createDocumentFragment(), fh = document.createDocumentFragment();
        for (var i = 1; i <= L; i++) {
          var cls = bad[i] ? ' bad' : (wn[i] ? ' warn' : '');
          fg.appendChild(el('div', 'ln' + cls, String(i)));
          fh.appendChild(el('div', 'hl-line' + cls));
        }
        gut.appendChild(fg); hl.appendChild(fh);
      } else {
        var nums = []; for (var k = 1; k <= L; k++) { nums.push(k); }
        gut.style.whiteSpace = 'pre';
        gut.textContent = nums.join('\n');
      }
      gut.scrollTop = ta.scrollTop; hl.scrollTop = ta.scrollTop;

      lint.textContent = '';
      if (!text.trim()) { lint.appendChild(el('p', 'lint-hint', '尚未輸入內容。')); return; }
      if (!errs.length && !warns.length) {
        lint.appendChild(el('p', 'lint-ok', '✓ 語法檢查通過，共 ' + count + (kind === 'rules' ? ' 條規則。' : ' 筆 log。')));
        return;
      }
      var ul = el('ul', 'lintlist');
      errs.slice(0, 20).forEach(function (e) { ul.appendChild(el('li', 'err', '第 ' + e.n + ' 行錯誤：' + e.msg)); });
      if (errs.length > 20) { ul.appendChild(el('li', 'err', '還有 ' + (errs.length - 20) + ' 行錯誤未列出。')); }
      warns.slice(0, 20).forEach(function (w) { ul.appendChild(el('li', 'wn', '警告：' + warnText(w))); });
      if (warns.length > 20) { ul.appendChild(el('li', 'wn', '還有 ' + (warns.length - 20) + ' 則警告未列出。')); }
      lint.appendChild(ul);
    }

    ta.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(refresh, 120); });
    ta.addEventListener('scroll', function () { gut.scrollTop = ta.scrollTop; hl.scrollTop = ta.scrollTop; });
    ED[id] = { refresh: refresh };
  }
  function setVal(id, text) { $(id).value = text; ED[id].refresh(); }

  /* =========================================================
     七、示範資料
     ========================================================= */
  var SAMPLE_A = [
    '# 範例 A：舊版規則（虛構示範）',
    '允許 TCP 任意 -> 192.168.1.10 80',
    '允許 TCP 任意 -> 192.168.1.10 443',
    '允許 TCP 10.0.0.0/24 -> 192.168.1.20 22',
    '允許 UDP 10.0.0.0/24 -> 192.168.1.53 53',
    '允許 ICMP 任意 -> 任意 任意',
    '拒絕 TCP 任意 -> 任意 23'
  ].join('\n');

  var SAMPLE_B = [
    '# 範例 B：新版規則（虛構示範，混用英文寫法與服務名稱）',
    'allow tcp any -> 192.168.1.10 https',
    'deny tcp any -> any telnet',
    'deny tcp 10.0.0.0/24 -> 192.168.1.20 ssh',
    'allow udp 10.0.0.0/24 -> 192.168.1.53 dns',
    'permit icmp any -> any any',
    'allow tcp 10.0.1.0/24 -> 192.168.1.30 8080-8090',
    'deny tcp 10.0.1.0/24 -> 192.168.1.30 8085'
  ].join('\n');

  var SAMPLE_RULES = [
    '# 規則由上到下比對，先命中者生效（虛構示範）',
    '允許 TCP 10.0.0.0/16 -> 任意 443',
    '允許 TCP 任意 -> 192.168.1.10 https',
    '拒絕 TCP 10.0.1.0/24 -> 任意 443',
    '拒絕 TCP 10.0.0.0/24 -> 192.168.1.20 22',
    '允許 UDP 10.0.0.0/24 -> 192.168.1.53 dns',
    'permit icmp any -> any any',
    'deny tcp any -> any 23',
    'allow tcp 10.0.1.0/24 -> 192.168.1.30 8080-8090',
    '允許 TCP 10.0.0.0/24 -> 任意 443'
  ].join('\n');

  var SAMPLE_LOGS = [
    '# 連線紀錄（虛構示範，203.0.113.x 與 198.51.100.x 為文件保留網段）',
    '2026-10-08 09:15:02 TCP 10.0.1.7 -> 192.168.1.10 443 允許',
    '2026-10-08 09:15:20 TCP 203.0.113.7 -> 192.168.1.10 443 允許',
    '2026-10-08 09:15:40 TCP 10.0.0.8 -> 192.168.1.20 22 拒絕',
    '2026-10-08 09:16:11 UDP 10.0.0.9 -> 192.168.1.53 53 允許',
    '2026-10-08 09:17:03 ICMP 198.51.100.4 -> 192.168.1.1 任意 允許',
    '2026-10-08 09:18:30 TCP 198.51.100.9 -> 192.168.1.40 23 拒絕',
    '2026-10-08 09:19:55 TCP 10.0.1.15 -> 192.168.1.30 8085 允許',
    '2026-10-08 09:21:12 TCP 203.0.113.50 -> 192.168.1.10 80 拒絕',
    '2026-10-08 09:22:40 UDP 198.51.100.77 -> 192.168.1.53 53 允許',
    '2026-10-08 09:23:05 TCP 10.0.1.7 -> 192.168.1.10 443 允許'
  ].join('\n');

  /* =========================================================
     八、分頁一：規則比對
     ========================================================= */
  var DS = { entries: null, view: 'side', showSame: false };

  function renderDiff() {
    var box = $('result');
    box.textContent = '';
    var o = parseRules($('oldRules').value), n = parseRules($('newRules').value);
    if (!o.rules.length && !n.rules.length && !o.errors.length && !n.errors.length) {
      DS.entries = null;
      $('diffTools').hidden = true;
      box.appendChild(el('p', 'panel empty', '兩邊都沒有規則。請貼上規則，或按「填入範例 A／B」。'));
      return;
    }
    var d = buildDiff(o.rules, n.rules);
    DS.entries = d.entries;
    $('diffTools').hidden = false;

    var counts = el('div', 'counts');
    counts.appendChild(countTile('新增', d.counts.add, 'add'));
    counts.appendChild(countTile('刪除', d.counts.del, 'del'));
    counts.appendChild(countTile('修改', d.counts.mod, 'mod'));
    counts.appendChild(countTile('順序調整', d.counts.moved, 'moved'));
    counts.appendChild(countTile('不變', d.counts.same, 'same'));
    box.appendChild(counts);

    if (d.counts.moved) {
      box.appendChild(el('p', 'panel notice', '有 ' + d.counts.moved + ' 條規則內容沒變、只有順序改變。防火牆由上往下比對，順序改變可能改變實際行為，屬於高風險異動，請特別審查。'));
    }
    if (o.errors.length) { box.appendChild(problemPanel('舊版格式有誤的行', o.errors, true)); }
    if (n.errors.length) { box.appendChild(problemPanel('新版格式有誤的行', n.errors, true)); }
    if (o.errors.length || n.errors.length) {
      box.appendChild(el('p', 'say', '有格式錯誤的行沒有參與比對，規則編號只計算格式正確的規則。請修正後再按一次「比對」。'));
    }
    var dupList = [];
    d.dups.old.forEach(function (r) { dupList.push({ n: r.line, text: '（舊版）' + ruleText(r) }); });
    d.dups.neu.forEach(function (r) { dupList.push({ n: r.line, text: '（新版）' + ruleText(r) }); });
    if (dupList.length) { box.appendChild(problemPanel('重複的規則', dupList, false)); }

    var warns = analyze(n.rules);
    if (warns.length) { box.appendChild(warnPanel('新版規則的遮蔽與冗餘分析', warns)); }

    var host = el('div'); host.id = 'diffList';
    box.appendChild(host);
    renderDiffList();
  }

  var SIGN = { add: '+', del: '−', mod: '~', moved: '↕', same: '=' };
  var TYPE_NAME = { add: '新增', del: '刪除', mod: '修改', moved: '順序調整', same: '不變' };

  function explain(e) {
    if (e.type === 'add') { return '新版多了這一條。' + plain(e.after) + '。'; }
    if (e.type === 'del') { return '舊版有，新版沒有。' + plain(e.before) + '。'; }
    if (e.type === 'mod') { return '連線條件相同，但動作從「' + e.before.action + '」改成「' + e.after.action + '」。'; }
    if (e.type === 'moved') { return '規則內容沒變，但順序從第 ' + e.before.no + ' 條移到第 ' + e.after.no + ' 條。這是高風險異動，請確認新順序符合預期。'; }
    return '';
  }

  function renderDiffList() {
    var host = $('diffList');
    if (!host || !DS.entries) { return; }
    host.textContent = '';
    var rows = DS.entries.filter(function (e) { return e.type !== 'same' || DS.showSame; });
    var sec = el('section', 'panel');
    var changed = DS.entries.some(function (e) { return e.type !== 'same'; });
    sec.appendChild(el('h2', '', DS.view === 'side' ? '差異明細（左右並排）' : '差異明細（統整）'));
    if (!rows.length) {
      sec.appendChild(el('p', 'empty', changed ? '沒有可顯示的項目。' : '兩份規則的內容與順序完全相同。若要查看全部規則，請勾選「顯示不變的規則」。'));
      host.appendChild(sec);
      return;
    }
    if (DS.view === 'side') {
      var head = el('div', 'dhead');
      head.appendChild(el('span', '', ''));
      head.appendChild(el('span', '', '舊版'));
      head.appendChild(el('span', '', '新版'));
      sec.appendChild(head);
    }
    var ul = el('ul', 'dlist');
    rows.forEach(function (e) {
      var li = el('li', 'de de-' + e.type + (DS.view === 'uni' ? ' u' : ''));
      var sign = el('span', 'sign s-' + e.type, SIGN[e.type]);
      sign.setAttribute('title', TYPE_NAME[e.type]);
      li.appendChild(sign);
      if (DS.view === 'side') {
        var c1 = el('div', 'col'), c2 = el('div', 'col');
        if (e.before) { c1.appendChild(ruleNode(e.before, '#' + e.before.no)); } else { c1.appendChild(el('span', 'none', '（無）')); }
        if (e.after) { c2.appendChild(ruleNode(e.after, '#' + e.after.no)); } else { c2.appendChild(el('span', 'none', '（無）')); }
        li.appendChild(c1); li.appendChild(c2);
      } else {
        var ls = el('div', 'ulines');
        var line = function (mark, cls, r) {
          var d = el('div', 'uline ' + cls);
          d.appendChild(el('span', 'mark', mark));
          d.appendChild(ruleNode(r, '#' + r.no));
          ls.appendChild(d);
        };
        if (e.type === 'add') { line('+', 'u-add', e.after); }
        else if (e.type === 'del') { line('−', 'u-del', e.before); }
        else if (e.type === 'mod') { line('−', 'u-del', e.before); line('+', 'u-add', e.after); }
        else if (e.type === 'moved') { line('↕', 'u-moved', e.after); }
        else { line(' ', 'u-same', e.after); }
        li.appendChild(ls);
      }
      var say = explain(e);
      if (say || e.type === 'moved') {
        var p = el('p', 'say');
        if (e.type === 'moved') { p.appendChild(el('span', 'tagw movedtag', '順序調整')); p.appendChild(document.createTextNode(' ')); }
        p.appendChild(document.createTextNode(say));
        li.appendChild(p);
      }
      ul.appendChild(li);
    });
    sec.appendChild(ul);
    host.appendChild(sec);
  }

  function exportDiff() {
    if (!DS.entries) { return; }
    var rows = [['類型', '舊版第幾條', '新版第幾條', '動作', '協定', '來源', '目的', '埠號', '備註']];
    DS.entries.forEach(function (e) {
      var r = e.after || e.before;
      rows.push([TYPE_NAME[e.type], e.before ? e.before.no : '', e.after ? e.after.no : '', r.action, r.proto, disp(r.src), disp(r.dst), r.port, e.type === 'mod' ? '動作由「' + e.before.action + '」改為「' + e.after.action + '」' : explain(e)]);
    });
    downloadCsv('firewall-diff-' + stamp() + '.csv', rows);
  }

  /* =========================================================
     九、分頁二：規則與 Log 對應
     ========================================================= */
  var MS = { rows: null, filter: 'all', rp: null, def: '拒絕' };

  function defaultAction() { return $('defPolicy').value === 'allow' ? '允許' : '拒絕'; }

  function renderMap() {
    var box = $('mapResult');
    box.textContent = '';
    var rp = parseRules($('mapRules').value);
    var lp = parseLogs($('mapLogs').value);
    if (!rp.rules.length && !lp.logs.length && !rp.errors.length && !lp.errors.length) {
      MS.rows = null;
      box.appendChild(el('p', 'panel empty', '規則和 log 都是空的。請貼上內容，或按「填入範例規則」與「填入測試 Log」。'));
      return;
    }
    var def = defaultAction();
    var rows = lp.logs.map(function (lg) {
      var found = null;
      for (var i = 0; i < rp.rules.length; i++) { if (ruleHits(rp.rules[i], lg)) { found = rp.rules[i]; break; } }
      var final = found ? found.action : def;
      return { log: lg, rule: found, final: final, mismatch: !!(lg.action && lg.action !== final) };
    });
    MS.rows = rows; MS.rp = rp; MS.def = def;

    var total = rows.length;
    var allow = rows.filter(function (r) { return r.final === '允許'; }).length;
    var deny = total - allow;
    var unmatched = rows.filter(function (r) { return !r.rule; }).length;
    var mismatch = rows.filter(function (r) { return r.mismatch; }).length;
    var hitCount = {};
    rows.forEach(function (r) { if (r.rule) { hitCount[r.rule.no] = (hitCount[r.rule.no] || 0) + 1; } });
    var top = Object.keys(hitCount).map(function (k) { return { no: Number(k), n: hitCount[k] }; })
      .sort(function (a, b) { return b.n - a.n || a.no - b.no; }).slice(0, 3);

    /* 摘要儀表板 */
    var dash = el('section', 'panel dash');
    dash.appendChild(el('h2', '', '結果摘要'));
    var stats = el('div', 'stats');
    var stat = function (num, label, cls) { var s = el('div', 'stat' + (cls ? ' ' + cls : '')); s.appendChild(el('b', '', String(num))); s.appendChild(el('span', '', label)); return s; };
    stats.appendChild(stat(total, '總解析筆數'));
    stats.appendChild(stat(unmatched, '未命中任何規則（套用' + (def === '允許' ? '預設允許' : '預設拒絕') + '）', unmatched ? 'bad' : ''));
    stats.appendChild(stat(mismatch, '與 log 記錄動作不一致', mismatch ? 'bad' : ''));
    dash.appendChild(stats);

    if (total) {
      var ap = Math.round(allow / total * 100), dp = 100 - ap;
      var ratio = el('div', 'ratio');
      ratio.setAttribute('role', 'img');
      ratio.setAttribute('aria-label', '允許 ' + ap + '%，拒絕 ' + dp + '%');
      var ra = el('i', 'r-allow'); ra.style.width = ap + '%';
      var rd = el('i', 'r-deny'); rd.style.width = dp + '%';
      ratio.appendChild(ra); ratio.appendChild(rd);
      dash.appendChild(ratio);
      var rt = el('div', 'ratiotxt');
      rt.appendChild(el('span', 'good', '允許 ' + ap + '%（' + allow + ' 筆）'));
      rt.appendChild(el('span', 'badtxt', '拒絕 ' + dp + '%（' + deny + ' 筆）'));
      dash.appendChild(rt);
    }
    dash.appendChild(el('h3', '', '最常被命中的規則（前 3 名）'));
    if (top.length) {
      var tl = el('ul', 'top3');
      top.forEach(function (t, idx) {
        var li = el('li');
        li.appendChild(el('span', 'n', (idx + 1) + '.'));
        li.appendChild(ruleNode(rp.rules[t.no - 1], '#' + t.no));
        li.appendChild(el('span', 'hits', t.n + ' 筆'));
        tl.appendChild(li);
      });
      dash.appendChild(tl);
    } else {
      dash.appendChild(el('p', 'empty', '沒有任何 log 命中規則。'));
    }
    box.appendChild(dash);

    if (rp.errors.length) { box.appendChild(problemPanel('規則格式有誤的行', rp.errors, true)); }
    if (lp.errors.length) { box.appendChild(problemPanel('Log 格式有誤的行', lp.errors, true)); }
    if (rp.errors.length || lp.errors.length) {
      box.appendChild(el('p', 'say', '有格式錯誤的行沒有參與對應。注意：規則被略過會讓後面規則的編號往前移。'));
    }
    var warns = analyze(rp.rules);
    if (warns.length) { box.appendChild(warnPanel('規則遮蔽與冗餘分析', warns)); }

    /* 篩選與匯出 */
    var tb = el('div', 'panel toolbar');
    var seg = el('div', 'seg');
    seg.setAttribute('role', 'group'); seg.setAttribute('aria-label', '篩選 log');
    [['all', '全部'], ['deny', '僅顯示拒絕'], ['issue', '僅顯示未命中／異常']].forEach(function (f) {
      var b = el('button', '', f[1]);
      b.type = 'button';
      b.setAttribute('aria-pressed', MS.filter === f[0] ? 'true' : 'false');
      b.addEventListener('click', function () {
        MS.filter = f[0];
        Array.prototype.forEach.call(seg.children, function (c) { c.setAttribute('aria-pressed', c === b ? 'true' : 'false'); });
        renderLogTable();
      });
      seg.appendChild(b);
    });
    tb.appendChild(seg);
    var ex = el('button', 'ghost', '匯出比對報告 (CSV)');
    ex.type = 'button';
    ex.addEventListener('click', exportMap);
    tb.appendChild(ex);
    box.appendChild(tb);

    var host = el('div'); host.id = 'logTable';
    box.appendChild(host);
    renderLogTable();
  }

  function renderLogTable() {
    var host = $('logTable');
    if (!host || !MS.rows) { return; }
    host.textContent = '';
    var rows = MS.rows.filter(function (r) {
      if (MS.filter === 'deny') { return r.final === '拒絕'; }
      if (MS.filter === 'issue') { return !r.rule || r.mismatch; }
      return true;
    });
    var CAP = 1000;
    var sec = el('section', 'panel');
    sec.appendChild(el('h2', '', 'Log 明細（顯示 ' + Math.min(rows.length, CAP) + ' / ' + rows.length + ' 筆' + (MS.filter === 'all' ? '' : '，已篩選') + '）'));
    if (!rows.length) { sec.appendChild(el('p', 'empty', MS.rows.length ? '沒有符合篩選條件的 log。' : '沒有可顯示的 log。')); host.appendChild(sec); return; }
    if (rows.length > CAP) { sec.appendChild(el('p', 'say', '為了讓頁面順暢，最多顯示前 ' + CAP + ' 筆；摘要數字與匯出的 CSV 包含全部。')); }

    var wrap = el('div', 'tablewrap');
    var table = el('table', 'logtable');
    var thead = el('thead'), htr = el('tr');
    ['行', '時間', '連線', '最終動作', '命中', '備註'].forEach(function (h) { htr.appendChild(el('th', '', h)); });
    thead.appendChild(htr); table.appendChild(thead);
    var tbody = el('tbody');
    rows.slice(0, CAP).forEach(function (r) {
      var lg = r.log;
      var tr = el('tr', (!r.rule || r.mismatch) ? 'issue' : '');
      tr.appendChild(el('td', 'mono', String(lg.n)));
      tr.appendChild(el('td', 'mono', lg.date + ' ' + lg.time));
      tr.appendChild(el('td', 'mono', lg.proto + ' ' + lg.src + ' → ' + lg.dst + (lg.proto === 'ICMP' ? '' : ':' + lg.port)));
      var td = el('td'); td.appendChild(el('span', 'pill ' + (r.final === '允許' ? 'allow' : 'deny'), r.final)); tr.appendChild(td);
      tr.appendChild(el('td', '', r.rule ? '第 ' + r.rule.no + ' 條' : '預設政策'));
      var note = [];
      if (!r.rule) { note.push('沒有任何規則符合'); }
      if (r.mismatch) { note.push('log 記錄為「' + lg.action + '」，與最終動作不一致'); }
      tr.appendChild(el('td', 'notecell', note.join('；')));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody); wrap.appendChild(table); sec.appendChild(wrap);
    host.appendChild(sec);
  }

  function exportMap() {
    if (!MS.rows) { return; }
    var out = [['行', '日期', '時間', '協定', '來源', '目的', '埠號', 'log 記錄動作', '命中規則序', '命中規則內容', '最終動作', '判定來源', '備註']];
    MS.rows.forEach(function (r) {
      var lg = r.log, note = [];
      if (!r.rule) { note.push('沒有任何規則符合'); }
      if (r.mismatch) { note.push('與 log 記錄動作不一致'); }
      out.push([lg.n, lg.date, lg.time, lg.proto, lg.src, lg.dst, lg.port, lg.action, r.rule ? r.rule.no : '', r.rule ? ruleText(r.rule) : '', r.final, r.rule ? '規則' : (MS.def === '允許' ? '預設允許' : '預設拒絕'), note.join('；')]);
    });
    downloadCsv('firewall-log-map-' + stamp() + '.csv', out);
  }

  /* =========================================================
     十、匯入 log 檔
     ========================================================= */
  var MAX_BYTES = 2 * 1024 * 1024;
  function say(msg, bad) {
    var m = $('importMsg');
    m.hidden = false;
    m.textContent = msg;
    m.style.color = bad ? 'var(--del)' : 'var(--muted)';
  }
  // CSV：逗號換成空白，沒有「->」欄就補上，第一列若是標題就略過
  function csvToLogText(text) {
    var out = [], skipped = 0;
    text.replace(/^﻿/, '').split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line) { return; }
      var cells = line.split(',').map(function (c) { return c.trim().replace(/^"|"$/g, ''); });
      if (i === 0 && !/^\d/.test(cells[0])) { skipped = 1; return; }
      if (cells.length >= 6 && cells.indexOf('->') < 0) { cells.splice(4, 0, '->'); }
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
      setVal('mapLogs', text);
      var n = text.split(/\r?\n/).filter(function (l) { var t = l.trim(); return t && t.charAt(0) !== '#'; }).length;
      say('已匯入「' + file.name + '」，共 ' + n + ' 行' + note + '。內容只在你的瀏覽器內處理，沒有上傳。', false);
      renderMap();
    };
    reader.readAsText(file);
  }

  /* =========================================================
     十一、事件與初始化
     ========================================================= */
  function showTab(which) {
    var isDiff = which === 'diff';
    $('viewDiff').hidden = !isDiff;
    $('viewLog').hidden = isDiff;
    $('tabDiff').setAttribute('aria-selected', isDiff ? 'true' : 'false');
    $('tabLog').setAttribute('aria-selected', isDiff ? 'false' : 'true');
  }
  function setPressed(a, b, firstOn) {
    $(a).setAttribute('aria-pressed', firstOn ? 'true' : 'false');
    $(b).setAttribute('aria-pressed', firstOn ? 'false' : 'true');
  }

  makeEditor('oldRules', 'rules');
  makeEditor('newRules', 'rules');
  makeEditor('mapRules', 'rules');
  makeEditor('mapLogs', 'logs');

  $('tabDiff').addEventListener('click', function () { showTab('diff'); });
  $('tabLog').addEventListener('click', function () { showTab('log'); });

  // 分頁一
  $('compareBtn').addEventListener('click', renderDiff);
  $('fillA').addEventListener('click', function () { setVal('oldRules', SAMPLE_A); });
  $('fillB').addEventListener('click', function () { setVal('newRules', SAMPLE_B); });
  $('clearOld').addEventListener('click', function () { setVal('oldRules', ''); });
  $('clearNew').addEventListener('click', function () { setVal('newRules', ''); });
  $('sampleBtn').addEventListener('click', function () { setVal('oldRules', SAMPLE_A); setVal('newRules', SAMPLE_B); renderDiff(); });
  $('clearBtn').addEventListener('click', function () {
    setVal('oldRules', ''); setVal('newRules', '');
    $('result').textContent = ''; $('diffTools').hidden = true; DS.entries = null;
  });
  $('viewSide').addEventListener('click', function () { DS.view = 'side'; setPressed('viewSide', 'viewUni', true); renderDiffList(); });
  $('viewUni').addEventListener('click', function () { DS.view = 'uni'; setPressed('viewSide', 'viewUni', false); renderDiffList(); });
  $('showSame').addEventListener('change', function () { DS.showSame = this.checked; renderDiffList(); });
  $('exportDiff').addEventListener('click', exportDiff);

  // 分頁二
  $('mapBtn').addEventListener('click', renderMap);
  $('fillRules').addEventListener('click', function () { setVal('mapRules', SAMPLE_RULES); });
  $('fillLogs').addEventListener('click', function () { setVal('mapLogs', SAMPLE_LOGS); });
  $('clearRules').addEventListener('click', function () { setVal('mapRules', ''); });
  $('clearLogs').addEventListener('click', function () { setVal('mapLogs', ''); $('importMsg').hidden = true; });
  $('mapSampleBtn').addEventListener('click', function () { setVal('mapRules', SAMPLE_RULES); setVal('mapLogs', SAMPLE_LOGS); renderMap(); });
  $('useNewBtn').addEventListener('click', function () { setVal('mapRules', $('newRules').value); renderMap(); });
  $('mapClearBtn').addEventListener('click', function () {
    setVal('mapRules', ''); setVal('mapLogs', '');
    $('mapResult').textContent = ''; $('importMsg').hidden = true; MS.rows = null;
  });
  $('defPolicy').addEventListener('change', function () { if (MS.rows) { renderMap(); } });
  $('importBtn').addEventListener('click', function () { $('logFile').click(); });
  $('logFile').addEventListener('change', function () { importLogFile(this.files && this.files[0]); this.value = ''; });
  $('mapLogs').addEventListener('dragover', function (e) { e.preventDefault(); });
  $('mapLogs').addEventListener('drop', function (e) {
    e.preventDefault();
    importLogFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
  });

  // 開啟頁面時先載入示範資料，讓畫面不是空的
  setVal('oldRules', SAMPLE_A);
  setVal('newRules', SAMPLE_B);
  setVal('mapRules', SAMPLE_RULES);
  setVal('mapLogs', SAMPLE_LOGS);
  renderDiff();
  renderMap();
})();
