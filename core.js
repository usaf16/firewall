/* 核心邏輯：解析、比對、分析。不碰 DOM，主執行緒與 Web Worker 共用。 */
(function (root) {
  'use strict';

  var ANY = '任意';
  var ACTIONS = {
    '允許': '允許', 'ALLOW': '允許', 'PERMIT': '允許', 'ACCEPT': '允許', 'PASS': '允許',
    '拒絕': '拒絕', 'DENY': '拒絕', 'DROP': '拒絕', 'BLOCK': '拒絕', 'REJECT': '拒絕'
  };
  var SERVICES = { HTTP: 80, HTTPS: 443, SSH: 22, DNS: 53, FTP: 21, TELNET: 23, SMTP: 25, NTP: 123, SMB: 445, RDP: 3389, MYSQL: 3306 };
  var PROTOS = ['TCP', 'UDP', 'ICMP'];

  function has(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
  function isAny(t) { var u = t.toUpperCase(); return t === ANY || u === 'ANY' || u === 'ALL' || t === '*'; }
  function actionOf(t) { var u = t.toUpperCase(); return has(ACTIONS, u) ? ACTIONS[u] : ''; }
  function arrowProblem(t) {
    if (t === '->' || t === '→') { return ''; }
    if (/^[-=]*>+$|^→+$/.test(t)) { return '箭頭請寫成 ->，目前是「' + t + '」。'; }
    return '來源與目的之間要用「->」連接，目前是「' + t + '」。';
  }

  /* ---------- IPv4 / IPv6 ---------- */
  var ZERO = BigInt(0), ONE = BigInt(1), ALL128 = (ONE << BigInt(128)) - ONE;

  function ipToInt(s) {
    var q = s.split('.');
    return (((Number(q[0]) * 256 + Number(q[1])) * 256 + Number(q[2])) * 256 + Number(q[3])) >>> 0;
  }
  function intToIp(n) { return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  function maskOf(m) { return m === 0 ? 0 : (0xFFFFFFFF << (32 - m)) >>> 0; }
  function mask6(len) { return len === 0 ? ZERO : (ALL128 ^ ((ONE << BigInt(128 - len)) - ONE)); }
  function hexToBig(addr) { return BigInt('0x' + addr.split(':').join('')); }
  function bigToGroups(n) {
    var h = n.toString(16);
    while (h.length < 32) { h = '0' + h; }
    var g = [];
    for (var i = 0; i < 8; i++) { g.push(h.substr(i * 4, 4)); }
    return g;
  }
  function compress6(canon) {
    var g = canon.split(':').map(function (x) { return x.replace(/^0+(?=.)/, ''); });
    var bestS = -1, bestL = 0, curS = -1, curL = 0;
    for (var i = 0; i < 8; i++) {
      if (g[i] === '0') { if (curS < 0) { curS = i; curL = 0; } curL++; if (curL > bestL) { bestL = curL; bestS = curS; } }
      else { curS = -1; curL = 0; }
    }
    if (bestL < 2) { return g.join(':'); }
    var left = g.slice(0, bestS).join(':'), right = g.slice(bestS + bestL).join(':');
    return left + '::' + right;
  }

  function parseV6(t) {
    var m = /^([0-9A-Fa-f:]+)(?:\/(\d+))?$/.exec(t);
    if (!m) { return { ok: false, msg: 'IPv6 位址格式不對：「' + t + '」（不支援內嵌 IPv4 與區域識別碼）。' }; }
    var addr = m[1], parts, dbl = addr.indexOf('::');
    if (addr.indexOf(':::') >= 0 || dbl !== addr.lastIndexOf('::')) { return { ok: false, msg: 'IPv6 位址只能有一個「::」：「' + t + '」。' }; }
    if (dbl >= 0) {
      var h = addr.slice(0, dbl), tl = addr.slice(dbl + 2);
      var head = h ? h.split(':') : [], tail = tl ? tl.split(':') : [];
      if (head.length + tail.length > 7) { return { ok: false, msg: 'IPv6 位址的群組太多：「' + t + '」。' }; }
      parts = head.concat(new Array(8 - head.length - tail.length).fill('0'), tail);
    } else {
      parts = addr.split(':');
      if (parts.length !== 8) { return { ok: false, msg: 'IPv6 位址必須有 8 組（或用「::」省略）：「' + t + '」。' }; }
    }
    for (var i = 0; i < 8; i++) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(parts[i])) { return { ok: false, msg: 'IPv6 位址每一組必須是 1 到 4 位十六進位：「' + t + '」。' }; }
    }
    var len = m[2] === undefined ? 128 : Number(m[2]);
    if (len > 128) { return { ok: false, msg: '不合法的 CIDR 遮罩格式 (' + t + ')，IPv6 遮罩必須是 0 到 128。' }; }
    if (len === 0) { return { ok: true, norm: ANY }; }
    var n = hexToBig(parts.map(function (x) { return ('0000' + x.toLowerCase()).slice(-4); }).join(':'));
    return { ok: true, norm: bigToGroups(n & mask6(len)).join(':') + '/' + len };
  }

  function parseIp(t) {
    if (isAny(t)) { return { ok: true, norm: ANY }; }
    if (t.indexOf(':') >= 0) { return parseV6(t); }
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d+))?$/.exec(t);
    if (!m) { return { ok: false, msg: '位址格式不對：「' + t + '」。請寫成 10.0.0.5、10.0.0.0/24、IPv6（如 2001:db8::/32）或「任意」。' }; }
    for (var i = 1; i <= 4; i++) {
      if (Number(m[i]) > 255) { return { ok: false, msg: 'IP 位址每一段必須是 0 到 255：「' + t + '」。' }; }
    }
    var mask = m[5] === undefined ? 32 : Number(m[5]);
    if (mask > 32) { return { ok: false, msg: '不合法的 CIDR 遮罩格式 (' + t + ')，遮罩必須是 0 到 32。' }; }
    if (mask === 0) { return { ok: true, norm: ANY }; }
    var addr = m[1] + '.' + m[2] + '.' + m[3] + '.' + m[4];
    return { ok: true, norm: intToIp((ipToInt(addr) & maskOf(mask)) >>> 0) + '/' + mask };
  }

  // 預先算好比對用的數值，避免大量 log 比對時重複解析字串
  function prepIp(norm) {
    if (norm === ANY) { return { any: true }; }
    var p = norm.split('/'), len = Number(p[1]);
    if (p[0].indexOf(':') >= 0) { var mm = mask6(len); return { f: 6, n: hexToBig(p[0]) & mm, len: len, mm: mm }; }
    var m = maskOf(len);
    return { f: 4, n: (ipToInt(p[0]) & m) >>> 0, len: len, m: m };
  }
  function prepHost(addr) {
    if (addr.indexOf(':') >= 0) { return { f: 6, n: hexToBig(addr) }; }
    return { f: 4, n: ipToInt(addr) };
  }
  function ipHit(spec, ip) {
    if (spec.any) { return true; }
    if (spec.f !== ip.f) { return false; }
    return spec.f === 4 ? ((ip.n & spec.m) >>> 0) === spec.n : (ip.n & spec.mm) === spec.n;
  }
  function ipCover(a, b) {
    if (a.any) { return true; }
    if (b.any) { return false; }
    if (a.f !== b.f || a.len > b.len) { return false; }
    return a.f === 4 ? ((b.n & a.m) >>> 0) === a.n : (b.n & a.mm) === a.n;
  }

  /* ---------- 埠號、變數 ---------- */
  function parsePort(t) {
    if (isAny(t)) { return { ok: true, norm: ANY }; }
    var parts = t.split(','), ranges = [];
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (p === '') { return { ok: false, msg: '埠號清單裡有空的項目：「' + t + '」，多個埠號請用逗號連接且不加空白（例如 80,443）。' }; }
      if (isAny(p)) { return { ok: true, norm: ANY }; }
      var u = p.toUpperCase();
      if (has(SERVICES, u)) { ranges.push([SERVICES[u], SERVICES[u]]); continue; }
      var m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p);
      if (!m) { return { ok: false, msg: '埠號格式不對：「' + p + '」。請寫成 443、8080-8090、80,443、服務名稱（如 HTTPS）、變數（如 $WEB）或「任意」。' }; }
      var a = Number(m[1]), b = m[2] === undefined ? a : Number(m[2]);
      if (a < 1 || a > 65535 || b < 1 || b > 65535) { return { ok: false, msg: '埠號必須在 1 到 65535 之間：「' + p + '」。' }; }
      if (a > b) { return { ok: false, msg: '埠號範圍的起點不能大於終點：「' + p + '」。' }; }
      ranges.push([a, b]);
    }
    ranges.sort(function (x, y) { return x[0] - y[0]; });
    var merged = [];
    ranges.forEach(function (r) {
      var last = merged[merged.length - 1];
      if (last && r[0] <= last[1] + 1) { last[1] = Math.max(last[1], r[1]); } else { merged.push([r[0], r[1]]); }
    });
    return { ok: true, norm: merged.map(function (r) { return r[0] === r[1] ? String(r[0]) : r[0] + '-' + r[1]; }).join(',') };
  }
  // 埠號欄位可以用 $變數（服務物件群組）
  function parsePortVars(t, vars) {
    if (t.indexOf('$') < 0) { return parsePort(t); }
    var out = [], parts = t.split(',');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (p.charAt(0) === '$') {
        var k = p.slice(1).toUpperCase();
        if (!has(vars, k)) { return { ok: false, msg: '未定義的變數 ' + p + '（請先在規則上方用「$名稱 = 80,443」定義）。' }; }
        out.push(vars[k]);
      } else { out.push(p); }
    }
    return parsePort(out.join(','));
  }
  function portRanges(s) {
    return s.split(',').map(function (x) { var r = x.split('-'); return [Number(r[0]), Number(r[r.length - 1])]; });
  }
  function portCover(a, b) {
    if (!a) { return true; }
    if (!b) { return false; }
    return b.every(function (y) { return a.some(function (x) { return x[0] <= y[0] && y[1] <= x[1]; }); });
  }
  function portHit(ranges, v) {
    if (!ranges) { return true; }
    if (v === null) { return false; }
    for (var i = 0; i < ranges.length; i++) { if (v >= ranges[i][0] && v <= ranges[i][1]) { return true; } }
    return false;
  }

  /* ---------- 規則與 log 解析 ---------- */
  var DEF_RE = /^\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)$/;
  function parseDefinition(line, vars) {
    var m = DEF_RE.exec(line);
    if (!m) { return { error: '變數定義格式不對，請寫成「$名稱 = 80,443」（名稱用英文、數字、底線）。' }; }
    var name = m[1].toUpperCase();
    if (has(vars, name)) { return { error: '變數 $' + name + ' 已經定義過了。' }; }
    var v = parsePortVars(m[2], vars);
    if (!v.ok) { return { error: v.msg }; }
    if (v.norm === ANY) { return { error: '變數的值不能是「任意」。' }; }
    vars[name] = v.norm;
    return {};
  }

  function parseRuleLine(line, vars) {
    var p = line.split(/\s+/);
    if (p.length !== 6) {
      return { error: '欄位數量不對，應該是「動作 協定 來源 -> 目的 埠號」共 6 個部分（目前 ' + p.length + ' 個）。多個埠號請用逗號連接且不加空白，例如 80,443。' };
    }
    var action = actionOf(p[0]);
    if (!action) { return { error: '動作必須是「允許」或「拒絕」（也可寫 allow、permit、deny、drop 等），目前是「' + p[0] + '」。' }; }
    var proto = isAny(p[1]) ? ANY : p[1].toUpperCase();
    if (proto !== ANY && PROTOS.indexOf(proto) < 0) { return { error: '協定必須是 TCP、UDP、ICMP 或「任意」，目前是「' + p[1] + '」。' }; }
    var src = parseIp(p[2]);
    if (!src.ok) { return { error: '來源：' + src.msg }; }
    var ap = arrowProblem(p[3]);
    if (ap) { return { error: ap }; }
    var dst = parseIp(p[4]);
    if (!dst.ok) { return { error: '目的：' + dst.msg }; }
    var port = parsePortVars(p[5], vars);
    if (!port.ok) { return { error: port.msg }; }
    if (proto === 'ICMP' && port.norm !== ANY) { return { error: 'ICMP 沒有埠號，埠號請寫「任意」。' }; }
    return {
      rule: {
        action: action, proto: proto, src: src.norm, dst: dst.norm, port: port.norm,
        key: [proto, src.norm, dst.norm, port.norm].join('|'),
        _s: prepIp(src.norm), _d: prepIp(dst.norm), _p: port.norm === ANY ? null : portRanges(port.norm)
      }
    };
  }

  // 規則順序有意義：保留全部有效規則，no = 第幾條有效規則，line = 原始行號。$變數定義行不算規則。
  function parseRules(text) {
    var rules = [], errors = [], vars = {};
    text.split(/\r?\n/).forEach(function (raw, i) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') { return; }
      if (line.charAt(0) === '$') {
        var d = parseDefinition(line, vars);
        if (d.error) { errors.push({ n: i + 1, text: line, msg: d.error }); }
        return;
      }
      var r = parseRuleLine(line, vars);
      if (r.error) { errors.push({ n: i + 1, text: line, msg: r.error }); return; }
      r.rule.line = i + 1;
      r.rule.no = rules.length + 1;
      rules.push(r.rule);
    });
    return { rules: rules, errors: errors, vars: vars };
  }
  // 只掃變數定義（行數很多時，給輸入框上色用）
  function scanVars(lines) {
    var vars = {};
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i].trim();
      if (l.charAt(0) === '$') { parseDefinition(l, vars); }
    }
    return vars;
  }

  function stripMask(norm) { return norm.replace(/\/(32|128)$/, ''); }
  function isHost(norm) { return /\/(32|128)$/.test(norm); }

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
    if (src.norm === ANY || !isHost(src.norm)) { return { error: '來源必須是單一 IP 位址，目前是「' + p[3] + '」。' }; }
    var ap = arrowProblem(p[4]);
    if (ap) { return { error: ap }; }
    var dst = parseIp(p[5]);
    if (!dst.ok) { return { error: '目的：' + dst.msg }; }
    if (dst.norm === ANY || !isHost(dst.norm)) { return { error: '目的必須是單一 IP 位址，目前是「' + p[5] + '」。' }; }
    var port;
    if (proto === 'ICMP') {
      if (!isAny(p[6]) && p[6] !== '-') { return { error: 'ICMP 沒有埠號，埠號請寫「任意」。' }; }
      port = ANY;
    } else {
      var pp = parsePort(p[6]);
      if (!pp.ok || pp.norm === ANY || /[-,]/.test(pp.norm)) { return { error: 'log 的埠號必須是單一數字或服務名稱，目前是「' + p[6] + '」。' }; }
      port = pp.norm;
    }
    var action = '';
    if (p.length === 8) {
      action = actionOf(p[7]);
      if (!action) { return { error: '動作必須是「允許」或「拒絕」，目前是「' + p[7] + '」。' }; }
    }
    var s = stripMask(src.norm), d = stripMask(dst.norm);
    return { log: { date: p[0], time: p[1], proto: proto, src: s, dst: d, port: port, action: action, _s: prepHost(s), _d: prepHost(d) } };
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

  // 輸入框上色用：判斷單一欄位是否格式錯誤（畫紅色波浪底線）
  function tokenBad(kind, idx, tok, toks, vars) {
    if (kind === 'rules') {
      if (toks[0] && toks[0].charAt(0) === '$') {
        if (idx === 0) { return !/^\$[A-Za-z_][A-Za-z0-9_]*(=\S*)?$/.test(tok); }
        if (idx === 1) { return tok !== '='; }
        if (idx === 2) { var dv = parsePortVars(tok, vars); return !dv.ok || dv.norm === ANY; }
        return true;
      }
      if (idx === 0) { return !actionOf(tok); }
      if (idx === 1) { return !isAny(tok) && PROTOS.indexOf(tok.toUpperCase()) < 0; }
      if (idx === 2 || idx === 4) { return !parseIp(tok).ok; }
      if (idx === 3) { return arrowProblem(tok) !== ''; }
      if (idx === 5) {
        var pv = parsePortVars(tok, vars);
        return !pv.ok || (toks[1] && toks[1].toUpperCase() === 'ICMP' && pv.norm !== ANY);
      }
      return true;
    }
    if (idx === 0) { return !/^\d{4}-\d{2}-\d{2}$/.test(tok); }
    if (idx === 1) { return !/^\d{2}:\d{2}:\d{2}$/.test(tok); }
    if (idx === 2) { return PROTOS.indexOf(tok.toUpperCase()) < 0; }
    if (idx === 3 || idx === 5) { var ip = parseIp(tok); return !ip.ok || ip.norm === ANY || !isHost(ip.norm); }
    if (idx === 4) { return arrowProblem(tok) !== ''; }
    if (idx === 6) {
      if (toks[2] && toks[2].toUpperCase() === 'ICMP') { return !isAny(tok) && tok !== '-'; }
      var pp = parsePort(tok); return !pp.ok || pp.norm === ANY || /[-,]/.test(pp.norm);
    }
    if (idx === 7) { return !actionOf(tok); }
    return true;
  }

  /* ---------- 比對與分析 ---------- */
  function covers(a, b) {
    return (a.proto === ANY || a.proto === b.proto) && ipCover(a._s, b._s) && ipCover(a._d, b._d) && portCover(a._p, b._p);
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
  function ruleHits(rule, log) {
    return (rule.proto === ANY || rule.proto === log.proto) && ipHit(rule._s, log._s) && ipHit(rule._d, log._d) &&
      portHit(rule._p, log.port === ANY ? null : Number(log.port));
  }

  // 規則與 log 對應（可在 Web Worker 內執行）
  function computeMap(rulesText, logsText, defAction) {
    var rp = parseRules(rulesText), lp = parseLogs(logsText);
    var rules = rp.rules, rows = new Array(lp.logs.length);
    for (var k = 0; k < lp.logs.length; k++) {
      var lg = lp.logs[k], found = null;
      for (var i = 0; i < rules.length; i++) { if (ruleHits(rules[i], lg)) { found = rules[i]; break; } }
      var fin = found ? found.action : defAction;
      delete lg._s; delete lg._d;
      rows[k] = { log: lg, no: found ? found.no : 0, final: fin, mismatch: !!(lg.action && lg.action !== fin) };
    }
    return { rp: rp, logErrors: lp.errors, rows: rows };
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

  /* ---------- 顯示用文字 ---------- */
  function disp(s) {
    if (s === ANY) { return s; }
    var p = s.split('/');
    if (p[0].indexOf(':') >= 0) { return compress6(p[0]) + (p[1] === undefined || p[1] === '128' ? '' : '/' + p[1]); }
    return p[1] === undefined || p[1] === '32' ? p[0] : s;
  }
  function ruleText(r) { return r.action + ' ' + r.proto + ' ' + disp(r.src) + ' -> ' + disp(r.dst) + ' ' + r.port; }
  function plain(r) {
    var where = function (v) { return v === ANY ? '任意位置' : disp(v); };
    var portText = r.proto === 'ICMP' ? '' : (r.port === ANY ? '，任意埠號' : '，埠號 ' + r.port);
    return r.action + '：' + (r.proto === ANY ? '任何協定' : r.proto) + ' 從 ' + where(r.src) + ' 連到 ' + where(r.dst) + portText;
  }
  // 網段實體範圍（滑鼠懸停提示）
  function cidrInfo(norm) {
    var parts = norm.split('/'), len = Number(parts[1]);
    if (parts[0].indexOf(':') >= 0) {
      if (len === 128) { return '單一主機 ' + compress6(parts[0]); }
      var net = hexToBig(parts[0]) & mask6(len);
      var last = net | (ALL128 ^ mask6(len));
      var bits = 128 - len;
      var count = bits <= 40 ? Math.pow(2, bits).toLocaleString('en-US') : '2^' + bits;
      return compress6(bigToGroups(net).join(':')) + ' – ' + compress6(bigToGroups(last).join(':')) + '（共 ' + count + ' 個位址）';
    }
    var n4 = (ipToInt(parts[0]) & maskOf(len)) >>> 0;
    var size = Math.pow(2, 32 - len), l4 = (n4 + size - 1) >>> 0;
    if (len === 32) { return '單一主機 ' + parts[0]; }
    if (len === 31) { return intToIp(n4) + ' – ' + intToIp(l4) + '（2 個位址，點對點連線）'; }
    return intToIp(n4) + ' – ' + intToIp(l4) + '（共 ' + size.toLocaleString('en-US') + ' 個位址，可用主機 ' + intToIp(n4 + 1) + ' – ' + intToIp(l4 - 1) + '）';
  }

  root.FWCore = {
    ANY: ANY, isAny: isAny, actionOf: actionOf,
    parseRules: parseRules, parseLogs: parseLogs, scanVars: scanVars, tokenBad: tokenBad,
    analyze: analyze, warnText: warnText, computeMap: computeMap, buildDiff: buildDiff,
    disp: disp, ruleText: ruleText, plain: plain, cidrInfo: cidrInfo
  };
})(typeof self !== 'undefined' ? self : this);
