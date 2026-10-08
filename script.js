(function () {
  'use strict';

  var C = self.FWCore;
  var ANY = C.ANY;
  var disp = C.disp, ruleText = C.ruleText, plain = C.plain, analyze = C.analyze, warnText = C.warnText;
  var parseRules = C.parseRules, parseLogs = C.parseLogs, buildDiff = C.buildDiff;

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined) { e.textContent = text; }
    return e;
  }

  /* =========================================================
     一、畫面小元件
     ========================================================= */
  function hostPort(addr, port) { return addr.indexOf(':') >= 0 ? '[' + disp(addr) + ']:' + port : addr + ':' + port; }

  function addrSpan(v) {
    if (v === ANY) { var a = el('span', 'any', ANY); a.title = '任意位址（所有 IPv4 與 IPv6）'; return a; }
    var s = el('span', 'ip', disp(v));
    s.title = C.cidrInfo(v);
    if (!/\/(32|128)$/.test(v)) { s.className = 'ip cidr'; }
    return s;
  }

  function ruleNode(r, label) {
    var d = el('div', 'rule');
    if (label) { d.appendChild(el('em', 'lab', label)); }
    d.appendChild(el('span', 'act ' + (r.action === '允許' ? 'allow' : 'deny'), r.action));
    d.appendChild(el('span', r.proto === ANY ? 'pro any' : 'pro', r.proto));
    d.appendChild(addrSpan(r.src));
    d.appendChild(el('span', 'arrow', '→'));
    d.appendChild(addrSpan(r.dst));
    d.appendChild(r.port === ANY ? el('span', 'any', '任意埠') : el('span', 'port', '埠 ' + r.port));
    return d;
  }

  function problemPanel(title, list, showMsg) {
    var sec = el('section', 'panel errors');
    sec.appendChild(el('h2', '', title + '（' + list.length + '）'));
    var ul = el('ul', 'plain');
    list.slice(0, 200).forEach(function (e) {
      var li = el('li');
      li.appendChild(el('div', 'rule', '第 ' + e.n + ' 行：' + e.text));
      li.appendChild(el('p', 'say', showMsg ? e.msg : '與前面的規則比對條件相同，已略過這一行。'));
      ul.appendChild(li);
    });
    if (list.length > 200) { ul.appendChild(el('li', 'say', '還有 ' + (list.length - 200) + ' 筆未列出。')); }
    sec.appendChild(ul);
    return sec;
  }

  function warnPanel(title, warns) {
    var sec = el('section', 'panel warnpanel');
    sec.appendChild(el('h2', '', title + '（' + warns.length + '）'));
    var ul = el('ul', 'plain');
    warns.slice(0, 200).forEach(function (w) {
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
     二、CSV 匯出
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
     三、暫存（localStorage）與主題
     ========================================================= */
  var STORE = 'fw-diff-v2', THEME_KEY = 'fw-theme';
  function loadSaved() {
    try { var s = localStorage.getItem(STORE); return s ? JSON.parse(s) : null; } catch (e) { return null; }
  }
  function fmtOf(id) { var s = $(id + 'Fmt'); return s ? s.value : 'auto'; }
  function save() {
    try {
      localStorage.setItem(STORE, JSON.stringify({
        oldRules: $('oldRules').value, newRules: $('newRules').value,
        mapRules: $('mapRules').value, mapLogs: $('mapLogs').value, def: $('defPolicy').value,
        fmts: { oldRules: fmtOf('oldRules'), newRules: fmtOf('newRules'), mapRules: fmtOf('mapRules') }
      }));
    } catch (e) { /* 無痕模式或儲存空間已滿（大檔案）時略過 */ }
  }
  function applyTheme(t) {
    document.documentElement.setAttribute('data-fw-theme', t);
    var b = $('themeBtn');
    b.textContent = t === 'dark' ? '切換為淺色模式' : '切換為深色模式';
    b.setAttribute('aria-pressed', t === 'dark' ? 'true' : 'false');
  }

  /* =========================================================
     四、輸入框：行號、語法上色、波浪底線、錯誤行反白、即時檢查
        只繪製畫面上看得到的行（加上前後緩衝），行數再多也不會變慢
     ========================================================= */
  var ED = {};
  var BUF = 25, LINT_MAX = 5000;

  function tokenClass(kind, idx, tok, toks) {
    if (kind === 'rules') {
      if (toks[0].charAt(0) === '$') { return idx === 0 ? 'tk-var' : (idx === 1 ? 'tk-arrow' : (idx === 2 ? 'tk-port' : '')); }
      if (idx === 0) { var a = C.actionOf(tok); return a === '允許' ? 'tk-allow' : (a === '拒絕' ? 'tk-deny' : ''); }
      if (idx === 1) { return C.isAny(tok) ? 'tk-any' : 'tk-proto'; }
      if (idx === 2 || idx === 4) { return C.isAny(tok) ? 'tk-any' : 'tk-ip'; }
      if (idx === 3) { return 'tk-arrow'; }
      if (idx === 5) { return C.isAny(tok) ? 'tk-any' : (tok.indexOf('$') >= 0 ? 'tk-var' : 'tk-port'); }
      return '';
    }
    if (idx === 0 || idx === 1) { return 'tk-date'; }
    if (idx === 2) { return 'tk-proto'; }
    if (idx === 3 || idx === 5) { return 'tk-ip'; }
    if (idx === 4) { return 'tk-arrow'; }
    if (idx === 6) { return C.isAny(tok) ? 'tk-any' : 'tk-port'; }
    if (idx === 7) { var b = C.actionOf(tok); return b === '允許' ? 'tk-allow' : (b === '拒絕' ? 'tk-deny' : ''); }
    return '';
  }

  // 其他格式（iptables、Cisco、CSV…）的簡易上色：動作、協定、位址、埠號、選項各一種顏色，不畫波浪底線
  function genericHighlight(container, line) {
    line.split(/([\s,;]+)/).forEach(function (p) {
      if (p === '') { return; }
      if (/^[\s,;]+$/.test(p)) { container.appendChild(document.createTextNode(p)); return; }
      var t = p.replace(/^["']|["']$/g, ''), cls = '', a = C.actionOf(t);
      if (a === '允許') { cls = 'tk-allow'; }
      else if (a === '拒絕') { cls = 'tk-deny'; }
      else if (/^(tcp|udp|icmp|ip|all|ipv4|ipv6)$/i.test(t)) { cls = 'tk-proto'; }
      else if (/^(any|\*)$/i.test(t)) { cls = 'tk-any'; }
      else if (/^[0-9a-f:.]+(\/\d+)?$/i.test(t) && /[.:]/.test(t)) { cls = 'tk-ip'; }
      else if (/^\d+([-:]\d+)?$/.test(t)) { cls = 'tk-port'; }
      else if (/^-{1,2}[A-Za-z]/.test(t) || /^(host|eq|range|gt|lt|neq|log|multiport)$/i.test(t)) { cls = 'tk-arrow'; }
      if (cls) { container.appendChild(el('span', cls, p)); } else { container.appendChild(document.createTextNode(p)); }
    });
  }

  // 上色層與輸入框逐字對齊，所以只用顏色與底線，不改粗細或斜體。格式錯誤的欄位畫紅色波浪底線。
  function highlightInto(container, line, kind, vars, fmt, tableMode) {
    var trimmed = line.trim();
    if (trimmed.charAt(0) === '#' || (kind === 'rules' && fmt !== 'simple' && trimmed.charAt(0) === '!')) { container.appendChild(el('span', 'tk-cm', line)); return; }
    if (kind === 'rules' && fmt !== 'simple' && (fmt !== 'auto' || C.guessKind(trimmed, tableMode) !== 'simple')) { genericHighlight(container, line); return; }
    var toks = trimmed ? trimmed.split(/\s+/) : [];
    var idx = 0;
    line.split(/(\s+)/).forEach(function (p) {
      if (p === '') { return; }
      if (/^\s+$/.test(p)) { container.appendChild(document.createTextNode(p)); return; }
      var cls = tokenClass(kind, idx, p, toks);
      if (C.tokenBad(kind, idx, p, toks, vars)) { cls += ' tk-bad'; }
      idx++;
      if (cls.trim()) { container.appendChild(el('span', cls.trim(), p)); } else { container.appendChild(document.createTextNode(p)); }
    });
  }

  function makeEditor(id, kind) {
    var ta = $(id), gut = $(id + 'Gut'), hl = $(id + 'Hl'), lint = $(id + 'Lint'), timer = 0;
    var hlIn = el('div', 'hl-inner'), gutIn = el('div', 'gut-inner');
    hl.appendChild(hlIn); gut.appendChild(gutIn);
    var lines = [''], bad = {}, wn = {}, vars = {}, win = { a: 0, b: -1 }, marked = 0, lh = 24;
    var fmt = 'auto', tableMode = null;
    var ed = { onchange: null };

    function lineH() { var v = parseFloat(getComputedStyle(ta).lineHeight); if (v > 0) { lh = v; } return lh; }

    function rebuild(a, b) {
      hlIn.textContent = ''; gutIn.textContent = '';
      var fh = document.createDocumentFragment(), fg = document.createDocumentFragment();
      for (var i = a; i <= b; i++) {
        var n = i + 1;
        var cls = (bad[n] ? ' bad' : (wn[n] ? ' warn' : '')) + (n === marked ? ' xhl' : '');
        var d = el('div', 'hl-line' + cls);
        highlightInto(d, lines[i].replace(/\r$/, ''), kind, vars, fmt, tableMode);
        fh.appendChild(d);
        fg.appendChild(el('div', 'ln' + cls, String(n)));
      }
      hlIn.appendChild(fh); gutIn.appendChild(fg);
      win = { a: a, b: b };
    }
    function place() {
      var top = (12 + win.a * lh - ta.scrollTop) + 'px';
      hlIn.style.top = top; gutIn.style.top = top;
      hlIn.style.left = (-ta.scrollLeft) + 'px';
      hlIn.style.width = ta.scrollWidth + 'px';
    }
    function sync(force) {
      lineH();
      var L = lines.length;
      var first = Math.max(0, Math.floor((ta.scrollTop - 12) / lh));
      var last = Math.min(L - 1, Math.ceil((ta.scrollTop + ta.clientHeight) / lh));
      if (force || win.b < win.a || first < win.a || last > win.b) { rebuild(Math.max(0, first - BUF), Math.min(L - 1, last + BUF)); }
      place();
    }
    // 上色層與行號欄只貼在輸入框「看得到文字」的範圍內，不要蓋到捲軸底下
    function fit() {
      var sbW = ta.offsetWidth - ta.clientWidth, sbH = ta.offsetHeight - ta.clientHeight;
      hl.style.right = sbW + 'px'; hl.style.bottom = sbH + 'px';
      gut.style.bottom = sbH + 'px';
    }

    function refresh() {
      var text = ta.value;
      lines = text.split('\n');
      var L = lines.length;
      vars = kind === 'rules' ? C.scanVars(lines) : {};
      fmt = kind === 'rules' ? fmtOf(id) : 'auto';
      tableMode = kind === 'rules' ? (fmt === 'csv' || fmt === 'aws' ? fmt : (fmt === 'auto' ? C.detectTableMode(lines) : null)) : null;
      bad = {}; wn = {};
      var errs = [], warns = [], count = 0, skipped = L > LINT_MAX, used = [], notes = [];
      if (!skipped) {
        if (kind === 'rules') {
          var pr = parseRules(text, fmt);
          errs = pr.errors; count = pr.rules.length; warns = analyze(pr.rules); used = pr.used; notes = pr.notes;
        } else {
          var pl = parseLogs(text);
          errs = pl.errors; count = pl.logs.length;
        }
        errs.forEach(function (e) { bad[e.n] = true; });
        warns.forEach(function (w) { wn[w.j.line] = true; });
      }
      ta.classList.add('hlmode');
      sync(true); fit();

      lint.textContent = '';
      if (!text.trim()) { lint.appendChild(el('p', 'lint-hint', '尚未輸入內容。')); return; }
      if (skipped) {
        lint.appendChild(el('p', 'lint-hint', '共 ' + L.toLocaleString('en-US') + ' 行，已略過逐行即時檢查（語法上色與波浪底線仍會顯示）。按「' + (kind === 'rules' ? '比對' : '對應') + '」會完整解析並回報錯誤。'));
        return;
      }
      if (kind === 'rules' && used.length) {
        var names = used.map(function (u) { return C.FORMAT_NAMES[u] || u; }).join('、');
        lint.appendChild(el('p', 'lint-hint', '辨識格式：' + names + (fmt === 'auto' ? '（自動偵測）' : '（手動指定）')));
      }
      notes.forEach(function (n) { lint.appendChild(el('p', 'lint-hint', n)); });
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

    function reveal(line) {
      lineH();
      var top = 12 + (line - 1) * lh;
      if (top < ta.scrollTop || top + lh > ta.scrollTop + ta.clientHeight) { ta.scrollTop = Math.max(0, top - ta.clientHeight / 3); }
    }
    // 讓指定行發亮（跨區連動），必要時捲動到可見範圍
    function mark(line) {
      marked = line || 0;
      sync(true);
      if (marked) { reveal(marked); }
    }
    // 點擊跳轉：把游標放到那一行並選取整行，方便直接修改
    function focusLine(line) {
      if (!line || line > lines.length) { return; }
      var start = 0;
      for (var i = 0; i < line - 1; i++) { start += lines[i].length + 1; }
      var end = start + lines[line - 1].length;
      ta.focus({ preventScroll: true });
      ta.setSelectionRange(start, end);
      reveal(line);
      var box = ta.closest('.editor');
      if (box && box.scrollIntoView) { box.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
    }

    ta.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(function () { refresh(); save(); if (ed.onchange) { ed.onchange(); } }, 150);
    });
    ta.addEventListener('scroll', function () { sync(false); });
    var fsel = $(id + 'Fmt');
    if (fsel) { fsel.addEventListener('change', function () { refresh(); save(); if (ed.onchange) { ed.onchange(); } }); }
    if (window.ResizeObserver) { new ResizeObserver(function () { fit(); sync(false); }).observe(ta); }
    ed.refresh = refresh; ed.mark = mark; ed.focusLine = focusLine;
    ED[id] = ed;
  }
  function setVal(id, text) { $(id).value = text; ED[id].refresh(); save(); }

  /* =========================================================
     五、示範資料
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
    '# 範例 B：新版規則（虛構示範，混用英文寫法、服務名稱、多埠號與 IPv6）',
    'allow tcp any -> 192.168.1.10 https',
    'deny tcp any -> any telnet',
    'deny tcp 10.0.0.0/24 -> 192.168.1.20 ssh',
    'allow udp 10.0.0.0/24 -> 192.168.1.53 dns',
    'permit icmp any -> any any',
    'allow tcp 10.0.1.0/24 -> 192.168.1.30 80,443,8080-8090',
    'deny tcp 10.0.1.0/24 -> 192.168.1.30 8085',
    'allow tcp 2001:db8:10::/48 -> 2001:db8:20::10 https'
  ].join('\n');

  var SAMPLE_RULES = [
    '# 規則由上到下比對，先命中者生效（虛構示範）',
    '# 服務物件群組：先定義變數，再在埠號欄使用',
    '$WEB = 80,443,8080-8090',
    '',
    '允許 TCP 10.0.0.0/16 -> 任意 443',
    '允許 TCP 任意 -> 192.168.1.10 https',
    '拒絕 TCP 10.0.1.0/24 -> 任意 443',
    '拒絕 TCP 10.0.0.0/24 -> 192.168.1.20 22',
    '允許 UDP 10.0.0.0/24 -> 192.168.1.53 dns',
    'permit icmp any -> any any',
    'deny tcp any -> any 23',
    'allow tcp 10.0.1.0/24 -> 192.168.1.30 8080-8090',
    '允許 TCP 10.0.0.0/24 -> 任意 443',
    'allow tcp 10.0.2.0/24 -> 192.168.1.30 $WEB',
    'allow tcp 2001:db8:10::/48 -> 2001:db8:20::10 $WEB'
  ].join('\n');

  var SAMPLE_LOGS = [
    '# 連線紀錄（虛構示範，203.0.113.x、198.51.100.x 與 2001:db8:: 為文件保留位址）',
    '2026-10-08 09:15:02 TCP 10.0.1.7 -> 192.168.1.10 443 允許',
    '2026-10-08 09:15:20 TCP 203.0.113.7 -> 192.168.1.10 443 允許',
    '2026-10-08 09:15:40 TCP 10.0.0.8 -> 192.168.1.20 22 拒絕',
    '2026-10-08 09:16:11 UDP 10.0.0.9 -> 192.168.1.53 53 允許',
    '2026-10-08 09:17:03 ICMP 198.51.100.4 -> 192.168.1.1 任意 允許',
    '2026-10-08 09:18:30 TCP 198.51.100.9 -> 192.168.1.40 23 拒絕',
    '2026-10-08 09:19:55 TCP 10.0.1.15 -> 192.168.1.30 8085 允許',
    '2026-10-08 09:21:12 TCP 203.0.113.50 -> 192.168.1.10 80 拒絕',
    '2026-10-08 09:22:40 UDP 198.51.100.77 -> 192.168.1.53 53 允許',
    '2026-10-08 09:23:05 TCP 10.0.1.7 -> 192.168.1.10 443 允許',
    '2026-10-08 09:24:10 TCP 10.0.2.8 -> 192.168.1.30 80 允許',
    '2026-10-08 09:25:00 TCP 2001:db8:10::5 -> 2001:db8:20::10 443 允許'
  ].join('\n');

  /* =========================================================
     六、分頁一：規則比對
     ========================================================= */
  // 各格式的範例（內容是同一批虛構規則的不同寫法）
  var FORMAT_SAMPLES = [
    { fmt: 'iptables', label: 'iptables', text: [
      '# iptables 範例（虛構）',
      '-A INPUT -p tcp -s 10.0.0.0/24 -d 192.168.1.20 --dport 22 -j DROP',
      '-A INPUT -p tcp -d 192.168.1.10 -m multiport --dports 80,443 -j ACCEPT',
      '-A INPUT -p udp -s 10.0.0.0/24 -d 192.168.1.53 --dport 53 -j ACCEPT',
      '-A INPUT -p icmp -j ACCEPT',
      '-A INPUT -p tcp --dport 23 -j DROP'].join('\n') },
    { fmt: 'cisco', label: 'Cisco ACL', text: [
      '! Cisco ACL 範例（虛構）',
      'access-list 101 deny tcp 10.0.0.0 0.0.0.255 host 192.168.1.20 eq 22',
      'access-list 101 permit tcp any host 192.168.1.10 eq 80 443',
      'access-list 101 permit udp 10.0.0.0 0.0.0.255 host 192.168.1.53 eq domain',
      'access-list 101 permit icmp any any',
      'access-list 101 deny tcp any any eq telnet'].join('\n') },
    { fmt: 'csv', label: 'CSV／Excel 表格', text: [
      '動作,協定,來源,目的,埠號',
      'deny,tcp,10.0.0.0/24,192.168.1.20,22',
      'allow,tcp,any,192.168.1.10,"80,443"',
      'allow,udp,10.0.0.0/24,192.168.1.53,53',
      'allow,icmp,any,any,any',
      'deny,tcp,any,any,23'].join('\n') },
    { fmt: 'aws', label: 'AWS 安全群組', text: [
      'Type,Protocol,Port range,Source',
      'HTTPS,TCP,443,0.0.0.0/0',
      'SSH,TCP,22,10.0.0.0/24',
      'Custom UDP,UDP,53,10.0.0.0/24',
      'All ICMP - IPv4,ICMP,All,0.0.0.0/0'].join('\n') }
  ];
  function buildFormatLists() {
    Array.prototype.forEach.call(document.querySelectorAll('.fmtlist'), function (box) {
      var target = box.dataset.target;
      FORMAT_SAMPLES.forEach(function (s) {
        var item = el('div', 'fmtitem');
        var head = el('div', 'fmthead');
        head.appendChild(el('strong', '', s.label));
        var b = el('button', 'minibtn', '填入「' + (target === 'mapRules' ? '規則' : '新版') + '」輸入框');
        b.type = 'button';
        b.addEventListener('click', function () {
          $(target + 'Fmt').value = s.fmt;
          setVal(target, s.text);
          if (target === 'mapRules') { renderMap(); } else { renderDiff(); }
        });
        head.appendChild(b);
        item.appendChild(head);
        item.appendChild(el('pre', 'fmtpre', s.text));
        box.appendChild(item);
      });
    });
  }

  var DS = { entries: null, view: 'side', showSame: false };

  function renderDiff() {
    var box = $('result');
    box.textContent = '';
    var o = parseRules($('oldRules').value, fmtOf('oldRules')), n = parseRules($('newRules').value, fmtOf('newRules'));
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
      box.appendChild(el('p', 'say', '有格式錯誤的行沒有參與比對，規則編號只計算格式正確的規則。請修正後再比對。'));
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
    var CAP = 500;
    if (rows.length > CAP) { sec.appendChild(el('p', 'say', '項目很多，畫面只顯示前 ' + CAP + ' 筆；上方統計與匯出的 CSV 包含全部。')); }
    if (DS.view === 'side') {
      var head = el('div', 'dhead');
      head.appendChild(el('span', '', ''));
      head.appendChild(el('span', '', '舊版'));
      head.appendChild(el('span', '', '新版'));
      sec.appendChild(head);
    }
    var ul = el('ul', 'dlist');
    rows.slice(0, CAP).forEach(function (e) {
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
     七、分頁二：規則與 Log 對應（大量資料用背景執行緒計算、虛擬捲動顯示）
     ========================================================= */
  var MS = { rows: null, filter: 'all', def: '拒絕', job: 0 };
  var PIN = 0;                       // 被「點擊鎖定」的規則行號
  var BIG_CHARS = 150000;            // log 文字超過這個長度就改用背景執行緒
  var ROW_H = 40;

  function defaultAction() { return $('defPolicy').value === 'allow' ? '允許' : '拒絕'; }

  var W = { w: null, bad: false, id: 0, cb: null };
  function getWorker() {
    if (W.bad) { return null; }
    if (W.w) { return W.w; }
    try {
      W.w = new Worker('worker.js');
      W.w.onmessage = function (e) {
        var d = e.data;
        if (!W.cb || d.id !== W.id) { return; }
        var cb = W.cb; W.cb = null;
        cb(d.ok ? d.result : null);
      };
      // 例如直接用 file:// 開啟時瀏覽器不允許 Worker，這時退回主執行緒計算
      W.w.onerror = function () { W.bad = true; W.w = null; var cb = W.cb; W.cb = null; if (cb) { cb(null); } };
    } catch (e) { W.bad = true; W.w = null; }
    return W.w;
  }
  function computeMapAsync(rulesText, logsText, def, fmt, cb) {
    var w = logsText.length > BIG_CHARS ? getWorker() : null;
    if (!w) { cb(C.computeMap(rulesText, logsText, def, fmt)); return; }
    W.id++;
    W.cb = function (res) { if (res) { cb(res); } else { setTimeout(function () { cb(C.computeMap(rulesText, logsText, def, fmt)); }, 0); } };
    w.postMessage({ id: W.id, rulesText: rulesText, logsText: logsText, def: def, fmt: fmt });
  }

  function renderMap() {
    var box = $('mapResult');
    var job = ++MS.job;
    PIN = 0;
    ED.mapRules.mark(0);
    var rulesText = $('mapRules').value, logsText = $('mapLogs').value, def = defaultAction();
    if (logsText.length > BIG_CHARS) {
      box.textContent = '';
      box.setAttribute('aria-busy', 'true');
      box.appendChild(el('p', 'panel loading', '正在處理約 ' + Math.round(logsText.length / 1024).toLocaleString('en-US') + ' KB 的 log…（在背景計算，畫面不會卡住）'));
    }
    computeMapAsync(rulesText, logsText, def, fmtOf('mapRules'), function (res) {
      if (job !== MS.job) { return; }
      box.removeAttribute('aria-busy');
      finishMap(res, def);
    });
  }

  function finishMap(res, def) {
    var box = $('mapResult');
    box.textContent = '';
    var rp = res.rp, rows = res.rows, logErrors = res.logErrors;
    if (!rp.rules.length && !rows.length && !rp.errors.length && !logErrors.length) {
      MS.rows = null;
      box.appendChild(el('p', 'panel empty', '規則和 log 都是空的。請貼上內容，或按「填入範例規則」與「填入測試 Log」。'));
      return;
    }
    rows.forEach(function (r) { r.rule = r.no ? rp.rules[r.no - 1] : null; });
    MS.rows = rows; MS.def = def;

    var total = rows.length, allow = 0, unmatched = 0, mismatch = 0, hitCount = {};
    rows.forEach(function (r) {
      if (r.final === '允許') { allow++; }
      if (!r.rule) { unmatched++; } else { hitCount[r.no] = (hitCount[r.no] || 0) + 1; }
      if (r.mismatch) { mismatch++; }
    });
    var deny = total - allow;
    var top = Object.keys(hitCount).map(function (k) { return { no: Number(k), n: hitCount[k] }; })
      .sort(function (a, b) { return b.n - a.n || a.no - b.no; }).slice(0, 3);

    /* 摘要儀表板 */
    var dash = el('section', 'panel dash');
    dash.appendChild(el('h2', '', '結果摘要'));
    var stats = el('div', 'stats');
    var stat = function (num, label, cls) { var s = el('div', 'stat' + (cls ? ' ' + cls : '')); s.appendChild(el('b', '', num.toLocaleString('en-US'))); s.appendChild(el('span', '', label)); return s; };
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
      rt.appendChild(el('span', 'good', '允許 ' + ap + '%（' + allow.toLocaleString('en-US') + ' 筆）'));
      rt.appendChild(el('span', 'badtxt', '拒絕 ' + dp + '%（' + deny.toLocaleString('en-US') + ' 筆）'));
      dash.appendChild(rt);
    }
    dash.appendChild(el('h3', '', '最常被命中的規則（前 3 名）'));
    if (top.length) {
      var tl = el('ul', 'top3');
      top.forEach(function (t, idx) {
        var li = el('li', 'hoverable');
        li.tabIndex = 0;
        li.appendChild(el('span', 'n', (idx + 1) + '.'));
        li.appendChild(ruleNode(rp.rules[t.no - 1], '#' + t.no));
        li.appendChild(el('span', 'hits', t.n.toLocaleString('en-US') + ' 筆'));
        var ln = rp.rules[t.no - 1].line;
        li.addEventListener('mouseenter', function () { ED.mapRules.mark(ln); });
        li.addEventListener('focus', function () { ED.mapRules.mark(ln); });
        li.addEventListener('mouseleave', function () { ED.mapRules.mark(PIN); });
        li.addEventListener('blur', function () { ED.mapRules.mark(PIN); });
        tl.appendChild(li);
      });
      dash.appendChild(tl);
    } else {
      dash.appendChild(el('p', 'empty', '沒有任何 log 命中規則。'));
    }
    box.appendChild(dash);

    if (rp.errors.length) { box.appendChild(problemPanel('規則格式有誤的行', rp.errors, true)); }
    if (logErrors.length) { box.appendChild(problemPanel('Log 格式有誤的行', logErrors, true)); }
    if (rp.errors.length || logErrors.length) {
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

  // 點擊「跳轉」：左側規則清單選取那一行並鎖定亮起；再點一次取消鎖定
  function jumpToRule(line) {
    if (PIN === line) { PIN = 0; ED.mapRules.mark(0); return; }
    PIN = line;
    ED.mapRules.mark(line);
    ED.mapRules.focusLine(line);
  }

  function renderLogTable() {
    var host = $('logTable');
    if (!host || !MS.rows) { return; }
    host.textContent = '';
    var view = MS.rows.filter(function (r) {
      if (MS.filter === 'deny') { return r.final === '拒絕'; }
      if (MS.filter === 'issue') { return !r.rule || r.mismatch; }
      return true;
    });
    var sec = el('section', 'panel');
    sec.appendChild(el('h2', '', 'Log 明細（' + view.length.toLocaleString('en-US') + ' / ' + MS.rows.length.toLocaleString('en-US') + ' 筆' + (MS.filter === 'all' ? '' : '，已篩選') + '）'));
    if (!view.length) { sec.appendChild(el('p', 'empty', MS.rows.length ? '沒有符合篩選條件的 log。' : '沒有可顯示的 log。')); host.appendChild(sec); return; }
    sec.appendChild(el('p', 'say', '滑鼠移到某一筆 log 上，左側規則清單會亮起它命中的規則；按「跳轉」可把游標放到那一行並鎖定亮起。表格只繪製看得到的列，筆數再多也順暢。'));

    var wrap = el('div', 'vwrap'), vt = el('div', 'vtable');
    var head = el('div', 'vrow vhead');
    ['行', '時間', '連線', '最終動作', '命中', '備註'].forEach(function (h) { head.appendChild(el('span', '', h)); });
    var vp = el('div', 'vport');
    var shown = Math.min(view.length, 12);
    vp.style.height = (shown * ROW_H) + 'px';
    var spacer = el('div', 'vspacer'); spacer.style.height = (view.length * ROW_H) + 'px';
    var inner = el('div', 'vinner');
    spacer.appendChild(inner); vp.appendChild(spacer);

    var drawn = { a: -1, b: -2 };
    function rowEl(r, i) {
      var lg = r.log;
      var row = el('div', 'vrow' + ((!r.rule || r.mismatch) ? ' issue' : ''));
      row.dataset.i = String(i);
      row.tabIndex = 0;
      row.appendChild(el('span', 'mono', String(lg.n)));
      row.appendChild(el('span', 'mono', lg.date + ' ' + lg.time));
      var conn = lg.proto + ' ' + disp(lg.src) + ' → ' + (lg.proto === 'ICMP' ? disp(lg.dst) : hostPort(lg.dst, lg.port));
      var c = el('span', 'mono', conn); c.title = conn; row.appendChild(c);
      var td = el('span'); td.appendChild(el('span', 'pill ' + (r.final === '允許' ? 'allow' : 'deny'), r.final)); row.appendChild(td);
      var hit = el('span', 'hitcell');
      if (r.rule) {
        hit.appendChild(document.createTextNode('第 ' + r.rule.no + ' 條 '));
        var jb = el('button', 'jump', '跳轉'); jb.type = 'button'; jb.dataset.line = String(r.rule.line);
        jb.title = '把左側規則清單的游標移到這一條，並鎖定亮起';
        hit.appendChild(jb);
      } else { hit.appendChild(document.createTextNode('預設政策')); }
      row.appendChild(hit);
      var note = [];
      if (!r.rule) { note.push('沒有任何規則符合'); }
      if (r.mismatch) { note.push('log 記錄為「' + lg.action + '」，與最終動作不一致'); }
      var nt = el('span', 'notecell', note.join('；')); nt.title = note.join('；'); row.appendChild(nt);
      return row;
    }
    function draw() {
      var st = vp.scrollTop, hh = vp.clientHeight || shown * ROW_H;
      var a = Math.max(0, Math.floor(st / ROW_H) - 6), b = Math.min(view.length - 1, Math.ceil((st + hh) / ROW_H) + 6);
      if (a === drawn.a && b === drawn.b) { return; }
      drawn = { a: a, b: b };
      inner.textContent = '';
      inner.style.top = (a * ROW_H) + 'px';
      var frag = document.createDocumentFragment();
      for (var i = a; i <= b; i++) { frag.appendChild(rowEl(view[i], i)); }
      inner.appendChild(frag);
    }
    var onRow = function (e) {
      var row = e.target.closest ? e.target.closest('.vrow') : null;
      if (!row || row.classList.contains('vhead')) { return; }
      var r = view[Number(row.dataset.i)];
      ED.mapRules.mark(r && r.rule ? r.rule.line : PIN);
    };
    vp.addEventListener('scroll', draw);
    vp.addEventListener('mouseover', onRow);
    vp.addEventListener('focusin', onRow);
    vp.addEventListener('mouseleave', function () { ED.mapRules.mark(PIN); });
    vp.addEventListener('focusout', function () { ED.mapRules.mark(PIN); });
    vp.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.jump') : null;
      if (b) { jumpToRule(Number(b.dataset.line)); }
    });

    vt.appendChild(head); vt.appendChild(vp); wrap.appendChild(vt); sec.appendChild(wrap);
    host.appendChild(sec);
    draw();
  }

  function exportMap() {
    if (!MS.rows) { return; }
    var out = [['行', '日期', '時間', '協定', '來源', '目的', '埠號', 'log 記錄動作', '命中規則序', '命中規則內容', '最終動作', '判定來源', '備註']];
    MS.rows.forEach(function (r) {
      var lg = r.log, note = [];
      if (!r.rule) { note.push('沒有任何規則符合'); }
      if (r.mismatch) { note.push('與 log 記錄動作不一致'); }
      out.push([lg.n, lg.date, lg.time, lg.proto, disp(lg.src), disp(lg.dst), lg.port, lg.action, r.rule ? r.rule.no : '', r.rule ? ruleText(r.rule) : '', r.final, r.rule ? '規則' : (MS.def === '允許' ? '預設允許' : '預設拒絕'), note.join('；')]);
    });
    downloadCsv('firewall-log-map-' + stamp() + '.csv', out);
  }

  /* =========================================================
     八、匯入 log 檔
     ========================================================= */
  var MAX_BYTES = 8 * 1024 * 1024;
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
    if (file.size > MAX_BYTES) { say('檔案太大（' + (file.size / 1048576).toFixed(1) + ' MB），請拆成 8 MB 以內再匯入。', true); return; }
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
      var n = 0;
      text.split(/\r?\n/).forEach(function (l) { var t = l.trim(); if (t && t.charAt(0) !== '#') { n++; } });
      say('已匯入「' + file.name + '」，共 ' + n.toLocaleString('en-US') + ' 行' + note + '。內容只在你的瀏覽器內處理，沒有上傳。', false);
      renderMap();
    };
    reader.readAsText(file);
  }

  /* =========================================================
     八之二、匯入規則設定檔（iptables-save、Cisco running-config、CSV、AWS JSON、簡化寫法純文字）
     ========================================================= */
  // Cisco running-config 含 hostname、interface 等雜行，只擷取 ACL 的部分
  function extractCisco(text) {
    var hasAcl = /^(ip\s+access-list|access-list\s+\S+\s+(permit|deny|remark))/mi.test(text);
    var isConfig = /^(hostname|interface|version|ip route|line|router|snmp-server|service|enable|username)\b/m.test(text);
    if (!hasAcl || !isConfig) { return null; }
    var out = [], names = {}, inBlock = false;
    text.split(/\r?\n/).forEach(function (raw) {
      var m = /^(ip|ipv6)\s+access-list\s+(?:extended\s+|standard\s+)?(\S+)/i.exec(raw);
      if (m) { inBlock = m[1].toLowerCase() === 'ip'; if (inBlock) { names[m[2]] = true; out.push('! ' + raw.trim()); } return; }
      if (/^access-list\s+\S+\s+/i.test(raw)) { names[raw.trim().split(/\s+/)[1]] = true; out.push(raw); inBlock = false; return; }
      if (inBlock && /^\s+\S/.test(raw)) { out.push(raw); return; }
      inBlock = false;
    });
    return { text: out.join('\n'), names: Object.keys(names) };
  }

  // AWS CLI：aws ec2 describe-security-groups 的 JSON 輸出（只取入站規則）
  function awsJsonToText(text) {
    var d;
    try { d = JSON.parse(text); } catch (e) { return null; }
    var groups = d && d.SecurityGroups ? d.SecurityGroups : (Array.isArray(d) && d[0] && d[0].IpPermissions ? d : null);
    if (!groups) { return null; }
    var out = ['Type,Protocol,Port range,Source'];
    groups.forEach(function (g) {
      out.push('# ' + (g.GroupId || '') + ' ' + (g.GroupName || '') + (g.Description ? ' - ' + g.Description : ''));
      (g.IpPermissions || []).forEach(function (p) {
        var proto = String(p.IpProtocol), port;
        if (proto === '-1') { proto = 'All'; port = 'All'; }
        else if (p.FromPort === undefined || p.FromPort === null || p.FromPort === -1) { port = 'All'; }
        else { port = p.FromPort === p.ToPort ? String(p.FromPort) : p.FromPort + '-' + p.ToPort; }
        var srcs = [];
        (p.IpRanges || []).forEach(function (r) { srcs.push(r.CidrIp); });
        (p.Ipv6Ranges || []).forEach(function (r) { srcs.push(r.CidrIpv6); });
        (p.UserIdGroupPairs || []).forEach(function (r) { srcs.push(r.GroupId || 'sg-?'); });
        (p.PrefixListIds || []).forEach(function (r) { srcs.push(r.PrefixListId); });
        srcs.forEach(function (s) { out.push(['Custom', proto, port, s].join(',')); });
      });
    });
    return { text: out.join('\n'), count: groups.length };
  }

  function importRulesFile(file, id) {
    if (!file) { return; }
    var msg = $(id + 'Msg');
    var show = function (t, bad) { msg.hidden = false; msg.textContent = t; msg.style.color = bad ? 'var(--del)' : 'var(--muted)'; };
    if (file.size > MAX_BYTES) { show('檔案太大（' + (file.size / 1048576).toFixed(1) + ' MB），請拆成 8 MB 以內再匯入。', true); return; }
    var okName = /\.(txt|conf|cfg|config|rules|ios|csv|json|log|v4|v6)$/i.test(file.name) || /^[^.]+$/.test(file.name) || file.type.indexOf('text/') === 0 || file.type === 'application/json';
    if (!okName) { show('只支援文字類的設定檔（.txt、.conf、.cfg、.rules、.csv、.json 等），「' + file.name + '」不是。', true); return; }
    var reader = new FileReader();
    reader.onerror = function () { show('讀取「' + file.name + '」失敗，請再試一次。', true); };
    reader.onload = function () {
      var text = String(reader.result).replace(/^﻿/, '');
      if (text.indexOf('\u0000') >= 0) { show('「' + file.name + '」看起來是二進位檔，不是文字設定檔。', true); return; }
      var note = '', fmt = 'auto';
      var js = /^\s*[\[{]/.test(text) ? awsJsonToText(text) : null;
      if (js) {
        text = js.text; fmt = 'aws';
        note = '，偵測到 AWS describe-security-groups JSON（' + js.count + ' 個安全群組，只取入站規則，已轉成表格）';
      } else {
        var cx = extractCisco(text);
        if (cx) {
          text = cx.text;
          note = '，偵測到 Cisco 設定檔，已只擷取 ' + cx.names.length + ' 個 ACL（' + cx.names.slice(0, 5).join('、') + (cx.names.length > 5 ? '…' : '') + '）';
        }
      }
      $(id + 'Fmt').value = fmt;
      setVal(id, text);
      var n = 0;
      text.split(/\r?\n/).forEach(function (l) { var t = l.trim(); if (t && t.charAt(0) !== '#' && t.charAt(0) !== '!') { n++; } });
      show('已匯入「' + file.name + '」，共 ' + n.toLocaleString('en-US') + ' 行內容' + note + '。檔案只在你的瀏覽器內處理，沒有上傳。', false);
      if (id === 'mapRules') { renderMap(); } else { renderDiff(); }
    };
    reader.readAsText(file);
  }

  // 拖放檔案到輸入框（只攔截檔案；拖文字進來仍照一般方式貼上）
  function enableFileDrop(taId, handler) {
    var ta = $(taId);
    ta.addEventListener('dragover', function (e) {
      if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') >= 0) { e.preventDefault(); }
    });
    ta.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) { e.preventDefault(); handler(e.dataTransfer.files[0]); }
    });
  }

  /* =========================================================
     九、事件與初始化
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

  // 邊改邊看：輸入內容改變後，右側結果自動更新。資料量很大時改為手動，避免每打一個字就重算。
  function liveMap() {
    if ($('mapLogs').value.length > BIG_CHARS) {
      if (!$('staleNote')) {
        var n = el('p', 'panel notice', '資料量大，已暫停即時更新。修改完請按「對應」重新計算。');
        n.id = 'staleNote';
        $('mapResult').insertBefore(n, $('mapResult').firstChild);
      }
    } else { renderMap(); }
  }
  ED.oldRules.onchange = renderDiff;
  ED.newRules.onchange = renderDiff;
  ED.mapRules.onchange = liveMap;
  ED.mapLogs.onchange = liveMap;

  $('tabDiff').addEventListener('click', function () { showTab('diff'); });
  $('tabLog').addEventListener('click', function () { showTab('log'); });

  // 主題與暫存
  var savedTheme = 'light';
  try { savedTheme = localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light'; } catch (e) { /* 略過 */ }
  applyTheme(savedTheme);
  $('themeBtn').addEventListener('click', function () {
    var t = document.documentElement.getAttribute('data-fw-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    try { localStorage.setItem(THEME_KEY, t); } catch (e) { /* 略過 */ }
  });

  var resetTimer = 0;
  $('resetBtn').addEventListener('click', function () {
    var b = this;
    if (!b.dataset.armed) {
      b.dataset.armed = '1';
      b.textContent = '再按一次確認清除';
      resetTimer = setTimeout(function () { delete b.dataset.armed; b.textContent = '清除暫存並還原範例'; }, 3000);
      return;
    }
    clearTimeout(resetTimer);
    delete b.dataset.armed;
    b.textContent = '清除暫存並還原範例';
    $('defPolicy').value = 'deny';
    $('importMsg').hidden = true;
    ['oldRules', 'newRules', 'mapRules'].forEach(function (k) { $(k + 'Fmt').value = 'auto'; });
    setVal('oldRules', SAMPLE_A); setVal('newRules', SAMPLE_B);
    setVal('mapRules', SAMPLE_RULES); setVal('mapLogs', SAMPLE_LOGS);
    try { localStorage.removeItem(STORE); } catch (e) { /* 略過 */ }
    renderDiff(); renderMap();
  });

  // 分頁一
  $('compareBtn').addEventListener('click', renderDiff);
  $('fillA').addEventListener('click', function () { setVal('oldRules', SAMPLE_A); renderDiff(); });
  $('fillB').addEventListener('click', function () { setVal('newRules', SAMPLE_B); renderDiff(); });
  $('clearOld').addEventListener('click', function () { setVal('oldRules', ''); renderDiff(); });
  $('clearNew').addEventListener('click', function () { setVal('newRules', ''); renderDiff(); });
  $('sampleBtn').addEventListener('click', function () { setVal('oldRules', SAMPLE_A); setVal('newRules', SAMPLE_B); renderDiff(); });
  $('clearBtn').addEventListener('click', function () {
    setVal('oldRules', ''); setVal('newRules', '');
    renderDiff();
  });
  $('viewSide').addEventListener('click', function () { DS.view = 'side'; setPressed('viewSide', 'viewUni', true); renderDiffList(); });
  $('viewUni').addEventListener('click', function () { DS.view = 'uni'; setPressed('viewSide', 'viewUni', false); renderDiffList(); });
  $('showSame').addEventListener('change', function () { DS.showSame = this.checked; renderDiffList(); });
  $('exportDiff').addEventListener('click', exportDiff);

  // 分頁二
  $('mapBtn').addEventListener('click', renderMap);
  $('fillRules').addEventListener('click', function () { setVal('mapRules', SAMPLE_RULES); renderMap(); });
  $('fillLogs').addEventListener('click', function () { setVal('mapLogs', SAMPLE_LOGS); renderMap(); });
  $('clearRules').addEventListener('click', function () { setVal('mapRules', ''); renderMap(); });
  $('clearLogs').addEventListener('click', function () { setVal('mapLogs', ''); $('importMsg').hidden = true; renderMap(); });
  $('mapSampleBtn').addEventListener('click', function () { setVal('mapRules', SAMPLE_RULES); setVal('mapLogs', SAMPLE_LOGS); renderMap(); });
  $('useNewBtn').addEventListener('click', function () { $('mapRulesFmt').value = fmtOf('newRules'); setVal('mapRules', $('newRules').value); renderMap(); });
  $('mapClearBtn').addEventListener('click', function () {
    setVal('mapRules', ''); setVal('mapLogs', '');
    $('importMsg').hidden = true; renderMap();
  });
  $('defPolicy').addEventListener('change', function () { save(); renderMap(); });
  $('importBtn').addEventListener('click', function () { $('logFile').click(); });
  $('logFile').addEventListener('change', function () { importLogFile(this.files && this.files[0]); this.value = ''; });
  enableFileDrop('mapLogs', importLogFile);

  // 匯入規則設定檔：三個規則輸入框共用一個檔案選擇器
  var pendingRuleTarget = 'newRules';
  [['impOld', 'oldRules'], ['impNew', 'newRules'], ['impMap', 'mapRules']].forEach(function (p) {
    $(p[0]).addEventListener('click', function () { pendingRuleTarget = p[1]; $('ruleFile').click(); });
    enableFileDrop(p[1], function (f) { importRulesFile(f, p[1]); });
  });
  $('ruleFile').addEventListener('change', function () { importRulesFile(this.files && this.files[0], pendingRuleTarget); this.value = ''; });

  // 開啟頁面：優先回填上次暫存的內容，沒有才載入示範資料
  var saved = loadSaved();
  var pick = function (k, dflt) { return saved && typeof saved[k] === 'string' ? saved[k] : dflt; };
  if (saved && (saved.def === 'allow' || saved.def === 'deny')) { $('defPolicy').value = saved.def; }
  if (saved && saved.fmts) {
    ['oldRules', 'newRules', 'mapRules'].forEach(function (k) {
      var v = saved.fmts[k];
      if (typeof v === 'string' && $(k + 'Fmt').querySelector('option[value="' + v + '"]')) { $(k + 'Fmt').value = v; }
    });
  }
  buildFormatLists();
  setVal('oldRules', pick('oldRules', SAMPLE_A));
  setVal('newRules', pick('newRules', SAMPLE_B));
  setVal('mapRules', pick('mapRules', SAMPLE_RULES));
  setVal('mapLogs', pick('mapLogs', SAMPLE_LOGS));
  if (!saved) { try { localStorage.removeItem(STORE); } catch (e) { /* 略過 */ } }
  renderDiff();
  renderMap();
})();
