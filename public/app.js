(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let me = null;
  let authMode = 'login';
  let currentName = null;
  let editorMode = 'ui';

  // ---------- theme ----------
  function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    localStorage.setItem('theme', t);
    $('#theme-toggle').textContent = t === 'dark' ? '☾' : '☀';
  }
  applyTheme(document.documentElement.dataset.theme);
  $('#theme-toggle').addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  // ---------- toast ----------
  let toastTimer;
  function toast(msg, err) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.toggle('err', !!err);
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (el.hidden = true), 2600);
  }

  // ---------- api ----------
  async function api(path, opts = {}) {
    if (opts.body !== undefined && typeof opts.body !== 'string') {
      opts.body = JSON.stringify(opts.body);
      opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers);
    }
    const res = await fetch(path, opts);
    const ct = res.headers.get('Content-Type') || '';
    const data = ct.includes('json') ? await res.json() : await res.text();
    if (!res.ok) throw new Error((data && data.error) || '请求失败 ' + res.status);
    return data;
  }

  // ---------- auth ----------
  function renderAuth() {
    const box = $('#user-box');
    const openBtn = $('#open-auth');
    if (me) {
      openBtn.hidden = true;
      box.hidden = false;
      $('#user-name').textContent = me.username;
      const roleEl = $('#user-role');
      roleEl.textContent = { super: '超级管理员', admin: '管理员', user: '用户' }[me.role] || me.role;
      roleEl.className = 'badge ' + me.role;
    } else {
      openBtn.hidden = false;
      box.hidden = true;
    }
    const isStaff = me && (me.role === 'admin' || me.role === 'super');
    const isSuper = me && me.role === 'super';
    $('[data-view="users"]').hidden = !isStaff;
    $('[data-view="sql"]').hidden = !isSuper;
    $('[data-view="audit"]').hidden = !isSuper;
    $('#new-data').hidden = !isStaff;
    if (!isStaff && !$('#view-data').hidden === false) switchView('data');
  }

  function openAuth(mode) {
    authMode = mode;
    $$('.seg[data-auth]').forEach((b) => b.classList.toggle('active', b.dataset.auth === mode));
    $('#auth-submit').textContent = mode === 'login' ? '登录' : '注册';
    $('#auth-msg').textContent = '';
    $('#auth-modal').hidden = false;
    $('#auth-form [name=username]').focus();
  }
  $('#open-auth').addEventListener('click', () => openAuth('login'));
  $('#close-auth').addEventListener('click', () => ($('#auth-modal').hidden = true));
  $$('.seg[data-auth]').forEach((b) => b.addEventListener('click', () => openAuth(b.dataset.auth)));

  $('#auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = { username: fd.get('username'), password: fd.get('password') };
    try {
      const data = await api('/api/' + authMode, { method: 'POST', body });
      if (authMode === 'register') {
        if (data.status === 'pending') {
          toast('注册成功，等待管理员审核通过后方可登录');
        } else if (data.isFirst) {
          toast('首个账户已注册，自动成为超级管理员，请登录');
          openAuth('login');
        } else {
          toast('注册成功');
          openAuth('login');
        }
        return;
      }
      $('#auth-modal').hidden = true;
      me = { uid: data.uid, username: data.username, role: data.role };
      renderAuth();
      toast('欢迎，' + data.username);
      loadAll();
    } catch (err) {
      $('#auth-msg').textContent = err.message;
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST' }).catch(() => {});
    me = null;
    renderAuth();
    toast('已退出登录');
  });

  // ---------- views ----------
  function switchView(name) {
    $$('.view').forEach((v) => (v.hidden = v.id !== 'view-' + name));
    $$('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
    if (name === 'users') loadUsers();
    if (name === 'audit') loadAudit();
  }
  $$('.nav-btn').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.view)));

  // ---------- data ----------
  async function loadData() {
    const list = await api('/api/data');
    const grid = $('#data-list');
    grid.innerHTML = '';
    if (!list.length) {
      grid.innerHTML = '<p class="note">暂无数据' + (me && (me.role === 'admin' || me.role === 'super') ? '，点击「+ 新建数据」创建' : '') + '</p>';
      return;
    }
    for (const item of list) {
      const card = document.createElement('div');
      card.className = 'card';
      const d = document.createElement('div');
      d.className = 'card-name';
      d.textContent = item.name;
      const apiLine = document.createElement('div');
      apiLine.className = 'card-api';
      const apiText = document.createElement('code');
      apiText.textContent = '/api/' + item.name;
      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = '复制';
      copyBtn.title = '复制 API 地址';
      copyBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const url = location.origin + '/api/' + item.name;
        try {
          await navigator.clipboard.writeText(url);
          copyBtn.textContent = '已复制';
        } catch {
          toast(url);
        }
        setTimeout(() => (copyBtn.textContent = '复制'), 1200);
      });
      apiLine.append(apiText, copyBtn);
      const m = document.createElement('div');
      m.className = 'card-meta';
      m.textContent = '更新于 ' + item.updated_at;
      card.append(d, apiLine, m);
      card.addEventListener('click', () => openEditor(item.name));
      grid.appendChild(card);
    }
  }

  $('#new-data').addEventListener('click', () => openEditor(null));
  $('#editor-close').addEventListener('click', () => ($('#editor').hidden = true));

  $$('.seg[data-mode]').forEach((b) =>
    b.addEventListener('click', () => {
      syncEditor();
      editorMode = b.dataset.mode;
      $$('.seg[data-mode]').forEach((x) => x.classList.toggle('active', x === b));
      $('#ui-editor').hidden = editorMode !== 'ui';
      $('#json-editor').hidden = editorMode !== 'json';
    })
  );

  async function openEditor(name) {
    currentName = name;
    $('#editor').hidden = false;
    $('#editor-name').value = name || '';
    $('#editor-name').disabled = false;
    $('#editor-delete').hidden = !name;
    $('#editor-note').hidden = true;
    let text = '[]';
    if (name) {
      try {
        text = await api('/api/data/' + encodeURIComponent(name));
        if (typeof text !== 'string') text = JSON.stringify(text, null, 2);
      } catch (err) {
        toast(err.message, true);
        return;
      }
    }
    $('#json-editor').value = text;
    editorMode = 'ui';
    $$('.seg[data-mode]').forEach((x) => x.classList.toggle('active', x.dataset.mode === 'ui'));
    $('#ui-editor').hidden = false;
    $('#json-editor').hidden = true;
    renderUiEditor(parseJson(text));
    $('#editor').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function parseJson(text) {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  function syncEditor() {
    if (editorMode === 'ui') {
      $('#json-editor').value = JSON.stringify(collectUiData(), null, 2);
    }
  }

  // UI 列表编辑器：支持对象数组 / 普通数组 / 对象
  function renderUiEditor(data) {
    const box = $('#ui-editor');
    box.innerHTML = '';
    const note = $('#editor-note');
    note.hidden = true;

    if (data === null || data === undefined) {
      note.hidden = false;
      note.className = 'note error';
      note.textContent = 'JSON 解析失败，请在 JSON 标签页修正后再切换';
      return;
    }

    if (Array.isArray(data) && data.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
      const cols = [];
      for (const row of data) for (const k of Object.keys(row)) if (!cols.includes(k)) cols.push(k);
      if (!cols.length) cols.push('value');
      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      cols.forEach((c) => {
        const th = document.createElement('th');
        th.textContent = c;
        hr.appendChild(th);
      });
      const thDel = document.createElement('th');
      thDel.textContent = '';
      hr.appendChild(thDel);
      thead.appendChild(hr);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      data.forEach((row, idx) => {
        const tr = document.createElement('tr');
        cols.forEach((c) => {
          const td = document.createElement('td');
          const input = document.createElement('input');
          input.value = row[c] === undefined || row[c] === null ? '' : typeof row[c] === 'object' ? JSON.stringify(row[c]) : String(row[c]);
          input.addEventListener('input', () => {
            let v = input.value;
            if (row[c] !== undefined && typeof row[c] === 'number') v = v === '' ? '' : Number(v);
            row[c] = v;
          });
          td.appendChild(input);
          tr.appendChild(td);
        });
        const tdDel = document.createElement('td');
        const del = document.createElement('button');
        del.className = 'row-del';
        del.textContent = '×';
        del.addEventListener('click', () => {
          data.splice(idx, 1);
          renderUiEditor(data);
        });
        tdDel.appendChild(del);
        tr.appendChild(tdDel);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      box.appendChild(table);
      const add = document.createElement('button');
      add.className = 'add-row';
      add.textContent = '+ 添加一行';
      add.addEventListener('click', () => {
        const empty = {};
        cols.forEach((c) => (empty[c] = ''));
        data.push(empty);
        renderUiEditor(data);
      });
      box.appendChild(add);
      box._data = data;
    } else {
      note.hidden = false;
      note.className = 'note';
      note.textContent = '当前数据不是对象数组，已切换为 JSON 编辑模式（可导入 JSON 文件后使用）';
      editorMode = 'json';
      $$('.seg[data-mode]').forEach((x) => x.classList.toggle('active', x.dataset.mode === 'json'));
      box.hidden = true;
      $('#json-editor').hidden = false;
    }
  }

  function collectUiData() {
    const box = $('#ui-editor');
    if (box._data) return box._data;
    return parseJson($('#json-editor').value) ?? [];
  }

  $('#editor-save').addEventListener('click', async () => {
    syncEditor();
    const text = $('#json-editor').value;
    try {
      JSON.parse(text);
    } catch (err) {
      toast('JSON 不合法: ' + err.message, true);
      return;
    }
    const name = ($('#editor-name').value || '').trim();
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
      toast('名称需为 1-64 位字母、数字、下划线或短横线', true);
      return;
    }
    const renamed = !!currentName && name !== currentName;
    try {
      if (renamed) {
        await api('/api/data/rename', { method: 'POST', body: { from: currentName, to: name } });
      }
      await api('/api/data/' + encodeURIComponent(name), { method: 'PUT', body: text });
      currentName = name;
      $('#editor-delete').hidden = false;
      toast((renamed ? '已重命名为 ' : '已保存 ') + name);
      loadData();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $('#editor-delete').addEventListener('click', async () => {
    if (!currentName) return;
    if (!confirm('确定删除数据「' + currentName + '」？')) return;
    try {
      await api('/api/data/' + encodeURIComponent(currentName), { method: 'DELETE' });
      $('#editor').hidden = true;
      currentName = null;
      toast('已删除');
      loadData();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // 导入 JSON 文件（新建或覆盖编辑器内容）
  $('#import-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    const text = await file.text();
    try {
      JSON.parse(text);
    } catch (err) {
      toast('文件不是合法 JSON: ' + err.message, true);
      return;
    }
    const suggested = file.name.replace(/\.json$/i, '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64) || 'imported';
    await openEditor(null);
    $('#editor-name').value = suggested;
    $('#json-editor').value = text;
    syncFromJson();
    toast('已导入文件，确认名称后点击保存');
  });

  function syncFromJson() {
    editorMode = 'ui';
    $$('.seg[data-mode]').forEach((x) => x.classList.toggle('active', x.dataset.mode === 'ui'));
    $('#ui-editor').hidden = false;
    $('#json-editor').hidden = true;
    renderUiEditor(parseJson($('#json-editor').value));
  }

  // ---------- users ----------
  async function loadUsers() {
    try {
      const users = await api('/api/admin/users');
      const tbody = $('#users-table tbody');
      tbody.innerHTML = '';
      const statusText = { pending: '待审核', active: '正常', banned: '已封禁' };
      for (const u of users) {
        const tr = document.createElement('tr');
        const cells = [u.uid, u.username];
        cells.forEach((v, i) => {
          const td = document.createElement('td');
          if (i === 1) td.className = 'mono';
          td.textContent = v;
          tr.appendChild(td);
        });
        const tdRole = document.createElement('td');
        const roleSel = document.createElement('select');
        ['user', 'admin', 'super'].forEach((r) => {
          const opt = document.createElement('option');
          opt.value = r;
          opt.textContent = { user: '用户', admin: '管理员', super: '超级管理员' }[r];
          opt.selected = u.role === r;
          roleSel.appendChild(opt);
        });
        roleSel.disabled = !me || me.role !== 'super' || u.uid === me.uid;
        roleSel.addEventListener('change', async () => {
          try {
            await api('/api/admin/setrole', { method: 'POST', body: { uid: u.uid, role: roleSel.value } });
            toast('已更新 ' + u.username + ' 的角色');
            loadUsers();
          } catch (err) {
            toast(err.message, true);
            loadUsers();
          }
        });
        tdRole.appendChild(roleSel);
        tr.appendChild(tdRole);

        const tdStatus = document.createElement('td');
        const st = document.createElement('span');
        st.className = 'badge ' + u.status;
        st.textContent = statusText[u.status] || u.status;
        tdStatus.appendChild(st);
        tr.appendChild(tdStatus);

        const tdCreated = document.createElement('td');
        tdCreated.textContent = u.created_at || '-';
        tr.appendChild(tdCreated);
        const tdLogin = document.createElement('td');
        tdLogin.textContent = u.last_login || '-';
        tr.appendChild(tdLogin);

        const tdOp = document.createElement('td');
        if (u.status === 'pending') {
          const btn = document.createElement('button');
          btn.className = 'btn btn-primary';
          btn.textContent = '通过审核';
          btn.addEventListener('click', async () => {
            try {
              await api('/api/admin/approve', { method: 'POST', body: { uid: u.uid } });
              toast('已通过 ' + u.username);
              loadUsers();
            } catch (err) {
              toast(err.message, true);
            }
          });
          tdOp.appendChild(btn);
        }
        if (me && me.role === 'super' && u.uid !== me.uid && u.uid !== 1) {
          const btn = document.createElement('button');
          btn.className = 'btn btn-danger';
          btn.style.marginLeft = '6px';
          btn.textContent = u.status === 'banned' ? '解封' : '封禁';
          btn.addEventListener('click', async () => {
            try {
              const r = await api('/api/admin/ban', { method: 'POST', body: { uid: u.uid } });
              toast(r.status === 'banned' ? '已封禁 ' + u.username : '已解封 ' + u.username);
              loadUsers();
            } catch (err) {
              toast(err.message, true);
            }
          });
          tdOp.appendChild(btn);
        }
        tr.appendChild(tdOp);
        tbody.appendChild(tr);
      }
    } catch (err) {
      toast(err.message, true);
    }
  }

  // ---------- sql ----------
  $('#sql-run').addEventListener('click', async () => {
    const sql = $('#sql-input').value.trim();
    const msg = $('#sql-msg');
    const result = $('#sql-result');
    if (!sql) return;
    msg.textContent = '执行中…';
    msg.className = 'note';
    result.innerHTML = '';
    try {
      const data = await api('/api/admin/query', { method: 'POST', body: { sql } });
      if (data.columns) {
        msg.textContent = '返回 ' + data.rows.length + ' 行';
        msg.className = 'note ok';
        const table = document.createElement('table');
        const thead = document.createElement('thead');
        const hr = document.createElement('tr');
        data.columns.forEach((c) => {
          const th = document.createElement('th');
          th.textContent = c;
          hr.appendChild(th);
        });
        thead.appendChild(hr);
        table.appendChild(thead);
        const tbody = document.createElement('tbody');
        for (const row of data.rows) {
          const tr = document.createElement('tr');
          for (const c of data.columns) {
            const td = document.createElement('td');
            const v = row[c];
            td.textContent = v === null || v === undefined ? 'NULL' : typeof v === 'object' ? JSON.stringify(v) : String(v);
            td.className = 'mono';
            tr.appendChild(td);
          }
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        result.appendChild(table);
      } else {
        msg.textContent = '执行成功';
        msg.className = 'note ok';
        const meta = document.createElement('p');
        meta.className = 'note mono';
        meta.textContent = JSON.stringify(data.meta || {});
        result.appendChild(meta);
      }
    } catch (err) {
      msg.textContent = err.message;
      msg.className = 'note error';
    }
  });

  // ---------- audit ----------
  async function loadAudit() {
    try {
      const rows = await api('/api/admin/audit');
      const tbody = $('#audit-table tbody');
      tbody.innerHTML = '';
      for (const r of rows) {
        const tr = document.createElement('tr');
        [r.id, r.created_at, (r.uid || '-') + ' ' + (r.username || ''), r.action, r.detail || ''].forEach((v) => {
          const td = document.createElement('td');
          td.textContent = String(v);
          if (r.action && r.action.startsWith('sql')) td.className = 'mono';
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      }
    } catch (err) {
      toast(err.message, true);
    }
  }

  // ---------- init ----------
  async function loadAll() {
    await loadData().catch((e) => toast(e.message, true));
  }

  async function init() {
    try {
      me = await api('/api/me');
    } catch {
      me = null;
    }
    renderAuth();
    await loadAll();
  }
  init();
})();
