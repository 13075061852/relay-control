  // Runs in the main controller scope, using the existing accessible modal and pagination.
  const consoleFilters = {nodes: {query:'', status:'all', sort:'default'}, forward: {query:'', status:'all', sort:'default'}};
  function rowStatus(row, kind) {
    const cell = kind === 'nodes' ? row.querySelector('[data-metric="status"]') : row.cells[8];
    return cell?.textContent.trim() || '';
  }
  function rowExpiry(row, kind) { return row.cells[kind === 'nodes' ? 1 : 7]?.textContent.trim() || ''; }
  function filterConsoleRows(selector, kind) {
    const all = [...document.querySelectorAll(selector)];
    const filter = consoleFilters[kind];
    const today = new Date(); today.setHours(0,0,0,0);
    const rows = all.filter(row => {
      row.hidden = true;
      const status = rowStatus(row, kind);
      const date = new Date(rowExpiry(row, kind) + 'T00:00:00');
      const days = (date - today) / 86400000;
      const match = filter.status === 'all' ||
        (filter.status === 'ok' && /可用|正常|生效|运行|有效|启用/.test(status) && !/未|异常|停用|过期/.test(status)) ||
        (filter.status === 'issue' && /失败|异常|过期|到期|超额|停用|禁用|耗尽|用尽/.test(status)) ||
        (filter.status === 'unknown' && /未检测|未设置/.test(status)) ||
        (filter.status === 'soon' && days >= 0 && days <= 7) ||
        (filter.status === 'expired' && days < 0);
      const text = [...row.cells].slice(0, kind === 'nodes' ? 8 : 11).map(c => c.textContent).join(' ').toLowerCase();
      return match && filter.query.toLowerCase().trim().split(/\s+/).every(word => text.includes(word));
    });
    all.forEach((row,index)=>{if(row.dataset.consoleOrder === undefined)row.dataset.consoleOrder=String(index);});
    if (filter.sort === 'default') rows.sort((a,b)=>Number(a.dataset.consoleOrder)-Number(b.dataset.consoleOrder));
    if (filter.sort !== 'default') rows.sort((a,b) => {
      if (filter.sort === 'name') return a.cells[0].textContent.localeCompare(b.cells[0].textContent, 'zh-CN');
      if (filter.sort === 'expiry') return (rowExpiry(a,kind).match(/^\d{4}-/) ? rowExpiry(a,kind) : '9999').localeCompare(rowExpiry(b,kind).match(/^\d{4}-/) ? rowExpiry(b,kind) : '9999');
      const metric = row => { const n = parseFloat(row.cells[filter.sort === 'latency' ? 5 : 6].textContent); return Number.isFinite(n) ? n : (filter.sort === 'latency' ? Infinity : -Infinity); };
      return filter.sort === 'latency' ? metric(a)-metric(b) : metric(b)-metric(a);
    });
    const tbody = all[0]?.parentElement;
    if (tbody) rows.forEach(row => tbody.append(row));
    const empty = document.querySelector(`[data-console-empty="${kind}"]`);
    const panel = document.querySelector(kind === 'nodes' ? '.nodes-panel' : '.forward-list');
    if (panel) {
      panel.classList.toggle('console-no-results', rows.length === 0);
      const exportButton = panel.querySelector('.console-toolbar [data-export-rows]');
      if (exportButton) exportButton.disabled = rows.length === 0;
    }
    if (empty) {
      empty.hidden = rows.length !== 0;
      const noRecords = all.length === 0;
      empty.querySelector('b').textContent = noRecords ? (kind === 'nodes' ? '尚未添加节点' : '尚未创建转发') : '没有匹配的记录';
      empty.querySelector('p').textContent = noRecords ? (kind === 'nodes' ? '添加第一个上游节点，开始管理你的中转连接。' : '选择一个上游节点，即可创建 SOCKS5、VLESS 或订阅转发。') : '试试其他关键词，或清除筛选条件查看全部记录。';
      empty.querySelector('button').textContent = noRecords ? (kind === 'nodes' ? '添加节点' : '创建转发') : '清除筛选';
    }
    const count = document.querySelector(`[data-console-count="${kind}"]`);
    if (count) count.textContent = `匹配 ${rows.length} / ${all.length} 条`;
    return rows;
  }
  let toastTimer;
  const consoleToast = message => {
    let el = document.querySelector('.console-toast');
    if (!el) { el = document.createElement('div'); el.className = 'console-toast'; el.setAttribute('role','status'); document.body.append(el); }
    el.textContent = message; el.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 5000);
  };
  function consoleCSV(kind) {
    const rows = filterConsoleRows(kind === 'nodes' ? '.node-row' : '.forward-row', kind);
    const table = document.querySelector(kind === 'nodes' ? '.nodes-panel table' : '.forward-list table');
    if (!table || !rows.length) { consoleToast('没有可导出的记录'); return; }
    // Exported columns stay credential-free; the client-IP column is appended last.
    const indexes = kind === 'nodes' ? [0, 1, 2, 3, 4, 5, 6, 7] : [0, 1, 2, 3, 4, 5, 6, 7, 8, 10];
    const headings = [...table.querySelectorAll('thead th')];
    const cell = value => '"' + (/^[\s]*[=+@\-]/.test(value) ? "'" : '') + value.replaceAll('"','""') + '"';
    const pick = (list, index) => (list[index]?.textContent || '').trim();
    const data = [ indexes.map(index => pick(headings, index)), ...rows.map(row => indexes.map(index => pick([...row.cells], index))) ];
    const url = URL.createObjectURL(new Blob(['\ufeff' + data.map(row=>row.map(cell).join(',')).join('\r\n')], {type:'text/csv;charset=utf-8'}));
    const link = document.createElement('a'); link.href=url; link.download=`relay-${kind}-${new Date().toISOString().slice(0,10)}.csv`; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
    (kind === 'nodes' ? renderNodePagination : renderForwardPagination)();
    consoleToast('已导出筛选结果，不包含密码、UUID 或订阅链接');
  }
  const sourceIpTime = value => {
    const when = new Date(Number(value) * 1000);
    if (!value || Number.isNaN(when.getTime())) return '—';
    const pad = number => String(number).padStart(2, '0');
    return `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())} ${pad(when.getHours())}:${pad(when.getMinutes())}`;
  };
  const postForwardIpAction = async (path, id, ip) => {
    const csrf = document.querySelector('[name="csrf"]')?.value || '';
    const response = await fetch(path, {
      method: 'POST',
      headers: {Accept: 'application/json'},
      body: new URLSearchParams({csrf, id, ip})
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) throw new Error(data.error || '操作失败');
    return data;
  };
  const loadForwardSourceIps = async modal => {
    const body = modal.querySelector('[data-source-ip-body]');
    const summary = modal.querySelector('[data-source-ip-summary]');
    const note = modal.querySelector('[data-source-ip-note]');
    if (summary) summary.textContent = '正在读取…';
    if (note) { note.hidden = true; note.textContent = ''; }
    if (body) body.replaceChildren();
    try {
      const response = await fetch(`/forward/ips?id=${encodeURIComponent(modal.dataset.forwardId || '')}`, {headers: {Accept: 'application/json'}});
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || '读取失败');
      if (summary) {
        const blocked = data.blocked_count ? ` · 已禁用 ${data.blocked_count} 个` : '';
        summary.textContent = data.total
          ? `共 ${data.total} 个 IP${blocked} · ${data.connections} 次连接 · 采集于 ${sourceIpTime(data.collected_at)}`
          : (data.blocked_count ? `已禁用 ${data.blocked_count} 个 IP` : '这个转发还没有被使用过');
      }
      if (note && data.error) { note.hidden = false; note.textContent = '采集提示：' + data.error; }
      if (!body) return;
      if (!data.ips.length) {
        const row = body.insertRow(); const empty = row.insertCell();
        empty.colSpan = 8; empty.className = 'muted'; empty.textContent = '暂无来源 IP 记录。';
        return;
      }
      data.ips.forEach(item => {
        const row = document.createElement('tr');
        if (item.blocked) row.className = 'ip-blocked-row';
        const add = (text, className, title) => {
          const td = document.createElement('td');
          if (className) td.className = className;
          if (title) td.title = title;
          td.textContent = text;
          row.append(td);
          return td;
        };
        const ipCell = add(item.ip, 'ip-cell');
        if (item.blocked) {
          const badge = document.createElement('span');
          badge.className = 'ip-blocked-badge';
          badge.textContent = '已禁用';
          if (item.blocked_at) badge.title = `禁用时间 ${sourceIpTime(item.blocked_at)}`;
          ipCell.append(document.createElement('br'), badge);
        }
        const place = add(item.place || '待解析');
        if (item.operator) {
          const operator = document.createElement('span');
          operator.className = 'muted';
          operator.textContent = item.operator;
          place.append(document.createElement('br'), operator);
        }
        if (item.operator_raw) place.title = item.operator_raw;
        add(item.kind || '待解析');
        add(String(item.count));
        add(sourceIpTime(item.first));
        add(sourceIpTime(item.last));
        add((item.targets || []).join('、') || '—', 'muted');
        const action = document.createElement('td');
        action.className = 'ip-action-cell';
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'secondary ip-block-button';
        button.dataset.forwardIpAction = item.blocked ? 'unblock' : 'block';
        button.dataset.ipAddress = item.ip;
        button.textContent = item.blocked ? '解除禁用' : '禁用';
        if (item.blocked_at) button.title = `禁用时间 ${sourceIpTime(item.blocked_at)}`;
        action.append(button);
        row.append(action);
        body.append(row);
      });
      if (data.error) consoleToast('IP 采集提示：' + data.error);
    } catch (error) {
      if (summary) summary.textContent = error.message;
    }
  };
  const bindForwardIpActions = modal => {
    if (modal.dataset.ipActionsBound === '1') return;
    modal.dataset.ipActionsBound = '1';
    modal.addEventListener('click', async event => {
      const button = event.target.closest('[data-forward-ip-action]');
      if (!button || button.disabled) return;
      const blocking = button.dataset.forwardIpAction === 'block';
      if (button.dataset.confirming !== '1') {
        // Two-step confirm: the second click performs the change.
        button.dataset.confirming = '1';
        button.classList.add('ip-confirm');
        button.textContent = blocking ? '确认禁用？' : '确认解除？';
        window.setTimeout(() => {
          if (!button.isConnected) return;
          button.dataset.confirming = '';
          button.classList.remove('ip-confirm');
          button.textContent = button.dataset.forwardIpAction === 'block' ? '禁用' : '解除禁用';
        }, 6000);
        return;
      }
      button.disabled = true;
      try {
        const data = await postForwardIpAction(blocking ? '/forward/ip-block' : '/forward/ip-unblock',
          modal.dataset.forwardId || '', button.dataset.ipAddress || '');
        consoleToast(data.message || '来源 IP 状态已更新');
        await loadForwardSourceIps(modal);
      } catch (error) {
        consoleToast(error.message);
        button.disabled = false;
        button.dataset.confirming = '';
        button.classList.remove('ip-confirm');
        button.textContent = blocking ? '禁用' : '解除禁用';
      }
    });
  };
  const showForwardSourceIps = async opener => {
    const modal = document.getElementById('source-ip-modal');
    if (!modal || !opener) return;
    modal.dataset.forwardId = opener.dataset.forwardSourceIps || '';
    const title = modal.querySelector('#source-ip-title');
    if (title) title.textContent = `${opener.dataset.forwardSourceLabel || '转发'} · 来源 IP`;
    bindForwardIpActions(modal);
    openModal(modal, opener);
    await loadForwardSourceIps(modal);
  };
  ['nodes','forward'].forEach(kind => {
    const panel = document.querySelector(kind === 'nodes' ? '.nodes-panel' : '.forward-list');
    if (!panel) return;
    const headings=[...panel.querySelectorAll('thead th')].map(th=>th.textContent);
    panel.querySelectorAll('tbody tr').forEach(row=>[...row.cells].forEach((cell,index)=>{cell.dataset.consoleLabel=headings[index]||'';}));
    const toolbar = document.createElement('div'); toolbar.className='console-toolbar';
    toolbar.innerHTML = `<input type="search" aria-label="搜索${kind === 'nodes' ? '节点' : '转发'}" placeholder="搜索用户、地区、地址或名称…"><select aria-label="筛选状态"><option value="all">全部状态</option><option value="ok">可用 / 正常</option><option value="issue">需要关注</option><option value="soon">7 天内到期</option><option value="expired">已到期</option><option value="unknown">尚未检测 / 设置</option></select><select aria-label="排序"><option value="default">默认排序</option><option value="name">名称排序</option><option value="expiry">到期时间优先</option>${kind === 'nodes' ? '<option value="latency">延迟从低到高</option><option value="speed">速度从高到低</option>' : ''}</select><select aria-label="每页数量"><option value="10">10 条 / 页</option><option value="25">25 条 / 页</option><option value="50">50 条 / 页</option><option value="100">100 条 / 页</option></select>${kind === 'nodes'
      ? '<button type="button" class="secondary" data-migrate-export title="导出节点、客户与转发配置，用于迁移">导出迁移包</button><button type="button" class="secondary" data-migrate-import>导入迁移包</button>'
      : '<button type="button" class="secondary" data-export-rows title="导出元数据，不包含访问凭据">导出 CSV</button>'}<span class="console-count" data-console-count="${kind}" aria-live="polite"></span>`;
    panel.prepend(toolbar);
    const empty = document.createElement('div'); empty.className='console-empty'; empty.dataset.consoleEmpty=kind; empty.hidden=true;
    empty.innerHTML='<span class="console-empty-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h2m-2 10h2m7-10h1m-1 10h1"/></svg></span><b></b><p></p><button type="button" class="secondary"></button>';
    panel.querySelector('.tablewrap').after(empty);
    empty.querySelector('button').addEventListener('click', event => {
      if (!panel.querySelector(kind === 'nodes' ? '.node-row' : '.forward-row')) {
        openModal(document.getElementById(kind === 'nodes' ? 'add-node-modal' : 'create-forward-modal'), event.currentTarget);
        return;
      }
      Object.assign(consoleFilters[kind], {query:'', status:'all', sort:'default'});
      toolbar.querySelector('input').value='';
      status.value='all'; sort.value='default'; pager.page=1; renderPage();
      toolbar.querySelector('input').focus();
    });
    const [status,sort,size] = toolbar.querySelectorAll('select');
    const pager = kind === 'nodes' ? pagination : forwardPagination;
    const renderPage = kind === 'nodes' ? renderNodePagination : renderForwardPagination;
    try { const saved = Number(localStorage.getItem(`relay-page-size-${kind}`)); if ([10,25,50,100].includes(saved)) { pager.pageSize=saved; size.value=String(saved); } } catch(_) {}
    toolbar.querySelector('input').addEventListener('input', event=>{ consoleFilters[kind].query=event.target.value; pager.page=1; renderPage(); });
    status.addEventListener('change',()=>{consoleFilters[kind].status=status.value;pager.page=1;renderPage();});
    sort.addEventListener('change',()=>{consoleFilters[kind].sort=sort.value;pager.page=1;renderPage();});
    size.addEventListener('change',()=>{pager.pageSize=Number(size.value);pager.page=1;try{localStorage.setItem(`relay-page-size-${kind}`,size.value);}catch(_){}renderPage();});
    const exportRows = toolbar.querySelector('[data-export-rows]');
    if (exportRows) exportRows.addEventListener('click',()=>consoleCSV(kind));
    toolbar.querySelector('[data-migrate-export]')?.addEventListener('click',()=>{ window.location.href = '/migrate/export'; });
    toolbar.querySelector('[data-migrate-import]')?.addEventListener('click', event=>{
      const modal = document.getElementById('migrate-import-modal');
      if (modal) { const text = modal.querySelector('[name="bundle"]'); if (text) text.value = ''; openModal(modal, event.currentTarget); }
    });
  });
  document.addEventListener('keydown',event=>{
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase()==='k' && !document.querySelector('.modal:not([hidden])')) { const search=document.querySelector('.view:not([hidden]) .console-toolbar input');if(search){event.preventDefault();search.focus();search.select();} }
  });
  const opsHost = document.querySelector('#host-view');
  if (opsHost) {
    const panel = document.createElement('section'); panel.className='panel console-ops';
    panel.innerHTML='<h3>安全与维护</h3><p>备份仅保存在服务器，不向浏览器传输密钥。保留最近 10 份，升级前备份不参与清理。</p><div class="actions"><button type="button" data-console-op="backup">创建安全备份</button><button type="button" class="secondary" data-console-op="sessions/revoke">退出其他会话</button><button type="button" class="secondary" data-console-op="refresh">刷新记录</button><button type="button" class="secondary" data-console-op="logout">安全退出</button></div><div class="console-op-status" role="status"></div><details><summary>服务器备份记录</summary><div data-console-backups class="console-note"></div></details><h3 style="margin-top:24px">最近操作</h3><p>记录管理操作的时间、类型与结果，不记录密码和订阅链接。</p><div class="tablewrap"><table><thead><tr><th>时间</th><th>操作</th><th>结果</th></tr></thead><tbody data-console-events></tbody></table></div>';
    opsHost.append(panel);
    let loading=false;
    const loadOps=async()=>{
      if(loading)return;loading=true;
      try {
        const response=await fetch('/ops/status',{headers:{Accept:'application/json'}});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'读取失败');
        const body=panel.querySelector('[data-console-events]');body.replaceChildren();
        for(const item of data.events){const row=document.createElement('tr');for(const text of [new Date(item.time*1000).toLocaleString('zh-CN'),item.action,item.ok?'成功':'未完成']){const td=document.createElement('td');td.textContent=text;row.append(td);}body.append(row);}
        if(!data.events.length){const row=body.insertRow();const td=row.insertCell();td.colSpan=3;td.textContent='暂无操作记录，后续管理操作将在这里显示。';}
        const list=panel.querySelector('[data-console-backups]');list.replaceChildren();
        for(const item of data.backups){const line=document.createElement('p');line.textContent=`${item.name} · ${(item.size/1024).toFixed(1)} KB`;list.append(line);}
        if(!data.backups.length)list.textContent='尚无手动备份。升级前备份已另行保存。';
        panel.querySelector('.console-op-status').textContent='更新于 '+new Date().toLocaleTimeString('zh-CN');
      }catch(error){panel.querySelector('.console-op-status').textContent=error.message;}finally{loading=false;}
    };
    const modal=document.createElement('div');modal.className='modal';modal.id='console-confirm';modal.hidden=true;modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.setAttribute('aria-labelledby','console-confirm-title');
    modal.innerHTML='<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="console-confirm-title">退出其他会话？</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><p>其他浏览器和设备将需要重新登录，当前会话不受影响。</p><div class="actions"><button type="button" data-console-confirm>确认退出</button><button type="button" class="secondary" data-modal-close>取消</button></div></section>';
    document.querySelector('.workspace').append(modal);
    const runOp=async(action,button)=>{
      if(button.disabled)return;button.disabled=true;
      try{const csrf=document.querySelector('[name="csrf"]').value;const response=await fetch('/ops/'+action,{method:'POST',headers:{Accept:'application/json'},body:new URLSearchParams({csrf})});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'操作失败');consoleToast(data.message);await loadOps();}catch(error){consoleToast(error.message);}finally{button.disabled=false;}
    };
    panel.addEventListener('click',event=>{const button=event.target.closest('[data-console-op]');if(!button)return;const action=button.dataset.consoleOp;if(action==='logout'){document.querySelector('.confirm-logout-form')?.requestSubmit();return;}if(action==='refresh'){loadOps();return;}if(action==='sessions/revoke'){openModal(modal,button);return;}runOp(action,button);});
    modal.querySelector('[data-console-confirm]').addEventListener('click',event=>{closeModal(modal);runOp('sessions/revoke',panel.querySelector('[data-console-op="sessions/revoke"]'));});
    let loaded=false;const maybeLoad=()=>{if(!opsHost.hidden&&!loaded){loaded=true;loadOps();}};
    new MutationObserver(maybeLoad).observe(opsHost,{attributes:true,attributeFilter:['hidden']});maybeLoad();
  }

  // Bulk node creation from the node-management view.
  (() => {
    const modal = document.getElementById('bulk-create-node-modal');
    if (!modal) return;
    const form = modal.querySelector('form');
    const user = form.querySelector('[name="user"]');
    const upstream = form.querySelector('[name="upstream"]');
    const expiry = form.querySelector('[name="quota_expires_on"]');
    const prefix = form.querySelector('[name="label_prefix"]');
    const modes = form.querySelector('[name="modes"]');
    const modeBoxes = [...form.querySelectorAll('[data-bulk-mode]')];
    const syncModes = () => { modes.value = modeBoxes.filter(box => box.checked).map(box => box.value).join(','); };
    const syncUser = () => {
      const selectedUser = user.value;
      const options = [...upstream.options];
      options.forEach(option => { option.hidden = Boolean(selectedUser) && option.dataset.nodeUser !== selectedUser; });
      const current = upstream.selectedOptions[0];
      if (!current || current.hidden) {
        const first = options.find(option => !option.hidden && option.value);
        if (first) upstream.value = first.value;
      }
      const selected = upstream.selectedOptions[0];
      const selectedExpiry = selected?.dataset.nodeExpiry || user.selectedOptions[0]?.dataset.expiry || '';
      expiry.value = selectedExpiry;
      if (!prefix.value || prefix.dataset.autoLabel === '1') {
        prefix.value = selectedUser;
        prefix.dataset.autoLabel = '1';
      }
    };
    const syncUpstream = () => {
      const selected = upstream.selectedOptions[0];
      if (selected?.dataset.nodeExpiry) expiry.value = selected.dataset.nodeExpiry;
    };
    user.addEventListener('change', syncUser);
    upstream.addEventListener('change', syncUpstream);
    prefix.addEventListener('input', () => { prefix.dataset.autoLabel = '0'; });
    modeBoxes.forEach(box => box.addEventListener('change', syncModes));
    syncModes();
    syncUser();
  })();

  // Show the forwards associated with a node user.
  document.addEventListener('click', event => {
    const opener = event.target.closest('[data-user-forwards]');
    if (!opener) return;
    event.preventDefault();
    const modal = document.getElementById('user-forward-modal');
    if (!modal) return;
    const cards = modal.querySelector('[data-user-forward-cards]');
    const summary = modal.querySelector('[data-user-forward-summary]');
    const title = modal.querySelector('#user-forward-title');
    let forwards = [];
    try { forwards = JSON.parse(opener.dataset.userForwards || '[]'); } catch (_) {}
    if (title) title.textContent = `${opener.dataset.userName || '用户'} · 转发`;
    if (summary) summary.textContent = forwards.length ? `共 ${forwards.length} 条转发` : '当前用户暂无转发';
    if (cards) {
      cards.replaceChildren();
      if (!forwards.length) {
        const empty = document.createElement('div');
        empty.className = 'user-forward-empty';
        empty.textContent = '当前用户暂无转发';
        cards.append(empty);
      } else {
        forwards.forEach(item => {
          const card = document.createElement('article');
          card.className = 'user-forward-card';

          const info = document.createElement('div');
          info.className = 'user-forward-card-info';
          const heading = document.createElement('div');
          heading.className = 'user-forward-card-heading';
          const name = document.createElement('h3');
          name.textContent = item.label || '未命名转发';
          const type = document.createElement('span');
          type.className = 'user-forward-type';
          type.textContent = item.mode || '—';
          heading.append(name, type);
          info.append(heading);

          const stats = document.createElement('div');
          stats.className = 'user-forward-stats';
          [['流量额度', item.quota], ['已用流量', item.used], ['到期日期', item.expires]].forEach(([label, value]) => {
            const stat = document.createElement('div');
            stat.className = 'user-forward-stat';
            const caption = document.createElement('span');
            caption.textContent = label;
            const content = document.createElement('b');
            content.textContent = value || '—';
            stat.append(caption, content);
            stats.append(stat);
          });
          const status = document.createElement('span');
          status.className = /正常|有效/.test(item.status || '') ? 'user-forward-status ok' : 'user-forward-status issue';
          status.textContent = item.status || '—';
          stats.append(status);
          info.append(stats);

          const access = document.createElement('div');
          access.className = 'user-forward-card-access';
          if (item.id) {
            const qr = document.createElement('img');
            qr.className = 'user-forward-qr';
            qr.src = `/forward/qr?id=${encodeURIComponent(item.id)}`;
            qr.alt = `${item.label || '节点'}二维码`;
            access.append(qr);
          }
          const accessBody = document.createElement('div');
          accessBody.className = 'user-forward-access-body';
          const accessTitle = document.createElement('span');
          accessTitle.className = 'user-forward-access-title';
          accessTitle.textContent = '节点链接';
          accessBody.append(accessTitle);
          if (item.value) {
            const link = document.createElement('textarea');
            link.readOnly = true;
            link.rows = 3;
            link.value = item.value;
            link.setAttribute('aria-label', `${item.label || '节点'}链接`);
            const actions = document.createElement('div');
            actions.className = 'user-forward-actions';
            const copy = document.createElement('button');
            copy.type = 'button';
            copy.className = 'secondary';
            copy.textContent = '复制链接';
            copy.dataset.copyValue = item.value;
            actions.append(copy);
            if (item.id) {
              const remove = document.createElement('form');
              remove.className = 'confirm-delete-form';
              remove.method = 'post';
              remove.action = '/forward/delete';
              remove.dataset.returnPath = '/nodes';
              remove.dataset.deleteLabel = item.label || '未命名转发';
              const csrf = document.querySelector('[name="csrf"]')?.value || '';
              const csrfField = document.createElement('input');
              csrfField.type = 'hidden';
              csrfField.name = 'csrf';
              csrfField.value = csrf;
              const idField = document.createElement('input');
              idField.type = 'hidden';
              idField.name = 'id';
              idField.value = item.id;
              const removeButton = document.createElement('button');
              removeButton.type = 'submit';
              removeButton.className = 'danger';
              removeButton.textContent = '删除链接';
              remove.append(csrfField, idField, removeButton);
              actions.append(remove);
            }
            accessBody.append(link, actions);
          } else {
            const unavailable = document.createElement('span');
            unavailable.className = 'user-forward-unavailable';
            unavailable.textContent = '暂无可用链接';
            accessBody.append(unavailable);
          }
          access.append(accessBody);
          card.append(info, access);
          cards.append(card);
        });
      }
    }
    openModal(modal, opener);
  });

  // Load a migration bundle file into the import textarea.
  document.addEventListener('change', async event => {
    const input = event.target.closest('[data-migrate-file]');
    if (!input || !input.files || !input.files.length) return;
    const modal = input.closest('#migrate-import-modal');
    const textarea = modal?.querySelector('[name="bundle"]');
    if (!textarea) return;
    try {
      textarea.value = await input.files[0].text();
      textarea.focus();
      consoleToast(`已载入 ${input.files[0].name}，确认后点击开始导入`);
    } catch (error) {
      consoleToast('读取迁移文件失败');
    }
  });

  // 服务器自身带宽实测（直连多流）
  const formatBandwidth = value => {
    if (value == null || Number.isNaN(Number(value))) return '—';
    const number = Number(value);
    if (number >= 100) return number.toFixed(0);
    if (number >= 10) return number.toFixed(1);
    if (number >= 1) return number.toFixed(2);
    return number.toFixed(2);
  };
  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-bandwidth-test]');
    if (!button) return;
    const original = button.textContent;
    button.disabled = true;
    button.textContent = '测速中…';
    const setField = (name, value) => document.querySelectorAll(`[data-bandwidth-field="${name}"]`).forEach(item => { item.textContent = value; });
    ['download', 'upload', 'single'].forEach(name => setField(name, '…'));
    setField('download-note', '测试中');
    setField('upload-note', '测试中');
    const csrf = document.querySelector('form[action="/logout"] input[name="csrf"]');
    try {
      const body = new URLSearchParams();
      if (csrf) body.set('csrf', csrf.value);
      const response = await fetch('/host/bandwidth', {
        method: 'POST',
        headers: {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
        body
      });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || '测速失败');
      setField('download', data.download_mbps ? formatBandwidth(data.download_mbps) : '—');
      setField('upload', data.upload_mbps ? formatBandwidth(data.upload_mbps) : '—');
      setField('single', data.single_mbps ? formatBandwidth(data.single_mbps) : '—');
      setField('download-note', data.download_mbps
        ? `${data.download_streams} 流 · ${(data.download_bytes / 1048576).toFixed(1)} MB / ${data.download_seconds}s`
        : (data.download_error || '无数据'));
      setField('upload-note', data.upload_mbps
        ? `${data.upload_streams} 流 · ${(data.upload_bytes / 1048576).toFixed(1)} MB / ${data.upload_seconds}s`
        : (data.upload_error || '无数据'));
      setField('single-note', data.download_source || '—');
      const stamp = new Date((data.measured_at || Date.now() / 1000) * 1000);
      setField('checked_at', `${String(stamp.getHours()).padStart(2, '0')}:${String(stamp.getMinutes()).padStart(2, '0')}`);
      setField('source', `下载源 ${data.download_source || '—'}`);
      consoleToast(`测速完成：下载 ${formatBandwidth(data.download_mbps)} Mbps · 上传 ${formatBandwidth(data.upload_mbps)} Mbps`);
    } catch (error) {
      ['download', 'upload', 'single'].forEach(name => setField(name, '—'));
      setField('download-note', '测速失败');
      setField('upload-note', '测速失败');
      consoleToast(error.message || '测速失败');
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  });
