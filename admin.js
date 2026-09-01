const adminApiPrefix=location.pathname.startsWith('/gift')?'/gift':'';
const adminApi=path=>adminApiPrefix+path;
const el=id=>document.getElementById(id);

const request=async(path,options={})=>{
  const response=await fetch(adminApi(path),options);
  const data=await response.json();
  if(!response.ok){const error=new Error(data.message||'请求失败。');error.status=response.status;throw error;}
  return data;
};

const setMessage=(id,message='')=>{el(id).textContent=message;};
const showLogin=()=>{el('login-view').hidden=false;el('admin-view').hidden=true;el('logout').hidden=true;};
const showAdmin=()=>{el('login-view').hidden=true;el('admin-view').hidden=false;el('logout').hidden=false;};
const showAdminPage=viewId=>{
  document.querySelectorAll('.admin-page').forEach(page=>{page.hidden=page.id!==viewId;});
  document.querySelectorAll('.nav-item').forEach(item=>{item.classList.toggle('is-active',item.dataset.view===viewId);});
};
const showGeneratedCodes=codes=>{
  const output=el('generated-codes-text');
  output.value=codes.map(item=>{
    const redeemUrl=new URL(`${adminApiPrefix}/`,location.origin);
    redeemUrl.searchParams.set('key',item.code);
    return `${item.product_name}----${item.code}----${redeemUrl.href}`;
  }).join('\n');
  el('generated-codes').hidden=!codes.length;
};
const copyGeneratedCodes=async()=>{
  const output=el('generated-codes-text');
  if(!output.value)return;
  try{await navigator.clipboard.writeText(output.value);}catch(error){output.select();document.execCommand('copy');}
  setMessage('inventory-message',`已复制 ${output.value.split('\n').filter(Boolean).length} 个激活码。`);
};
const cell=(value,className='')=>{const node=document.createElement('td');node.textContent=value||'--';if(className)node.className=className;return node;};

const renderInventory=items=>{
  const body=el('inventory-body');body.replaceChildren();
  if(!items.length){const row=document.createElement('tr');row.className='empty-row';const item=cell('暂无库存');item.colSpan=9;row.append(item);body.append(row);return;}
  items.forEach(item=>{
    const row=document.createElement('tr');
    row.append(cell(String(item.id)),cell(item.product_name),cell(item.soop_account_name),cell(item.item_code_idxs,'code-value'),cell(item.created_by),cell(item.created_at),cell(item.activation_code,'code-value'));
    const status=item.activation_code?(item.claim_status==='claimed'?'已领取':item.claim_status==='processing'?'领取中':'未领取'):'未生成';
    row.append(cell(status,`status-${item.claim_status||'available'}`));
    const action=document.createElement('td');
    if(!item.activation_code){const button=document.createElement('button');button.type='button';button.className='layui-btn generate-btn';button.textContent='生成激活码';button.addEventListener('click',()=>generateCode(item.id,button));action.append(button);}else{action.textContent='--';}
    row.append(action);body.append(row);
  });
};

const renderPagination=(target,data,onChange)=>{const node=el(target),pages=Math.max(1,Math.ceil(data.total/data.page_size));node.replaceChildren();const previous=document.createElement('button'),next=document.createElement('button'),summary=document.createElement('span');previous.type=next.type='button';previous.textContent='上一页';next.textContent='下一页';previous.disabled=data.page<=1;next.disabled=data.page>=pages;summary.textContent=`第 ${data.page} / ${pages} 页，共 ${data.total} 条`;previous.addEventListener('click',()=>onChange(data.page-1));next.addEventListener('click',()=>onChange(data.page+1));node.append(previous,summary,next);};

const renderClaims=items=>{
  const body=el('claims-body');body.replaceChildren();
  if(!items.length){const row=document.createElement('tr');row.className='empty-row';const item=cell('暂无领取记录');item.colSpan=7;row.append(item);body.append(row);return;}
  items.forEach(item=>{const row=document.createElement('tr');row.append(cell(String(item.id)),cell(item.activation_code,'code-value'),cell(item.claim_account),cell(item.product_name),cell(item.claimed_item_code_idxs,'code-value'),cell(item.soop_account_name),cell(item.claimed_at));body.append(row);});
};

const truncateLogMessage=value=>{
  const text=String(value||'--').replace(/\s+/g,' ').trim();
  return text.length>140?`${text.slice(0,140)}...`:text;
};
const levelClass=value=>`log-level-${String(value||'').toLowerCase().replace(/[^a-z]/g,'')}`;
const showSystemLogDetail=item=>{
  el('system-log-detail-level').textContent=item.level||'--';
  el('system-log-detail-module').textContent=item.logger_name||'--';
  el('system-log-detail-time').textContent=item.created_at||'--';
  el('system-log-detail-message').textContent=item.message||'--';
  el('system-log-detail-trace').textContent=item.trace||'未记录异常堆栈。';
  el('system-log-detail-dialog').showModal();
};
const renderSystemLogs=items=>{
  const body=el('system-logs-body');body.replaceChildren();
  if(!items.length){const row=document.createElement('tr');row.className='empty-row';const item=cell('暂无系统日志');item.colSpan=5;row.append(item);body.append(row);return;}
  items.forEach(item=>{
    const row=document.createElement('tr');
    row.append(cell(item.level||'--',`log-level ${levelClass(item.level)}`),cell(item.logger_name),cell(truncateLogMessage(item.message),'log-summary'),cell(item.created_at));
    const action=document.createElement('td'),button=document.createElement('button');
    button.type='button';button.className='layui-btn layui-btn-primary log-detail-button';button.textContent='详情';button.addEventListener('click',()=>showSystemLogDetail(item));
    action.append(button);row.append(action);body.append(row);
  });
};

const loadInventory=async(page=1)=>{setMessage('table-message');const search=el('inventory-search').value.trim();try{const data=await request(`/api/admin/inventory?page=${page}&page_size=20&q=${encodeURIComponent(search)}`);renderInventory(data.inventory||[]);renderPagination('inventory-pagination',data,loadInventory);}catch(error){if(error.status===401){showLogin();return;}setMessage('table-message',error.message);}};
const loadClaims=async(page=1)=>{setMessage('claims-message');const search=el('claims-search').value.trim();try{const data=await request(`/api/admin/claims?page=${page}&page_size=20&q=${encodeURIComponent(search)}`);renderClaims(data.claims||[]);renderPagination('claims-pagination',data,loadClaims);}catch(error){if(error.status===401){showLogin();return;}setMessage('claims-message',error.message);}};
const loadSystemLogs=async(page=1)=>{setMessage('system-logs-message');const search=el('system-logs-search').value.trim();try{const data=await request(`/api/admin/system-logs?page=${page}&page_size=20&q=${encodeURIComponent(search)}`);renderSystemLogs(data.logs||[]);renderPagination('system-logs-pagination',data,loadSystemLogs);}catch(error){if(error.status===401){showLogin();return;}setMessage('system-logs-message',error.message);}};
const generateCode=async(id,button)=>{button.disabled=true;try{const data=await request('/api/admin/activation-codes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({inventory_id:id})});setMessage('table-message',`已生成激活码：${data.code}`);await loadInventory();}catch(error){setMessage('table-message',error.message);}finally{button.disabled=false;}};

el('login-form').addEventListener('submit',async event=>{event.preventDefault();setMessage('login-message');try{await request('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:el('admin-username').value,password:el('admin-password').value})});el('admin-password').value='';showAdmin();loadInventory();loadClaims();loadSystemLogs();}catch(error){setMessage('login-message',error.message);}});
el('inventory-import-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget;setMessage('inventory-message');const button=form.querySelector('button[type="submit"]');button.disabled=true;try{const data=await request('/api/admin/inventory/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:el('inventory-import-text').value})});form.reset();showGeneratedCodes(data.codes||[]);setMessage('inventory-message',data.message);await loadInventory();}catch(error){setMessage('inventory-message',error.message);}finally{button.disabled=false;}});
el('refresh').addEventListener('click',()=>loadInventory(1));
el('refresh-claims').addEventListener('click',()=>loadClaims(1));
el('inventory-search-button').addEventListener('click',()=>loadInventory(1));
el('claims-search-button').addEventListener('click',()=>loadClaims(1));
el('refresh-system-logs').addEventListener('click',()=>loadSystemLogs(1));
el('system-logs-search-button').addEventListener('click',()=>loadSystemLogs(1));
el('inventory-search').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();loadInventory(1);}});
el('claims-search').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();loadClaims(1);}});
el('system-logs-search').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();loadSystemLogs(1);}});
el('copy-generated-codes').addEventListener('click',copyGeneratedCodes);
el('close-system-log-detail').addEventListener('click',()=>el('system-log-detail-dialog').close());
el('logout').addEventListener('click',async()=>{await request('/api/admin/logout',{method:'POST'});showLogin();});
document.querySelectorAll('.nav-item').forEach(item=>item.addEventListener('click',()=>showAdminPage(item.dataset.view)));
request('/api/admin/session').then(data=>{if(data.authenticated){showAdmin();loadInventory();loadClaims();loadSystemLogs();}else showLogin();}).catch(showLogin);
