const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
const apiPrefix=window.location.pathname==='/gift'||window.location.pathname.startsWith('/gift/')?'/gift':'';
const api=path=>apiPrefix+path;

// Keep every activation-code field in sync with the target page's plain text input behavior.
const activationFields=$$('#code,#global-code,#qr-code,#order-id');
const key=new URLSearchParams(window.location.search).get('key');
if(key) activationFields.forEach(field=>{field.value=key;});

const activateTab=tab=>{$$('.layui-tab-title li').forEach(x=>x.classList.toggle('layui-this',x.dataset.tab===tab));$$('.layui-tab-item').forEach(x=>x.classList.toggle('layui-show',x.dataset.panel===tab));};
$('#tabs').addEventListener('click',e=>{const li=e.target.closest('li');if(!li||li.classList.contains('tab-disabled'))return;activateTab(li.dataset.tab)});
const setTabEnabled=(tab,enabled)=>{const item=$(`[data-tab="${tab}"]`);item.classList.toggle('tab-disabled',!enabled);item.setAttribute('aria-disabled',String(!enabled));item.tabIndex=enabled?0:-1;};
fetch(api('/api/config')).then(r=>r.json()).then(config=>{setTabEnabled('steam',config.features.steam);setTabEnabled('qr',config.features.qr);if(!config.features.steam&&$('.layui-tab-title .layui-this').classList.contains('tab-disabled'))activateTab('global');}).catch(()=>{});
const setGlobalLoading=active=>{$('#global-loading').hidden=!active;$('#global-redeem-form button[type="submit"]').disabled=active;};
const isEmail=value=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const closeResultModal=()=>{$('#result-modal').hidden=true;};
const showResultModal=message=>{$('#result-modal-message').textContent=message;$('#result-modal').hidden=false;$('#result-modal-confirm').focus();};
$('#result-modal-close').addEventListener('click',closeResultModal);$('#result-modal-confirm').addEventListener('click',closeResultModal);$('#result-modal').addEventListener('click',e=>{if(e.target===e.currentTarget)closeResultModal();});
$('#global-redeem-form').addEventListener('submit',async e=>{e.preventDefault();const msg=$('#global-form-message'),code=$('#global-code').value.trim(),username=$('#global-user').value.trim(),password=$('#global-password').value;if(code.length<12||!username||!password){msg.textContent='请填写完整的激活码、全球账号和密码。';return}if(!isEmail(username)){msg.textContent='请输入正确的邮箱格式。';return}msg.textContent='';setGlobalLoading(true);try{const r=await fetch(api('/api/redeem/global'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,username,password})}),d=await r.json();showResultModal(d.message);}catch{showResultModal('后端服务未启动，请运行 python server.py。')}finally{setGlobalLoading(false);}});$('#check-global-order').addEventListener('click',()=>{$('[data-tab="orders"]').click()});
$('#redeem-form').addEventListener('submit',async e=>{e.preventDefault();const msg=$('#form-message'),code=$('#code').value.trim(),uid=$('#player-id').value.trim();if(code.length<12||uid.length<3){msg.textContent='请输入完整激活码和 Steam 账号。';return}$('#progress-steam').style.display='block';$('#progress-bar').style.width='35%';msg.textContent='正在处理...';try{const r=await fetch(api('/api/redeem'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,player_id:uid,player_name:$('#player-name').value.trim()})});const d=await r.json();$('#progress-bar').style.width=r.ok?'100%':'0%';msg.textContent=d.message;}catch{msg.textContent='后端服务未启动，请运行 python server.py。'}});
$('#check-order-short').addEventListener('click',()=>{$('[data-tab="orders"]').click()});
$('#query-order').addEventListener('click',async()=>{const code=$('#order-id').value.trim(),out=$('#order-result');if(!code){out.textContent='请输入激活码。';return}try{const r=await fetch(api('/api/orders/'+encodeURIComponent(code))),d=await r.json();out.textContent=d.message||`${d.status} · ${d.reward}`}catch{out.textContent='查询失败，请确认后端已启动。'}});
$('#generate-qr').addEventListener('click',()=>{if(!$('#qr-code').value.trim()){$('#qr-result').textContent='请输入激活码。';return}$('#qr-box').style.display='block';$('#qr-result').textContent='二维码已生成，请使用对应客户端扫码。'});
