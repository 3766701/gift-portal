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
const responseMessage=async response=>{
  try{const data=await response.json();if(data.message)return data.message;}catch(error){}
  if(response.status===504)return '服务器处理超时，请稍后使用激活码查询提货状态。';
  return response.ok?'服务器响应异常，请稍后重试。':`请求失败（HTTP ${response.status}），请稍后重试。`;
};
const showCompletedQueryResult=(code,reward)=>{const message=$('#result-modal-message'),product=document.createElement('span');product.className='query-reward';product.textContent=reward;message.replaceChildren(document.createTextNode(`激活码:${code}/ 商品名称:`),product,document.createTextNode(' 已完成，请及时登录游戏查看游戏库存到账情况感谢您的购买!'));$('#result-modal').hidden=false;$('#result-modal-confirm').focus();};
const clearQueryHistory=()=>{$('#order-result').textContent='';$('#history-row').style.display='none';$('#history').replaceChildren();};
const showQueryHistory=details=>{const used=details.status==='已领取',table=$('#history'),headers=['序号','激活码','商品','兑换成功时间'],head=document.createElement('thead'),headRow=document.createElement('tr'),body=document.createElement('tbody'),row=document.createElement('tr');headers.forEach(label=>{const cell=document.createElement('th');cell.textContent=label;headRow.append(cell)});head.append(headRow);['1',details.code,details.reward,details.used_at||'--'].forEach(value=>{const cell=document.createElement('td');cell.textContent=value;row.append(cell)});body.append(row);table.replaceChildren(head,body);$('#history-row').style.display='block';$('#order-result').textContent=used?`激活码:${details.code}/ 商品名称:${details.reward} 已完成，请及时登录游戏查看游戏库存到账情况感谢您的购买!`:details.message;};
const queryActivationCode=async(code,{showHistory=false}={})=>{if(!code){if(showHistory)clearQueryHistory();showResultModal('请输入激活码。');return}try{const r=await fetch(api('/api/orders/'+encodeURIComponent(code))),d=await r.json();if(r.status===404){if(showHistory)clearQueryHistory();showResultModal('对不起，查询不到该激活码！');return}if(showHistory)showQueryHistory(d);if(d.status==='未领取'){showResultModal('该激活码还未提货，请先提交后，再查询结果哦!');return}if(d.status==='已领取'){showCompletedQueryResult(d.code||code,d.reward);return}showResultModal(d.message||'查询失败，请稍后重试。')}catch{if(showHistory)clearQueryHistory();showResultModal('查询失败，请确认后端已启动。')}};
$('#result-modal-close').addEventListener('click',closeResultModal);$('#result-modal-confirm').addEventListener('click',closeResultModal);$('#result-modal').addEventListener('click',e=>{if(e.target===e.currentTarget)closeResultModal();});
$('#global-redeem-form').addEventListener('submit',async e=>{e.preventDefault();const msg=$('#global-form-message'),code=$('#global-code').value.trim(),username=$('#global-user').value.trim(),password=$('#global-password').value;if(code.length<12||!username||!password){msg.textContent='请填写完整的激活码、全球账号和密码。';return}if(!isEmail(username)){msg.textContent='请输入正确的邮箱格式。';return}msg.textContent='';setGlobalLoading(true);try{const r=await fetch(api('/api/redeem/global'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,username,password})});showResultModal(await responseMessage(r));}catch{showResultModal('无法连接提货服务，请稍后重试。')}finally{setGlobalLoading(false);}});$('#check-global-order').addEventListener('click',()=>{queryActivationCode($('#global-code').value.trim())});
$('#redeem-form').addEventListener('submit',async e=>{e.preventDefault();const msg=$('#form-message'),code=$('#code').value.trim(),uid=$('#player-id').value.trim();if(code.length<12||uid.length<3){msg.textContent='请输入完整激活码和 Steam 账号。';return}$('#progress-steam').style.display='block';$('#progress-bar').style.width='35%';msg.textContent='正在处理...';try{const r=await fetch(api('/api/redeem'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,player_id:uid,player_name:$('#player-name').value.trim()})});$('#progress-bar').style.width=r.ok?'100%':'0%';msg.textContent=await responseMessage(r);}catch{msg.textContent='无法连接提货服务，请稍后重试。'}});
$('#check-order-short').addEventListener('click',()=>{queryActivationCode($('#code').value.trim())});
$('#query-order').addEventListener('click',()=>{queryActivationCode($('#order-id').value.trim(),{showHistory:true})});
$('#generate-qr').addEventListener('click',()=>{if(!$('#qr-code').value.trim()){$('#qr-result').textContent='请输入激活码。';return}$('#qr-box').style.display='block';$('#qr-result').textContent='二维码已生成，请使用对应客户端扫码。'});
