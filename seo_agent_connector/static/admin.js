(() => {
  const note = document.querySelector('[data-notice]');
  const formDialog = document.querySelector('[data-form-dialog]');
  const secretDialog = document.querySelector('[data-secret-dialog]');
  const secretValue = document.querySelector('[data-secret-value]');
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const readable = { 'articles:read':'Чтение', 'articles:write':'Создание и изменение', 'articles:publish':'Публикация' };
  let guideStep = 1;
  const show = text => { note.textContent = text; note.hidden = false; };
  async function api(path, options={}) {
    const method = options.method || 'GET';
    const headers = {...(options.headers || {})};
    if (method !== 'GET') { headers['Content-Type']='application/json'; headers['X-Requested-With']='SEOAgentConnector'; }
    const response = await fetch(path,{...options,headers,credentials:'same-origin'});
    const data = await response.json().catch(()=>({}));
    if (!response.ok) throw new Error(data.error || `Ошибка (${response.status})`);
    return data;
  }
  document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => {
    document.querySelectorAll('[data-tab]').forEach(item => item.classList.toggle('active', item === button));
    document.querySelectorAll('[data-panel]').forEach(item => item.hidden = item.dataset.panel !== button.dataset.tab);
  }));
  document.querySelector('[data-theme]').addEventListener('click', () => {
    const mode = document.documentElement.dataset.theme;
    document.documentElement.dataset.theme = mode === 'dark' ? 'light' : mode === 'light' ? '' : 'dark';
  });
  async function loadTokens() {
    const {tokens=[]} = await api('/admin/seo-agent/tokens');
    const body = document.querySelector('[data-token-rows]');
    body.innerHTML = tokens.map(t => `<tr><td>${esc(t.name)}</td><td>${(t.scopes||[]).map(s=>esc(readable[s]||s)).join(', ')}</td><td>${esc(t.created_at)}</td><td>${esc(t.expires_at||'Без срока')}</td><td>${esc(t.last_used_at||'—')}</td><td class="${t.revoked_at?'error':'success'}">${t.revoked_at?'Отозван':(t.expires_at && t.expires_at < new Date().toISOString()?'Истёк':'Активен')}</td><td>${t.revoked_at?'—':`<button class="secondary" data-revoke="${esc(t.id)}">Отозвать</button>`}</td></tr>`).join('');
    document.querySelector('[data-token-empty]').hidden = tokens.length > 0;
  }
  async function loadDiagnostics() {
    const d = await api('/admin/seo-agent/diagnostics');
    const checks = Object.fromEntries(d.checks.map(check => [check.id, check]));
    const cards = [
      ['Домен сайта', d.base_url, 'success'], ['Версия коннектора', d.version, 'success'], ['Publishing API', `v${d.api_version}`, 'success'],
      ['HTTPS', checks.https.detail, checks.https.status], ['База данных', checks.storage.detail, checks.storage.status],
      ['Создание черновиков', checks.repository.status === 'success' ? 'Доступно через ArticleRepository.' : checks.repository.detail, checks.repository.status],
      ['Редактирование статей', checks.repository.status === 'success' ? 'Доступно через ArticleRepository.' : checks.repository.detail, checks.repository.status],
      ['Готовность к публикации', checks.publish.detail, checks.publish.status], ['Последнее обращение к API', d.last_api_at || 'Пока не было', 'success']
    ].map(([title,value,status])=>`<article class="card"><h3>${esc(title)}</h3><p>${esc(value)}</p><span class="status ${esc(status)}">${status==='success'?'Готово':status==='warning'?'Требует внимания':'Ошибка'}</span></article>`).join('');
    document.querySelector('[data-overview]').innerHTML = cards;
    document.querySelector('[data-checks]').innerHTML = d.checks.map(c=>`<article class="card"><h3>${esc(c.title)} · <span class="status ${esc(c.status)}">${c.status==='success'?'Успешно':c.status==='warning'?'Предупреждение':'Ошибка'}</span></h3><p>${esc(c.detail)}</p></article>`).join('');
    const pub = d.checks.find(c=>c.id==='publish');
    document.querySelector('[data-publish-status]').textContent = pub?.status === 'success' ? 'Публикация настроена.' : 'Публикация не настроена. Черновики доступны; для публичных страниц подключите обработчик публикации.';
    const auth = checks.auth, repository = checks.repository;
    document.querySelector('[data-guide-auth]').textContent = auth.detail;
    document.querySelector('[data-guide-repository]').textContent = repository.detail;
    document.querySelector('[data-guide-publish]').textContent = pub.detail;
  }
  function showGuide(step) {
    guideStep = Math.max(1, Math.min(6, step));
    document.querySelectorAll('[data-guide-step]').forEach(node => node.hidden = Number(node.dataset.guideStep) !== guideStep);
    document.querySelector('[data-guide-progress]').textContent = `Шаг ${guideStep} из 6`;
    document.querySelector('[data-guide-back]').disabled = guideStep === 1;
    document.querySelector('[data-guide-next]').disabled = guideStep === 6;
    document.querySelector('[data-guide-next]').textContent = guideStep === 6 ? 'Готово' : 'Далее';
  }
  document.querySelector('[data-guide-next]').addEventListener('click',()=>showGuide(guideStep+1));
  document.querySelector('[data-guide-back]').addEventListener('click',()=>showGuide(guideStep-1));
  document.querySelector('[data-guide-check]').addEventListener('click',async()=>{await loadDiagnostics();show('Проверка окружения обновлена. Проверьте результаты во вкладке «Диагностика».')});
  document.querySelector('[data-guide-token]').addEventListener('click',()=>{document.querySelector('[data-tab="tokens"]').click();formDialog.showModal()});
  document.querySelector('[data-create-open]').addEventListener('click',()=>formDialog.showModal());
  document.querySelector('[data-close]').addEventListener('click',()=>formDialog.close());
  document.querySelector('[data-create-form]').addEventListener('submit',async event=>{
    event.preventDefault(); const form=event.currentTarget; const button=form.querySelector('[type=submit]'); button.disabled=true;
    try {
      const data=Object.fromEntries(new FormData(form)); data.scopes=[...form.querySelectorAll('[name=scopes]:checked')].map(x=>x.value); if(data.expires_in==='never') data.expires_in=null;
      if(!data.scopes.length) throw new Error('Выберите хотя бы одно право.');
      const result=await api('/admin/seo-agent/tokens',{method:'POST',body:JSON.stringify(data)});
      form.reset(); formDialog.close(); secretValue.textContent=result.token; secretDialog.showModal(); show('Токен создан. Сохраните его до закрытия окна.'); await loadTokens();
    } catch(error){show(error.message)} finally{button.disabled=false}
  });
  async function closeSecret(){ secretValue.textContent=''; secretDialog.close(); }
  document.querySelector('[data-secret-close]').addEventListener('click',closeSecret);
  document.querySelector('[data-secret-done]').addEventListener('click',closeSecret);
  secretDialog.addEventListener('cancel',()=>{secretValue.textContent=''});
  document.querySelector('[data-copy]').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(secretValue.textContent);show('Токен скопирован. Сохраните его в безопасном месте.')}catch{show('Копирование запрещено браузером. Выделите и скопируйте токен вручную.')}});
  document.querySelector('[data-token-rows]').addEventListener('click',async event=>{
    const button=event.target.closest('[data-revoke]'); if(!button)return;
    if(!window.confirm('Отозвать этот токен? Запросы с ним сразу перестанут работать. Другие токены останутся активны.'))return;
    button.disabled=true; try{await api(`/admin/seo-agent/tokens/${encodeURIComponent(button.dataset.revoke)}/revoke`,{method:'POST',body:'{}'});show('Токен отозван.');await loadTokens()}catch(error){show(error.message)}
  });
  document.querySelector('[data-refresh]').addEventListener('click',()=>loadDiagnostics().catch(e=>show(e.message)));
  Promise.all([loadTokens(),loadDiagnostics()]).catch(error=>show(error.message));
})();
