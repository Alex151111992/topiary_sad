(() => {
  const $ = selector => document.querySelector(selector);
  const form = $('#product-form');
  let products = [], csrf = '', photoUrl = '', savedImage = '', saving = false;
  const money = value => new Intl.NumberFormat('ru-RU',{style:'currency',currency:'RUB',maximumFractionDigits:2}).format(value);
  function message(selector,text,error=false) { const node=$(selector); node.textContent=text; node.classList.toggle('error',error); }
  function deny(text) {
    $('#admin-workspace').hidden=true; $('#access-message').hidden=false;
    $('#access-message').replaceChildren(document.createTextNode(text+' '));
    const link=document.createElement('a'); link.href='/#login'; link.textContent='Войти на сайт'; $('#access-message').append(link);
    csrf=''; products=[]; closeEditor();
  }
  async function api(path,options={}) {
    const response=await fetch(path,{credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(20000),...options});
    let body; try { body=await response.json(); } catch { throw new Error('Сервер не ответил. Попробуйте позже.'); }
    if ([401,403].includes(response.status)) deny(body.error || 'Нет доступа к панели.');
    if (!response.ok) throw new Error(body.error || 'Не удалось выполнить запрос.');
    return body;
  }
  function preview() {
    $('#preview-name').textContent=form.elements.name.value.trim() || 'Название изделия';
    $('#preview-description').textContent=form.elements.desc.value;
    $('#preview-category').textContent=form.elements.category.value.trim() || 'Категория';
    $('#preview-price').textContent=money(Number(form.elements.price.value) || 0);
    $('#preview-image').src=photoUrl || (form.elements.removePhoto.checked ? '' : savedImage) || '/assets/catalog-placeholder.svg';
    $('#preview-publication').textContent=form.elements.published.value==='1' ? 'После сохранения товар будет доступен посетителям сайта.' : 'Черновик доступен только администратору.';
  }
  function revokePhoto() { if(photoUrl) URL.revokeObjectURL(photoUrl); photoUrl=''; }
  function closeEditor() { revokePhoto(); $('#editor').hidden=true; form.reset(); savedImage=''; message('#save-status',''); }
  function openEditor(product=null) {
    if (saving) return;
    closeEditor(); $('#editor').hidden=false;
    $('#editor-title').textContent=product ? 'Редактировать изделие' : 'Новое изделие';
    for(const key of ['id','version','name','desc','price','category']) form.elements[key].value=product?.[key] ?? '';
    form.elements.published.value=product ? (product.published ? '1':'0') : '1';
    savedImage=product?.img || ''; preview();
    $('#editor').scrollIntoView({behavior:'smooth',block:'start'}); form.elements.name.focus({preventScroll:true});
  }
  function filters() {
    const selected=$('#filter-category').value;
    const categories=[...new Set(products.map(p=>p.category))].sort((a,b)=>a.localeCompare(b,'ru'));
    $('#filter-category').replaceChildren(new Option('Все категории',''),...categories.map(c=>new Option(c,c)));
    if(categories.includes(selected)) $('#filter-category').value=selected;
    $('#categories').replaceChildren(...categories.map(c=>new Option(c,c)));
  }
  function renderList() {
    const search=$('#product-search').value.trim().toLocaleLowerCase('ru');
    const category=$('#filter-category').value, state=$('#filter-status').value;
    const shown=products.filter(p=>(!category || p.category===category) && (!state || (state==='published')===p.published) &&
      `${p.name} ${p.desc}`.toLocaleLowerCase('ru').includes(search));
    $('#product-count').textContent=`Показано ${shown.length} из ${products.length}`;
    const rows=shown.map(product=>{
      const row=document.createElement('tr'), first=document.createElement('td'), cell=document.createElement('div'); cell.className='product-cell';
      const img=document.createElement('img'); img.className='thumb'; img.src=product.img; img.alt='';
      img.addEventListener('error',()=>{img.src='/assets/catalog-placeholder.svg';},{once:true});
      const title=document.createElement('strong'); title.textContent=product.name; cell.append(img,title); first.append(cell); row.append(first);
      for(const text of [product.category,money(product.price)]) { const td=document.createElement('td'); td.textContent=text; row.append(td); }
      const stateCell=document.createElement('td'), badge=document.createElement('span'); badge.className=product.published?'badge':'badge draft'; badge.textContent=product.published?'Опубликовано':'Черновик'; stateCell.append(badge); row.append(stateCell);
      const action=document.createElement('td'), button=document.createElement('button'); button.type='button'; button.className='secondary'; button.textContent='Изменить'; button.setAttribute('aria-label',`Изменить ${product.name}`); button.disabled=saving; button.addEventListener('click',()=>openEditor(product)); action.append(button); row.append(action);
      return row;
    });
    if(!rows.length) { const row=document.createElement('tr'), td=document.createElement('td'); td.colSpan=5; td.textContent='Изделия не найдены. Измените фильтры или добавьте новое.'; row.append(td); rows.push(row); }
    $('#product-list').replaceChildren(...rows);
  }
  async function reload() { const result=await api('/api/admin/products'); products=result.products; filters(); renderList(); }
  $('#new-product').addEventListener('click',()=>openEditor());
  for(const selector of ['#close-editor','#cancel-edit']) $(selector).addEventListener('click',()=>{if(!saving)closeEditor();});
  for(const selector of ['#product-search','#filter-category','#filter-status']) $(selector).addEventListener('input',renderList);
  $('#reset-filters').addEventListener('click',()=>{ $('#product-search').value=$('#filter-category').value=$('#filter-status').value=''; renderList(); });
  form.addEventListener('input',preview);
  $('#photo').addEventListener('change',()=>{
    revokePhoto(); const file=$('#photo').files[0];
    if(file && (file.size>4*1024*1024 || !['image/jpeg','image/png','image/webp'].includes(file.type))) {
      $('#photo').value=''; message('#save-status','Выберите JPEG, PNG или WebP до 4 МБ.',true);
    } else { if(file) photoUrl=URL.createObjectURL(file); message('#save-status',''); }
    preview();
  });
  form.addEventListener('submit',async event=>{
    event.preventDefault(); if(saving || !csrf || !form.reportValidity())return;
    const data=new FormData(form); saving=true;
    for(const control of form.elements) control.disabled=true;
    $('#new-product').disabled=$('#close-editor').disabled=true; renderList(); message('#save-status','Сохраняем изделие…');
    try {
      const result=await api('/api/admin/products',{method:'POST',headers:{'X-CSRF-Token':csrf},body:data});
      // Update the visible state from the persisted server row before refreshing the list.
      const index=products.findIndex(p=>p.id===result.product.id);
      if(index<0) products.unshift(result.product); else products[index]=result.product;
      filters(); renderList(); savedImage=result.product.img; revokePhoto();
      form.elements.id.value=result.product.id; form.elements.version.value=result.product.version;
      $('#photo').value=''; form.elements.removePhoto.checked=false; preview();
      $('#editor-title').textContent='Редактировать изделие';
      message('#save-status',result.product.published?'Изделие сохранено и опубликовано в каталоге.':'Изделие сохранено как черновик.');
    } catch(error) { message('#save-status',error.message || 'Проверьте соединение и повторите действие.',true); }
    finally {
      saving=false; for(const control of form.elements) control.disabled=false;
      $('#new-product').disabled=$('#close-editor').disabled=false; renderList();
    }
  });
  window.addEventListener('beforeunload',revokePhoto);
  (async()=>{
    try {
      const session=await api('/api/admin/session'); csrf=session.csrfToken;
      await reload(); $('#access-message').hidden=true; $('#admin-workspace').hidden=false;
    } catch(error) { if(!$('#access-message').querySelector('a')) message('#access-message',error.message,true); }
  })();
})();
