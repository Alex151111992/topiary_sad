import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';

const root=fileURLToPath(new URL('../',import.meta.url));
const php=process.env.PHP_BINARY || 'php';
const phpArgs=['-n','-d','display_errors=0'];
if(process.platform==='win32') phpArgs.push('-d',`extension_dir=${join(dirname(php),'ext')}`);
for(const ext of ['pdo_sqlite','fileinfo','gd']) phpArgs.push('-d',`extension=${ext}`);
const password='A local fixture phrase for admin tests';

test('PHP catalogue: persistent products, roles and image pipeline',async t=>{
  const folder=mkdtempSync(join(tmpdir(),'topiary-admin-test-'));
  const listener=createServer(); await new Promise(r=>listener.listen(0,'127.0.0.1',r));
  const port=listener.address().port; await new Promise(r=>listener.close(r));
  const origin=`http://127.0.0.1:${port}`;
  const env={...process.env,SITE_ORIGIN:origin,AUTH_DB_PATH:join(folder,'accounts.sqlite')};
  let child,stderr='';
  async function start(){
    child=spawn(php,[...phpArgs,'-S',`127.0.0.1:${port}`,'-t',root,join(root,'tests/php-router.php')],{env,windowsHide:true});
    child.stderr.on('data',c=>stderr=(stderr+c).slice(-10000));
    let launchError; child.on('error',e=>launchError=e);
    for(let i=0;i<60;i++){
      if(launchError)throw launchError;
      if(child.exitCode!==null)throw new Error(stderr);
      try{if((await fetch(origin+'/api/catalog')).ok)return;}catch{}
      await new Promise(r=>setTimeout(r,100));
    } throw new Error('PHP not ready: '+stderr);
  }
  async function stop(){if(child?.exitCode===null)await new Promise(r=>{child.once('exit',r);child.kill();});}
  t.after(async()=>{await stop();const resolved=realpathSync(folder);assert.equal(dirname(resolved),realpathSync(tmpdir()));assert.ok(basename(resolved).startsWith('topiary-admin-test-'));rmSync(resolved,{recursive:true,force:true});});
  await start();
  const get=(path,cookie='')=>fetch(origin+path,{headers:{Cookie:cookie},redirect:'manual'});
  const json=(path,body,cookie='')=>fetch(origin+path,{method:'POST',headers:{Origin:origin,Cookie:cookie,'Content-Type':'application/json'},body:JSON.stringify(body)});
  const role=(operation,email)=>execFileSync(php,[...phpArgs,'bin/set-admin.php',operation,'email',email],{cwd:root,env,windowsHide:true});
  async function account(email){const r=await json('/api/auth/register',{email,password,confirmPassword:password});assert.equal(r.status,201);return r.headers.get('set-cookie').split(';')[0];}
  let adminCookie,customerCookie,csrf,product,photoPath;
  const png=execFileSync(php,[...phpArgs,'-r','$image=imagecreatetruecolor(8,8);imagepng($image);'],{windowsHide:true});
  function form(values={},photo=null){
    const data=new FormData();
    for(const [key,value]of Object.entries({id:'',version:'',name:'Тестовый топиар',desc:'Проверка общего каталога',price:'1234.56',category:'Фигуры',published:'1',...values}))data.append(key,String(value));
    if(photo)data.append('photo',new Blob([photo.body],{type:photo.type}),photo.name);
    return data;
  }
  const save=(data,extra={})=>fetch(origin+'/api/admin/products',{method:'POST',headers:{Origin:origin,Cookie:adminCookie,'X-CSRF-Token':csrf,...extra},body:data});
  await t.test('public seed and locked admin API, no URL-based admin',async()=>{
    const rows=(await (await get('/api/catalog')).json()).products;assert.equal(rows.length,3);
    for(const path of ['/api/admin/session','/api/admin/products','/api/admin/products?admin=true'])assert.equal((await get(path)).status,401);
    for(const path of ['/catalog.php','/email-auth.php','/bin/set-admin.php','/tests/php-admin.test.mjs','/.git/config','/README_ADMIN.md'])assert.equal((await get(path)).status,404);
    assert.equal((await get('/admin')).status,200);
  });
  await t.test('normal and forged registration cannot obtain administrator rights',async()=>{
    customerCookie=await account('customer@example.test');
    adminCookie=await account('operator@example.test');
    assert.equal((await get('/api/admin/session',customerCookie)).status,403);
    assert.equal((await get('/api/admin/products?admin=1',adminCookie)).status,403);
    const r=await json('/api/auth/register',{email:'forged@example.test',password,confirmPassword:password,role:'admin',admin:true});
    assert.equal(r.status,201);const cookie=r.headers.get('set-cookie').split(';')[0];assert.equal((await get('/api/admin/session',cookie)).status,403);
  });
  await t.test('operator grants a role to an existing account; token tied to session',async()=>{
    role('grant','operator@example.test');
    const session=await (await get('/api/admin/session',adminCookie)).json();assert.equal(session.admin,true);assert.match(session.csrfToken,/^[a-f0-9]{64}$/);csrf=session.csrfToken;
    assert.equal((await (await get('/api/auth/session',adminCookie)).json()).admin,true);
    assert.equal((await (await get('/api/auth/session',customerCookie)).json()).admin,false);
  });
  await t.test('CSRF, Origin, content type, wrong method and missing fields rejected',async()=>{
    assert.equal((await save(form(),{'X-CSRF-Token':''})).status,403);
    assert.equal((await save(form(),{Origin:'https://other.example'})).status,403);
    assert.equal((await save(form(),{'Sec-Fetch-Site':'cross-site'})).status,403);
    assert.equal((await fetch(origin+'/api/admin/products',{method:'DELETE',headers:{Cookie:adminCookie}})).status,405);
    assert.equal((await save(JSON.stringify({name:'wrong'}),{'Content-Type':'application/json'})).status,415);
    for(const values of [{name:''},{price:'-1'},{price:'1e9'},{price:'1.111'},{price:'0'},{published:'admin'},{category:''},{id:'../1'}])assert.equal((await save(form(values))).status,422,JSON.stringify(values));
  });
  await t.test('create product with real PNG; private path and re-encoded public image',async()=>{
    const response=await save(form({}, {body:png,type:'image/png',name:'../../payload.php.png'}));assert.equal(response.status,201);
    product=(await response.json()).product;assert.equal(product.price,1234.56);assert.equal(product.version,1);assert.equal(product.published,true);photoPath=product.img;
    assert.match(photoPath,/^\/media\/[a-f0-9]{32}\.png$/);
    const image=await get(photoPath);assert.equal(image.status,200);assert.equal(image.headers.get('content-type'),'image/png');assert.equal(image.headers.get('x-content-type-options'),'nosniff');assert.match(image.headers.get('content-security-policy'),/sandbox/);
    assert.ok(Buffer.from(await image.arrayBuffer()).subarray(0,8).equals(png.subarray(0,8)));
    assert.equal(readdirSync(join(folder,'catalog-images')).length,1);
    const publicRows=(await (await get('/api/catalog')).json()).products;assert.ok(publicRows.some(p=>p.id===product.id));assert.equal(publicRows.find(p=>p.id===product.id).version,undefined);
  });
  await t.test('persistence across PHP restart, same admin session retained',async()=>{
    await stop();await start();
    assert.ok((await (await get('/api/catalog')).json()).products.some(p=>p.id===product.id));
    assert.equal((await get('/api/admin/session',adminCookie)).status,200);
  });
  await t.test('customer cannot write even with an administrator CSRF token',async()=>{
    assert.equal((await save(form(),{Cookie:customerCookie})).status,403);
    assert.equal((await save(form(),{Cookie:''})).status,401);
  });
  await t.test('edit as draft; photo hidden from public; conflicts do not overwrite',async()=>{
    const response=await save(form({id:product.id,version:product.version,published:'0',price:'900.50',name:'<img src=x onerror=alert(1)>'}));assert.equal(response.status,200);
    product=(await response.json()).product;assert.equal(product.version,2);assert.equal(product.img,photoPath);
    assert.ok(!(await (await get('/api/catalog')).json()).products.some(p=>p.id===product.id));
    assert.equal((await get(photoPath)).status,404);assert.equal((await get(photoPath,customerCookie)).status,404);assert.equal((await get(photoPath,adminCookie)).status,200);
    assert.equal((await save(form({id:product.id,version:1}))).status,409);
    assert.equal((await save(form({id:999999,version:1}))).status,404);
    assert.equal((await (await get('/api/admin/products',adminCookie)).json()).products.find(p=>p.id===product.id).price,900.5);
  });
  await t.test('malicious, damaged, oversized and too-wide images rejected',async()=>{
    for(const photo of [
      {body:'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',type:'image/svg+xml',name:'photo.svg'},
      {body:'<?php echo 1;',type:'image/png',name:'photo.png'},
      {body:png.subarray(0,32),type:'image/png',name:'broken.png'},
      {body:Buffer.alloc(4*1024*1024+1),type:'image/png',name:'huge.png'},
    ])assert.equal((await save(form({},photo))).status,422,photo.name);
    const wide=execFileSync(php,[...phpArgs,'-r','$image=imagecreatetruecolor(4097,1);imagepng($image);'],{windowsHide:true});
    assert.equal((await save(form({},{body:wide,type:'image/png',name:'wide.png'}))).status,422);
    assert.equal(readdirSync(join(folder,'catalog-images')).length,1);
  });
  await t.test('remove photo and publish; replaced private file cleaned up',async()=>{
    const response=await save(form({id:product.id,version:product.version,removePhoto:'1',published:'1'}));assert.equal(response.status,200);
    product=(await response.json()).product;assert.equal(product.img,'/assets/catalog-placeholder.svg');
    assert.equal(readdirSync(join(folder,'catalog-images')).length,0);assert.equal((await get(photoPath)).status,404);
    assert.ok((await (await get('/api/catalog')).json()).products.some(p=>p.id===product.id));
  });
  await t.test('role revocation and logout immediately prevent administrative requests',async()=>{
    role('revoke','operator@example.test');assert.equal((await get('/api/admin/session',adminCookie)).status,403);
    role('grant','operator@example.test');assert.equal((await get('/api/admin/session',adminCookie)).status,200);
    assert.equal((await json('/api/auth/logout',{},adminCookie)).status,200);assert.equal((await get('/api/admin/session',adminCookie)).status,401);
  });
  assert.doesNotMatch(stderr,/Fatal error|Uncaught/);
});
