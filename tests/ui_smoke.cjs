const {JSDOM,VirtualConsole}=require('jsdom');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawn,spawnSync}=require('node:child_process');
const {createInterface}=require('node:readline');
const {randomBytes}=require('node:crypto');
const assert=require('node:assert/strict');
(async()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'securefi-ui-'));
 const root=path.resolve(__dirname,'..');
 const python=process.env.PYTHON||(process.platform==='win32'?'python':'python3');
 const db=path.join(temp,'demo.db'), accessToken=randomBytes(32).toString('hex');
 const seeded=spawnSync(python,['-m','securefi','--db',db,'demo'],{cwd:root,encoding:'utf8'});
 if(seeded.status!==0)throw Error(seeded.stderr||'Python demo setup failed');
 const server=spawn(python,['-m','securefi','--db',db,'serve','--port','0'],{cwd:root,env:{...process.env,SECUREFI_TOKEN:accessToken,SECUREFI_AI_PROVIDER:'rules',SECUREFI_CHAIN_ENABLED:'0',SECUREFI_OLLAMA_URL:'http://127.0.0.1:11434'},stdio:['ignore','pipe','pipe']});
 let url;
 try {
 url=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Server startup timeout')),10000);
 const lines=createInterface({input:server.stdout});
 lines.on('line',line=>{if(line.startsWith('SecureFI: http')){clearTimeout(timer);resolve(line.slice(10).trim()+'/');}});
 server.on('error',e=>{clearTimeout(timer);reject(e)});});
 const errors=[];const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
 const dom=await JSDOM.fromURL(url,{resources:'usable',runScripts:'dangerously',virtualConsole:vc,beforeParse(w){
  w.fetch=(target,options)=>fetch(new URL(target,url),options);
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true};w.HTMLDialogElement.prototype.close=function(){this.open=false};
 }});
 const w=dom.window,d=w.document,$=s=>d.querySelector(s);
 const until=async fn=>{for(let i=0;i<100;i++){if(fn())return;await new Promise(r=>setTimeout(r,30));}throw Error('Timed out')};
 const submit=s=>$(s).dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));
 await until(()=>typeof $('#login-form').onsubmit==='function');
 $('#token').value=accessToken;submit('#login-form');
 await until(()=>!$('#workspace').hidden);assert.match($('#content').textContent,/Active exposures/);
 for(const tab of ['findings','assets','controls','activity','integrations','overview']){$(`[data-tab="${tab}"]`).click();assert.ok($('#content').textContent.length>100);}
 $('[data-tab="findings"]').click();$('[data-finding="1"]').click();assert.equal($('#modal').open,true);
 $('#review-form select[name="status"]').value='resolved';$('#review-form textarea[name="note"]').value='Test review';
 submit('#review-form');await until(()=>$('#modal-error').textContent.length>0);assert.match($('#modal-error').textContent,/verification/);
 $('#review-form textarea[name="verification"]').value='Synthetic retest passed';submit('#review-form');await until(()=>!$('#modal').open);
 $('[data-tab="assets"]').click();$('#add-asset').click();$('#asset-form input[name="name"]').value='<script>throw Error("XSS")</script>';
 $('#asset-form input[name="owner"]').value='DOM test';submit('#asset-form');await until(()=>!$('#modal').open);await until(()=>$('#content').textContent.includes('<script>throw Error("XSS")</script>'));
 assert.equal($('#content script'),null);
 $('[data-tab="controls"]').click();$('[data-control="access"]').click();$('#evidence-form textarea').value='Synthetic DOM evidence';submit('#evidence-form');await until(()=>!$('#modal').open);
 await until(()=>$('#content').textContent.includes('1 evidence record'));$('[data-control="access"]').click();
 $('#control-form input').value='Team';$('#control-form select').value='reviewed';$('#control-form textarea').value='Evidence checked';submit('#control-form');await until(()=>!$('#modal').open);
 await until(()=>$('#content').textContent.includes('reviewed'));
 $('[data-tab="integrations"]').click();$('#generate-draft').click();
 await until(()=>$('#content').textContent.includes('Draft #'));
 $('[data-draft-review]').click();$('#draft-review-form textarea').value='Reviewed draft in UI test';submit('#draft-review-form');
 await until(()=>!$('#modal').open);await until(()=>$('#content').textContent.includes('approved'));
 $('#freeze-snapshot').click();await until(()=>$('#content').textContent.includes('Snapshot #'));
 $('[data-ledger-verify]').click();await until(()=>$('#modal').open);
 assert.match($('#modal-content').textContent,/Snapshot has not been anchored/);$('#close-modal').click();
 $('#logout').click();assert.equal($('#login').hidden,false);assert.equal(w.sessionStorage.getItem('securefi-token'),null);
 assert.deepEqual(errors,[]);console.log('PASS: DOM integration, login, all tabs, AI draft review, snapshot verification, resolution validation, review save, asset creation, XSS escaping, evidence, control review and logout.');
 w.close();
 } finally {
 await new Promise(resolve=>{server.once('exit',resolve);server.kill();});
 fs.rmSync(temp,{recursive:true,force:true});
 }
})().catch(e=>{console.error(e);process.exit(1)});
