/* AZURE NOTES — public browser configuration. NEVER store credentials here. */
(() => {
  'use strict';
  const CONFIG = Object.freeze({
    APP_NAME: 'Azure Notes',
    GAS_WEB_APP_URL: 'https://script.google.com/macros/s/AKfycbxbwJOWVRC2Jj3YmxKtfypCpaz2P6CRgoiiI1nhu1WelwXs0L1_XL31gyie1_ZGKlF_SA/exec',
    API_TIMEOUT_MS: 32000,
    BRIDGE_TIMEOUT_MS: 15000,
    PBKDF2_ITERATIONS: 310000,
    STORE_KEY: 'azurenotes:session:v1',
    CACHE_VERSION: 1
  });
  const subscribers = new Set();
  let bridge = null, bridgeReady = null, bridgePort = null, bridgeNonce = '';
  const pending = new Map();
  const authParamCache=new Map();
  const performanceSamples=[];
  const logPerformance=(label,elapsed,extra={})=>{
    const metric={label,ms:Math.round(elapsed),at:new Date().toISOString(),...extra};
    performanceSamples.push(metric);if(performanceSamples.length>100)performanceSamples.shift();
    const method=elapsed>2500?'warn':'info';
    console[method](`[AZURE SPEED] ${label}: ${metric.ms} ms`,extra);
    return metric;
  };
  const SPEED={
    entries:performanceSamples,
    mark(label,elapsed,extra={}){return logPerformance(label,elapsed,extra);},
    report(){console.table(performanceSamples);return performanceSamples.slice();},
    clear(){performanceSamples.length=0;},
  };
  const cleanUrl = () => CONFIG.GAS_WEB_APP_URL.trim();
  const secureOrigin = (origin) => {
    try { const h = new URL(origin).hostname; return h === 'script.google.com' || h === 'script.googleusercontent.com' || h.endsWith('.googleusercontent.com'); }
    catch (_) { return false; }
  };
  function resolveResponse(m) {
    if (!m || m.channel !== 'azure-rpc' || m.type !== 'response' || !pending.has(m.requestId)) return;
    const work = pending.get(m.requestId); pending.delete(m.requestId); clearTimeout(work.timeout);
    logPerformance('API '+work.action,performance.now()-work.started,{serverMs:typeof m.response?.serverMs==='number'?m.response.serverMs:null,ok:!!m.response?.success});
    if (!m.response || m.response.success !== true) {
      const e = new Error(m.response?.error?.message || 'Backend request failed.'); e.code = m.response?.error?.code || 'UNKNOWN';
      if (e.code === 'UNAUTHORIZED') { sessionStorage.removeItem(CONFIG.STORE_KEY); subscribers.forEach(fn => fn(e)); }
      work.reject(e);
    } else work.resolve(m.response.data);
  }
  // Apps Script is hosted inside nested Google iframe wrappers. The inner frame
  // sends a dedicated MessagePort to this top-level website, authenticated by
  // a one-time random channel id and a strict target-origin whitelist.
  function initializeBridge() {
    if (bridgeReady) return bridgeReady;
    const bridgeStarted=performance.now();
    bridgeReady = new Promise((resolve,reject) => {
      if (!/^https:\/\/script\.google\.com\/macros\/s\/[^/]+\/exec/.test(cleanUrl())) {
        bridgeReady = null; reject(new Error('Edit GAS_WEB_APP_URL in config.js with your deployed Apps Script /exec URL.')); return;
      }
      bridgeNonce = requestId().replace(/[^\w-]/g,'')+'-'+requestId().replace(/[^\w-]/g,'');
      const handleReady = e => {
        if (!secureOrigin(e.origin)) return;
        if (e.data?.channel !== 'azure-rpc' || e.data?.type !== 'ready' || e.data?.nonce !== bridgeNonce || !e.ports?.[0]) return;
        window.removeEventListener('message',handleReady); clearTimeout(timeout);
        bridgePort = e.ports[0]; bridgePort.onmessage = event => resolveResponse(event.data); bridgePort.start(); logPerformance('GAS bridge ready',performance.now()-bridgeStarted); resolve();
      };
      const timeout = setTimeout(() => {
        window.removeEventListener('message',handleReady);
        bridgeReady = null;
        if(bridge){bridge.remove();bridge=null;}
        reject(new Error('Apps Script bridge unavailable. Check the deployment, ALLOWED_ORIGINS, iframe restrictions and network.'));
      },CONFIG.BRIDGE_TIMEOUT_MS);
      window.addEventListener('message',handleReady);
      bridge = document.createElement('iframe'); bridge.id = 'azurenotes-api-bridge'; bridge.title = 'Secure Google Apps Script connection';
      bridge.referrerPolicy='no-referrer-when-downgrade';bridge.setAttribute('aria-hidden','true');
      Object.assign(bridge.style,{position:'fixed',top:'-5px',left:'-5px',width:'1px',height:'1px',opacity:'0',border:'0',pointerEvents:'none'});
      bridge.onerror=()=>{clearTimeout(timeout);window.removeEventListener('message',handleReady);bridgeReady=null;if(bridge){bridge.remove();bridge=null;}reject(new Error('Unable to load Google Apps Script.'));};
      document.body.append(bridge);
      bridge.src=cleanUrl()+(cleanUrl().includes('?')?'&':'?')+'bridge=1&channel='+encodeURIComponent(bridgeNonce)+'&origin='+encodeURIComponent(location.origin);
    });return bridgeReady;
  }
  function requestId() { return (crypto.randomUUID?.() || (Date.now() + '-' + Math.random().toString(36).slice(2))); }
  const Auth = {
    get() { try { const v = JSON.parse(sessionStorage.getItem(CONFIG.STORE_KEY) || 'null'); return v && v.token && Date.parse(v.expiresAt) > Date.now() ? v : null; } catch (_) { return null; } },
    set(v) { sessionStorage.setItem(CONFIG.STORE_KEY, JSON.stringify(v)); },
    clear() { sessionStorage.removeItem(CONFIG.STORE_KEY); },
    onExpired(fn) { subscribers.add(fn); return () => subscribers.delete(fn); },
    async derive(password, salt, iterations = CONFIG.PBKDF2_ITERATIONS) {
      if (!crypto.subtle) throw new Error('Web Crypto requires HTTPS or localhost.');
      if (password.length < 10 || password.length > 128) throw new Error('Password must contain 10–128 characters.');
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      const normalized = salt.replace(/-/g, '+').replace(/_/g, '/');
      const bytes = Uint8Array.from(atob(normalized + '='.repeat((4 - normalized.length % 4) % 4)), c => c.charCodeAt(0));
      const bits = new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:bytes,iterations,hash:'SHA-256'},key,256));
      return btoa(String.fromCharCode(...bits)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    },
    salt() { const bytes = crypto.getRandomValues(new Uint8Array(20)); return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); },
    async register(displayName,email,password){const salt=Auth.salt();const verifier=await Auth.derive(password,salt);const result=await API.call('register',{displayName,email,salt,verifier},{public:true});authParamCache.delete(String(email||'').trim().toLowerCase());return result;},
    async login(email,password){
      const normalized=String(email||'').trim().toLowerCase();
      const params=await Auth.prefetch(normalized);
      const verifier=await Auth.derive(password,params.salt,params.iterations);
      const result=await API.call('login',{email:normalized,verifier},{public:true});
      authParamCache.delete(normalized);Auth.set(result);return result;
    },
    prefetch(email){
      const normalized=String(email||'').trim().toLowerCase();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized))return Promise.reject(new Error('Enter a valid email.'));
      const cached=authParamCache.get(normalized);if(cached&&Date.now()-cached.at<60000)return cached.promise;authParamCache.delete(normalized);
      const pending=API.call('getAuthParams',{email:normalized},{public:true}).catch(err=>{authParamCache.delete(normalized);throw err;});
      authParamCache.set(normalized,{promise:pending,at:Date.now()});
      if(authParamCache.size>8)authParamCache.delete(authParamCache.keys().next().value);
      return pending;
    },
    async reset(token,password){const salt=Auth.salt();const verifier=await Auth.derive(password,salt);const result=await API.call('resetPassword',{token,salt,verifier},{public:true});authParamCache.clear();return result;},
    async change(currentPassword,newPassword,email){const params=await API.call('getAuthParams',{email},{public:true});const currentVerifier=await Auth.derive(currentPassword,params.salt,params.iterations);const salt=Auth.salt();const verifier=await Auth.derive(newPassword,salt);const result=await API.call('changePassword',{currentVerifier,salt,verifier});authParamCache.clear();return result;},
    async logout(){try{await API.call('logout');}finally{Auth.clear();}}
  };
  const API = {
    async ready(){return initializeBridge();},
    async call(action,payload={},options={}){
      await initializeBridge();
      const id=requestId(); const started=performance.now();const token=options.public ? '' : Auth.get()?.token || '';
      if(!token&&!options.public) {const e=new Error('Sign in to continue.');e.code='UNAUTHORIZED';throw e;}
      const promise=new Promise((resolve,reject)=>{
        const timeout=setTimeout(()=>{pending.delete(id);logPerformance('API '+action+' TIMEOUT',performance.now()-started);const e=new Error('Request timed out. The operation may have reached the server; check before retrying.');e.code='TIMEOUT';reject(e);},options.timeout||CONFIG.API_TIMEOUT_MS);
        pending.set(id,{resolve,reject,timeout,started,action});
      });
      bridgePort.postMessage({channel:'azure-rpc',type:'request',requestId:id,action,payload,token});
      return promise;
    }
  };
  const Utils = {
    escape(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));},
    date(s){const d=new Date(s);return isNaN(d)?'—':new Intl.DateTimeFormat('en-US',{month:'short',day:'numeric',year:'numeric'}).format(d);},
    ago(s){const diff=Date.now()-Date.parse(s);if(!Number.isFinite(diff))return '—';if(diff<60000)return 'Just now';if(diff<3600000)return Math.floor(diff/60000)+'m ago';if(diff<86400000)return Math.floor(diff/3600000)+'h ago';if(diff<604800000)return Math.floor(diff/86400000)+'d ago';return Utils.date(s);},
    debounce(fn,ms){let t;return (...args)=>{clearTimeout(t);t=setTimeout(()=>fn(...args),ms);};},
    download(filename,data,type='text/plain'){const url=URL.createObjectURL(new Blob([data],{type}));const a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);},
    initials(name){return (String(name||'U').trim().split(/\s+/).slice(0,2).map(w=>w[0]).join('')||'U').toUpperCase();}
  };
  window.AZURE = Object.freeze({CONFIG,API,Auth,Utils,Perf:SPEED});
  // Start the single shared RPC bridge early, without delaying first paint.
  const warm=()=>{if(/^https:\/\/script\.google\.com\/macros\/s\/[^/]+\/exec/.test(cleanUrl()))API.ready().catch(e=>console.warn('[AZURE SPEED] Background bridge warmup failed:',e.message));};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',warm,{once:true});else queueMicrotask(warm);
  window.addEventListener('load',()=>{
    const n=performance.getEntriesByType('navigation')[0];
    if(n)logPerformance('Document load',n.loadEventEnd||performance.now(),{domInteractiveMs:Math.round(n.domInteractive),transferBytes:n.transferSize});
  },{once:true});
})();
