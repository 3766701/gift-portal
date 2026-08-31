// Browserless Akamai bmak runner.
//
// This executes the served Akamai bundle in Node's VM with a deliberately
// small browser-compatible surface.  It never opens a browser and never
// performs an authentication request.  The caller owns the HTTP transport.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

function arg(name, fallback = '') {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const bundlePath = arg('--bundle', process.argv[2]);
const targetUrl = arg('--target-url', 'https://accounts.krafton.com/v2/zh_CN/web/login-main');
const scriptUrl = arg('--script-url', targetUrl);
const outputPath = arg('--out', path.join(process.cwd(), 'node_sensor_telemetry.txt'));
const cookieHeader = arg('--cookie', process.env.KRAFTON_NODE_COOKIE || '');
const userAgent = arg('--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36');
const waitMs = Number(arg('--wait-ms', '250')) || 0;
if (!bundlePath) throw new Error('bundle path required');

function proxyObject(seed = {}) {
  return new Proxy(seed, {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (process.env.NODE_REPAIR_BROWSER_KEYS === '1' && typeof prop === 'string') {
        // One current bundle decodes the browser property `location` with a
        // corrupted UTF-16 tail in the minimal VM.  Chromium exposes the
        // canonical property on Document/Window; restore only this exact
        // prefix rather than turning every missing property into a stub.
        if (prop.startsWith('locat')) return location;
      }
      if (prop === Symbol.toStringTag) return 'Object';
      if (prop === 'length') return 0;
      return undefined;
    },
    set(target, prop, value) { target[prop] = value; return true; }
  });
}

function installEventTarget(obj) {
  const listeners = new Map();
  obj.addEventListener = (type, fn) => {
    if (typeof fn !== 'function') return;
    const list = listeners.get(String(type)) || [];
    if (!list.includes(fn)) list.push(fn);
    listeners.set(String(type), list);
  };
  obj.removeEventListener = (type, fn) => {
    const list = listeners.get(String(type)) || [];
    listeners.set(String(type), list.filter(x => x !== fn));
  };
  obj.dispatchEvent = (event) => {
    const list = (listeners.get(String(event && event.type)) || []).slice();
    for (const fn of list) { try { fn.call(obj, event); } catch (_) {} }
    return true;
  };
  return obj;
}

function element() {
  const e = proxyObject({
    style: {}, dataset: {}, children: [], childNodes: [], attributes: [],
    ownerDocument: null, parentNode: null, nodeType: 1,
    appendChild(x) { this.children.push(x); return x; },
    removeChild() {},
    setAttribute(k, v) { this.attributes.push([k, String(v)]); this[k] = String(v); },
    getAttribute(k) { return this[k] ?? null; },
    addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
    getContext() { return proxyObject({}); },
    getBoundingClientRect() { return {x:0,y:0,width:0,height:0,top:0,left:0,right:0,bottom:0}; },
    getElementsByTagName() { return []; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    cloneNode() { return element(); }, toDataURL() { return 'data:image/png;base64,'; },
    focus() {}, blur() {}, click() {}
  });
  return installEventTarget(e);
}

const parsed = new URL(targetUrl);
const location = proxyObject({
  href: targetUrl, protocol: parsed.protocol, host: parsed.host,
  hostname: parsed.hostname, pathname: parsed.pathname, search: parsed.search,
  hash: parsed.hash, origin: parsed.origin,
  assign(url) { this.href = String(url); }, replace(url) { this.href = String(url); }, reload() {}
});
const document = proxyObject({
  cookie: cookieHeader, documentElement: element(), body: element(), head: element(),
  URL: targetUrl,
  createElement: element, createElementNS: element,
  getElementsByTagName() { return []; }, getElementsByClassName() { return []; },
  querySelector() { return null; }, querySelectorAll() { return []; },
  addEventListener() {}, removeEventListener() {}, hasFocus() { return true; },
  readyState: 'complete', createEvent() { return {initEvent() {}, initCustomEvent() {}}; }
});
installEventTarget(document);
document.visibilityState = 'visible';
const navigator = proxyObject({
  userAgent, appName: 'Netscape', appVersion: '5.0', platform: 'Win32',
  language: 'zh-CN', languages: ['zh-CN', 'zh'], cookieEnabled: true,
  hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0,
  plugins: [], mimeTypes: [], webdriver: false,
  userAgentData: {brands: [], mobile: false, platform: 'Windows'}
});
const screen = proxyObject({width: 1365, height: 768, availWidth: 1365, availHeight: 728, colorDepth: 24, pixelDepth: 24});
const history = {
  length: 1, state: null,
  pushState(_state, _title, url) { if (url) location.href = String(url); },
  replaceState(_state, _title, url) { if (url) location.href = String(url); },
  back() {}, forward() {}, go() {}
};
const mediaQuery = (query) => ({matches:false, media:String(query), onchange:null, addListener(){}, removeListener(){}, addEventListener(){}, removeEventListener(){}, dispatchEvent(){return true;}});
const visualViewport = {width:1365, height:768, scale:1, offsetLeft:0, offsetTop:0, pageLeft:0, pageTop:0, addEventListener(){}, removeEventListener(){}};
const performance = {timeOrigin: Date.now() - 5000, now: () => Date.now() % 1000000, getEntriesByType: () => []};
const localStorage = {getItem(){return null;}, setItem(){}, removeItem(){}, clear(){}, key(){return null;}, length:0};
const cryptoObj = {getRandomValues(a){const b=crypto.randomBytes(a.byteLength); new Uint8Array(a.buffer,a.byteOffset,a.byteLength).set(b); return a;}, subtle:{}};
const currentScript = element();
currentScript.src = scriptUrl; currentScript.async = false;
document.scripts = [currentScript]; document.currentScript = currentScript;
document.getElementsByTagName = (name) => String(name).toLowerCase() === 'script' ? document.scripts : [];
document.location = location;

function nodeBrowserKey(value) {
  const key = String(value);
  if (key.startsWith('locat')) return 'location';
  if (key.startsWith('re') && /[^A-Za-z0-9_$]/.test(key.slice(2))) return 'replace';
  if (key.startsWith('str') && /[^A-Za-z0-9_$]/.test(key.slice(3))) return 'stringify';
  if (key.startsWith('a') && /[^A-Za-z0-9_$]/.test(key.slice(1))) return 'applyFunc';
  return key;
}

function nodeAkamaiTableKey(value, table) {
  const key = String(value);
  if (table && typeof table[key] === 'function') return key;
  if (table && key.startsWith('E0K')) {
    const candidates = Object.keys(table).filter((k) => k.startsWith('E0K') && typeof table[k] === 'function');
    if (candidates.length === 1) return candidates[0];
  }
  return key;
}

const context = {
  console, document, navigator, screen, location, history, performance,
  localStorage, sessionStorage: localStorage, crypto: cryptoObj,
  // Keep standard constructors explicit on the VM global.  Some freshly
  // served Akamai variants run feature-polyfills before creating their
  // window alias and otherwise observe an incomplete global Object.
  Math, Object, Array, String, Number, Boolean, Date, RegExp, JSON, Error,
  TypeError, Function, Symbol, Map, Set, WeakMap, Promise, Intl,
  encodeURIComponent, decodeURIComponent, escape, unescape,
  parseInt, parseFloat, isNaN, isFinite,
  isSecureContext: true, devicePixelRatio: 1,
  innerWidth: 1365, innerHeight: 768, outerWidth: 1365, outerHeight: 768,
  setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  requestAnimationFrame: (f) => setTimeout(() => f(performance.now()), 0), cancelAnimationFrame: clearTimeout,
  atob(s){return Buffer.from(String(s), 'base64').toString('latin1');},
  btoa(s){return Buffer.from(String(s), 'latin1').toString('base64');},
  TextEncoder, TextDecoder, URL, URLSearchParams, Uint8Array, ArrayBuffer, Proxy, Reflect,
  XMLHttpRequest: class {open(){this.readyState=1;} setRequestHeader(){} send(){this.readyState=4; if(this.onreadystatechange)this.onreadystatechange();}},
  fetch(){return Promise.resolve({ok:true,status:200,text:async()=>'',json:async()=>({})});},
  WebSocket: class {}, Worker: class {}, SharedWorker: class {},
  MutationObserver: class {observe(){} disconnect(){}},
  __nodeBrowserKey: nodeBrowserKey,
  __nodeAkamaiTableKey: nodeAkamaiTableKey,
};
const rawWindow = Object.assign({}, context, {
  Math, Object, Array, String, Number, Boolean, Date, RegExp, JSON, Error, TypeError,
  Function, Symbol, Map, Set, WeakMap, Promise, Intl, Uint8Array, ArrayBuffer,
  URL, URLSearchParams, encodeURIComponent, decodeURIComponent, escape, unescape,
  parseInt, parseFloat, isNaN, isFinite, location, history, navigator, document, screen,
  performance, browser: {}, matchMedia: mediaQuery, visualViewport,
  getComputedStyle() { return proxyObject({getPropertyValue(){return '';}}); },
  Navigator: function Navigator(){}, ServiceWorker: function ServiceWorker(){},
  ServiceWorkerContainer: function ServiceWorkerContainer(){},
  ServiceWorkerRegistration: function ServiceWorkerRegistration(){},
});
installEventTarget(rawWindow);
for (const name of ['DeviceMotionEvent','TouchEvent','HTMLIFrameElement','File','Notification',
  'ApplePayError','ApplePaySession','ApplePaySetup','ApplePaySetupFeature','OfflineAudioContext',
  'PublicKeyCredential','AuthenticatorResponse','AuthenticatorAttestationResponse',
  'AuthenticatorAssertionResponse','MediaMetadata','AudioContext','ContentIndex',
  'OffscreenCanvas','MediaSource','FileReader','Blob','FormData']) {
  rawWindow[name] = function(){ };
}
if (process.env.NODE_TRACE_GLOBAL_STATIC === '1') {
  for (const name of ['String','Array','Object','Number','Symbol','parseFloat','btoa','history','document']) {
    const original = rawWindow[name];
    if (original === undefined || original === null) continue;
    rawWindow[name] = new Proxy(original, {
      get(target, prop, receiver) {
        const v = Reflect.get(target, prop, receiver);
        if (v === undefined && typeof prop !== 'symbol') console.error('STATIC_MISS', name, String(prop));
        return v;
      },
      apply(target, thisArg, args) { return Reflect.apply(target, thisArg, args); },
      construct(target, args, newTarget) { return Reflect.construct(target, args, newTarget); }
    });
  }
}
rawWindow.chrome = {};
if (process.env.NODE_SEED_OBFUSCATED_GLOBALS === '1') {
  // The classic-script browser global also exposes function-expression names
  // while the bundle's self-bootstrap is running.  Keep this opt-in until a
  // current served variant proves it needs the compatibility alias.
  rawWindow.dDPSOEMXvf = function dDPSOEMXvf() {};
}
const missingGlobalStubs = new Map();
function missingGlobalStub(name) {
  if (missingGlobalStubs.has(name)) return missingGlobalStubs.get(name);
  const fn = function() { return missingGlobalStub(`${name}()`); };
  const stub = new Proxy(fn, {
    get(target, prop) {
      if (prop === 'name') return name;
      if (prop === 'prototype') return {};
      if (prop in target) return target[prop];
      if (process.env.NODE_DEBUG_WINDOW_MISS === '1') console.error('WINDOW_STUB_GET', name, String(prop));
      return missingGlobalStub(`${name}.${String(prop)}`);
    },
    apply() { return missingGlobalStub(`${name}()`); },
    construct() { return {}; },
    set(target, prop, value) { target[prop] = value; return true; }
  });
  missingGlobalStubs.set(name, stub);
  return stub;
}
const windowObj = new Proxy(rawWindow, {
  get(target, prop, receiver) {
    let value = Reflect.get(target, prop, receiver);
    // In Chrome a classic script's top-level declarations are also visible
    // as window properties.  The VM global (`context`) and our window facade
    // are separate objects, so mirror that lookup explicitly.  This matters
    // for newer bundles that resolve an obfuscated constructor through
    // `window[fn.name]` during bootstrap.
    if (value === undefined && typeof prop !== 'symbol' && prop in context) {
      value = context[prop];
    }
    if (process.env.NODE_TRACE_WINDOW_GET === '1' && typeof prop !== 'symbol') {
      const n = (globalThis.__node_window_get_count = (globalThis.__node_window_get_count || 0) + 1);
      if (n <= Number(process.env.NODE_TRACE_WINDOW_GET_MAX || 300)) {
        console.error('WINDOW_GET', n, String(prop), typeof value);
      }
    }
    if (process.env.NODE_DEBUG_WINDOW_MISS === '1' && value === undefined && typeof prop !== 'symbol') {
      console.error('WINDOW_MISS', String(prop));
    }
    if (value === undefined && typeof prop !== 'symbol') {
      // A few builds encode the global Object name through a runtime table;
      // when the table is incomplete its decoded key is a printable `Ob...`
      // token.  Preserve the native Object API for that shape.
      if (process.env.NODE_REPAIR_MISSING_OBJECT === '1' && String(prop).startsWith('Ob')) {
        return Object;
      }
      // The same table can leave the browser constructor's suffix intact
      // while corrupting its tail.  These are stable constructor families,
      // so restore the native VM equivalent instead of returning a callable
      // dummy.
      if (process.env.NODE_REPAIR_MISSING_OBJECT === '1') {
        const missingName = String(prop);
        if (process.env.NODE_REPAIR_BROWSER_KEYS === '1' && missingName.startsWith('locat')) {
          return location;
        }
        const missMap = process.env.NODE_WINDOW_MISS_MAP || '';
        if (missMap && missingName === 'dDPSOEMXvf') {
          if (missMap === 'location') return location;
          if (missMap === 'window') return windowObj;
          if (missMap === 'document') return document;
          if (missMap === 'navigator') return navigator;
          if (missMap === 'performance') return performance;
          if (missMap === 'global') return context;
          if (missMap === 'object') return {};
          if (missMap === 'function') return function(){};
        }
        if (missingName.startsWith('TextEnc')) return TextEncoder;
        if (missingName.startsWith('TextDec')) return TextDecoder;
        if (missingName.startsWith('Uint8')) return Uint8Array;
        if (missingName.startsWith('ArrayBuf')) return ArrayBuffer;
        if (missingName.startsWith('setT')) return setTimeout;
        if (missingName.startsWith('setI')) return setInterval;
        if (missingName.startsWith('clearT')) return clearTimeout;
        if (missingName.startsWith('clearI')) return clearInterval;
        if (missingName.startsWith('requestA')) return context.requestAnimationFrame;
        if (missingName.startsWith('cancelA')) return context.cancelAnimationFrame;
        if (missingName.startsWith('queueM')) return queueMicrotask;
      }
      if (process.env.NODE_STUB_MISSING_GLOBALS === '1') {
        return missingGlobalStub(String(prop));
      }
    }
    return value;
  },
  set(target, prop, value, receiver) { return Reflect.set(target, prop, value, receiver); }
});
rawWindow.window = windowObj; rawWindow.self = windowObj; rawWindow.global = windowObj; rawWindow.globalThis = windowObj;
rawWindow.frames = windowObj; rawWindow.parent = windowObj; rawWindow.top = windowObj; rawWindow.opener = null;
rawWindow.origin = parsed.origin; document.defaultView = windowObj; rawWindow.document = document;
context.window = windowObj; context.self = windowObj; context.global = context; context.globalThis = context;
if (process.env.NODE_REPAIR_BROWSER_CHAIN === '1') {
  // Optional compatibility mode for a variant that dereferences a browser
  // chain through an object created inside its bytecode VM.
  Object.prototype.window = windowObj;
  Object.prototype.location = location;
  Object.prototype.protocol = parsed.protocol;
}

const vmGlobal = process.env.NODE_GLOBAL_IS_WINDOW === '1' ? windowObj : context;
const vmContext = vm.createContext(vmGlobal);
let asyncError = null;
process.on('uncaughtException', (e) => { asyncError = String(e); });
process.on('unhandledRejection', (e) => { asyncError = String(e); });

if (process.env.NODE_DEBUG_INSPECTOR === '1') {
  const inspector = require('inspector');
  const session = new inspector.Session();
  session.connect();
  session.post('Debugger.enable');
  session.post('Debugger.setPauseOnExceptions', {state: 'all'});
  session.on('Debugger.paused', (msg) => {
    const p = msg.params || {};
    const frame = (p.callFrames || [])[0];
    const loc = frame && frame.location ? frame.location : {};
    console.error('INSPECT_PAUSED', p.reason, frame && frame.functionName, loc.lineNumber, loc.columnNumber);
    if (frame) {
      if (frame.location && frame.location.scriptId) {
        session.post('Debugger.getScriptSource', {scriptId: frame.location.scriptId}, (err, res) => {
          const src = res && res.scriptSource;
          if (src) console.error('INSPECT_SOURCE', src.slice(Math.max(0, loc.columnNumber - 900), loc.columnNumber + 1300));
        });
      }
      for (const scope of (frame.scopeChain || [])) {
        if (!scope.object || !scope.object.objectId) continue;
        session.post('Runtime.getProperties', {objectId: scope.object.objectId, ownProperties: true}, (err, res) => {
          if (err || !res || !res.result) return;
          const names = res.result.map((x) => {
            const v = x.value;
            let preview = v && v.type;
            if (v && v.value !== undefined) preview += ':' + String(v.value).slice(0, 80);
            return x.name + '=' + preview;
          });
          console.error('INSPECT_SCOPE', scope.type, scope.name || '', names.slice(0, 260).join('|'));
          const undef = res.result.filter((x) => x.value && x.value.type === 'undefined').map((x) => x.name);
          if (undef.length) console.error('INSPECT_UNDEFINED', scope.type, undef.join(','));
        });
      }
      let exprs = [
        'typeof K3', 'typeof K3 && K3 && typeof K3.window',
        'K3 && K3.window && typeof K3.window.location',
        'K3 && K3.window && K3.window.location && K3.window.location.protocol',
        'typeof window', 'typeof location', 'typeof protocol',
        'typeof Lx', 'typeof dDPSOEMXvf', 'typeof arguments',
        'String(PT()[hT(Fq)](F5,nV))',
        'typeof K3[PT()[hT(Fq)](F5,nV)]',
        'String(bv()[sz(Aw)].call(null,xO,Sj,Mj,Aw,Ym))',
        'typeof K3[PT()[hT(Fq)](F5,nV)][bv()[sz(Aw)].call(null,xO,Sj,Mj,Aw,Ym)]',
        'String(PT()[hT(ng)](hS2,n6))',
        'typeof K3[PT()[hT(Fq)](F5,nV)][bv()[sz(Aw)].call(null,xO,Sj,Mj,Aw,Ym)][PT()[hT(ng)](hS2,n6)]',
        'K3[PT()[hT(Fq)](F5,nV)][bv()[sz(Aw)].call(null,xO,Sj,Mj,Aw,Ym)][PT()[hT(ng)](hS2,n6)]',
        'String(wO()[hC(mz)].call(null,TC,rj,vt,Pc))',
      ];
      if (frame.functionName === 'qDJ') {
        exprs = exprs.concat([
          'String(PT()[hT(Fq)].call(null,F5,UA2))',
          'typeof K3[PT()[hT(Fq)].call(null,F5,UA2)]',
          'String(lv(typeof YG()[lc(Pc)],kO(mO()[Jg(Oq)].call(null,S5,Wc,Nm),[][[]]))?YG()[lc(hj)](sg,FC,Lz,EK):YG()[lc(rg)](Aw,Hj,KL,QH2))',
          'JSON.stringify(String(lv(typeof YG()[lc(Pc)],kO(mO()[Jg(Oq)].call(null,S5,Wc,Nm),[][[]]))?YG()[lc(hj)](sg,FC,Lz,EK):YG()[lc(rg)](Aw,Hj,KL,QH2)))',
          'String(lv(typeof YG()[lc(Pc)],kO(mO()[Jg(Oq)].call(null,S5,Wc,Nm),[][[]]))?YG()[lc(hj)](sg,FC,Lz,EK):YG()[lc(rg)](Aw,Hj,KL,QH2)).length',
          'Array.from(String(lv(typeof YG()[lc(Pc)],kO(mO()[Jg(Oq)].call(null,S5,Wc,Nm),[][[]]))?YG()[lc(hj)](sg,FC,Lz,EK):YG()[lc(rg)](Aw,Hj,KL,QH2))).map(function(x){return x.charCodeAt(0)}).join(",")',
          'Object.keys(K3[PT()[hT(Fq)].call(null,F5,UA2)]).slice(0,40).join(",")',
          'typeof K3[PT()[hT(Fq)].call(null,F5,UA2)][lv(typeof YG()[lc(Pc)],kO(mO()[Jg(Oq)].call(null,S5,Wc,Nm),[][[]]))?YG()[lc(hj)](sg,FC,Lz,EK):YG()[lc(rg)](Aw,Hj,KL,QH2)]',
          'String(lv(typeof bv()[sz(Ic)],\'undefined\')?bv()[sz(gT)].apply(null,[d32,Up,Gq(Ic),zO,gQ2]):bv()[sz(KT)](zO,xl,Tl,KT,OG))',
          'typeof K3[PT()[hT(Fq)].call(null,F5,UA2)][lv(typeof YG()[lc(Pc)],kO(mO()[Jg(Oq)].call(null,S5,Wc,Nm),[][[]]))?YG()[lc(hj)](sg,FC,Lz,EK):YG()[lc(rg)](Aw,Hj,KL,QH2)][lv(typeof bv()[sz(Ic)],\'undefined\')?bv()[sz(gT)].apply(null,[d32,Up,Gq(Ic),zO,gQ2]):bv()[sz(KT)](zO,xl,Tl,KT,OG)]',
          'String(PT()[hT(Gn)](Tg,D32))',
          'String(UT()[wL(KL)].call(null,gT,YL,QT,Oq,d32,K5))',
          'typeof K3[PT()[hT(Gn)](Tg,D32)]',
          'typeof K3[PT()[hT(Gn)](Tg,D32)][UT()[wL(KL)].call(null,gT,YL,QT,Oq,d32,K5)]',
        ]);
      }
      if (frame.functionName === 'Ijh') {
        exprs = exprs.concat([
          'String(GQ()[b6(EG)](l3,Pn,RR))',
          'JSON.stringify(String(GQ()[b6(EG)](l3,Pn,RR)))',
          'String(GQ()[b6(EG)](l3,Pn,RR)).length',
          'Array.from(String(GQ()[b6(EG)](l3,Pn,RR))).map(function(x){return x.charCodeAt(0)}).join(",")',
          'typeof t5w',
          'Object.keys(t5w).join(",")',
          'Object.keys(t5w).map(function(k){return JSON.stringify(k)+":"+typeof t5w[k]+":"+String(t5w[k]).slice(0,160)}).join("|")',
          'typeof t5w[GQ()[b6(EG)](l3,Pn,RR)]',
          'String(Vm()[kL(Ed)](HA,XY,lT,xm,Bq))',
          'JSON.stringify(String(Vm()[kL(Ed)](HA,XY,lT,xm,Bq)))',
          'typeof IZ',
          'Object.keys(IZ).join(",")',
          'Object.keys(IZ).map(function(k){return JSON.stringify(k)+":"+typeof IZ[k]+":"+String(IZ[k]).slice(0,180)}).join("|")',
          'typeof IZ[Vm()[kL(Ed)](HA,XY,lT,xm,Bq)]',
        ]);
      }
      if (frame.functionName !== 'g12') {
        exprs = exprs.concat([
          'typeof Bc', 'String(Bc)', 'typeof VO', 'VO && Object.keys(VO).join(",")',
          'typeof Ps', 'typeof fp', 'typeof nxJ', 'typeof pG',
          'typeof arguments[0]', 'String(arguments[0])',
          'typeof document', 'document && typeof document.location',
          'document && document.location && document.location.pathname',
          'typeof location', 'location && location.pathname',
        ]);
        if (frame.functionName === 'nxJ') {
          exprs = exprs.concat([
            'String(jfJ)', 'String(B8)', 'String(PJ)', 'String(X2)', 'String(O3)',
            'RIJ && RIJ.length', 'RIJ && String(RIJ[0])', 'RIJ && String(RIJ[1])',
            'String(PT()[hT(gT)](Kq,tM))',
            'String(SZ()[jg(bw)](EC,FD2,Cv,xL))',
            'typeof K3[PT()[hT(gT)](Kq,tM)]',
            'String(PT()[hT(Fq)](F5,TL))',
            'String(bv()[sz(Aw)](xO,gT,qL,Aw,BF))',
            'String(mO()[Jg(YL)].apply(null,[J5,lq,HM]))',
            'typeof K3[bv()[sz(Aw)](xO,gT,qL,Aw,BF)]',
          ]);
        }
        if (frame.functionName === 'BG') {
          exprs = exprs.concat([
            'String(Rv)', 'WT && WT.length', 'WT && String(WT[0])',
            'typeof Xq', 'Xq && Object.keys(Xq).join(",")',
            'String(bv()[sz(KT)](zO,F5,Gq(fs),KT,nj))',
            'typeof Xq[bv()[sz(KT)](zO,F5,Gq(fs),KT,nj)]',
            'String(bv()[sz(KT)].call(null,zO,Qz,Gg,KT,nj))',
            'String(bv()[sz(KT)](zO,Ag,fE,KT,nj))',
            'String(bv()[sz(KT)](zO,rg,YE,KT,nj))',
            'String(bv()[sz(KT)](zO,jj,qg,KT,nj))',
            'String(bv()[sz(KT)].apply(null,[zO,V5,mv,KT,nj]))',
            'String(sz(KT))',
            'typeof bv()[sz(KT)]',
            'String(bv()[sz(KT)])',
            'typeof __nodeBrowserKey',
            '__nodeBrowserKey("re϶\\x00")',
            'String(PT()[hT(xL)].call(null,Ez,bC))',
            'String(PT()[hT(Pc)](mG,tw))',
          ]);
        }
      }
      for (const expression of exprs) {
        session.post('Debugger.evaluateOnCallFrame', {callFrameId: frame.callFrameId, expression}, (err, res) => {
          const value = res && res.result;
          console.error('INSPECT_EVAL', expression, err ? String(err) : value && (value.type + ':' + (value.value === undefined ? value.description : String(value.value))));
        });
      }
    }
    session.post('Debugger.resume');
  });
}

async function main() {
  let source = fs.readFileSync(bundlePath, 'utf8');
  if (process.env.NODE_DEBUG_DEFINE_PROPERTY === '1') {
    const nativeDefineProperty = Object.defineProperty;
    Object.defineProperty = function(target, property, descriptor) {
      try {
        console.error('DEFINE_PROPERTY', typeof target, String(property), descriptor && Object.keys(descriptor).join(','));
      } catch (_) {}
      return nativeDefineProperty.call(Object, target, property, descriptor);
    };
    context.Object = Object;
    rawWindow.Object = Object;
  }
  if (process.env.NODE_DEBUG_REGEX === '1') {
    const NativeRegExp = RegExp;
    function DebugRegExp(pattern, flags) {
      console.error('REGEX_PATTERN', JSON.stringify(String(pattern)), JSON.stringify(flags));
      return new NativeRegExp(pattern, flags);
    }
    DebugRegExp.prototype = NativeRegExp.prototype;
    rawWindow.RegExp = DebugRegExp;
    context.RegExp = DebugRegExp;
  }
  if (process.env.NODE_REPAIR_REGEX !== '0') {
    const NativeRegExp = rawWindow.RegExp;
    function RepairRegExp(pattern, flags) {
      try { return new NativeRegExp(pattern, flags); }
      catch (e) {
        const text = String(pattern);
        if (text.startsWith('[\\') && !text.includes(']')) return new NativeRegExp('[\\x0C]', flags);
        throw e;
      }
    }
    RepairRegExp.prototype = NativeRegExp.prototype;
    rawWindow.RegExp = RepairRegExp;
    context.RegExp = RepairRegExp;
  }
  if (process.env.NODE_DEBUG_IB === '1') {
    source = source.replace(
      'function ZR(){Ib={};',
      'function ZR(){Ib=new Proxy({}, {get(t,p){console.error("IB_GET",String(p),typeof t[p]); return t[p];},set(t,p,v){console.error("IB_SET",String(p),typeof v); t[p]=v; return true;}});'
    );
  }
  if (process.env.NODE_DEBUG_GBV === '1') {
    source = source.replace(
      'function Gbv(V7F,E4v){',
      'function Gbv(V7F,E4v){if(typeof globalThis.__gbv_count!=="number")globalThis.__gbv_count=0;if(globalThis.__gbv_count++<80){try{console.error("GBV_CALL",globalThis.__gbv_count,String(V7F),Array.isArray(E4v)?E4v.length:typeof E4v,Array.isArray(E4v)?E4v.slice(0,8).map(function(x){if(x===null)return "null";if(x===undefined)return "undefined";try{return typeof x+":"+String(x).slice(0,80)}catch(_){return typeof x;}}):"");}catch(_){}}'
    );
  }
  if (process.env.NODE_DEBUG_QDJ === '1') {
    source = source.replace(
      'catch(hdJ){vl.splice(Xv(XQJ,fs),Infinity,fA2);}',
      'catch(hdJ){console.error("QDJ_ERR",String(hdJ));vl.splice(Xv(XQJ,fs),Infinity,fA2);}'
    );
    source = source.replace(
      'catch(w3J){vl.splice(Xv(P7J,fs),Infinity,fA2);',
      'catch(w3J){console.error("QDJ_INNER_ERR",String(w3J));vl.splice(Xv(P7J,fs),Infinity,fA2);'
    );
  }
  if (process.env.NODE_DEBUG_HP === '1') {
    source = source.replace(
      "var Hp=function g12(XF2,kh2){'use strict';",
      "var Hp=function g12(XF2,kh2){try{console.error('HP_ENTRY',String(XF2),Array.isArray(kh2),kh2&&kh2.length,kh2&&kh2[0]&&typeof kh2[0]);}catch(_){};'use strict';"
    );
  }
  if (process.env.NODE_DEBUG_MF2 === '1') {
    source = source.replace(
      'var mf2=K3["window"]["location"]&&K3["window"]["location"]["protocol"]===\'http:\';',
      'var mf2=(console.error("MF2",typeof K3,!!K3,typeof K3["window"],K3["window"]&&typeof K3["window"]["location"],K3["window"]&&K3["window"]["location"]&&K3["window"]["location"]["protocol"]),K3["window"]["location"]&&K3["window"]["location"]["protocol"]===\'http:\');'
    );
  }
  if (process.env.NODE_DEBUG_HP_CATCH === '1') {
    const hpStart = source.indexOf('var Hp=function g12');
    const hpBodyStart = hpStart >= 0 ? source.indexOf('var Nh2=g12;switch(XF2){', hpStart) : -1;
    if (hpBodyStart >= 0) {
      const hpEnd = source.indexOf('break;}};var', hpBodyStart);
      if (hpEnd >= 0) {
        const hpHead = 'var Nh2=g12;switch(XF2){';
        const hpTail = 'break;}}';
        const hpCatch = 'var Nh2=g12;try{switch(XF2){';
        const hpCatchTail = 'break;}}catch(__hp_err){try{console.error("HP_ERR",String(__hp_err),"xf",String(XF2),"arg0",kh2&&kh2[0]&&Object.keys(kh2[0]).join(","));}catch(__hp_log_err){}throw __hp_err;}}';
        source = source.slice(0, hpBodyStart) + hpCatch +
          source.slice(hpBodyStart + hpHead.length, hpEnd) + hpCatchTail +
          source.slice(hpEnd + hpTail.length);
      }
    }
  }
  if (process.env.NODE_WRAP_GBV === '1') {
    const gbvStart = source.indexOf('function Gbv(V7F,E4v){');
    const gbvEndMarker = '};var Ebv';
    const gbvEnd = gbvStart >= 0 ? source.indexOf(gbvEndMarker, gbvStart) : -1;
    if (gbvStart >= 0 && gbvEnd >= 0) {
      const head = 'function Gbv(V7F,E4v){';
      const bodyStart = gbvStart + head.length;
      const body = source.slice(bodyStart, gbvEnd);
      source = source.slice(0, gbvStart) + head + 'try{' + body +
        '}catch(e){try{console.error("GBV_ERR",String(e),JSON.stringify({V7F:V7F,E4v:Array.isArray(E4v)?E4v.slice(0,8):typeof E4v,r8v:r8v,Ubv:Ubv,d5v:d5v,AdF:AdF,TR:TR,K8:K8,Ag:Ag,hQ:hQ,Dn:Dn,VU_ctor:typeof VU["constructor"],VU_array:typeof VU["Array"],index0:d5v&&d5v[Dn],index1:d5v&&d5v[Ag],indexh:d5v&&d5v[hQ],adfUbv0:AdF&&AdF[Ubv&&Ubv[Dn]],adfUbv0_0:AdF&&AdF[Ubv&&Ubv[Dn]]&&AdF[Ubv[Dn]][Dn],rdValue:RdF&&RdF[AdF&&AdF[Ubv&&Ubv[Dn]]&&AdF[Ubv[Dn]][Dn]]}));}catch(_){} throw e;}' +
        '}' + source.slice(gbvEnd + 1);
    }
  }
  if (process.env.NODE_STUB_IB !== '0') {
    const stubValue = JSON.stringify(process.env.NODE_STUB_IB_VALUE || '');
    source = source.replace(
      'function ZR(){Ib={};',
      `function ZR(){Ib=new Proxy({}, {get(t,p){if(!(p in t)){t[p]=p==="sjs_se_global_subkey"?[]:function(){return ${stubValue};};} return t[p];},set(t,p,v){t[p]=v; return true;}});`
    );
  }
  // New Akamai builds occasionally route a string through the bytecode
  // interpreter's object branch.  In a real browser this arrives as a boxed
  // DOM/string object; Node's primitive string takes the wrong branch and
  // reaches a non-callable property.  Box only this exact interpreter local
  // when the served bundle contains it.  Older bundles do not contain the
  // pattern, so this is a no-op for them.
  if (process.env.NODE_REPAIR_STRING_CASEA !== '0') {
    source = source.replace(
      'var V46=M76[P3];',
      'var V46=M76[P3];if(typeof V46==="string")V46=Object(V46);'
    );
  }
  // In one current bundle family the interpreter adds its `K` opcode
  // handler through a browser-only initialization branch.  The live browser
  // object is observably `function(rn,A,dr){return Hc.apply(this,[c4,arguments]);}`;
  // install the same closure-local handler when that branch is skipped in
  // the minimal VM.
  if (process.env.NODE_REPAIR_ZG_K !== '0') {
    source = source.replace(
      'return gQ.call(this,QI);',
      'if(typeof this.K!=="function")this.K=function(rn,A,dr){return Hc.apply(this,[c4,arguments]);};return gQ.call(this,QI);'
    );
    source = source.replace(
      /var ([A-Za-z_$][A-Za-z0-9_$]*)=new zg\(\);/g,
      'var $1=new zg();if(typeof $1.K!=="function"){for(var __wk in $1){if(typeof $1[__wk]==="function"&&String($1[__wk]).indexOf("Hc.apply(this,[c4,arguments])")>=0){$1.K=$1[__wk];break;}}}'
    );
  }
  // Some served variants obtain the Array-iterator method through the same
  // obfuscated lookup table.  In Chromium that lookup resolves to `next`,
  // while the minimal VM can retain the encoded token.  The object is still
  // the native Array Iterator; aliasing only missing properties to its native
  // `next` method preserves the browser operation without stubbing unrelated
  // globals.
  if (process.env.NODE_REPAIR_ITERATOR_KEYS === '1') {
    source = source.replace(
      /([A-Za-z_$][A-Za-z0-9_$]*)=\[\]\[['"](?:keys|\\x6b\\x65\\x79\\x73)['"]\]\(\);/g,
      '$1=[]["keys"]();if($1&&typeof $1.next==="function")$1=new Proxy($1,{get:function(t,p){if(typeof p==="string"&&p.indexOf("sjs_")===0)return t[p];return typeof t[p]==="undefined"?t.next.bind(t):t[p];}});'
    );
  }
  // The bytecode VM constructor in another served family exposes its entry
  // dispatcher as the short property `w` in Chromium.  The minimal VM can
  // leave that property under a control-character token even though the
  // function body is identical.  Recover only that known dispatcher by its
  // stable closure signature; this does not manufacture arbitrary methods.
  if (process.env.NODE_REPAIR_DB_METHODS !== '0') {
    source = source.replace(
      /var ([A-Za-z_$][A-Za-z0-9_$]*)=new DB\(\);/g,
      'var $1=new DB();if(typeof $1.w!=="function"){for(var __dbk in $1){if(typeof $1[__dbk]==="function"&&String($1[__dbk]).indexOf("V1.apply(this,[nX,arguments])")>=0){$1.w=$1[__dbk];break;}}}'
    );
  }
  // A further VM family stores lazy helpers on an obfuscated table `Lx`.
  // One lookup can be decoded as a non-printable token in Node even though
  // the corresponding lazy helper is already present in the table.  Prefer
  // the table's exact repeated-character key for that family; leave all
  // unrelated properties untouched.
  if (process.env.NODE_REPAIR_LX_METHODS !== '0') {
    source = source.replace(
      'function SQ(){Lx={};',
      'function SQ(){Lx=new Proxy({}, {get:function(t,p){var v=t[p];if(v!==undefined)return v;if(typeof p==="string"&&p.indexOf("sjs_")===0)return v;if(typeof p==="string"&&p.length>2&&p.slice(0,2)==="HJ"){var ks=Object.getOwnPropertyNames(t);for(var i=0;i<ks.length;i++){var tail=ks[i].slice(2);if(tail.length>2&&/^([A-Za-z])\\1+$/.test(tail))return t[ks[i]];}}return v;},set:function(t,p,v){t[p]=v;return true;}});'
    );
  }
  // Same VM layout as above, with a different obfuscated constructor name.
  // The browser exposes its entry dispatcher as `D`; the Node variant can
  // retain it under DEL (or another control token).  Match the dispatcher
  // closure rather than guessing over every property.
  if (process.env.NODE_REPAIR_PD_METHODS !== '0') {
    source = source.replace(
      /var ([A-Za-z_$][A-Za-z0-9_$]*)=new Pd\(\);/g,
      'var $1=new Pd();if(typeof $1.D!=="function"){for(var __pdk in $1){if(typeof $1[__pdk]==="function"&&String($1[__pdk]).indexOf("Z7.apply(this,[jl,arguments])")>=0){$1.D=$1[__pdk];break;}}}'
    );
  }
  if (process.env.NODE_REPAIR_BROWSER_KEYS === '1') {
    // The same UTF-16 decode drift can affect String.prototype methods.  The
    // current bundle emits a key beginning with `re` where Chromium resolves
    // `replace`; route only this known bytecode access through the normalizer.
    source = source.replace(
      'Xq[bv()[sz(KT)](zO,F5,Gq(fs),KT,nj)]',
      'Xq[__nodeBrowserKey(bv()[sz(KT)](zO,F5,Gq(fs),KT,nj))]'
    );
    for (const expr of [
      'bv()[sz(KT)].call(null,zO,Qz,Gg,KT,nj)',
      'bv()[sz(KT)](zO,Ag,fE,KT,nj)',
      'bv()[sz(KT)](zO,rg,YE,KT,nj)',
      'bv()[sz(KT)](zO,jj,qg,KT,nj)',
      'bv()[sz(KT)].apply(null,[zO,V5,mv,KT,nj])',
    ]) {
      source = source.replaceAll('[' + expr + ']', '[__nodeBrowserKey(' + expr + ')]');
    }
    source = source.replace(
      '[UT()[wL(KL)].call(null,gT,YL,QT,Oq,d32,K5)]',
      '[__nodeBrowserKey(UT()[wL(KL)].call(null,gT,YL,QT,Oq,d32,K5))]'
    );
    source = source.replaceAll(
      'IZ[Vm()[kL(Ed)](HA,XY,lT,xm,Bq)]',
      'IZ[__nodeAkamaiTableKey(Vm()[kL(Ed)](HA,XY,lT,xm,Bq),IZ)]'
    );
    // A newer served VM decodes the lB dispatcher key as `G`, while the
    // instance stores the same function under a control-character key.
    // Recover only the method whose closure signature identifies that
    // dispatcher; do not alias arbitrary missing properties.
    source = source.replace(
      /var ([A-Za-z_$][A-Za-z0-9_$]*)=new lB\(\);/g,
      'var $1=new lB();if(typeof $1.G!=="function"){for(var __lbk in $1){if(typeof $1[__lbk]==="function"&&String($1[__lbk]).indexOf("JI.apply(this,[c7,arguments])")>=0){$1.G=$1[__lbk];break;}}}'
    );
    source = source.replace(
      'var MbJ=mp.apply(null,[hd,[WrJ,pv,pv,GXJ,GVJ]]);',
      'var MbJ=mp.apply(null,[hd,[WrJ,pv,pv,GXJ,GVJ]]);if(typeof MbJ==="function"){var __nodeMbJ=MbJ;MbJ=function(){return __nodeBrowserKey(__nodeMbJ.apply(this,arguments));};}'
    );
    source = source.replace(
      "function bv(){var bmJ=Object['\\x63\\x72\\x65\\x61\\x74\\x65'](Object['\\x70\\x72\\x6f\\x74\\x6f\\x74\\x79\\x70\\x65']);",
      "function bv(){var bmJ=Object['\\x63\\x72\\x65\\x61\\x74\\x65'](Object['\\x70\\x72\\x6f\\x74\\x6f\\x74\\x79\\x70\\x65']);bmJ=new Proxy(bmJ,{get:function(t,p){var v=t[p];if(typeof v===\"function\"){return function(){return __nodeBrowserKey(v.apply(this,arguments));};}return v;},set:function(t,p,v){t[p]=v;return true;}});"
    );
  }
  if (process.env.NODE_DEBUG_PK === '1') {
    const pkMarker = 'var tHg=new pK();var NN,Y,CN,WQ;';
    source = source.replace(pkMarker, 'var tHg=new pK();console.error(\"PK_INSTANCE_KEYS\",Object.keys(tHg).join(\",\"));for(var __pkx of Object.keys(tHg)){try{console.error(\"PK_METHOD\",__pkx,typeof tHg[__pkx],typeof tHg[__pkx]===\"function\"?String(tHg[__pkx]).slice(0,260):String(tHg[__pkx]).slice(0,120));}catch(__pke){console.error(\"PK_METHOD_ERR\",__pkx,String(__pke));}}console.error(\"PK_Q_TYPE\",typeof tHg.Q);var NN,Y,CN,WQ;');
    const pkCall = 'tHg[Rt()[Mk(Lp)].apply(null,[Zp,lK])](p6g,VC()[Yt(W9)].apply(null,[Jx,b8,ED(ED([])),p0]),z0);';
    source = source.replace(pkCall, 'var __pk_rt=Rt();var __pk_name=Mk(Lp);var __pk_rt_fn=__pk_rt[__pk_name];var __pk_zp=Zp;var __pk_lk=lK;var __pk_call_key=__pk_rt_fn.apply(null,[__pk_zp,__pk_lk]);console.error(\"PK_CALL_KEY\",String(__pk_call_key),typeof tHg[__pk_call_key],Object.keys(tHg).join(\",\"),\"Lp=\"+String(Lp),\"MkLp=\"+String(__pk_name),\"Zp=\"+String(__pk_zp),\"lK=\"+String(__pk_lk),\"RtFn=\"+String(__pk_rt_fn).slice(0,500),\"RtProto=\"+Object.getOwnPropertyNames(Object.getPrototypeOf(__pk_rt)).join(\",\"),\"ProtoKeys=\"+Object.getOwnPropertyNames(Object.getPrototypeOf(tHg)).join(\",\"));' + pkCall.replace('Rt()[Mk(Lp)].apply(null,[Zp,lK])','__pk_call_key'));
  }
  if (process.env.NODE_DEBUG_WX === '1') {
    source = source.replace(
      'Wx=function(ER,vq){return cx.apply(this,[VA,arguments]);};',
      'Wx=function(ER,vq){var __wxv=cx.apply(this,[VA,arguments]);if(typeof globalThis.__wx_count!=="number")globalThis.__wx_count=0;if(globalThis.__wx_count++<120){try{console.error("WX_CALL",globalThis.__wx_count,String(ER),vq&&vq.length,Array.isArray(vq)?vq.slice(0,4).map(function(x){return typeof x+":"+String(x).slice(0,80)}).join("|"):typeof vq,"=>",typeof __wxv,String(__wxv).slice(0,180));}catch(__wxe){}}return __wxv;};'
    );
  }
  if (process.env.NODE_DUMP_TRANSFORMED === '1') {
    const dump = path.join(path.dirname(outputPath), path.basename(outputPath, path.extname(outputPath)) + '.transformed.js');
    fs.mkdirSync(path.dirname(dump), {recursive:true});
    fs.writeFileSync(dump, source, 'utf8');
    console.error('TRANSFORMED_SOURCE', dump);
  }
  vm.runInContext(source, vmContext, {filename: bundlePath, timeout: 30000});
  if (waitMs > 0) await new Promise(resolve => setTimeout(resolve, waitMs));
  const body = document.body;
  const now = () => Date.now();
  const emit = (target, type, extra = {}) => target.dispatchEvent(Object.assign({
    type, target: body, currentTarget: target, isTrusted: true, timeStamp: now(),
    clientX: 320, clientY: 240, pageX: 320, pageY: 240, screenX: 420, screenY: 340,
    movementX: 3, movementY: 2, buttons: 0, button: 0, detail: 0,
  }, extra));
  // bmak records interaction cadence through DOM listeners.  These are
  // deterministic, low-volume synthetic events; no browser is involved.
  for (const [type, extra] of [
    ['focus', {}], ['mousemove', {clientX:180, clientY:220, pageX:180, pageY:220}],
    ['mousemove', {clientX:420, clientY:360, pageX:420, pageY:360, movementX:7, movementY:6}],
    ['mousedown', {buttons:1}], ['mouseup', {buttons:0}],
    ['wheel', {deltaX:0, deltaY:280, wheelDelta:-280}],
    ['keydown', {key:'Tab', code:'Tab', keyCode:9, which:9}],
    ['keyup', {key:'Tab', code:'Tab', keyCode:9, which:9}],
    ['mousemove', {clientX:640, clientY:420, pageX:640, pageY:420, movementX:5, movementY:4}],
    ['click', {clientX:640, clientY:420, pageX:640, pageY:420}],
    ['visibilitychange', {}],
  ]) {
    emit(windowObj, type, extra); emit(document, type, extra); emit(body, type, extra);
  }
  const bmak = windowObj.bmak || context.bmak;
  if (!bmak) throw new Error('bmak was not installed');
  if (process.env.NODE_DEBUG_BMAK === '1') {
    console.error('BMAK_KEYS', Object.keys(bmak).join(','));
    try { console.error('BMAK_LIST_KEYS', Object.keys(bmak.listFunctions || {}).join(',')); } catch (_) {}
    try { console.error('BMAK_STATE', JSON.stringify({firstLoad:bmak.firstLoad,startTs:bmak.startTs,now:Date.now()})); } catch (_) {}
    for (const k of Object.keys(bmak)) {
      if (/sensor|telemetry|submit|cookie|page|data/i.test(k)) {
        try { console.error('BMAK_FIELD', k, typeof bmak[k], typeof bmak[k] === 'string' ? bmak[k].length : String(bmak[k]).slice(0, 140)); } catch (_) {}
      }
    }
  }
  if (process.env.NODE_SKIP_FORM_SUBMIT !== '1' && typeof bmak.form_submit === 'function') {
    try { bmak.form_submit(); } catch (_) {}
  }
  let method = 'get_telemetry';
  if (typeof bmak[method] !== 'function') {
    method = Object.keys(bmak).find(k => /^get_te/.test(k) && typeof bmak[k] === 'function');
  }
  if (!method) throw new Error('telemetry method was not installed; keys=' + Object.keys(bmak).join(','));
  const telemetry = String(bmak[method]());
  if (process.env.NODE_DEBUG_TELEMETRY === '1') console.error('TELEMETRY_INFO', telemetry.length, telemetry.slice(0, 1200), 'TAIL', telemetry.slice(-1200));
  if (!telemetry || !telemetry.includes('sensor_data=')) throw new Error('telemetry missing sensor_data');
  const encoded = new URLSearchParams(telemetry.replaceAll('&&&', '&')).get('sensor_data');
  if (!encoded) throw new Error('sensor_data parameter is empty');
  const raw = Buffer.from(encoded.replaceAll(' ', '+'), 'base64').toString('utf8');
  fs.mkdirSync(path.dirname(outputPath), {recursive:true});
  fs.writeFileSync(outputPath, telemetry, 'utf8');
  const fields = raw.split(';', 8);
  const type = fields.length >= 7 ? fields[6] : '';
  process.stdout.write(JSON.stringify({ok:true, method, telemetry_len:telemetry.length, sensor_len:raw.length, sensor_type:type, output:outputPath, async_error:asyncError}, null, 2) + '\n');
  process.exit(0);
}

main().catch((e) => {
  // Do not dump a 500KB minified bundle into the login log.  The first line
  // and the final stack frames are sufficient to identify a fresh variant;
  // the original bundle remains in the reverse-artifact directory.
  const stack = e && e.stack ? String(e.stack).split('\n') : [];
  process.stdout.write(JSON.stringify({
    ok:false,
    error:String(e),
    stack: stack.length > 8 ? stack.slice(0, 1).concat(stack.slice(-7)) : stack,
    async_error:asyncError
  }, null, 2) + '\n');
  process.exit(2);
});
