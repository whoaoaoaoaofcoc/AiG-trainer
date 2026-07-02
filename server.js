const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');
const fs      = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.set('trust proxy', 1); // Railway за прокси — для req.ip и secure-cookie

// ─── Токен из cookie / заголовка / тела ─────────────────────────────────────
function parseCookies(req) {
  const h = req.headers.cookie;
  const out = {};
  if (!h) return out;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function getReqToken(req) {
  if (req.body && req.body.token) return req.body.token;
  const c = parseCookies(req);
  if (c.at) return c.at;
  const a = req.headers.authorization;
  if (a && a.startsWith('Bearer ')) return a.slice(7);
  return null;
}
const COOKIE_SECURE = !!process.env.RAILWAY_ENVIRONMENT || process.env.NODE_ENV === 'production';
function setAuthCookie(res, token) {
  res.cookie('at', token, {
    httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax',
    maxAge: 365 * 24 * 60 * 60 * 1000, path: '/'
  });
}

// ─── Rate-limit логина (простой in-memory по IP) ────────────────────────────
const _loginHits = new Map();
function loginRateLimited(req) {
  const ip = (req.ip || req.headers['x-forwarded-for'] || 'unknown').toString();
  const now = Date.now();
  let rec = _loginHits.get(ip);
  if (!rec || now - rec.first > 15 * 60 * 1000) rec = { count: 0, first: now };
  rec.count++;
  _loginHits.set(ip, rec);
  return rec.count > 20; // >20 попыток за 15 минут
}

// ─── Гейт контента: без валидного токена отдаём только вход/админку/api ──────
const OPEN_PATHS = new Set(['/', '/index.html', '/ulyana-panel-8472.html', '/favicon.ico']);
function contentGate(req, res, next) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  let p;
  try { p = decodeURIComponent(req.path); } catch { p = req.path; }
  if (p.startsWith('/api/') || OPEN_PATHS.has(p)) return next();
  if (validToken(getReqToken(req))) return next();
  if (p.endsWith('.html')) return res.redirect(302, '/');
  return res.status(403).type('text/plain; charset=utf-8').send('Требуется вход. Откройте главную страницу.');
}
app.use(contentGate);

app.use(express.static(path.join(__dirname, 'public')));

// ─── Config ───────────────────────────────────────────────────────────────────
const GROQ_API_KEY       = process.env.GROQ_API_KEY       || '';
const GEMINI_API_KEY     = process.env.GEMINI_API_KEY     || '';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const ADMIN_PASSWORD     = process.env.ADMIN_PASSWORD     || 'admin123';
const MAX_DEVICES        = 2;
const DATA_FILE          = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const TOKEN_SECRET       = process.env.TOKEN_SECRET || 'medtrainer-secret-2024';

// Legacy single static user (backward compat)
const STATIC_USER = (process.env.STATIC_USER || '').toLowerCase();
const STATIC_PASS = process.env.STATIC_PASS || '';
const STATIC_NAME = process.env.STATIC_NAME || STATIC_USER;

function makeStaticToken(username) {
  return 'ST:' + crypto.createHmac('sha256', TOKEN_SECRET).update(username).digest('hex');
}

// Stateless токен — переживает рестарты, не хранится в DB
function makeUserToken(username) {
  const jti = crypto.randomBytes(8).toString('hex'); // уникальный ID сессии
  const exp = Date.now() + 365 * 24 * 60 * 60 * 1000; // 1 год
  const payload = Buffer.from(JSON.stringify({ u: username, e: exp, j: jti })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  return 'UT:' + payload + '.' + sig;
}

function verifyUserToken(token) {
  if (!token || !token.startsWith('UT:')) return null;
  const rest = token.slice(3);
  const dot = rest.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = rest.slice(0, dot);
  const sig = rest.slice(dot + 1);
  if (sig !== crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex')) return null;
  try {
    const d = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() > d.e) return null;
    return { username: d.u, jti: d.j };
  } catch { return null; }
}

// ─── Stateless multi-user accounts ───────────────────────────────────────────
// Живут только в env vars — переживают Railway рестарты без базы данных.
// Формат: STATIC_USERS=login:pass:Имя Фамилия,login2:pass2:Имя2
// Устаревший вариант (STATIC_USER/STATIC_PASS/STATIC_NAME) тоже поддерживается.
const staticUsers = {}; // {username: {name, pass, token, noLimit, aiUsage}}

function buildStaticUsers() {
  // Обработать STATIC_USERS сначала
  for (const entry of (process.env.STATIC_USERS || '').split(',')) {
    const parts = entry.trim().split(':');
    if (parts.length < 2) continue;
    const u = parts[0].trim().toLowerCase();
    const pass = parts[1].trim();
    const name = parts.slice(2).join(':').trim() || u;
    if (!u || !pass) continue;
    staticUsers[u] = { name, pass, token: makeStaticToken(u), noLimit: false, aiUsage: {} };
  }
  // Legacy STATIC_USER перезаписывает (и получает noLimit как у администратора)
  if (STATIC_USER && STATIC_PASS) {
    staticUsers[STATIC_USER] = {
      name: STATIC_NAME, pass: STATIC_PASS,
      token: makeStaticToken(STATIC_USER), noLimit: true, aiUsage: {}
    };
  }
}
buildStaticUsers();
console.log(`Статических пользователей: ${Object.keys(staticUsers).length}`);

// ─── File-based storage ───────────────────────────────────────────────────────
// Structure: { users: {username: {...}}, invites: {code: {...}}, tokens: {token: {...}} }

function loadDB() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) { console.error('loadDB error:', e.message); }
  return { users: {}, invites: {}, tokens: {} };
}

function saveDB(db) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  } catch (e) { console.error('saveDB error:', e.message); }
}

let DB = loadDB();
console.log(`База данных загружена: ${Object.keys(DB.users).length} пользователей, ${Object.keys(DB.invites).length} инвайтов`);

// ─── Helpers ──────────────────────────────────────────────────────────────────
function hash(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}


function purgeExpiredUsers() {
  const now = new Date();
  let changed = false;
  for (const [uname, u] of Object.entries(DB.users)) {
    if (u.expiresAt && new Date(u.expiresAt) < now) {
      delete DB.users[uname];
      console.log(`Удалён истёкший пользователь: ${uname}`);
      changed = true;
    }
  }
  if (changed) saveDB(DB);
}
purgeExpiredUsers();
setInterval(purgeExpiredUsers, 60 * 60 * 1000); // каждый час

function activeSessionsFor(username) {
  const u = DB.users[username];
  if (!u) return [];
  const now = Date.now();
  return (u.sessions || []).filter(s => s.exp > now);
}

function createToken(username) {
  const u = DB.users[username];
  if (!u) return null;
  const active = activeSessionsFor(username);
  if (active.length >= MAX_DEVICES) return null;
  const token = makeUserToken(username);
  const pl = token.slice(3, token.lastIndexOf('.'));
  const d = JSON.parse(Buffer.from(pl, 'base64url').toString());
  u.sessions = [...active, { jti: d.j, exp: d.e }];
  saveDB(DB);
  return token;
}

function validToken(token) {
  if (!token) return null;
  for (const [username, su] of Object.entries(staticUsers)) {
    if (token === su.token) return { username, isStatic: true };
  }
  const ut = verifyUserToken(token);
  return ut || null;
}

function userExpired(username) {
  const u = DB.users[username];
  return u?.expiresAt && new Date(u.expiresAt) < new Date();
}

// ─── API: register ────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { invite, username, password } = req.body;
  if (!invite || !username || !password)
    return res.json({ ok: false, error: 'Заполните все поля' });

  const code = invite.trim().toUpperCase();
  const inv = DB.invites[code];
  if (!inv) return res.json({ ok: false, error: 'Неверный инвайт-код' });
  if (inv.used) return res.json({ ok: false, error: 'Этот инвайт уже использован' });
  if (inv.expiresAt && new Date(inv.expiresAt) < new Date())
    return res.json({ ok: false, error: 'Инвайт-код истёк' });

  const u = username.trim().toLowerCase();
  if (!/^[a-zа-яё0-9_]{3,20}$/i.test(u))
    return res.json({ ok: false, error: 'Логин: 3-20 символов, буквы/цифры/_' });
  if (DB.users[u] || staticUsers[u])
    return res.json({ ok: false, error: 'Такой логин уже занят' });
  if (password.length < 6)
    return res.json({ ok: false, error: 'Пароль минимум 6 символов' });

  DB.invites[code].used = true;
  DB.users[u] = {
    username: u,
    password: hash(password),
    name: inv.name,
    expiresAt: inv.expiresAt || null,
    inviteCode: code
  };
  saveDB(DB);

  const token = createToken(u);
  if (!token) return res.json({ ok: false, error: 'Аккаунт уже используется на другом устройстве.' });
  setAuthCookie(res, token);
  res.json({ ok: true, token, name: u });
});

// ─── API: login ───────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'Введите логин и пароль' });
  if (loginRateLimited(req)) return res.status(429).json({ ok: false, error: 'Слишком много попыток входа. Подождите 15 минут.' });

  const u = username.trim().toLowerCase();

  const su = staticUsers[u];
  if (su && su.pass === password) {
    setAuthCookie(res, su.token);
    return res.json({ ok: true, token: su.token, name: su.name });
  }

  const user = DB.users[u];
  if (!user || user.password !== hash(password))
    return res.json({ ok: false, error: 'Неверный логин или пароль' });
  if (userExpired(u))
    return res.json({ ok: false, error: 'Срок доступа истёк. Обратитесь к автору.' });

  let token = createToken(u);
  if (!token) {
    // Вытесняем самую старую сессию чтобы освободить место
    const user2 = DB.users[u];
    if (user2?.sessions?.length) {
      user2.sessions.sort((a, b) => a.exp - b.exp);
      user2.sessions.shift();
      saveDB(DB);
    }
    token = createToken(u);
  }
  setAuthCookie(res, token);
  res.json({ ok: true, token, name: u });
});

// ─── API: check-token ─────────────────────────────────────────────────────────
app.post('/api/check-token', (req, res) => {
  const tok = getReqToken(req);
  const s = validToken(tok);
  if (!s) return res.json({ ok: false });
  setAuthCookie(res, tok); // миграция/продление: выдаём cookie при валидном токене
  if (s.isStatic) {
    const su = staticUsers[s.username];
    const today = new Date().toISOString().slice(0, 10);
    const used = (su.aiUsage?.date === today) ? (su.aiUsage.count || 0) : 0;
    return res.json({ ok: true, name: su.name, aiUsed: used, aiLimit: su.noLimit ? null : DAILY_AI_LIMIT });
  }
  if (DB.users[s.username] && userExpired(s.username)) return res.json({ ok: false });
  const user = DB.users[s.username];
  const today = new Date().toISOString().slice(0, 10);
  const used = (user?.aiUsage?.date === today) ? (user.aiUsage.count || 0) : 0;
  res.json({ ok: true, name: s.username, aiUsed: used, aiLimit: DAILY_AI_LIMIT });
});

// ─── API: logout ──────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.clearCookie('at', { path: '/' });
  res.json({ ok: true });
});

// ─── API: AI (OpenRouter / Gemini / Groq) ─────────────────────────────────────
const DAILY_AI_LIMIT = 50; // запросов в день на пользователя

function checkAiLimit(username) {
  const su = staticUsers[username];
  if (su) {
    if (su.noLimit) return true;
    const today = new Date().toISOString().slice(0, 10);
    if (!su.aiUsage || su.aiUsage.date !== today) su.aiUsage = { date: today, count: 0 };
    if (su.aiUsage.count >= DAILY_AI_LIMIT) return false;
    su.aiUsage.count++;
    return true;
  }
  const user = DB.users[username];
  if (!user) return false;
  if (user.noLimit) return true;
  const today = new Date().toISOString().slice(0, 10);
  if (!user.aiUsage || user.aiUsage.date !== today) user.aiUsage = { date: today, count: 0 };
  if (user.aiUsage.count >= DAILY_AI_LIMIT) return false;
  user.aiUsage.count++;
  saveDB(DB);
  return true;
}

app.post('/api/ask', async (req, res) => {
  const { prompt, context } = req.body;
  const s = validToken(getReqToken(req));
  if (!s || (!s.isStatic && DB.users[s.username] && userExpired(s.username)))
    return res.status(403).json({ error: 'Нет доступа. Войдите заново.' });
  if (!GROQ_API_KEY && !OPENROUTER_API_KEY && !GEMINI_API_KEY)
    return res.status(500).json({ error: 'API ключ не настроен' });

  if (!checkAiLimit(s.username))
    return res.status(429).json({ error: `Лимит ${DAILY_AI_LIMIT} запросов в день исчерпан. Возвращайся завтра! 😊` });

  try {
    const messages = [];
    if (context) {
      messages.push({ role: 'user', content: context });
      messages.push({ role: 'assistant', content: 'Понял, учту.' });
    }
    messages.push({ role: 'user', content: prompt });

    // ── 1. Groq (самый надёжный, идёт первым) ───────────────────────────────
    if (GROQ_API_KEY) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 12000);
        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST', signal: ctrl.signal,
          headers: { 'Authorization': `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages, temperature: 0.4, max_tokens: 2000 })
        });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          const text = data.choices?.[0]?.message?.content;
          if (text) return res.json({ ok: true, text });
        } else {
          console.log('Groq статус:', r.status);
        }
      } catch(e) { console.log('Groq error:', e.message); }
    }

    // ── 2. OpenRouter (только 2 самые надёжные модели) ─────────────────────
    if (OPENROUTER_API_KEY) {
      const OR_MODELS = [
        'google/gemini-2.0-flash-exp:free',
        'meta-llama/llama-3.3-70b-instruct:free',
      ];
      for (const model of OR_MODELS) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 8000);
        let r;
        try {
          r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
            method: 'POST', signal: ctrl.signal,
            headers: {
              'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
              'Content-Type': 'application/json',
              'HTTP-Referer': 'https://aig-trainer-production.up.railway.app',
              'X-Title': 'AiG Trainer'
            },
            body: JSON.stringify({ model, messages, temperature: 0.4, max_tokens: 2000 })
          });
        } catch(e) { clearTimeout(timer); continue; }
        clearTimeout(timer);
        if (r.status === 429 || r.status === 503 || !r.ok) continue;
        const data = await r.json();
        const text = data.choices?.[0]?.message?.content;
        if (text) return res.json({ ok: true, text });
      }
      console.log('OpenRouter: модели не ответили, пробую Gemini');
    }

    // ── 3. Gemini (запасной) ────────────────────────────────────────────────
    if (GEMINI_API_KEY) {
      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;
        const contents = messages.map(m => ({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: m.content }]
        }));
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 25000);
        const r = await fetch(url, {
          method: 'POST', signal: ctrl.signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents, generationConfig: { temperature: 0.4, maxOutputTokens: 2000 } })
        });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) return res.json({ ok: true, text });
        } else {
          console.log('Gemini статус:', r.status);
        }
      } catch(e) { console.log('Gemini error:', e.message); }
    }

    return res.status(502).json({ error: 'ИИ временно недоступен, попробуй через минуту.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Admin helpers ────────────────────────────────────────────────────────────
function adminAuth(req, res) {
  if (req.body.password !== ADMIN_PASSWORD) {
    res.status(403).json({ error: 'Неверный пароль' }); return false;
  }
  return true;
}

// ─── Admin: list users ────────────────────────────────────────────────────────
app.post('/api/admin/users', (req, res) => {
  if (!adminAuth(req, res)) return;
  const safe = {};
  for (const [uname, u] of Object.entries(DB.users)) {
    const today = new Date().toISOString().slice(0, 10);
    const aiUsedToday = (u.aiUsage?.date === today) ? (u.aiUsage.count || 0) : 0;
    safe[uname] = { name: u.name, expiresAt: u.expiresAt, devices: activeSessionsFor(uname).length, noLimit: !!u.noLimit, type: 'db', aiUsedToday };
  }
  for (const [uname, su] of Object.entries(staticUsers)) {
    const today = new Date().toISOString().slice(0, 10);
    const aiUsedToday = (su.aiUsage?.date === today) ? (su.aiUsage.count || 0) : 0;
    safe[uname] = { name: su.name, expiresAt: null, devices: '∞', noLimit: su.noLimit, type: 'static', aiUsedToday };
  }
  res.json({ users: safe });
});

// ─── Admin: delete user ───────────────────────────────────────────────────────
app.post('/api/admin/delete-user', (req, res) => {
  if (!adminAuth(req, res)) return;
  const u = req.body.username;
  delete DB.users[u];
  saveDB(DB);
  res.json({ ok: true });
});

// ─── Admin: toggle AI limit ───────────────────────────────────────────────────
app.post('/api/admin/toggle-limit', (req, res) => {
  if (!adminAuth(req, res)) return;
  const u = DB.users[req.body.username];
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  u.noLimit = !u.noLimit;
  saveDB(DB);
  res.json({ ok: true, noLimit: u.noLimit });
});

// ─── Admin: reset devices ─────────────────────────────────────────────────────
app.post('/api/admin/reset-devices', (req, res) => {
  if (!adminAuth(req, res)) return;
  const ur = DB.users[req.body.username];
  if (ur) { ur.sessions = []; saveDB(DB); }
  res.json({ ok: true });
});

// ─── Admin: add invite ────────────────────────────────────────────────────────
app.post('/api/admin/add-invite', (req, res) => {
  if (!adminAuth(req, res)) return;
  const { name, days } = req.body;
  if (!name) return res.status(400).json({ error: 'Укажите имя' });

  const code = crypto.randomBytes(4).toString('hex').toUpperCase();
  let expiresAt = null;
  if (days) {
    const d = new Date();
    d.setDate(d.getDate() + parseInt(days));
    expiresAt = d.toISOString();
  }
  DB.invites[code] = { code, name, expiresAt, used: false };
  saveDB(DB);
  res.json({ ok: true, code });
});

// ─── Admin: list invites ──────────────────────────────────────────────────────
app.post('/api/admin/invites', (req, res) => {
  if (!adminAuth(req, res)) return;
  const result = {};
  for (const [code, inv] of Object.entries(DB.invites)) {
    result[code] = { name: inv.name, expiresAt: inv.expiresAt, used: inv.used };
  }
  res.json({ invites: result });
});

// ─── Admin: delete invite ─────────────────────────────────────────────────────
app.post('/api/admin/delete-invite', (req, res) => {
  if (!adminAuth(req, res)) return;
  delete DB.invites[req.body.code];
  saveDB(DB);
  res.json({ ok: true });
});

// ─── Admin: export backup ─────────────────────────────────────────────────────
app.post('/api/admin/export', (req, res) => {
  if (!adminAuth(req, res)) return;
  res.json({ db: DB });
});

// ─── Admin: import backup ─────────────────────────────────────────────────────
app.post('/api/admin/import', (req, res) => {
  if (!adminAuth(req, res)) return;
  if (!req.body.db) return res.status(400).json({ error: 'Нет данных' });
  DB = req.body.db;
  saveDB(DB);
  res.json({ ok: true });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
