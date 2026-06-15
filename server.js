const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');
const fs      = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Config ───────────────────────────────────────────────────────────────────
const GROQ_API_KEY        = process.env.GROQ_API_KEY        || ''; // устарело
const GEMINI_API_KEY      = process.env.GEMINI_API_KEY      || '';
const OPENROUTER_API_KEY  = process.env.OPENROUTER_API_KEY  || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD  || 'admin123';
const MAX_DEVICES    = 2; // allow same user on 2 devices
const DATA_FILE      = process.env.DATA_FILE || path.join(__dirname, 'data.json');

// Stateless auth — survives Railway restarts (set these env vars in Railway)
const STATIC_USER   = (process.env.STATIC_USER || '').toLowerCase();
const STATIC_PASS   = process.env.STATIC_PASS   || '';
const STATIC_NAME   = process.env.STATIC_NAME   || STATIC_USER;
const TOKEN_SECRET  = process.env.TOKEN_SECRET  || 'medtrainer-secret-2024';

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
  if (STATIC_USER && token === makeStaticToken(STATIC_USER)) return { username: STATIC_USER };
  // Stateless — проверяем подпись
  const ut = verifyUserToken(token);
  if (!ut) return null;
  // Проверяем что сессия ещё зарегистрирована (лимит устройств)
  const u = DB.users[ut.username];
  if (!u) return ut; // DB пуста — доверяем токену
  const allowed = (u.sessions || []).some(s => s.jti === ut.jti && s.exp > Date.now());
  if (!allowed) return null;
  return ut;
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
  if (DB.users[u])
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
  res.json({ ok: true, token, name: u });
});

// ─── API: login ───────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'Введите логин и пароль' });

  const u = username.trim().toLowerCase();

  // Stateless login — always works, no DB needed
  if (STATIC_USER && u === STATIC_USER && STATIC_PASS && password === STATIC_PASS) {
    const token = makeStaticToken(u);
    return res.json({ ok: true, token, name: STATIC_NAME });
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
  res.json({ ok: true, token, name: u });
});

// ─── API: check-token ─────────────────────────────────────────────────────────
app.post('/api/check-token', (req, res) => {
  const s = validToken(req.body.token);
  if (!s) return res.json({ ok: false });
  if (DB.users[s.username] && userExpired(s.username)) return res.json({ ok: false });
  const user = DB.users[s.username];
  const today = new Date().toISOString().slice(0, 10);
  const used = (user?.aiUsage?.date === today) ? (user.aiUsage.count || 0) : 0;
  res.json({ ok: true, name: s.username, aiUsed: used, aiLimit: 50 });
});

// ─── API: AI (OpenRouter / Gemini / Groq) ─────────────────────────────────────
const DAILY_AI_LIMIT = 50; // запросов в день на пользователя

function checkAiLimit(username) {
  if (username === STATIC_USER) return true;
  const user = DB.users[username];
  if (!user) return false;
  if (user.noLimit) return true;
  const today = new Date().toISOString().slice(0, 10);
  if (!user.aiUsage || user.aiUsage.date !== today) {
    user.aiUsage = { date: today, count: 0 };
  }
  if (user.aiUsage.count >= DAILY_AI_LIMIT) return false;
  user.aiUsage.count++;
  saveDB(DB);
  return true;
}

app.post('/api/ask', async (req, res) => {
  const { token, prompt, context } = req.body;
  const s = validToken(token);
  if (!s || (DB.users[s.username] && userExpired(s.username)))
    return res.status(403).json({ error: 'Нет доступа. Войдите заново.' });
  const apiKey = OPENROUTER_API_KEY || GEMINI_API_KEY || GROQ_API_KEY;
  if (!apiKey)
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

    // ── 1. OpenRouter (бесплатные модели, перебор по очереди) ──────────────────
    if (OPENROUTER_API_KEY) {
      const OR_MODELS = [
        'google/gemini-2.0-flash-exp:free',
        'deepseek/deepseek-chat:free',
        'meta-llama/llama-3.3-70b-instruct:free',
        'deepseek/deepseek-r1:free',
        'qwen/qwen2.5-72b-instruct:free',
        'mistralai/mistral-7b-instruct:free',
      ];
      for (const model of OR_MODELS) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 30000);
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
            body: JSON.stringify({ model, messages, temperature: 0.15, max_tokens: 1500 })
          });
        } catch(e) { clearTimeout(timer); continue; }
        clearTimeout(timer);
        if (r.status === 429 || r.status === 503 || !r.ok) continue;
        const data = await r.json();
        const text = data.choices?.[0]?.message?.content;
        if (text) return res.json({ ok: true, text });
      }
      console.log('OpenRouter: все модели не ответили, пробую Gemini');
    }

    // ── 2. Gemini (запасной если OpenRouter не помог) ───────────────────────
    if (GEMINI_API_KEY) {
      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;
        const contents = messages.map(m => ({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: m.content }]
        }));
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 30000);
        const r = await fetch(url, {
          method: 'POST', signal: ctrl.signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents, generationConfig: { temperature: 0.15, maxOutputTokens: 1500 } })
        });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) return res.json({ ok: true, text });
        }
      } catch(e) { console.log('Gemini error:', e.message); }
      console.log('Gemini не ответил, пробую Groq');
    }

    // ── 3. Groq (последний резерв) ───────────────────────────────────────────
    if (GROQ_API_KEY) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 30000);
        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST', signal: ctrl.signal,
          headers: { 'Authorization': `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages, temperature: 0.15, max_tokens: 1500 })
        });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          const text = data.choices?.[0]?.message?.content;
          if (text) return res.json({ ok: true, text });
        }
      } catch(e) { console.log('Groq error:', e.message); }
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
    safe[uname] = { name: u.name, expiresAt: u.expiresAt, devices: activeSessionsFor(uname).length, noLimit: !!u.noLimit };
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
