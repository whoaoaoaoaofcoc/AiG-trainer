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

function activeTokensFor(username) {
  const now = Date.now();
  return Object.values(DB.tokens).filter(t =>
    t.username === username && new Date(t.expiresAt).getTime() > now
  );
}

function createToken(username) {
  const active = activeTokensFor(username);
  if (active.length >= MAX_DEVICES) return null;
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  DB.tokens[token] = {
    token, username,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
  };
  saveDB(DB);
  return token;
}

function validToken(token) {
  if (!token) return null;
  // Stateless token check — works even after restarts
  if (STATIC_USER && token === makeStaticToken(STATIC_USER)) {
    return { username: STATIC_USER };
  }
  const t = DB.tokens[token];
  if (!t) return null;
  if (new Date(t.expiresAt).getTime() <= Date.now()) {
    delete DB.tokens[token];
    saveDB(DB);
    return null;
  }
  return t;
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

  // Clear expired tokens for this user first
  for (const [tok, t] of Object.entries(DB.tokens)) {
    if (t.username === u && new Date(t.expiresAt).getTime() <= Date.now()) {
      delete DB.tokens[tok];
    }
  }

  const token = createToken(u);
  if (!token) {
    // Force create token (remove oldest for this user)
    const userToks = Object.entries(DB.tokens)
      .filter(([, t]) => t.username === u)
      .sort(([, a], [, b]) => new Date(a.createdAt) - new Date(b.createdAt));
    if (userToks.length > 0) delete DB.tokens[userToks[0][0]];
    saveDB(DB);
    const tok2 = createToken(u);
    return res.json({ ok: true, token: tok2, name: u });
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
  // STATIC_USER (владелец) без ограничений
  if (username === STATIC_USER) return true;
  const user = DB.users[username];
  if (!user) return false;
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

    if (OPENROUTER_API_KEY) {
      // OpenRouter — перебираем бесплатные модели по очереди при 429
      const FREE_MODELS = [
        'meta-llama/llama-3.3-70b-instruct:free',
        'google/gemini-2.0-flash-exp:free',
        'deepseek/deepseek-chat-v3-0324:free',
        'qwen/qwen3-235b-a22b:free',
      ];
      let lastErr = '';
      for (const model of FREE_MODELS) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 50000);
        let r;
        try {
          r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
            method: 'POST',
            signal: controller.signal,
            headers: {
              'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
              'Content-Type': 'application/json',
              'HTTP-Referer': 'https://aig-trainer-production.up.railway.app',
              'X-Title': 'AiG Trainer'
            },
            body: JSON.stringify({ model, messages, temperature: 0.15, max_tokens: 1500 })
          });
        } catch(e) { lastErr = e.message; continue; }
        finally { clearTimeout(timer); }
        if (r.status === 429 || r.status === 503) { lastErr = 'rate-limited'; continue; }
        if (!r.ok) { lastErr = 'error ' + r.status; continue; }
        const data = await r.json();
        return res.json({ ok: true, text: data.choices?.[0]?.message?.content || '' });
      }
      return res.status(502).json({ error: 'Все AI модели временно перегружены. Попробуй через минуту.' });
    } else if (GEMINI_API_KEY) {
      // Нативный Gemini API
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;
      const contents = messages.map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }]
      }));
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents, generationConfig: { temperature: 0.15, maxOutputTokens: 1500 } })
      });
      if (!r.ok) return res.status(502).json({ error: 'Ошибка AI: ' + await r.text() });
      const data = await r.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      return res.json({ ok: true, text });
    } else {
      // Groq fallback
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages, temperature: 0.15, max_tokens: 1500 })
      });
      if (!r.ok) return res.status(502).json({ error: 'Ошибка AI: ' + await r.text() });
      const data = await r.json();
      return res.json({ ok: true, text: data.choices?.[0]?.message?.content || '' });
    }
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
    safe[uname] = { name: u.name, expiresAt: u.expiresAt, devices: activeTokensFor(uname).length };
  }
  res.json({ users: safe });
});

// ─── Admin: delete user ───────────────────────────────────────────────────────
app.post('/api/admin/delete-user', (req, res) => {
  if (!adminAuth(req, res)) return;
  const u = req.body.username;
  delete DB.users[u];
  for (const [tok, t] of Object.entries(DB.tokens)) {
    if (t.username === u) delete DB.tokens[tok];
  }
  saveDB(DB);
  res.json({ ok: true });
});

// ─── Admin: reset devices ─────────────────────────────────────────────────────
app.post('/api/admin/reset-devices', (req, res) => {
  if (!adminAuth(req, res)) return;
  for (const [tok, t] of Object.entries(DB.tokens)) {
    if (t.username === req.body.username) delete DB.tokens[tok];
  }
  saveDB(DB);
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
