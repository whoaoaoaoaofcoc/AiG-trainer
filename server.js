const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Конфиг ──────────────────────────────────────────────────────────────────
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const MAX_DEVICES = 1;
const DATA_FILE = path.join(__dirname, 'data.json');

// ─── Персистентность ──────────────────────────────────────────────────────────
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const d = JSON.parse(raw);
      Object.assign(USERS, d.users || {});
      Object.assign(INVITES, d.invites || {});
      Object.assign(TOKENS, d.tokens || {});
      console.log(`Данные загружены: ${Object.keys(USERS).length} польз., ${Object.keys(INVITES).length} инвайтов`);
    }
  } catch (e) {
    console.error('Ошибка загрузки data.json:', e.message);
  }
}

function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: USERS, invites: INVITES, tokens: TOKENS }, null, 2));
  } catch (e) {
    console.error('Ошибка сохранения data.json:', e.message);
  }
}

// Пользователи: { username: { password, name, expiresAt, inviteCode } }
const USERS = {};

// Инвайт-коды: { code: { name, expiresAt, used: false } }
const INVITES = {};

// Токены (сессии): { token: { username, createdAt, expiresAt } }
const TOKENS = {};

loadData();

// ─── Вспомогательные ─────────────────────────────────────────────────────────
function hash(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function activeTokensFor(username) {
  const now = new Date();
  return Object.entries(TOKENS)
    .filter(([, s]) => s.username === username && new Date(s.expiresAt) > now)
    .sort((a, b) => new Date(a[1].createdAt) - new Date(b[1].createdAt));
}

function createToken(username) {
  const active = activeTokensFor(username);
  if (active.length >= MAX_DEVICES) {
    return null; // отказ — уже залогинен на другом устройстве
  }
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  TOKENS[token] = {
    username,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
  };
  saveData();
  return token;
}

function validToken(token) {
  const s = TOKENS[token];
  if (!s) return null;
  if (new Date(s.expiresAt) < new Date()) { delete TOKENS[token]; saveData(); return null; }
  return s;
}

function userExpired(username) {
  const u = USERS[username];
  return u?.expiresAt && new Date(u.expiresAt) < new Date();
}

// ─── API: регистрация по инвайту ─────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { invite, username, password } = req.body;
  if (!invite || !username || !password)
    return res.json({ ok: false, error: 'Заполните все поля' });

  const inv = INVITES[invite.trim().toUpperCase()];
  if (!inv) return res.json({ ok: false, error: 'Неверный инвайт-код' });
  if (inv.used) return res.json({ ok: false, error: 'Этот инвайт уже использован' });
  if (inv.expiresAt && new Date(inv.expiresAt) < new Date())
    return res.json({ ok: false, error: 'Инвайт-код истёк' });

  const u = username.trim().toLowerCase();
  if (!/^[a-zа-яё0-9_]{3,20}$/i.test(u))
    return res.json({ ok: false, error: 'Логин: 3-20 символов, буквы/цифры/_' });
  if (USERS[u]) return res.json({ ok: false, error: 'Такой логин уже занят' });
  if (password.length < 6) return res.json({ ok: false, error: 'Пароль минимум 6 символов' });

  inv.used = true;
  USERS[u] = { password: hash(password), name: inv.name, expiresAt: inv.expiresAt, inviteCode: invite };
  const token = createToken(u);
  saveData();
  if (!token) return res.json({ ok: false, error: 'Аккаунт уже используется на другом устройстве. Обратитесь к автору.' });
  res.json({ ok: true, token, name: inv.name });
});

// ─── API: вход ───────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'Введите логин и пароль' });

  const u = username.trim().toLowerCase();
  const user = USERS[u];
  if (!user || user.password !== hash(password))
    return res.json({ ok: false, error: 'Неверный логин или пароль' });
  if (userExpired(u))
    return res.json({ ok: false, error: 'Срок доступа истёк. Обратитесь к автору.' });

  const token = createToken(u);
  if (!token) return res.json({ ok: false, error: 'Этот аккаунт уже открыт на другом устройстве. Сначала выйди там или попроси автора сбросить сессию.' });
  res.json({ ok: true, token, name: user.name });
});

// ─── API: проверка токена ─────────────────────────────────────────────────────
app.post('/api/check-token', (req, res) => {
  const s = validToken(req.body.token);
  if (s && !userExpired(s.username))
    return res.json({ ok: true, name: USERS[s.username]?.name });
  res.json({ ok: false });
});

// ─── API: Groq ────────────────────────────────────────────────────────────────
app.post('/api/ask', async (req, res) => {
  const { token, prompt, context } = req.body;
  const s = validToken(token);
  if (!s || userExpired(s.username))
    return res.status(403).json({ error: 'Нет доступа. Войдите заново.' });
  if (!GROQ_API_KEY)
    return res.status(500).json({ error: 'API ключ не настроен' });

  try {
    const messages = [];
    if (context) {
      messages.push({ role: 'user', content: context });
      messages.push({ role: 'assistant', content: 'Понял, учту.' });
    }
    messages.push({ role: 'user', content: prompt });

    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages, temperature: 0.3, max_tokens: 1500 })
    });

    if (!r.ok) return res.status(502).json({ error: 'Ошибка Groq: ' + await r.text() });
    const data = await r.json();
    res.json({ ok: true, text: data.choices?.[0]?.message?.content || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Админка: auth helper ─────────────────────────────────────────────────────
function adminAuth(req, res) {
  if (req.body.password !== ADMIN_PASSWORD) {
    res.status(403).json({ error: 'Неверный пароль' }); return false;
  }
  return true;
}

// ─── Админка: список пользователей ───────────────────────────────────────────
app.post('/api/admin/users', (req, res) => {
  if (!adminAuth(req, res)) return;
  const safe = {};
  for (const [u, info] of Object.entries(USERS)) {
    safe[u] = { name: info.name, expiresAt: info.expiresAt, devices: activeTokensFor(u).length };
  }
  res.json({ users: safe });
});

// ─── Админка: удалить пользователя ───────────────────────────────────────────
app.post('/api/admin/delete-user', (req, res) => {
  if (!adminAuth(req, res)) return;
  const u = req.body.username;
  delete USERS[u];
  for (const [t, s] of Object.entries(TOKENS)) {
    if (s.username === u) delete TOKENS[t];
  }
  saveData();
  res.json({ ok: true });
});

// ─── Админка: сбросить устройства пользователя ───────────────────────────────
app.post('/api/admin/reset-devices', (req, res) => {
  if (!adminAuth(req, res)) return;
  const u = req.body.username;
  for (const [t, s] of Object.entries(TOKENS)) {
    if (s.username === u) delete TOKENS[t];
  }
  saveData();
  res.json({ ok: true });
});

// ─── Админка: создать инвайт ──────────────────────────────────────────────────
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
  INVITES[code] = { name, expiresAt, used: false };
  saveData();
  res.json({ ok: true, code });
});

// ─── Админка: список инвайтов ─────────────────────────────────────────────────
app.post('/api/admin/invites', (req, res) => {
  if (!adminAuth(req, res)) return;
  res.json({ invites: INVITES });
});

// ─── Админка: удалить инвайт ─────────────────────────────────────────────────
app.post('/api/admin/delete-invite', (req, res) => {
  if (!adminAuth(req, res)) return;
  delete INVITES[req.body.code];
  saveData();
  res.json({ ok: true });
});

// ─── Запуск ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
