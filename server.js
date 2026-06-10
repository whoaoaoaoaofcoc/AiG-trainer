const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Конфиг ──────────────────────────────────────────────────────────────────
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Пользователи: { username: { password, name, expiresAt } }
let USERS = JSON.parse(process.env.USERS || '{}');

// Сессии: { token: { username, expiresAt } }
const SESSIONS = {};

// ─── Вспомогательные ─────────────────────────────────────────────────────────
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function isValidUser(username, password) {
  const user = USERS[username];
  if (!user) return false;
  if (user.password !== hashPassword(password)) return false;
  if (user.expiresAt && new Date(user.expiresAt) < new Date()) return false;
  return true;
}

function isValidToken(token) {
  const session = SESSIONS[token];
  if (!session) return false;
  if (new Date(session.expiresAt) < new Date()) {
    delete SESSIONS[token];
    return false;
  }
  return true;
}

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 дней
  SESSIONS[token] = { username, expiresAt: expiresAt.toISOString() };
  return token;
}

// ─── API: вход ───────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'Введите логин и пароль' });

  const u = username.trim().toLowerCase();
  if (!isValidUser(u, password)) {
    return res.json({ ok: false, error: 'Неверный логин, пароль или истёк срок доступа' });
  }

  const token = createSession(u);
  return res.json({ ok: true, token, name: USERS[u].name });
});

// ─── API: проверка токена ─────────────────────────────────────────────────────
app.post('/api/check-token', (req, res) => {
  const { token } = req.body;
  if (isValidToken(token)) {
    const { username } = SESSIONS[token];
    return res.json({ ok: true, name: USERS[username]?.name });
  }
  return res.json({ ok: false });
});

// ─── API: запрос к Groq ───────────────────────────────────────────────────────
app.post('/api/ask', async (req, res) => {
  const { token, prompt, context } = req.body;

  if (!isValidToken(token)) {
    return res.status(403).json({ error: 'Нет доступа. Войдите заново.' });
  }

  if (!GROQ_API_KEY) {
    return res.status(500).json({ error: 'API ключ не настроен на сервере' });
  }

  try {
    const messages = [];
    if (context) {
      messages.push({ role: 'user', content: context });
      messages.push({ role: 'assistant', content: 'Понял, учту этот материал.' });
    }
    messages.push({ role: 'user', content: prompt });

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages,
        temperature: 0.3,
        max_tokens: 1500
      })
    });

    if (!response.ok) {
      const err = await response.text();
      return res.status(502).json({ error: 'Ошибка Groq: ' + err });
    }

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content || '';
    res.json({ ok: true, text });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Админка: список пользователей ───────────────────────────────────────────
app.post('/api/admin/users', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  const safe = {};
  for (const [u, info] of Object.entries(USERS)) {
    safe[u] = { name: info.name, expiresAt: info.expiresAt };
  }
  res.json({ users: safe });
});

// ─── Админка: добавить пользователя ──────────────────────────────────────────
app.post('/api/admin/add-user', (req, res) => {
  const { password, username, userPassword, name, days } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  if (!username || !userPassword || !name) return res.status(400).json({ error: 'Заполните все поля' });

  const u = username.trim().toLowerCase();
  let expiresAt = null;
  if (days) {
    const d = new Date();
    d.setDate(d.getDate() + parseInt(days));
    expiresAt = d.toISOString();
  }

  USERS[u] = { password: hashPassword(userPassword), name, expiresAt };
  res.json({ ok: true });
});

// ─── Админка: удалить пользователя ───────────────────────────────────────────
app.post('/api/admin/delete-user', (req, res) => {
  const { password, username } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  delete USERS[username];
  res.json({ ok: true });
});

// ─── Запуск ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
