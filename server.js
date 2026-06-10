const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Конфиг ──────────────────────────────────────────────────────────────────
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Коды доступа: { код: { name, expiresAt (ISO string или null = бессрочно) } }
let ACCESS_CODES = JSON.parse(process.env.ACCESS_CODES || '{}');

// ─── Вспомогательные ─────────────────────────────────────────────────────────
function isValidCode(code) {
  const entry = ACCESS_CODES[code];
  if (!entry) return false;
  if (entry.expiresAt && new Date(entry.expiresAt) < new Date()) return false;
  return true;
}

// ─── API: проверка кода ───────────────────────────────────────────────────────
app.post('/api/check-code', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false, error: 'Введите код доступа' });
  if (isValidCode(code)) {
    return res.json({ ok: true, name: ACCESS_CODES[code].name });
  }
  return res.json({ ok: false, error: 'Неверный или просроченный код' });
});

// ─── API: запрос к Groq ───────────────────────────────────────────────────────
app.post('/api/ask', async (req, res) => {
  const { code, prompt, context } = req.body;

  if (!isValidCode(code)) {
    return res.status(403).json({ error: 'Нет доступа. Проверьте код.' });
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

// ─── Админка: список кодов ────────────────────────────────────────────────────
app.post('/api/admin/codes', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  res.json({ codes: ACCESS_CODES });
});

// ─── Админка: добавить код ────────────────────────────────────────────────────
app.post('/api/admin/add-code', (req, res) => {
  const { password, code, name, days } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  if (!code || !name) return res.status(400).json({ error: 'Укажите код и имя' });

  let expiresAt = null;
  if (days) {
    const d = new Date();
    d.setDate(d.getDate() + parseInt(days));
    expiresAt = d.toISOString();
  }

  ACCESS_CODES[code] = { name, expiresAt };
  res.json({ ok: true, code, name, expiresAt });
});

// ─── Админка: удалить код ─────────────────────────────────────────────────────
app.post('/api/admin/delete-code', (req, res) => {
  const { password, code } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  delete ACCESS_CODES[code];
  res.json({ ok: true });
});

// ─── Запуск ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
