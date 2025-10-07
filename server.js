// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const DB_FILE = path.join(__dirname, 'keys.db');
const db = new sqlite3.Database(DB_FILE);
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// init db
const schema = `
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_text TEXT NOT NULL UNIQUE,
  package TEXT,
  duration_days INTEGER,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  active INTEGER DEFAULT 1
);
`;
db.exec(schema);

// helper - generate human friendly key (16 chars)
function generateKey() {
  const raw = crypto.randomBytes(12).toString('base64');
  return raw.replace(/[^A-Za-z0-9]/g,'').toUpperCase().slice(0,16);
}

// create key endpoint
app.post('/api/keys', (req, res) => {
  const { packageName, durationDays } = req.body;
  const createdAt = new Date();
  const duration = parseInt(durationDays) || 1;
  const expiresAt = new Date(createdAt.getTime() + duration * 24*60*60*1000);

  const keyText = generateKey();
  const stmt = db.prepare(`INSERT INTO keys (key_text, package, duration_days, created_at, expires_at, active)
                           VALUES (?, ?, ?, ?, ?, 1)`);
  stmt.run(keyText, packageName||null, duration, createdAt.toISOString(), expiresAt.toISOString(), function(err) {
    if (err) return res.status(500).json({ error: 'DB error', details: err.message });
    res.json({
      id: this.lastID,
      key: keyText,
      package: packageName,
      duration_days: duration,
      created_at: createdAt.toISOString(),
      expires_at: expiresAt.toISOString()
    });
  });
});

// list keys
app.get('/api/keys', (req, res) => {
  db.all('SELECT * FROM keys ORDER BY id DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// download JSON (all keys)
app.get('/api/keys/download', (req, res) => {
  db.all('SELECT * FROM keys ORDER BY id DESC', (err, rows) => {
    if (err) return res.status(500).send('DB error');
    res.setHeader('Content-Disposition','attachment; filename=keys.json');
    res.json(rows);
  });
});

// verify key
app.post('/api/keys/verify', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ valid:false, message:'No key provided' });
  db.get('SELECT * FROM keys WHERE key_text = ?', [key], (err, row) => {
    if (err) return res.status(500).json({ valid:false, message:'DB error' });
    if (!row) return res.json({ valid:false, message:'Key not found' });
    if (!row.active) return res.json({ valid:false, message:'Key inactive' });
    const now = new Date();
    if (row.expires_at && new Date(row.expires_at) < now) {
      return res.json({ valid:false, message:'Key expired' });
    }
    return res.json({ valid:true, message:'Key valid', package: row.package });
  });
});

// serve frontend
app.use('/', express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`irq-loder server running on :${PORT}`));
