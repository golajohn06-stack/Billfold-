const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const Stripe = require('stripe');

const { STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET, BASE_URL, TOKEN_SECRET } = process.env;
const stripe = new Stripe(STRIPE_SECRET_KEY);
const DB = process.env.DB_PATH || 'data.json'; // MVP storage: put on a persistent disk, or swap for Postgres.

const load = () => { try { return JSON.parse(fs.readFileSync(DB)); } catch { return { users: {} }; } };
const save = (d) => fs.writeFileSync(DB, JSON.stringify(d));
const mac = (v) => crypto.createHmac('sha256', TOKEN_SECRET).update(v).digest('hex');
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const secure = (BASE_URL || '').startsWith('https');
const cookie = (res, val, age) => res.setHeader('Set-Cookie',
  `sid=${encodeURIComponent(val)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure ? '; Secure' : ''}`);
const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
const login = (res, email, u) => cookie(res, email + '.' + mac(email + ':' + (u.sv || 0)), 2592000);

function me(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const v = decodeURIComponent(m[1]), i = v.lastIndexOf('.');
  const email = v.slice(0, i);
  if (i < 1) return null;
  const db = load(), u = db.users[email];
  return u && eq(mac(email + ':' + (u.sv || 0)), v.slice(i + 1)) ? { email, db, u } : null;
}
const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error' }); });

// Simple in-memory limiter: max attempts per IP per route in 15 minutes.
const hits = new Map();
const limit = (max) => (req, res, next) => {
  const k = req.path + '|' + req.ip, now = Date.now();
  const a = (hits.get(k) || []).filter((t) => now - t < 900000);
  if (a.length >= max) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  a.push(now); hits.set(k, a); next();
};

// Email via Resend. Without RESEND_API_KEY the message is printed to the server log (dev only).
async function mail(to, subject, text) {
  if (!process.env.RESEND_API_KEY) { console.log('MAIL (dev):', to, subject, text); return; }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.MAIL_FROM, to, subject, text }),
  });
  if (!r.ok) throw new Error('mail failed ' + r.status);
}

function sendVerify(email, u) {
  const token = crypto.randomBytes(32).toString('hex');
  u.vt = { h: sha(token), exp: Date.now() + 86400000 };
  mail(email, 'Confirm your Billfold email',
    `Confirm your email to unlock Pro:\n\n${BASE_URL}/app.html?verify=${token}&e=${encodeURIComponent(email)}\n\nThis link works for 24 hours.`
  ).catch((e) => console.error(e));
}

const app = express();
app.set('trust proxy', 1); // correct client IPs behind Render, Railway, Fly
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'",
  });
  next();
});
app.get('/healthz', (req, res) => res.send('ok'));

// Stripe webhook needs the raw body, so it goes before express.json().
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  let ev;
  try { ev = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET); }
  catch { return res.sendStatus(400); }
  const obj = ev.data.object, db = load();
  if (ev.type === 'checkout.session.completed' && db.users[obj.client_reference_id]) {
    Object.assign(db.users[obj.client_reference_id], { pro: true, cust: obj.customer });
  }
  if (ev.type === 'customer.subscription.deleted') {
    Object.values(db.users).forEach((u) => { if (u.cust === obj.customer) u.pro = false; });
  }
  save(db);
  res.sendStatus(200);
});

app.use(express.json());
app.use(express.static('public'));

app.post('/api/signup', limit(20), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  if (pw.length < 8) return res.status(400).json({ error: 'Use a password with 8 or more characters.' });
  const db = load();
  if (db.users[email]) return res.status(409).json({ error: 'That email already has an account. Log in instead.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.users[email] = { salt, hash: hash(pw, salt), pro: false, inv: [], ok: false };
  sendVerify(email, db.users[email]);
  save(db); login(res, email, db.users[email]); res.json({ ok: true });
});

app.post('/api/login', limit(10), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const u = load().users[email];
  if (!u || !eq(hash(pw, u.salt), u.hash)) return res.status(401).json({ error: 'Wrong email or password.' });
  login(res, email, u); res.json({ ok: true });
});

// Password reset: same reply whether or not the email has an account, so it can't be used to probe emails.
app.post('/api/forgot', limit(5), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const db = load(), u = db.users[email];
  if (u) {
    const token = crypto.randomBytes(32).toString('hex');
    u.reset = { h: sha(token), exp: Date.now() + 3600000 };
    save(db);
    mail(email, 'Reset your Billfold password',
      `Use this link within an hour to choose a new password:\n\n${BASE_URL}/app.html?reset=${token}&e=${encodeURIComponent(email)}\n\nIf you didn't ask for this, you can ignore this email.`
    ).catch((e) => console.error(e));
  }
  res.json({ ok: true });
});

app.post('/api/reset', limit(10), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || ''), token = String(req.body.token || '');
  if (pw.length < 8) return res.status(400).json({ error: 'Use a password with 8 or more characters.' });
  const db = load(), u = db.users[email];
  if (!u || !u.reset || u.reset.exp < Date.now() || !eq(sha(token), u.reset.h)) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired. Request a new one.' });
  }
  u.salt = crypto.randomBytes(16).toString('hex');
  u.hash = hash(pw, u.salt);
  u.sv = (u.sv || 0) + 1; // signs out every other device
  delete u.reset; u.ok = true; // a working reset link also proves the email
  save(db); login(res, email, u); res.json({ ok: true });
});

app.post('/api/verify', limit(10), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), db = load(), u = db.users[email];
  if (!u || !u.vt || u.vt.exp < Date.now() || !eq(sha(String(req.body.token || '')), u.vt.h)) {
    return res.status(400).json({ error: 'This confirmation link is invalid or has expired. Log in and request a new one.' });
  }
  u.ok = true; delete u.vt; save(db); res.json({ ok: true });
});

app.post('/api/resend', limit(3), (req, res) => {
  const s = me(req);
  if (!s) return res.status(401).json({});
  if (s.u.ok === false) { sendVerify(s.email, s.u); save(s.db); }
  res.json({ ok: true });
});

app.post('/api/portal', wrap(async (req, res) => {
  const s = me(req);
  if (!s || !s.u.cust) return res.status(400).json({ error: 'No subscription found.' });
  const p = await stripe.billingPortal.sessions.create({ customer: s.u.cust, return_url: BASE_URL + '/app.html' });
  res.json({ url: p.url });
}));

app.post('/api/logout', (req, res) => { cookie(res, '', 0); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  const s = me(req);
  res.json(s ? { email: s.email, pro: !!s.u.pro, inv: s.u.inv, verified: s.u.ok !== false } : { email: null });
});

app.put('/api/inv', (req, res) => {
  const s = me(req);
  if (!s) return res.status(401).json({});
  const list = Array.isArray(req.body.inv) ? req.body.inv.slice(0, 500) : [];
  const m = new Date().toISOString().slice(0, 7);
  if (!s.u.pro && list.filter((v) => new Date(+v.t || 0).toISOString().slice(0, 7) === m).length > 3) {
    return res.status(402).json({ error: 'Free plan limit reached.' });
  }
  s.u.inv = list.map((v) => ({ n: String(v.n).slice(0, 60), c: String(v.c).slice(0, 80), a: +v.a || 0, p: v.p ? 1 : 0, t: +v.t || 0 }));
  save(s.db); res.json({ ok: true });
});

app.post('/api/checkout', wrap(async (req, res) => {
  const s = me(req);
  if (!s) return res.status(401).json({ error: 'Log in first.' });
  if (s.u.ok === false) return res.status(403).json({ error: 'Confirm your email first. Check your inbox for the link.' });
  const c = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
    client_reference_id: s.email,
    customer_email: s.email,
    success_url: BASE_URL + '/app.html?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: BASE_URL + '/app.html',
  });
  res.json({ url: c.url });
}));

// Backup for slow webhooks: confirm the paid session on return from Stripe.
app.get('/api/claim', wrap(async (req, res) => {
  const s = me(req);
  if (!s) return res.status(401).json({});
  const c = await stripe.checkout.sessions.retrieve(String(req.query.session_id));
  if (c.status !== 'complete' || c.client_reference_id !== s.email) return res.status(402).json({});
  Object.assign(s.u, { pro: true, cust: c.customer });
  save(s.db); res.json({ pro: true });
}));

app.listen(process.env.PORT || 3000, () => console.log('Billfold running'));
