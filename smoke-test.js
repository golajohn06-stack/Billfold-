// Usage: start the server (npm start), then in another terminal: node smoke-test.js [http://localhost:3000]
const base = process.argv[2] || 'http://localhost:3000';
let cookie = '', fails = 0;
async function call(method, path, body) {
  const r = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', cookie }, body: body && JSON.stringify(body) });
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
const check = (name, ok) => { console.log((ok ? 'PASS ' : 'FAIL ') + name); if (!ok) fails++; };

(async () => {
  const email = `test${Date.now()}@example.com`, pw = 'correct-horse-1', now = Date.now();
  const inv = (i) => ({ n: 'T' + i, c: 'Client', a: 100, p: 0, t: now + i });
  let r = await call('POST', '/api/signup', { email, password: pw }); check('signup', r.status === 200);
  r = await call('GET', '/api/me'); check('logged in, email unconfirmed', r.json.email === email && r.json.verified === false);
  r = await call('POST', '/api/checkout'); check('checkout blocked until email is confirmed', r.status === 403);
  r = await call('PUT', '/api/inv', { inv: [1, 2, 3].map(inv) }); check('3 free invoices saved', r.status === 200);
  r = await call('PUT', '/api/inv', { inv: [1, 2, 3, 4].map(inv) }); check('4th free invoice rejected', r.status === 402);
  await call('POST', '/api/logout');
  r = await call('GET', '/api/me'); check('logout works', r.json.email === null);
  r = await call('POST', '/api/login', { email, password: 'wrong-password' }); check('wrong password rejected', r.status === 401);
  r = await call('POST', '/api/login', { email, password: pw }); check('login works', r.status === 200);
  r = await call('GET', '/api/me'); check('invoices persisted', r.json.inv && r.json.inv.length === 3);
  r = await call('POST', '/api/forgot', { email }); check('forgot works for real email', r.status === 200);
  r = await call('POST', '/api/forgot', { email: 'nobody@example.com' }); check('forgot gives same reply for unknown email', r.status === 200);
  r = await call('POST', '/api/reset', { email, password: 'new-password-1', token: 'bad' }); check('bad reset token rejected', r.status === 400);
  console.log(fails ? `${fails} check(s) failed` : 'All checks passed');
  process.exit(fails ? 1 : 0);
})();
