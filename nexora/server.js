// Lizenz: LZS / ItsLivex License v2.0 – https://github.com/ItsLivex/ItsLivex-Officially-LICENSE/blob/main/LICENSE.md
require('dotenv').config();
const express = require('express'), fs = require('fs'), path = require('path'), crypto = require('crypto'), multer = require('multer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();
const ROOT = path.join(__dirname, 'products');
const SECRET = process.env.APP_SECRET, BASE = process.env.BASE_URL || 'http://localhost:3000';
if (!SECRET || !process.env.ADMIN_PASSWORD) { console.error('APP_SECRET und ADMIN_PASSWORD in .env setzen'); process.exit(1); }

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const safe = s => typeof s === 'string' && /^[\w .\-]{1,60}$/.test(s) && !s.includes('..');
const hmac = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Preise stehen in products/prices.txt, Format: Game/Produkt = 9.99
function prices() {
  const m = {};
  try {
    fs.readFileSync(path.join(ROOT, 'prices.txt'), 'utf8').split(/\r?\n/).forEach(l => {
      l = l.trim(); if (!l || l[0] === '#') return;
      const [k, v] = l.split('='); if (v) m[k.trim()] = parseFloat(v.replace(',', '.'));
    });
  } catch {}
  return m;
}
// Ordner products/<Game>/<Produkt>/ = ein Produkt. Nur mit Preis in prices.txt sichtbar.
function products() {
  const pr = prices(), out = [];
  for (const g of fs.existsSync(ROOT) ? fs.readdirSync(ROOT) : []) {
    const gp = path.join(ROOT, g);
    if (!safe(g) || !fs.statSync(gp).isDirectory()) continue;
    for (const n of fs.readdirSync(gp)) {
      const pp = path.join(gp, n);
      if (!safe(n) || !fs.statSync(pp).isDirectory()) continue;
      const key = g + '/' + n, price = pr[key];
      if (!(price > 0)) continue;
      let d = ''; try { d = fs.readFileSync(path.join(pp, 'info.txt'), 'utf8').trim(); } catch {}
      out.push({ key, game: g, name: n, description: d, price, files: fs.readdirSync(pp).filter(f => f !== 'info.txt').length });
    }
  }
  return out;
}

app.get('/api/products', (_, res) => res.json(products()));
app.get('/api/config', (_, res) => res.json({ discord: process.env.DISCORD_URL || '' }));

// Preise werden immer serverseitig aus prices.txt gelesen, nie vom Browser
app.post('/api/checkout', async (req, res) => {
  try {
    const all = products();
    const items = [...new Set(req.body.keys || [])].map(k => all.find(p => p.key === k)).filter(Boolean);
    if (!items.length) return res.status(400).json({ error: 'Warenkorb ist leer' });
    const s = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: items.map(p => ({ quantity: 1, price_data: { currency: 'eur', unit_amount: Math.round(p.price * 100), product_data: { name: p.key } } })),
      metadata: { keys: items.map(p => p.key).join('|') },
      success_url: BASE + '/success.html?s={CHECKOUT_SESSION_ID}',
      cancel_url: BASE
    });
    res.json({ url: s.url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Nach bezahlter Bestellung: signierte Download-Links
app.get('/api/order', async (req, res) => {
  try {
    const s = await stripe.checkout.sessions.retrieve(String(req.query.s));
    if (s.payment_status !== 'paid') return res.status(402).json({ error: 'Noch nicht bezahlt' });
    const out = [];
    for (const k of s.metadata.keys.split('|')) {
      const [g, n] = k.split('/'); if (!safe(g) || !safe(n)) continue;
      for (const f of fs.readdirSync(path.join(ROOT, g, n))) {
        if (f === 'info.txt') continue;
        out.push({ product: k, file: f, url: `/download?s=${s.id}&k=${encodeURIComponent(k)}&f=${encodeURIComponent(f)}&sig=${hmac(s.id + k + f)}` });
      }
    }
    res.json(out);
  } catch { res.status(400).json({ error: 'Bestellung nicht gefunden' }); }
});
app.get('/download', (req, res) => {
  const { s, k, f, sig } = req.query;
  if (![s, k, f, sig].every(x => typeof x === 'string') || !eq(sig, hmac(s + k + f))) return res.sendStatus(403);
  const [g, n] = k.split('/');
  if (![g, n, f].every(safe)) return res.sendStatus(400);
  res.download(path.join(ROOT, g, n, f));
});

// ---- Admin (nur mit Passwort aus .env) ----
const token = () => hmac('admin:' + process.env.ADMIN_PASSWORD);
const auth = (req, res, next) => (req.headers.cookie || '').split('; ').includes('adm=' + token()) ? next() : res.sendStatus(401);
app.post('/admin/login', async (req, res) => {
  const ok = typeof req.body.password === 'string' && eq(hmac(req.body.password), hmac(process.env.ADMIN_PASSWORD));
  if (!ok) { await new Promise(r => setTimeout(r, 1000)); return res.sendStatus(401); }
  res.setHeader('Set-Cookie', `adm=${token()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
  res.json({ ok: true });
});
app.get('/admin/check', auth, (_, res) => res.json({ ok: true }));
const up = multer({ dest: path.join(__dirname, 'tmp') });
app.post('/admin/upload', auth, up.array('files', 50), (req, res) => {
  const { game, name, price, description } = req.body;
  if (!safe(game) || !safe(name) || !(parseFloat(price) > 0)) return res.status(400).json({ error: 'Ungültige Eingabe' });
  const d = path.join(ROOT, game, name); fs.mkdirSync(d, { recursive: true });
  for (const f of req.files || []) {
    const fn = path.basename(f.originalname);
    if (safe(fn)) fs.renameSync(f.path, path.join(d, fn)); else fs.unlinkSync(f.path);
  }
  fs.writeFileSync(path.join(d, 'info.txt'), description || '');
  const pf = path.join(ROOT, 'prices.txt'), key = game + '/' + name;
  const t = (fs.existsSync(pf) ? fs.readFileSync(pf, 'utf8') : '').split(/\r?\n/).filter(l => l.split('=')[0].trim() !== key).join('\n').trim();
  fs.writeFileSync(pf, `${t}\n${key} = ${price}\n`);
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('Shop läuft auf ' + BASE));
