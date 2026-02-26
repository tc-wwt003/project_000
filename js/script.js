'use strict';

const SUPABASE_URL = 'https://uyueojhfvotwyhjrgmme.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV5dWVvamhmdm90d3loanJnbW1lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzIxMjEwMTIsImV4cCI6MjA4NzY5NzAxMn0.509kaW2qTkkDEtZ4pbCxWIXxSf1DwH9DVOZLYU7d0rM';

const VISITOR_PW_DEFAULT = 'portfolio2025';
const PBKDF2_SALT        = 'a3f8e2b1c4d5e6f7a8b9c0d1e2f3a4b5';
const PBKDF2_ITERS       = 250000;

/* Session TTL — visitor sessions expire after 24h */
const SESS_TTL = 24 * 3600_000;

/* Brute-force lockout tiers */
const LOCKOUT_TIERS = [
  { after: 3,  ms: 30_000    },  // 30 seconds
  { after: 5,  ms: 300_000   },  // 5 minutes
  { after: 10, ms: 3_600_000 },  // 1 hour
];
const LK = 'rs_lo_v'; // localStorage lockout key

/* ─── Supabase client init ──────────────────────────── */
let _db   = null;
let _auth = null;
let _ok   = false;

function initSupabase() {
  try {
    if (SUPABASE_URL === 'REPLACE_ME' || SUPABASE_KEY === 'REPLACE_ME') 
     {
      console.warn('Supabase config not set — running in offline-demo mode.');
      return false;
    }
    const client = supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: {
        // Keep admin session in memory only — cleared on tab close
        persistSession: false,
        autoRefreshToken: true,
      }
    });
    _db   = client;
    _auth = client.auth;
    _ok   = true;
    return true;
  } catch (e) {
    console.error('Supabase init failed:', e);
    return false;
  }
}

/* ═══════════════════════════════════════════════════════
   DATABASE HELPERS  (thin wrappers around Supabase client)
   ═══════════════════════════════════════════════════════ */

/* VISITORS */
async function dbGetVisitors() {
  if (!_ok) return [];
  try {
    const { data, error } = await _db
      .from('visitors')
      .select('*')
      .order('ts', { ascending: false });
    if (error) throw error;
    return data || [];
  } catch (e) { console.error('getVisitors:', e); return []; }
}

async function dbAddVisitor(rec) {
  if (!_ok) return { rec, isNew: false };
  try {
    const { error } = await _db
      .from('visitors')
      .insert([rec]);

    if (error) {
      // 23505 = unique_violation — email already registered, not a real error
      if (error.code === '23505') return { rec, isNew: false };
      throw error;
    }
    // Insert succeeded — this is a new visitor
    return { rec, isNew: true };
  } catch (e) {
    console.error('addVisitor:', e);
    return { rec, isNew: false };
  }
}

/* POSTS */
async function dbGetPosts(includeAll = false) {
  if (!_ok) return [];
  try {
    let q = _db.from('posts').select('*').order('ts', { ascending: false });
    if (!includeAll) q = q.eq('published', true);
    const { data, error } = await q;
    if (error) throw error;
    return data || [];
  } catch (e) { console.error('getPosts:', e); return []; }
}

async function dbSavePost(post) {
  if (!_ok) throw new Error('Supabase not connected');
  const { id, ...fields } = post;
  if (id) {
    // Update existing post
    const { error } = await _db
      .from('posts')
      .update(fields)
      .eq('id', id);
    if (error) throw error;
    return id;
  } else {
    // Insert new post
    const { data, error } = await _db
      .from('posts')
      .insert([fields])
      .select('id')
      .single();
    if (error) throw error;
    return data.id;
  }
}

async function dbUpdatePostField(id, fields) {
  if (!_ok) throw new Error('Supabase not connected');
  const { error } = await _db.from('posts').update(fields).eq('id', id);
  if (error) throw error;
}

async function dbDeletePost(id) {
  if (!_ok) throw new Error('Supabase not connected');
  const { error } = await _db.from('posts').delete().eq('id', id);
  if (error) throw error;
}

/* CONFIG */
async function dbGetSecConfig() {
  if (!_ok) return null;
  try {
    const { data, error } = await _db
      .from('config')
      .select('data')
      .eq('id', 'security')
      .maybeSingle();
    if (error) throw error;
    return data?.data || null;
  } catch { return null; }
}

async function dbSetSecConfig(payload) {
  if (!_ok) throw new Error('Supabase not connected');
  const { error } = await _db
    .from('config')
    .upsert([{ id: 'security', data: payload }], { onConflict: 'id' });
  if (error) throw error;
}

/* ═══════════════════════════════════════════════════════
   CRYPTO  (Web Crypto API — standard in all browsers)
   ═══════════════════════════════════════════════════════ */
function hex2buf(hex) {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) a[i/2] = parseInt(hex.slice(i, i+2), 16);
  return a;
}
function buf2hex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2,'0')).join('');
}
async function genHash(pw, saltHex) {
  const km = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt:hex2buf(saltHex), iterations:PBKDF2_ITERS, hash:'SHA-256' },
    km, 256
  );
  return buf2hex(new Uint8Array(bits));
}

/* ═══════════════════════════════════════════════════════
   BRUTE-FORCE LOCKOUT  (localStorage — per-device)
   ═══════════════════════════════════════════════════════ */
function getLO()   { try { return JSON.parse(localStorage.getItem(LK)) || {n:0,until:0}; } catch { return {n:0,until:0}; } }
function setLO(d)  { try { localStorage.setItem(LK, JSON.stringify(d)); } catch {} }
function clearLO() { try { localStorage.removeItem(LK); } catch {} }
function isLocked() { return getLO().until > Date.now(); }

function failAttempt() {
  const lo = getLO();
  lo.n = (lo.n || 0) + 1;
  const tier = [...LOCKOUT_TIERS].reverse().find(x => lo.n >= x.after);
  if (tier) lo.until = Date.now() + tier.ms;
  setLO(lo);
  return lo;
}

function lockMsg(until) {
  const s = Math.ceil((until - Date.now()) / 1000);
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.ceil(s/60)}m` : `${Math.ceil(s/3600)}h`;
}

/* ═══════════════════════════════════════════════════════
   VISITOR SESSION  (localStorage with expiry timestamp)
   ═══════════════════════════════════════════════════════ */
const SK = 'rs_sess';
function getSess() {
  try {
    const s = JSON.parse(localStorage.getItem(SK));
    if (!s) return null;
    if (s.exp && Date.now() > s.exp) { localStorage.removeItem(SK); return null; }
    return s;
  } catch { return null; }
}
function setSess(d) { try { localStorage.setItem(SK, JSON.stringify({...d, exp: Date.now() + SESS_TTL})); } catch {} }
function delSess()  { try { localStorage.removeItem(SK); } catch {} }

/* ─── General utils ─────────────────────────────────── */
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
let _tT;
function toast(h, ms=3500) {
  const t = document.getElementById('toast');
  t.innerHTML = h; t.classList.add('show');
  clearTimeout(_tT); _tT = setTimeout(() => t.classList.remove('show'), ms);
}

/* ═══════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════ */
let _vHash = null; // visitor pw hash held in memory only

async function init() {
  const ok = initSupabase();

  // Show Supabase badge in nav when connected
  if (ok) document.getElementById('db-badge').style.display = 'inline-flex';

  // Load visitor pw hash: from Supabase config table, or derive from default
  const cfg = await dbGetSecConfig();
  _vHash = cfg?.vHash
    ? cfg.vHash
    : await genHash(VISITOR_PW_DEFAULT, PBKDF2_SALT);

  // Visitor count on gate page
  const visitors = await dbGetVisitors();
  document.getElementById('gate-count').textContent = visitors.length || 0;

  // Resume existing visitor session if still valid
  const sess = getSess();
  if (sess) enterPf(sess, false);

  // Keyboard shortcut: Ctrl+Shift+A → admin gate
  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.shiftKey && e.key === 'A') { e.preventDefault(); openAdminGate(); }
  });

  // Sync admin panel if Supabase auth session expires mid-use
  if (_auth) {
    _auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_OUT' && document.getElementById('admin-overlay').classList.contains('open')) {
        exitAdmin(true);
      }
    });
  }
}

/* ═══════════════════════════════════════════════════════
   VISITOR GATE
   ═══════════════════════════════════════════════════════ */
document.getElementById('pw-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') checkPw();
});

async function checkPw() {
  const inp = document.getElementById('pw-input');
  const err = document.getElementById('pw-error');

  // 1 — check lockout before any crypto work
  if (isLocked()) {
    err.textContent = `Too many attempts. Locked for ${lockMsg(getLO().until)}.`;
    err.classList.add('show');
    inp.classList.add('shake'); setTimeout(() => inp.classList.remove('shake'), 500);
    return;
  }

  // 2 — hash input and compare (never compare plaintext)
  const inputHash = await genHash(inp.value, PBKDF2_SALT);
  if (inputHash === _vHash) {
    clearLO();
    err.classList.remove('show');
    inp.style.borderColor = 'var(--green)';
    inp.style.boxShadow = '0 0 0 1px var(--green),0 0 24px rgba(57,255,138,.1)';
    setTimeout(() => {
      document.getElementById('vf-section').classList.add('visible');
      document.getElementById('vf-name').focus();
    }, 300);
  } else {
    const lo = failAttempt();
    inp.classList.add('shake');
    err.textContent = lo.until > Date.now()
      ? `Access denied. Locked for ${lockMsg(lo.until)}.`
      : `Incorrect. ${(LOCKOUT_TIERS.find(x => lo.n < x.after)?.after - lo.n) || '?'} attempt(s) until lockout.`;
    err.classList.add('show');
    setTimeout(() => inp.classList.remove('shake'), 500);
  }
}

async function registerAndEnter() {
  const name  = document.getElementById('vf-name').value.trim();
  const email = document.getElementById('vf-email').value.trim();
  const co    = document.getElementById('vf-co').value.trim();
  let ok = true;
  ['vf-name','vf-email','vf-co'].forEach(id => document.getElementById(id).classList.remove('err'));
  if (!name)  { document.getElementById('vf-name').classList.add('err');  ok = false; }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    document.getElementById('vf-email').classList.add('err'); ok = false;
  }
  if (!co)    { document.getElementById('vf-co').classList.add('err');    ok = false; }
  if (!ok) return;

  const btn = document.querySelector('.vf-submit');
  btn.textContent = 'Saving...'; btn.disabled = true;

  const rec = {
    name, email, company: co,
    date: new Date().toLocaleDateString('en-US', {month:'short',day:'numeric',year:'numeric'}),
    mo:   `${new Date().getMonth()}:${new Date().getFullYear()}`,
    ts:   Date.now(),
  };

  const { rec: saved, isNew } = await dbAddVisitor(rec);
  setSess(saved);
  btn.textContent = 'CONFIRM IDENTITY → ENTER'; btn.disabled = false;
  enterPf(saved, isNew);
}

async function skipReg() {
  // Anon users have no SELECT on visitors, so we can't query by email.
  // Returning visitors will have a valid session in localStorage — check that first.
  const sess = getSess();
  if (sess) {
    enterPf(sess, false);
    return;
  }

  // No local session — ask for email and attempt a re-insert.
  // If the unique constraint fires (23505), the email is registered
  // and we reconstruct a minimal session from what they typed.
  const email = prompt('Enter your registered email address:');
  if (!email) return;
  const trimmed = email.trim().toLowerCase();
  if (!trimmed || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    toast('<span class="hi">Please enter a valid email address.</span>');
    return;
  }

  if (_ok) {
    // Attempt insert of a minimal probe record with ts:-1 as a sentinel
    const probe = { name: '~probe~', email: trimmed, company: '~probe~', date: '', mo: '', ts: -1 };
    const { error } = await _db.from('visitors').insert([probe]);

    if (error?.code === '23505') {
      // Unique violation — email definitely exists in the table
      const sess = { name: trimmed.split('@')[0], email: trimmed, company: '' };
      setSess(sess);
      enterPf(sess, false);
      return;
    }

    if (!error) {
      // Insert went through — email was not registered, clean up the probe
      await _db.from('visitors').delete().match({ email: trimmed, ts: -1 });
    }
    toast('<span class="hi">Email not found.</span> Please fill in the form above.');
    return;
  }

  // Supabase offline fallback
  toast('<span class="hi">Email not found.</span> Please fill in the form above.');
}

async function enterPf(s, isNew) {
  document.getElementById('gate-page').classList.remove('active');
  document.getElementById('portfolio-page').classList.add('active');
  const first = s.name.split(' ')[0];
  document.getElementById('nav-name').textContent = first;
  document.getElementById('sess-lbl').textContent = 'SESSION: ' + first.toUpperCase();
  if (isNew) toast(`<span class="ok">✓ Access granted.</span> Welcome, <span class="hi">${esc(s.name)}</span>. You're in the log.`, 4500);
  else        toast(`<span class="ok">✓</span> Welcome back, <span class="hi">${esc(first)}</span>.`, 3000);
}

async function loadLog() {
  // Visitor log moved to admin panel — anon users have no SELECT on visitors.
  // Nothing to update on the public side.
}

function switchTab(name, btn) {
  document.querySelectorAll('.tab-btn').forEach(b  => b.classList.remove('active'));
  document.querySelectorAll('.section').forEach(s  => s.classList.remove('visible'));
  if (btn) btn.classList.add('active');
  document.getElementById('sec-' + name).classList.add('visible');
  if (name === 'vis')  loadLog();
  if (name === 'soc')  setTimeout(triggerSkills, 100);
  if (name === 'blog') loadBlog();
}

function triggerSkills() {
  document.querySelectorAll('.skill-fill').forEach((el, i) => {
    setTimeout(() => { el.style.width = el.dataset.w + '%'; }, i * 80);
  });
}

async function exitPf() {
  delSess();
  document.getElementById('portfolio-page').classList.remove('active');
  document.getElementById('gate-page').classList.add('active');
  const inp = document.getElementById('pw-input');
  inp.value = ''; inp.style.borderColor = ''; inp.style.boxShadow = '';
  document.getElementById('vf-section').classList.remove('visible');
  const visitors = await dbGetVisitors();
  document.getElementById('gate-count').textContent = visitors.length;
}

/* ═══════════════════════════════════════════════════════
   BLOG — VISITOR SIDE
   ═══════════════════════════════════════════════════════ */
let blogFilter  = 'all';
let cachedPosts = [];
const catColors = {
  security:'var(--cyan)', development:'var(--green)',
  art:'var(--orange)',    general:'var(--dim)'
};

async function loadBlog() {
  document.getElementById('blog-post-list').innerHTML =
    '<div class="blog-empty"><div class="be-icon">◈</div><div class="be-txt">Loading...<br><span>Fetching from Supabase</span></div></div>';
  cachedPosts = await dbGetPosts(false);
  renderBlogList();
}

function filterBlog(cat, btn) {
  blogFilter = cat;
  document.querySelectorAll('.bf-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderBlogList();
}

function renderBlogList() {
  const filtered = blogFilter === 'all'
    ? cachedPosts
    : cachedPosts.filter(p => p.category === blogFilter);
  document.getElementById('blog-count-lbl').textContent =
    filtered.length + ' post' + (filtered.length !== 1 ? 's' : '');
  const c = document.getElementById('blog-post-list');
  if (!filtered.length) {
    c.innerHTML = `<div class="blog-empty"><div class="be-icon">◈</div>
      <div class="be-txt">${blogFilter === 'all'
        ? 'No posts published yet.<br><span>Check back soon.</span>'
        : 'No posts in this category.'}</div></div>`;
    return;
  }
  c.innerHTML = filtered.map(p => {
    const tags = (p.tags || []).filter(Boolean);
    return `<div class="post-row" onclick="openBlogPost('${esc(p.id)}')">
      <div class="post-meta-col">
        <div class="post-date-sm">${esc(p.date||'')}</div>
        <div class="post-cat-badge ${esc(p.category||'general')}">${esc(p.category||'general')}</div>
      </div>
      <div>
        <div class="post-title-main">${esc(p.title)}</div>
        <div class="post-excerpt">${esc(p.excerpt||'')}</div>
        ${tags.length ? `<div class="post-tags-row">${tags.map(t=>`<span class="ptag-sm">${esc(t.trim())}</span>`).join('')}</div>` : ''}
      </div>
      <div class="post-arrow">→</div>
    </div>`;
  }).join('');
}

async function openBlogPost(id) {
  const post = cachedPosts.find(p => p.id === id);
  if (!post) return;
  document.getElementById('pd-cat').textContent  = post.category || 'general';
  document.getElementById('pd-cat').style.color  = catColors[post.category] || 'var(--dim)';
  document.getElementById('pd-title').textContent = post.title;
  document.getElementById('pd-date').textContent  = post.date || '';
  const tags = (post.tags || []).filter(Boolean);
  document.getElementById('pd-tags-byline').textContent = tags.length ? '#' + tags.slice(0,3).join(' #') : '';
  document.getElementById('pd-body').innerHTML = renderMd(post.body || '');
  document.getElementById('pd-tags-footer').innerHTML = tags.length
    ? `<span class="lbl">Tags:</span>${tags.map(t=>`<span class="ptag-sm">${esc(t.trim())}</span>`).join('')}`
    : '';
  document.getElementById('blog-list-view').style.display = 'none';
  const dv = document.getElementById('blog-detail-view');
  dv.classList.add('visible');
  dv.scrollIntoView({ behavior:'smooth', block:'start' });
}

function closeBlogPost() {
  document.getElementById('blog-detail-view').classList.remove('visible');
  document.getElementById('blog-list-view').style.display = 'block';
}

/* Markdown renderer — escapes ALL content first, then applies safe structural transforms */
function renderMd(raw) {
  if (!raw) return '';
  let h = esc(raw);
  h = h.replace(/```([\s\S]*?)```/g, (_, c) => `<pre><code>${c.trim()}</code></pre>`);
  h = h.replace(/^### (.+)$/gm, (_, t) => `<h3>${t}</h3>`);
  h = h.replace(/^## (.+)$/gm,  (_, t) => `<h2>${t}</h2>`);
  h = h.replace(/\*\*(.+?)\*\*/g, (_, t) => `<strong>${t}</strong>`);
  h = h.replace(/`([^`]+)`/g,    (_, c) => `<code>${c}</code>`);
  h = h.replace(/^&gt; (.+)$/gm, (_, t) => `<blockquote><p>${t}</p></blockquote>`);
  h = h.replace(/^- (.+)$/gm,    (_, t) => `<li>${t}</li>`);
  h = h.replace(/(<li>[\s\S]*?<\/li>\n?)+/g, m => `<ul>${m}</ul>`);
  return h.split(/\n\n+/).map(p => {
    const t = p.trim(); if (!t) return '';
    if (/^<(h[23]|ul|pre|blockquote)/.test(t)) return t;
    return `<p>${t.replace(/\n/g, '<br>')}</p>`;
  }).join('\n');
}

/* ═══════════════════════════════════════════════════════
   ADMIN GATE — Supabase Auth (email + password)
   ═══════════════════════════════════════════════════════ */
function openAdminGate() {
  if (!_ok) {
    toast('<span style="color:var(--red)">Supabase not configured.</span> Add your project URL and anon key first.', 5000);
    return;
  }
  // Skip gate if already signed in
  _auth.getSession().then(({ data: { session } }) => {
    if (session) { openAdminPanel(); return; }
    document.getElementById('admin-gate').classList.add('open');
    setTimeout(() => document.getElementById('ag-email').focus(), 100);
  });
}

function closeAdminGate() {
  document.getElementById('admin-gate').classList.remove('open');
  document.getElementById('ag-email').value = '';
  document.getElementById('ag-pw').value    = '';
  document.getElementById('ag-error').classList.remove('show');
}

async function checkAdminPw() {
  const email = document.getElementById('ag-email').value.trim();
  const pw    = document.getElementById('ag-pw').value;
  const err   = document.getElementById('ag-error');
  const btn   = document.getElementById('ag-submit-btn');
  if (!email || !pw) { err.textContent = 'Email and password required.'; err.classList.add('show'); return; }

  btn.classList.add('loading');
  err.classList.remove('show');

  const { error } = await _auth.signInWithPassword({ email, password: pw });

  btn.classList.remove('loading');

  if (error) {
    const msg = error.status === 400
      ? 'Invalid email or password.'
      : error.status === 429
      ? 'Too many attempts. Try again later.'
      : 'Sign-in failed: ' + error.message;
    err.textContent = msg;
    err.classList.add('show');
    document.getElementById('ag-pw').classList.add('shake');
    setTimeout(() => document.getElementById('ag-pw').classList.remove('shake'), 500);
  } else {
    closeAdminGate();
    openAdminPanel();
  }
}

/* ═══════════════════════════════════════════════════════
   ADMIN PANEL
   ═══════════════════════════════════════════════════════ */
async function openAdminPanel() {
  document.getElementById('admin-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  const { data: { session } } = await _auth.getSession();
  document.getElementById('admin-email-lbl').textContent = session?.user?.email || 'admin';
  await refreshAdminData();
  adminTab('dashboard', document.querySelector('.admin-sidebar-item'));
}

async function exitAdmin(silent = false) {
  try { await _auth.signOut(); } catch {}
  document.getElementById('admin-overlay').classList.remove('open');
  document.body.style.overflow = '';
  if (!silent) toast('<span class="hi">Admin session ended.</span>', 2500);
}

async function refreshAdminData() {
  const [posts, visitors] = await Promise.all([dbGetPosts(true), dbGetVisitors()]);
  document.getElementById('a-stat-pub').textContent   = posts.filter(p => p.published).length;
  document.getElementById('a-stat-draft').textContent = posts.filter(p => !p.published).length;
  document.getElementById('a-stat-vis').textContent   = visitors.length;
  document.getElementById('a-stat-total').textContent = posts.length;
  renderAdminMiniList('admin-recent-list', posts.slice(0, 5));
  document.getElementById('admin-vis-count').textContent = visitors.length + ' records';
  document.getElementById('admin-vis-tbody').innerHTML = visitors.length
    ? visitors.map(v =>
        `<tr><td class="nc">${esc(v.name)}</td><td>${esc(v.email)}</td><td>${esc(v.company||'—')}</td><td>${esc(v.date||'—')}</td></tr>`
      ).join('')
    : '<tr><td colspan="4" style="color:var(--dimmer)">No visitors yet.</td></tr>';
}

function renderAdminMiniList(containerId, posts) {
  const c = document.getElementById(containerId);
  if (!c) return;
  if (!posts.length) {
    c.innerHTML = `<div style="padding:20px;font-family:'Share Tech Mono';font-size:10px;color:var(--dimmer)">No posts yet. Create your first →</div>`;
    return;
  }
  c.innerHTML = posts.map(p => `
    <div class="admin-post-row">
      <div class="apr-status ${p.published ? 'pub' : 'draft'}"></div>
      <div class="apr-info">
        <div class="apr-title">${esc(p.title)}</div>
        <div class="apr-sub">${esc((p.category||'general').toUpperCase())} · ${esc(p.date||'—')} · ${p.published
          ? '<span style="color:var(--green)">Published</span>'
          : '<span style="color:var(--dimmer)">Draft</span>'}</div>
      </div>
      <div class="apr-actions">
        <button class="apr-act-btn" onclick="editPost('${esc(p.id)}')">Edit</button>
        <button class="apr-act-btn" onclick="togglePublish('${esc(p.id)}',${!p.published})">${p.published ? 'Unpublish' : 'Publish'}</button>
        <button class="apr-act-btn del" onclick="confirmDelete('${esc(p.id)}','${esc(p.title)}')">Delete</button>
      </div>
    </div>`).join('');
}

async function renderAdminPostList() {
  let posts = await dbGetPosts(true);
  const f   = document.getElementById('admin-filter-status').value;
  if (f === 'published') posts = posts.filter(p =>  p.published);
  if (f === 'draft')     posts = posts.filter(p => !p.published);
  renderAdminMiniList('admin-all-posts-list', posts);
}

function adminTab(name, btn) {
  document.querySelectorAll('.admin-sidebar-item').forEach(i => i.classList.remove('active'));
  document.querySelectorAll('.admin-panel').forEach(p  => p.classList.remove('active'));
  if (btn) {
    btn.classList.add('active');
  } else {
    document.querySelectorAll('.admin-sidebar-item').forEach(i => {
      if (i.getAttribute('onclick')?.includes(`'${name}'`)) i.classList.add('active');
    });
  }
  const panel = document.getElementById('admin-panel-' + name);
  if (panel) panel.classList.add('active');
  if (name === 'posts')    renderAdminPostList();
  if (name === 'new')      resetEditor();
  if (name === 'security') loadSecurityPanel();
}

/* ─── Post editor ─────────────────────────────────── */
function resetEditor() {
  ['pf-id','pf-title','pf-tags','pf-excerpt','pf-body'].forEach(id => { document.getElementById(id).value = ''; });
  document.getElementById('pf-cat').value = '';
  document.getElementById('pf-published').checked = true;
  document.getElementById('editor-panel-title').textContent  = 'New Post';
  document.getElementById('publish-status-lbl').textContent = 'visible to visitors';
}

document.getElementById('pf-published').addEventListener('change', function () {
  document.getElementById('publish-status-lbl').textContent = this.checked
    ? 'visible to visitors' : 'saved as draft only';
});

async function editPost(id) {
  const posts = await dbGetPosts(true);
  const p = posts.find(x => x.id === id);
  if (!p) return;
  document.getElementById('pf-id').value      = p.id;
  document.getElementById('pf-title').value   = p.title   || '';
  document.getElementById('pf-cat').value     = p.category|| '';
  document.getElementById('pf-tags').value    = (p.tags   || []).join(', ');
  document.getElementById('pf-excerpt').value = p.excerpt || '';
  document.getElementById('pf-body').value    = p.body    || '';
  document.getElementById('pf-published').checked = !!p.published;
  document.getElementById('editor-panel-title').textContent = 'Edit Post';
  adminTab('new', null);
}

function cancelEdit() { adminTab('posts', null); }

async function savePost() {
  const title   = document.getElementById('pf-title').value.trim();
  const cat     = document.getElementById('pf-cat').value;
  const tags    = document.getElementById('pf-tags').value.split(',').map(t => t.trim()).filter(Boolean);
  const excerpt = document.getElementById('pf-excerpt').value.trim();
  const body    = document.getElementById('pf-body').value.trim();
  const pub     = document.getElementById('pf-published').checked;
  const eid     = document.getElementById('pf-id').value;
  if (!title || !cat || !excerpt || !body) {
    toast('<span style="color:var(--red)">✕ Fill in all required fields.</span>');
    return;
  }
  const date = new Date().toLocaleDateString('en-US', {month:'short',day:'numeric',year:'numeric'});
  try {
    await dbSavePost({
      ...(eid ? { id: eid } : {}),
      title, category: cat, tags, excerpt, body,
      published: pub, date,
      ...(eid ? {} : { ts: Date.now() }),
    });
    await refreshAdminData();
    if (document.getElementById('sec-blog').classList.contains('visible')) await loadBlog();
    toast(`<span class="ok">✓ Post ${eid ? 'updated' : 'saved'}.</span> "${esc(title)}"`, 4000);
    adminTab('posts', null);
  } catch (e) {
    toast(`<span style="color:var(--red)">✕ Save failed: ${esc(e.message)}</span>`, 5000);
  }
}

async function togglePublish(id, newState) {
  try {
    await dbUpdatePostField(id, { published: newState });
    await refreshAdminData();
    if (document.getElementById('sec-blog').classList.contains('visible')) await loadBlog();
    toast(`<span class="ok">✓</span> Post ${newState ? '<span class="ok">published</span>' : 'unpublished'}.`);
    renderAdminPostList();
  } catch (e) { toast(`<span style="color:var(--red)">✕ ${esc(e.message)}</span>`); }
}

let _delId = null;
function confirmDelete(id, title) {
  _delId = id;
  document.getElementById('cm-body').textContent = `Delete "${title}"? This cannot be undone.`;
  document.getElementById('confirm-modal').classList.add('open');
}
function closeConfirm() { document.getElementById('confirm-modal').classList.remove('open'); _delId = null; }

document.getElementById('cm-confirm-btn').addEventListener('click', async () => {
  if (!_delId) return;
  try {
    await dbDeletePost(_delId);
    await refreshAdminData();
    if (document.getElementById('sec-blog').classList.contains('visible')) await loadBlog();
    renderAdminPostList();
    toast('<span style="color:var(--red)">Post deleted.</span>');
  } catch (e) { toast(`<span style="color:var(--red)">✕ ${esc(e.message)}</span>`); }
  closeConfirm();
});

document.getElementById('confirm-modal').addEventListener('click', function (e) {
  if (e.target === this) closeConfirm();
});

/* ─── Security panel ──────────────────────────────── */
async function loadSecurityPanel() {
  const cfg = await dbGetSecConfig();
  const el  = document.getElementById('sec-panel-status');
  if (cfg?.vHash) {
    el.innerHTML = `<span style="color:var(--green)">✓ Custom visitor password active.</span>
      Stored as PBKDF2-SHA256 hash in Supabase.<br>
      <span style="color:var(--dimmer)">Last updated: ${cfg.updatedAt ? new Date(cfg.updatedAt).toLocaleString() : 'unknown'}</span>`;
  } else {
    el.innerHTML = `<span style="color:var(--amber)">⚠ Using default visitor password.</span><br>
      Set a custom password below to activate hash-only mode.`;
  }
  document.getElementById('new-visitor-pw').value = '';
}

async function saveNewVisitorPassword() {
  const pw  = document.getElementById('new-visitor-pw').value;
  if (!pw || pw.length < 10) {
    toast('<span style="color:var(--red)">✕ Password must be at least 10 characters.</span>');
    return;
  }
  const btn = document.querySelector('[onclick="saveNewVisitorPassword()"]');
  btn.disabled = true; btn.textContent = 'Hashing... (~1s)';
  try {
    const hash = await genHash(pw, PBKDF2_SALT);
    await dbSetSecConfig({ vHash: hash, updatedAt: Date.now() });
    _vHash = hash; // update in-memory hash immediately
    toast('<span class="ok">✓ Visitor password updated.</span> Hash stored in Supabase.', 5000);
    await loadSecurityPanel();
  } catch (e) {
    toast(`<span style="color:var(--red)">✕ Save failed: ${esc(e.message)}</span>`);
  } finally {
    btn.disabled = false; btn.textContent = 'Hash & Save →';
  }
}

init();
