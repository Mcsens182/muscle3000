/* Muscle 3000 — end-of-rest notifications.
   The app tells this worker "notify this phone at time T"; a Durable Object alarm fires at T
   and sends a Web Push (VAPID + aes128gcm payload, RFC 8291/8292).
   No secret to configure: the VAPID key pair is created on first use and kept in storage. */
import { DurableObject } from 'cloudflare:workers';

const ALLOWED = ['https://mcsens182.github.io', 'http://localhost:8765'];
const SUBJECT = 'https://mcsens182.github.io/muscle3000/';

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const concat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8));
}

/* RFC 8291: encrypt the payload for one subscription */
export async function encryptPayload(sub, text) {
  const uaPublic = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, concat(enc.encode(text), new Uint8Array([2]))));
  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(salt, 0); new DataView(header.buffer).setUint32(16, 4096); header[20] = asPublic.length; header.set(asPublic, 21);
  return concat(header, cipher);
}

/* RFC 8292: VAPID authorization header */
export async function vapidHeader(endpoint, keys) {
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const priv = await crypto.subtle.importKey('jwk', keys.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, enc.encode(head + '.' + body));
  return 'vapid t=' + head + '.' + body + '.' + b64u(sig) + ', k=' + keys.publicKey;
}

export async function newKeys() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { publicKey: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)), privateJwk: await crypto.subtle.exportKey('jwk', kp.privateKey) };
}

export class Pusher extends DurableObject {
  /* the "keys" instance holds the VAPID pair */
  async keys() {
    let k = await this.ctx.storage.get('keys');
    if (!k) { k = await newKeys(); await this.ctx.storage.put('keys', k); }
    return k;
  }
  /* one instance per phone: one pending notification at most, replaced by each new rest */
  async schedule(job) {
    await this.ctx.storage.put('job', job);
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 500, job.at));
  }
  async cancel() {
    await this.ctx.storage.delete('job');
    await this.ctx.storage.deleteAlarm();
  }
  async alarm() {
    const job = await this.ctx.storage.get('job'); if (!job) return;
    await this.ctx.storage.delete('job');
    let res; try { res = await fetch(job.sub.endpoint, {
      method: 'POST',
      headers: { Authorization: await vapidHeader(job.sub.endpoint, job.keys), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '120', Urgency: 'high' },
      body: await encryptPayload(job.sub, JSON.stringify({ title: job.title, body: job.body, tag: 'rest' }))
    }); } catch (e) { console.log('push error', String(e)); return; }
    if (!res.ok) console.log('push failed', res.status, await res.text());
  }
}

function cors(req) {
  const o = req.headers.get('Origin');
  return { 'Access-Control-Allow-Origin': ALLOWED.includes(o) ? o : ALLOWED[0], 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
}
const json = (req, data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...cors(req) } });

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors(req) });
    const url = new URL(req.url), keysObj = env.PUSH.get(env.PUSH.idFromName('vapid-keys'));
    if (url.pathname === '/key') return json(req, { key: (await keysObj.keys()).publicKey });
    if (req.method !== 'POST') return json(req, { ok: true, service: 'muscle3000-push' });
    let d; try { d = JSON.parse(await req.text()); } catch (e) { return json(req, { error: 'bad json' }, 400); }
    const ep = d && d.sub && d.sub.endpoint;
    if (!ep || !/^https:\/\//.test(ep) || !d.sub.keys || !d.sub.keys.p256dh || !d.sub.keys.auth) return json(req, { error: 'bad subscription' }, 400);
    const phone = env.PUSH.get(env.PUSH.idFromName('sub:' + ep));
    if (url.pathname === '/cancel') { await phone.cancel(); return json(req, { ok: true }); }
    if (url.pathname === '/schedule') {
      const at = +d.at; if (!(at > Date.now() - 5000 && at < Date.now() + 3 * 3600e3)) return json(req, { error: 'bad time' }, 400);
      await phone.schedule({ at, sub: d.sub, keys: await keysObj.keys(), title: String(d.title || 'Repos terminé').slice(0, 80), body: String(d.body || '').slice(0, 160) });
      return json(req, { ok: true });
    }
    return json(req, { error: 'not found' }, 404);
  }
};
