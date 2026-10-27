// "Sign in with Pubky Ring" OpenID Connect provider.
//
// A standard OpenID Connect provider (oidc-provider) whose only authentication
// step is a Pubky Ring QR code. The `sub` it issues is the user's Pubky public
// key (z-base-32), so a relying party can use it as a stable user ID; a Matrix
// server such as Tuwunel can take it as the Matrix localpart
// (`userid_claims = ["sub"]`).
//
// The Ring flow runs ENTIRELY on the server: the browser only shows the QR code
// and polls for the result. No homeserver cookie is ever set in the visitor's
// browser, so Safari's third-party cookie blocking does not get in the way.

import { createServer } from 'node:http'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { dirname } from 'node:path'
import Provider from 'oidc-provider'
import QRCode from 'qrcode'
import { Pubky, AuthFlowKind, PublicKey } from '@synonymdev/pubky'

const env = (name, fallback) => {
  const v = process.env[name] ?? fallback
  if (v === undefined) throw new Error(`Missing environment variable: ${name}`)
  return v
}

const PORT = Number(env('PORT', '4000'))
const ISSUER = env('ISSUER', `http://localhost:${PORT}`)
const CLIENT_ID = env('CLIENT_ID', 'pubky-ring')
const CLIENT_SECRET = env('CLIENT_SECRET')
const REDIRECT_URIS = env('REDIRECT_URIS').split(',').map((s) => s.trim())
const KEYS_FILE = env('KEYS_FILE', './data/keys.json')
const NEXUS_URL = env('NEXUS_URL', 'https://nexus.pubky.app')
const PUBKY_RELAY = process.env.PUBKY_RELAY || null
// Optional: only Pubky users whose homeserver is one of these public keys may
// sign in (comma-separated z-base-32 keys). Empty: any Pubky user.
const ALLOWED_HOMESERVERS = (process.env.ALLOWED_HOMESERVERS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
// How long a QR code stays valid before its flow is dropped.
const FLOW_TTL_MS = 10 * 60 * 1000

// --- Persistent keys --------------------------------------------------------
// The token and cookie signing keys must survive a restart, otherwise every
// session in progress becomes invalid.
function loadKeys() {
  if (existsSync(KEYS_FILE)) return JSON.parse(readFileSync(KEYS_FILE, 'utf8'))
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...privateKey.export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid: randomBytes(8).toString('hex') }
  const keys = { jwks: { keys: [jwk] }, cookies: [randomBytes(32).toString('base64url')] }
  mkdirSync(dirname(KEYS_FILE), { recursive: true })
  writeFileSync(KEYS_FILE, JSON.stringify(keys), { mode: 0o600 })
  return keys
}
const keys = loadKeys()

// --- Pubky profile ----------------------------------------------------------
// The display name comes from Nexus. A key unknown to Nexus (404) or an
// unreachable Nexus must not block the sign-in: fall back to a short name
// derived from the key.
async function pubkyName(key) {
  try {
    const r = await fetch(`${NEXUS_URL}/v0/user/${key}/details`, { signal: AbortSignal.timeout(3000) })
    if (r.ok) {
      const { name } = await r.json()
      if (typeof name === 'string' && name.trim()) return name.trim()
    }
  } catch {
    // Deliberate fallback: the name is only a display nicety.
  }
  return `pubky ${key.slice(0, 4)}…${key.slice(-4)}`
}

// --- OIDC provider ----------------------------------------------------------
const provider = new Provider(ISSUER, {
  clients: [
    {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uris: REDIRECT_URIS,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    },
  ],
  jwks: keys.jwks,
  cookies: { keys: keys.cookies },
  claims: { openid: ['sub'], profile: ['name', 'preferred_username'] },
  features: { devInteractions: { enabled: false } },
  interactions: { url: (ctx, interaction) => `/interaction/${interaction.uid}` },
  async findAccount(ctx, sub) {
    return {
      accountId: sub,
      async claims() {
        return { sub, preferred_username: sub, name: await pubkyName(sub) }
      },
    }
  },
})
// Behind a TLS reverse proxy (Traefik, Caddy, nginx): trust X-Forwarded-*.
provider.proxy = true

// --- Ring flows in progress -------------------------------------------------
// interaction uid -> { url, key, error, expires }
const flows = new Map()
const pubky = new Pubky()

function startFlow(uid) {
  const flow = pubky.startCookieAuthFlow('', AuthFlowKind.signin(), PUBKY_RELAY)
  const state = { url: flow.authorizationUrl, key: null, error: null, expires: Date.now() + FLOW_TTL_MS }
  flows.set(uid, state)
  flow
    .awaitToken()
    // `publicKey` is a property (pubky.d.ts), despite the `publicKey()` example in its docs.
    .then(async (token) => {
      const key = token.publicKey.z32()
      if (ALLOWED_HOMESERVERS.length) {
        // Where the user's own pkarr record says their homeserver is.
        const home = await pubky.getHomeserverOf(PublicKey.from(key))
        if (!home || !ALLOWED_HOMESERVERS.includes(home.z32())) {
          state.error = 'this Pubky account is not a member of this homeserver'
          return
        }
      }
      state.key = key
    })
    .catch((e) => { state.error = e?.message ?? String(e) })
  return state
}

setInterval(() => {
  const now = Date.now()
  for (const [uid, state] of flows) if (state.expires < now) flows.delete(uid)
}, 60_000).unref()

// --- Pages ------------------------------------------------------------------
const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

function signInPage(uid, qrDataUrl, link) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in with Pubky Ring</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8e8;margin:0;display:grid;place-items:center;min-height:100vh;padding:16px;box-sizing:border-box;overflow-wrap:break-word}
  main{max-width:380px;width:100%;text-align:center}
  h1{font-size:1.4rem;text-wrap:balance}
  p{color:#b4b8c0;text-wrap:pretty}
  img{width:100%;max-width:280px;height:auto;background:#fff;padding:12px;border-radius:12px;box-sizing:border-box}
  a.btn{display:inline-block;max-width:100%;margin-top:16px;padding:12px 20px;min-height:44px;box-sizing:border-box;border-radius:10px;background:#f2a900;color:#111;font-weight:600;text-decoration:none}
  #status{min-height:1.5em}
</style></head>
<body><main>
  <h1>Sign in with Pubky&nbsp;Ring</h1>
  <p>Scan this code with the Pubky&nbsp;Ring app, then approve the sign-in.</p>
  <img src="${qrDataUrl}" alt="Pubky Ring sign-in QR code" width="280" height="280">
  <p><a class="btn" href="${escapeHtml(link)}">Open Pubky&nbsp;Ring on this phone</a></p>
  <p id="status" role="status">Waiting for approval…</p>
</main>
<script>
  const status = document.getElementById('status')
  async function poll() {
    try {
      const r = await fetch('/interaction/${uid}/status', { cache: 'no-store' })
      const j = await r.json()
      if (j.state === 'approved') { status.textContent = 'Approved, redirecting…'; location.href = '/interaction/${uid}/complete'; return }
      if (j.state === 'error') { status.textContent = 'Sign-in failed: ' + j.message + '. Reload the page for a new code.'; return }
      if (j.state === 'expired') { status.textContent = 'This code has expired. Reload the page.'; return }
    } catch { /* network: try again */ }
    setTimeout(poll, 1500)
  }
  poll()
</script>
</body></html>`
}

function send(res, code, type, body) {
  res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' })
  res.end(body)
}

async function handleInteraction(req, res, uid, action) {
  const details = await provider.interactionDetails(req, res)
  if (details.uid !== uid) return send(res, 400, 'text/plain; charset=utf-8', 'Unknown interaction.')

  if (details.prompt.name === 'consent') {
    // Single, trusted client: grant the requested scopes.
    const grant = details.grantId
      ? await provider.Grant.find(details.grantId)
      : new provider.Grant({ accountId: details.session.accountId, clientId: details.params.client_id })
    const missing = details.prompt.details
    if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '))
    if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims)
    const grantId = await grant.save()
    return provider.interactionFinished(req, res, { consent: details.grantId ? {} : { grantId } }, { mergeWithLastSubmission: true })
  }

  if (details.prompt.name !== 'login') return send(res, 400, 'text/plain; charset=utf-8', `Unsupported step: ${details.prompt.name}`)

  if (action === 'status') {
    const state = flows.get(uid)
    if (!state || state.expires < Date.now()) return send(res, 200, 'application/json', JSON.stringify({ state: 'expired' }))
    if (state.error) return send(res, 200, 'application/json', JSON.stringify({ state: 'error', message: state.error }))
    return send(res, 200, 'application/json', JSON.stringify({ state: state.key ? 'approved' : 'waiting' }))
  }

  if (action === 'complete') {
    const state = flows.get(uid)
    if (!state?.key) return send(res, 409, 'text/plain; charset=utf-8', 'Sign-in not approved yet.')
    flows.delete(uid)
    return provider.interactionFinished(req, res, { login: { accountId: state.key } }, { mergeWithLastSubmission: false })
  }

  // Show the QR code. Reloading the page starts a fresh flow.
  const state = startFlow(uid)
  const qr = await QRCode.toDataURL(state.url, { width: 280, margin: 0 })
  return send(res, 200, 'text/html; charset=utf-8', signInPage(uid, qr, state.url))
}

const oidc = provider.callback()
createServer(async (req, res) => {
  const m = req.url.match(/^\/interaction\/([\w-]+)(?:\/(status|complete))?(?:\?.*)?$/)
  if (req.method === 'GET' && m) {
    try {
      await handleInteraction(req, res, m[1], m[2])
    } catch (e) {
      console.error('interaction', e)
      if (!res.headersSent) send(res, 400, 'text/plain; charset=utf-8', `Invalid or expired sign-in session: ${e.message}`)
    }
    return
  }
  if (req.url === '/healthz') return send(res, 200, 'text/plain', 'ok')
  oidc(req, res)
}).listen(PORT, () => console.log(`Pubky OIDC provider at ${ISSUER} (port ${PORT})`))
