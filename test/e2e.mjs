// Full OIDC flow against a running provider, without a phone: a throwaway
// Pubky identity plays the part of Pubky Ring.
//
//   BASE=http://localhost:4000 CLIENT_SECRET=... REDIRECT_URI=... node test/e2e.mjs

import { Pubky, Keypair } from '@synonymdev/pubky'

const BASE = process.env.BASE ?? 'http://localhost:4000'
const CLIENT_ID = process.env.CLIENT_ID ?? 'pubky-ring'
const CLIENT_SECRET = process.env.CLIENT_SECRET
const REDIRECT_URI = process.env.REDIRECT_URI

const jar = new Map()
async function get(url) {
  const r = await fetch(new URL(url, BASE), {
    redirect: 'manual',
    headers: { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') },
  })
  for (const c of r.headers.getSetCookie()) {
    const [kv] = c.split(';')
    const i = kv.indexOf('=')
    jar.set(kv.slice(0, i), kv.slice(i + 1))
  }
  return r
}
// Follows redirects inside the provider, stops at the redirect_uri.
async function follow(url) {
  let r = await get(url)
  while (r.status >= 300 && r.status < 400) {
    const loc = r.headers.get('location')
    if (loc.startsWith(REDIRECT_URI)) return { end: new URL(loc) }
    r = await get(loc)
  }
  return { r }
}

const auth = new URL('/auth', BASE)
auth.search = new URLSearchParams({
  client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code',
  scope: 'openid profile', state: 'test-state', nonce: 'test-nonce',
}).toString()

const { r: page } = await follow(auth.href)
const html = await page.text()
const uid = page.url.split('/interaction/')[1] ?? html.match(/\/interaction\/([\w-]+)\/status/)[1]
const link = html.match(/href="(pubkyauth:[^"]+)"/)[1].replace(/&#38;/g, '&')
console.log('1. QR page served, uid =', uid, '| link', link.slice(0, 40) + '…')

const keypair = Keypair.random()
const expectedKey = keypair.publicKey.z32()
const t0 = Date.now()
await new Pubky().signer(keypair).approveAuthRequest(link)
console.log('2. approval sent by the throwaway identity', expectedKey)

let state
for (let i = 0; i < 40; i += 1) {
  state = await (await get(`/interaction/${uid}/status`)).json()
  if (state.state !== 'waiting') break
  await new Promise((ok) => setTimeout(ok, 500))
}
console.log('3. state seen by the page:', JSON.stringify(state), `(${Date.now() - t0} ms)`)

const { end } = await follow(`/interaction/${uid}/complete`)
console.log('4. back to the client:', end.origin + end.pathname, 'state =', end.searchParams.get('state'))

const token = await (await fetch(new URL('/token', BASE), {
  method: 'POST',
  headers: {
    authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
    'content-type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({ grant_type: 'authorization_code', code: end.searchParams.get('code'), redirect_uri: REDIRECT_URI }),
})).json()
const idToken = JSON.parse(Buffer.from(token.id_token.split('.')[1], 'base64url'))
const info = await (await fetch(new URL('/me', BASE), { headers: { authorization: `Bearer ${token.access_token}` } })).json()
console.log('5. id_token.sub =', idToken.sub, '| userinfo =', JSON.stringify(info))

const ok = idToken.sub === expectedKey && info.sub === expectedKey && end.searchParams.get('state') === 'test-state'
console.log(ok ? 'RESULT: OK' : 'RESULT: FAILED')
process.exit(ok ? 0 : 1)
