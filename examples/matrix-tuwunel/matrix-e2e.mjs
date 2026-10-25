// Full Matrix sign-in (Tuwunel's m.login.sso flow) through the provider,
// approved by a throwaway Pubky identity.
//
//   MATRIX=http://localhost:8008 node examples/matrix-tuwunel/matrix-e2e.mjs
//
// SEED=<64 hex> replays the same identity, to check that a second sign-in
// lands on the same account.

import { Pubky, Keypair } from '@synonymdev/pubky'

const MATRIX = process.env.MATRIX ?? 'http://localhost:8008'
const IDP = process.env.IDP ?? 'pubky-ring'
const BACK = 'http://localhost:9999/done'

// One cookie jar per host: the provider and Tuwunel each set their own.
const jars = new Map()
async function get(url) {
  const u = new URL(url)
  const jar = jars.get(u.host) ?? new Map()
  jars.set(u.host, jar)
  const r = await fetch(u, { redirect: 'manual', headers: { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') } })
  for (const c of r.headers.getSetCookie()) {
    const [kv] = c.split(';')
    const i = kv.indexOf('=')
    jar.set(kv.slice(0, i), kv.slice(i + 1))
  }
  return r
}
async function follow(url, stop) {
  let r = await get(url)
  let current = url
  while (r.status >= 300 && r.status < 400) {
    current = new URL(r.headers.get('location'), current).href
    if (stop(current)) return { end: current }
    r = await get(current)
  }
  return { r, current }
}

const flows = await (await fetch(`${MATRIX}/_matrix/client/v3/login`)).json()
const sso = flows.flows.find((f) => f.type === 'm.login.sso')
console.log('1. SSO providers announced:', JSON.stringify(sso?.identity_providers?.map((p) => p.id)))

const start = `${MATRIX}/_matrix/client/v3/login/sso/redirect/${IDP}?redirectUrl=${encodeURIComponent(BACK)}`
const { r: page, current } = await follow(start, (u) => u.startsWith(BACK))
const html = await page.text()
const uid = current.split('/interaction/')[1]
const link = html.match(/href="(pubkyauth:[^"]+)"/)?.[1]?.replace(/&#38;/g, '&')
if (!link) { console.log('Unexpected page', page.status, current, html.slice(0, 300)); process.exit(1) }
console.log('2. provider QR page reached from Tuwunel')

const keypair = process.env.SEED ? Keypair.fromSecret(Buffer.from(process.env.SEED, 'hex')) : Keypair.random()
const key = keypair.publicKey.z32()
await new Pubky().signer(keypair).approveAuthRequest(link)
const origin = new URL(current).origin
for (let i = 0; i < 40; i += 1) {
  const s = await (await get(`${origin}/interaction/${uid}/status`)).json()
  if (s.state !== 'waiting') { console.log('3. state:', s.state); break }
  await new Promise((ok) => setTimeout(ok, 500))
}

let { end, r: confirmation } = await follow(`${origin}/interaction/${uid}/complete`, (u) => u.startsWith(BACK))
if (!end) {
  // Tuwunel asks to confirm a destination outside its allow list: read the link.
  const body = await confirmation.text()
  end = body.match(/class="auth-continue-link" href="([^"]+)"/)?.[1]?.replace(/&amp;/g, '&')
  console.log('4. Tuwunel confirmation page', confirmation.status, end ? '(link found)' : body.slice(0, 400))
}
const loginToken = new URL(end).searchParams.get('loginToken')
console.log('4. back to the client with a loginToken:', Boolean(loginToken))

const login = await (await fetch(`${MATRIX}/_matrix/client/v3/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ type: 'm.login.token', token: loginToken }),
})).json()
console.log('5. login:', login.user_id ?? JSON.stringify(login))

const profile = await (await fetch(`${MATRIX}/_matrix/client/v3/profile/${encodeURIComponent(login.user_id)}`, {
  headers: { authorization: `Bearer ${login.access_token}` },
})).json()
console.log('6. profile:', JSON.stringify(profile))

const SERVER_NAME = process.env.SERVER_NAME ?? new URL(MATRIX).hostname
const expected = `@${key}:${SERVER_NAME}`
console.log(login.user_id === expected ? `RESULT: OK (${expected})` : `RESULT: FAILED, expected ${expected}`)
process.exit(login.user_id === expected ? 0 : 1)
