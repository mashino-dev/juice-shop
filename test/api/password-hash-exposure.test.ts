/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/*
 * Defensive regression tests for the finding "Unauthenticated leak of unsalted MD5 password hashes
 * enables account takeover". All credentials are generated at runtime and assertion messages never
 * contain any secret value.
 */

import crypto from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { buildAssertion, loadVictimCredential, type VictimCredential } from './helpers/passkey'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
import { MemoryModel } from '../../models/memory'
import * as models from '../../models/index'

const jsonHeader = { 'content-type': 'application/json' }
const domain = config.get<string>('application.domain')
const MASK = '*'.repeat(32)

let app: Express

interface Fixture {
  id: number
  email: string
  password: string
  hash: string
  token: string
}

const randomPassword = () => 'Aa1!' + crypto.randomBytes(12).toString('base64url')
const randomEmail = () => `phx-${crypto.randomBytes(6).toString('hex')}@${domain}`
const bearer = (token: string) => ({ Authorization: 'Bearer ' + token, ...jsonHeader })

async function newUser (): Promise<Fixture> {
  const email = randomEmail()
  const password = randomPassword()
  await register(app, { email, password })
  const { token } = await login(app, { email, password })
  const payload: any = security.decode(token)
  return { id: payload.data.id, email, password, hash: security.hash(password), token }
}

function containsKey (value: unknown, key: string): boolean {
  if (value === null || typeof value !== 'object') return false
  if (Object.prototype.hasOwnProperty.call(value, key)) return true
  return Object.values(value as Record<string, unknown>).some((v) => containsKey(v, key))
}

function containsAny (value: unknown, secrets: string[]): boolean {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value) ?? ''
  return secrets.some((secret) => serialized.includes(secret))
}

function assertNoPasswordExposure (value: unknown, label: string, user: Fixture) {
  assert.equal(containsKey(value, 'password'), false, `${label}: must not contain a password property`)
  assert.equal(containsAny(value, [user.hash, user.password]), false, `${label}: must not contain the password hash or the clear text password`)
}

function assertSessionKeepsAuthorizationData (session: any, user: Fixture, label: string) {
  assert.equal(session?.data?.id, user.id, `${label}: id must be kept`)
  assert.equal(session?.data?.email, user.email, `${label}: email must be kept`)
  assert.equal(session?.data?.role, 'customer', `${label}: role must be kept`)
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('GET /rest/memories', () => {
  void it('1. is forbidden for unauthenticated users', async () => {
    const res = await request(app).get('/rest/memories')
    assert.equal(res.status, 401)
    assert.equal(containsKey(res.body, 'password'), false)
  })

  void it('2. is available for authenticated users', async () => {
    const user = await newUser()
    const res = await request(app).get('/rest/memories').set(bearer(user.token))
    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.ok(res.body.data.length > 0, 'seeded memories expected')
  })

  const forbiddenAttributes = [
    ['3', 'password'],
    ['4', 'role'],
    ['5', 'deluxeToken'],
    ['6', 'lastLoginIp'],
    ['7', 'totpSecret'],
    ['8', 'isActive'],
    ['9a', 'createdAt'],
    ['9b', 'updatedAt'],
    ['9c', 'deletedAt'],
    ['9d', 'email']
  ]
  for (const [number, attribute] of forbiddenAttributes) {
    void it(`${number}. does not expose the User attribute "${attribute}"`, async () => {
      const user = await newUser()
      const res = await request(app).get('/rest/memories').set(bearer(user.token))
      const authors = res.body.data.map((memory: any) => memory.User).filter(Boolean)
      assert.ok(authors.length > 0, 'memories with an author expected')
      for (const author of authors) {
        assert.equal(attribute in author, false, `memory author must not contain ${attribute}`)
      }
    })
  }

  void it('10. keeps the attributes required to display the photo wall', async () => {
    const user = await newUser()
    const res = await request(app).get('/rest/memories').set(bearer(user.token))
    const memory = res.body.data.find((m: any) => m.User)
    assert.equal(typeof memory.caption, 'string')
    assert.equal(typeof memory.imagePath, 'string')
    assert.equal(typeof memory.User.username, 'string')
    for (const author of res.body.data.map((m: any) => m.User).filter(Boolean)) {
      assert.deepEqual(Object.keys(author).filter((key) => key !== 'username'), [], 'author must be limited to the allowlist')
    }
  })
})

void describe('session and token do not carry the password hash', () => {
  void it('11. login response has no password', async () => {
    const email = randomEmail()
    const password = randomPassword()
    await register(app, { email, password })
    const res = await request(app).post('/rest/user/login').set(jsonHeader).send({ email, password })
    assert.equal(res.status, 200)
    assert.equal(containsKey(res.body, 'password'), false)
    assert.equal(containsAny(res.body.authentication, [security.hash(password), password]), false)
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('12. JWT payload has no password but keeps id, email and role', async () => {
    const user = await newUser()
    const payload = security.decode(user.token)
    assert.equal(containsKey(payload, 'password'), false)
    assert.equal(containsAny(payload, [user.hash, user.password]), false)
    assertSessionKeepsAuthorizationData(payload, user, 'JWT payload')
  })

  void it('12b. authorize() removes a password from any session payload', () => {
    const token = security.authorize({ data: { id: 4711, email: 'x@example.org', role: 'customer', password: security.hash(randomPassword()) } })
    const payload: any = security.decode(token)
    assert.equal(containsKey(payload, 'password'), false)
    assert.equal(payload.data.id, 4711)
    assert.equal(payload.data.role, 'customer')
  })

  void it('13. authenticatedUsers cache has no password but keeps id, email and role', async () => {
    const user = await newUser()
    const session = security.authenticatedUsers.get(user.token)
    assert.ok(session, 'session expected')
    assert.equal(containsKey(session, 'password'), false)
    assert.equal(containsAny(session, [user.hash, user.password]), false)
    assertSessionKeepsAuthorizationData(session, user, 'session cache')
  })

  void it('13b. authenticatedUsers.put() removes a password from a session object', () => {
    const token = 'token-' + crypto.randomBytes(8).toString('hex')
    security.authenticatedUsers.put(token, { data: { id: 4712, email: 'y@example.org', role: 'customer', password: security.hash(randomPassword()) } as unknown as UserModel })
    const session: any = security.authenticatedUsers.get(token)
    assert.equal(containsKey(session, 'password'), false)
    assert.equal(session.data.id, 4712)
    assert.equal(session.data.role, 'customer')
  })
})

void describe('responses do not contain the password hash', () => {
  void it('14. whoami (default response)', async () => {
    const user = await newUser()
    const res = await request(app).get('/rest/user/whoami').set(bearer(user.token)).set('Cookie', `token=${user.token}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.user.email, user.email)
    assertNoPasswordExposure(res.body, 'whoami', user)
  })

  void it('15. whoami with fields=password does not return the password', async () => {
    const user = await newUser()
    for (const fields of ['password', 'id,email,password', ' password ']) {
      const res = await request(app).get('/rest/user/whoami').query({ fields }).set('Cookie', `token=${user.token}`)
      assert.equal(res.status, 200)
      assertNoPasswordExposure(res.body, `whoami fields=${fields.trim()}`, user)
    }
  })

  void it('16. change-password response', async () => {
    const user = await newUser()
    const next = randomPassword()
    const res = await request(app).get('/rest/user/change-password').query({ current: user.password, new: next, repeat: next }).set(bearer(user.token))
    assert.equal(res.status, 200)
    assertNoPasswordExposure(res.body, 'change-password', user)
    assert.equal(containsAny(res.body, [security.hash(next), next]), false, 'change-password: must not contain the new hash or password')
  })

  void it('17. saveLoginIp response', async () => {
    const user = await newUser()
    const res = await request(app).get('/rest/saveLoginIp').set(bearer(user.token)).set('true-client-ip', '1.2.3.4')
    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '1.2.3.4')
    assertNoPasswordExposure(res.body, 'saveLoginIp', user)
  })

  void it('18. updateUserProfile issues a session without password', async () => {
    const user = await newUser()
    const res = await request(app).post('/profile').set('Cookie', `token=${user.token}`).type('form').send({ username: 'phx' + crypto.randomBytes(3).toString('hex') }).redirects(0)
    assert.equal(res.status, 302)
    assertNoPasswordExposure(res.text, 'profile response body', user)
    const cookie = (res.headers['set-cookie'] as unknown as string[] | undefined)?.find((c) => c.startsWith('token='))
    assert.ok(cookie, 'new token cookie expected')
    const newToken = decodeURIComponent(cookie.split(';')[0].substring('token='.length))
    assertNoPasswordExposure(security.decode(newToken), 'profile JWT payload', user)
    const session = security.authenticatedUsers.get(newToken)
    assertNoPasswordExposure(session, 'profile session cache', user)
    assertSessionKeepsAuthorizationData(session, user, 'profile session cache')
  })

  void it('19. deluxe membership response, token and session', async () => {
    const user = await newUser()
    const res = await request(app).post('/rest/deluxe-membership').set(bearer(user.token)).send({ paymentMode: 'none' })
    assert.equal(res.status, 200)
    assertNoPasswordExposure(res.body, 'deluxe response', user)
    const newToken = res.body.data.token
    assertNoPasswordExposure(security.decode(newToken), 'deluxe JWT payload', user)
    const session: any = security.authenticatedUsers.get(newToken)
    assertNoPasswordExposure(session, 'deluxe session cache', user)
    assert.equal(session.data.role, 'deluxe')
    assert.equal(session.data.id, user.id)
  })

  void it('20. passkey login session and token', async () => {
    const victim: VictimCredential = await loadVictimCredential()
    const host = { ...jsonHeader, host: 'localhost:3000' }
    const options = await request(app).post('/rest/passkey/login-options').set(host).send({ email: `passkey-user@${domain}` })
    assert.equal(options.status, 200)
    const assertion = buildAssertion(victim, options.body.options.challenge, { tamper: false, counter: 1 })
    const res = await request(app).post('/rest/passkey/login-verify').set(host).send({ assertion, authToken: options.body.authToken })
    assert.equal(res.status, 200)
    assert.equal(containsKey(res.body, 'password'), false)
    const token = res.body.authentication.token
    assert.equal(containsKey(security.decode(token), 'password'), false, 'passkey JWT payload must not contain a password')
    const session: any = security.authenticatedUsers.get(token)
    assert.equal(containsKey(session, 'password'), false, 'passkey session cache must not contain a password')
    assert.equal(session.data.email, `passkey-user@${domain}`)
    assert.ok(session.data.id)
  })

  void it('21. /api/Users list, single user and registration response', async () => {
    const user = await newUser()
    const list = await request(app).get('/api/Users').set(bearer(user.token))
    assert.equal(list.status, 200)
    assertNoPasswordExposure(list.body, 'GET /api/Users', user)
    const single = await request(app).get(`/api/Users/${user.id}`).set(bearer(user.token))
    assert.equal(single.status, 200)
    assertNoPasswordExposure(single.body, 'GET /api/Users/:id', user)
    const registration = { email: randomEmail(), password: randomPassword() }
    const created = await request(app).post('/api/Users').set(jsonHeader).send({ ...registration, passwordRepeat: registration.password })
    assert.equal(created.status, 201)
    assert.equal(containsKey(created.body, 'password'), false)
    assert.equal(containsAny(created.body, [security.hash(registration.password), registration.password]), false)
  })

  void it('22. authentication-details uses one fixed mask that reveals neither format nor length', async () => {
    const user = await newUser()
    const res = await request(app).get('/rest/user/authentication-details').set(bearer(user.token))
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 1)
    for (const entry of res.body.data) {
      assert.equal(entry.password, MASK, 'every password must be the same fixed mask')
    }
  })
})

void describe('verification of the current password uses the stored value, not the session', () => {
  void it('23. 2FA setup works for an existing MD5 user and rejects a wrong password', async () => {
    const user = await newUser()
    const secret = generateSecret()
    const setupToken = security.authorize({ secret, type: 'totp_setup_secret' })
    const wrong = await request(app).post('/rest/2fa/setup').set(bearer(user.token)).send({ password: randomPassword(), setupToken, initialToken: generateSync({ secret }) })
    assert.equal(wrong.status, 401)
    const res = await request(app).post('/rest/2fa/setup').set(bearer(user.token)).send({ password: user.password, setupToken, initialToken: generateSync({ secret }) })
    assert.equal(res.status, 200)
    const status = await request(app).get('/rest/2fa/status').set(bearer(user.token))
    assert.equal(status.body.setup, true)
    assertNoPasswordExposure(status.body, '2fa status', user)
    assertSessionKeepsAuthorizationData(security.authenticatedUsers.get(user.token), user, 'session after 2FA setup')
    assert.equal(containsKey(security.authenticatedUsers.get(user.token), 'password'), false)
  })

  void it('24. 2FA disable works for an existing MD5 user and rejects a wrong password', async () => {
    const email = randomEmail()
    const password = randomPassword()
    const totpSecret = generateSecret()
    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })
    const wrong = await request(app).post('/rest/2fa/disable').set(bearer(token)).send({ password: randomPassword() })
    assert.equal(wrong.status, 401)
    const res = await request(app).post('/rest/2fa/disable').set(bearer(token)).send({ password })
    assert.equal(res.status, 200)
    const status = await request(app).get('/rest/2fa/status').set(bearer(token))
    assert.equal(status.body.setup, false)
  })

  void it('23b. a password injected into the session cannot be used to pass the 2FA check', async () => {
    const user = await newUser()
    const attackerPassword = randomPassword()
    const forged = security.authorize({ data: { id: user.id, email: user.email, role: 'customer', password: security.hash(attackerPassword), totpSecret: '' } })
    security.authenticatedUsers.put(forged, security.decode(forged) as any)
    const secret = generateSecret()
    const res = await request(app).post('/rest/2fa/setup').set(bearer(forged)).send({
      password: attackerPassword,
      setupToken: security.authorize({ secret, type: 'totp_setup_secret' }),
      initialToken: generateSync({ secret })
    })
    assert.equal(res.status, 401)
  })

  void it('25. changePassword accepts the correct current password, also repeatedly', async () => {
    const user = await newUser()
    const second = randomPassword()
    const third = randomPassword()
    const first = await request(app).get('/rest/user/change-password').query({ current: user.password, new: second, repeat: second }).set(bearer(user.token))
    assert.equal(first.status, 200)
    const again = await request(app).get('/rest/user/change-password').query({ current: second, new: third, repeat: third }).set(bearer(user.token))
    assert.equal(again.status, 200, 'the current password must be checked against the stored value')
    const relogin = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: user.email, password: third })
    assert.equal(relogin.status, 200)
    const oldLogin = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: user.email, password: user.password })
    assert.equal(oldLogin.status, 401)
  })

  void it('26. changePassword rejects a wrong current password with 401 and keeps the password', async () => {
    const user = await newUser()
    const next = randomPassword()
    const res = await request(app).get('/rest/user/change-password').query({ current: randomPassword(), new: next, repeat: next }).set(bearer(user.token))
    assert.equal(res.status, 401)
    const stillWorks = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: user.email, password: user.password })
    assert.equal(stillWorks.status, 200)
  })

  void it('26b. a password injected into the session is not accepted as current password', async () => {
    const user = await newUser()
    const attackerPassword = randomPassword()
    const forged = security.authorize({ data: { id: user.id, email: user.email, role: 'customer', password: security.hash(attackerPassword) } })
    security.authenticatedUsers.put(forged, security.decode(forged) as any)
    const next = randomPassword()
    const res = await request(app).get('/rest/user/change-password').query({ current: attackerPassword, new: next, repeat: next }).set(bearer(forged))
    assert.equal(res.status, 401)
  })
})

void describe('UserModel scopes', () => {
  void it('excludes the password by default, including associations and bulk finders', async () => {
    const user = await newUser()
    const byPk = await UserModel.findByPk(user.id)
    assert.equal(byPk?.get('password'), undefined)
    const all = await UserModel.findAll()
    assert.ok(all.length > 0)
    assert.equal(all.some((u) => u.get('password') !== undefined), false)
    const memories = await MemoryModel.findAll({ include: [UserModel] })
    assert.equal(containsKey(memories.map((m) => m.toJSON()), 'password'), false)
  })

  void it('withPassword scope returns the stored hash for verification', async () => {
    const user = await newUser()
    const withPassword = await UserModel.scope('withPassword').findByPk(user.id)
    assert.equal(withPassword?.password === user.hash, true)
  })

  void it('keeps the finale excluded attributes consistent', async () => {
    const user = await newUser()
    const res = await request(app).get(`/api/Users/${user.id}`).set(bearer(user.token))
    assert.equal(res.body.data.email, user.email)
    assert.equal('totpSecret' in res.body.data, false)
  })
})

void describe('challenges', () => {
  void it('27. passwordHashLeakChallenge is defined but unavailable on Hardened and stays unsolved', async () => {
    const user = await newUser()
    await request(app).get('/rest/user/whoami').query({ fields: 'id,email,password' }).set('Cookie', `token=${user.token}`)
    const res = await request(app).get('/api/Challenges')
    const challenge = res.body.data.find((c: { key: string }) => c.key === 'passwordHashLeakChallenge')
    assert.ok(challenge, 'challenge must not be removed')
    assert.equal(challenge.disabledEnv, 'Hardened')
    assert.equal(challenge.solved, false)
    assert.deepEqual(utils.getChallengeEnablementStatus(challenges.passwordHashLeakChallenge), { enabled: false, disabledBecause: 'Hardened' })
  })

  void it('login SQL injection challenges and Union SQL Injection are unavailable on Hardened once the SQL injection is fixed', async () => {
    for (const key of ['loginAdminChallenge', 'loginJimChallenge', 'loginBenderChallenge', 'unionSqlInjectionChallenge']) {
      assert.equal(utils.isChallengeEnabled((challenges as Record<string, any>)[key]), false, `${key} must be unavailable`)
    }
    assert.equal(utils.isChallengeEnabled(challenges.weakPasswordChallenge), true)
  })

  void it('Union SQL Injection no longer exposes stored hashes and stays unsolved', async () => {
    const [hashRows]: any = await models.sequelize.query('SELECT password FROM Users')
    const res = await request(app).get('/rest/products/search').query({ q: "')) union select id,email,password,'4','5','6','7','8','9','10' from users--" })
    assert.equal(res.status, 200)
    assert.equal(hashRows.some((row: { password: string }) => res.text.includes(row.password)), false)
    await new Promise((resolve) => setTimeout(resolve, 300))
    assert.equal(challenges.unionSqlInjectionChallenge.solved, false)
  })
})

void describe('logging', () => {
  void it('29. password hash, clear text password and tokens are never written to stdout/stderr', async () => {
    const chunks: string[] = []
    const originalOut = process.stdout.write.bind(process.stdout)
    const originalErr = process.stderr.write.bind(process.stderr)
    process.stdout.write = ((chunk: any, ...rest: any[]) => { chunks.push(String(chunk)); return originalOut(chunk, ...rest) }) as typeof process.stdout.write
    process.stderr.write = ((chunk: any, ...rest: any[]) => { chunks.push(String(chunk)); return originalErr(chunk, ...rest) }) as typeof process.stderr.write
    let user: Fixture
    const next = randomPassword()
    try {
      user = await newUser()
      await request(app).get('/rest/user/whoami').query({ fields: 'id,email,password' }).set('Cookie', `token=${user.token}`)
      await request(app).get('/rest/memories').set(bearer(user.token))
      await request(app).get('/rest/saveLoginIp').set(bearer(user.token))
      await request(app).post('/rest/2fa/setup').set(bearer(user.token)).send({ password: randomPassword() })
      await request(app).get('/rest/user/change-password').query({ current: user.password, new: next, repeat: next }).set(bearer(user.token))
      await request(app).post('/rest/user/login').set(jsonHeader).send({ email: user.email, password: randomPassword() })
    } finally {
      process.stdout.write = originalOut as typeof process.stdout.write
      process.stderr.write = originalErr as typeof process.stderr.write
    }
    const output = chunks.join('')
    assert.equal(containsAny(output, [user.hash, user.password, security.hash(next), next, user.token]), false, 'no secret may appear in the log output')
  })
})
