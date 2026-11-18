/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import logger from '../../lib/logger'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
const forgedTimestamp = '1999-01-01T00:00:00.000Z'
let sequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const newCredentials = () => {
  sequence++
  return { email: `mass-assignment-${sequence}@example.com`, password: 'Sup3rS3cret!pw' }
}

async function register (extraFields: Record<string, unknown> = {}) {
  const credentials = newCredentials()
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ ...credentials, passwordRepeat: credentials.password, ...extraFields })
  return { res, credentials }
}

async function storedUser (email: string) {
  const user = await UserModel.findOne({ where: { email }, paranoid: false })
  assert.ok(user, `user ${email} must have been stored`)
  return user
}

const has = (object: object, key: string) => Object.prototype.hasOwnProperty.call(object, key)

void describe('anonymous registration (POST /api/Users) does not mass-assign privileged attributes', () => {
  void it('1. a regular JSON registration succeeds and stores server-side defaults', async () => {
    const { res, credentials } = await register()
    assert.equal(res.status, 201)
    const user = await storedUser(credentials.email)
    assert.equal(user.role, 'customer')
    assert.equal(user.deluxeToken, '')
    assert.equal(user.totpSecret, '')
    assert.equal(user.isActive, true)
    assert.ok(await WalletModel.findOne({ where: { UserId: user.id } }), 'a wallet must still be created')
  })

  void it('2. a regular urlencoded registration succeeds', async () => {
    const credentials = newCredentials()
    const res = await request(app)
      .post('/api/Users')
      .type('form')
      .send({ ...credentials, passwordRepeat: credentials.password })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).role, 'customer')
  })

  for (const role of ['admin', 'accounting', 'deluxe', 'not-a-role']) {
    void it(`3. role "${role}" in the JSON body is ignored and customer is stored`, async () => {
      const { res, credentials } = await register({ role })
      assert.equal(res.status, 201)
      assert.equal(res.body.data.role, 'customer')
      assert.equal((await storedUser(credentials.email)).role, 'customer')
    })
  }

  void it('3. role "admin" in a urlencoded body is ignored and customer is stored', async () => {
    const credentials = newCredentials()
    const res = await request(app)
      .post('/api/Users')
      .type('form')
      .send({ ...credentials, passwordRepeat: credentials.password, role: 'admin' })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).role, 'customer')
  })

  void it('4. a client-supplied deluxeToken is not stored', async () => {
    const { res, credentials } = await register({ deluxeToken: 'FORGED-DELUXE-TOKEN' })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).deluxeToken, '')
  })

  void it('5. a client-supplied totpSecret is not stored and no second factor is required to log in', async () => {
    const { res, credentials } = await register({ totpSecret: 'JBSWY3DPEHPK3PXP' })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).totpSecret, '')
    const loginRes = await request(app).post('/rest/user/login').set(jsonHeader).send(credentials)
    assert.equal(loginRes.status, 200)
    assert.ok(loginRes.body.authentication.token)
  })

  void it('6. a client-supplied isActive is not taken over', async () => {
    const { res, credentials } = await register({ isActive: false })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).isActive, true)
  })

  void it('7. a client-supplied id is not taken over', async () => {
    const { res, credentials } = await register({ id: 424242 })
    assert.equal(res.status, 201)
    assert.notEqual(res.body.data.id, 424242)
    assert.notEqual((await storedUser(credentials.email)).id, 424242)
  })

  void it('8. client-supplied createdAt, updatedAt and deletedAt are not taken over', async () => {
    const { res, credentials } = await register({ createdAt: forgedTimestamp, updatedAt: forgedTimestamp, deletedAt: forgedTimestamp })
    assert.equal(res.status, 201)
    const user = await storedUser(credentials.email)
    assert.equal(user.get('deletedAt'), null)
    assert.ok(new Date(user.get('createdAt') as string).getFullYear() > 2000)
    assert.ok(new Date(user.get('updatedAt') as string).getFullYear() > 2000)
    assert.notEqual(res.body.data.createdAt, forgedTimestamp)
    assert.notEqual(res.body.data.deletedAt, forgedTimestamp)
  })

  void it('9. a client-supplied lastLoginIp is not stored', async () => {
    const { res, credentials } = await register({ lastLoginIp: '6.6.6.6' })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).lastLoginIp, '0.0.0.0')
  })

  void it('10. an external profileImage URL is not stored', async () => {
    const { res, credentials } = await register({ profileImage: 'https://attacker.example/pixel.png' })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).profileImage, '/assets/public/images/uploads/default.svg')
  })

  void it('11. several privileged attributes sent together are all dropped', async () => {
    const { res, credentials } = await register({
      role: 'admin',
      deluxeToken: 'x',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      isActive: false,
      id: 777777,
      deletedAt: forgedTimestamp,
      lastLoginIp: '6.6.6.6',
      profileImage: 'https://attacker.example/pixel.png'
    })
    assert.equal(res.status, 201)
    const user = await storedUser(credentials.email)
    assert.deepEqual(
      [user.role, user.deluxeToken, user.totpSecret, user.isActive, user.get('deletedAt'), user.lastLoginIp, user.profileImage],
      ['customer', '', '', true, null, '0.0.0.0', '/assets/public/images/uploads/default.svg']
    )
    assert.notEqual(user.id, 777777)
  })

  void it('12. unknown attributes (also differently cased, nested or prototype-related) are not stored', async () => {
    const credentials = newCredentials()
    const rawJson = JSON.stringify({ ...credentials, passwordRepeat: credentials.password, isAdmin: true, Role: 'admin', ROLE: 'admin', permissions: ['*'], user: { role: 'admin' } })
      .replace(/}$/, ',"__proto__":{"role":"admin"},"constructor":{"prototype":{"role":"admin"}}}')
    const res = await request(app).post('/api/Users').set(jsonHeader).send(rawJson)
    assert.equal(res.status, 201)
    const user = await storedUser(credentials.email)
    assert.equal(user.role, 'customer')
    assert.equal(user.get('isAdmin'), undefined)
    assert.equal(has(res.body.data, 'isAdmin'), false)
    assert.equal(has(res.body.data, 'permissions'), false)
  })

  void it('13. passwordRepeat stays available to the follow-up challenge verification', async () => {
    challenges.passwordRepeatChallenge.solved = false
    const credentials = newCredentials()
    const res = await request(app).post('/api/Users').set(jsonHeader).send({ ...credentials, passwordRepeat: 'something else' })
    assert.equal(res.status, 201)
    assert.equal(challenges.passwordRepeatChallenge.solved, true)
  })

  void it('14. non-object request bodies do not cause a 500', async () => {
    for (const [contentType, body] of [
      ['text/plain', 'role=admin'],
      ['application/json', '[]'],
      ['application/json', '["role","admin"]'],
      ['application/json', '"role"'],
      ['application/json', '{}']
    ]) {
      const res = await request(app).post('/api/Users').set({ 'content-type': contentType }).send(body)
      assert.notEqual(res.status, 500, `${contentType} body ${body} must not produce a 500`)
    }
  })

  void it('15. the registration response contains neither password nor totpSecret', async () => {
    const { res } = await register({ totpSecret: 'JBSWY3DPEHPK3PXP' })
    assert.equal(res.status, 201)
    assert.equal(has(res.body.data, 'password'), false)
    assert.equal(has(res.body.data, 'totpSecret'), false)
  })

  void it('16. the registration response does not contain the injected deluxeToken', async () => {
    const { res } = await register({ deluxeToken: 'INJECTED-DELUXE-TOKEN' })
    assert.equal(res.status, 201)
    assert.ok(!res.body.data.deluxeToken)
    assert.equal(JSON.stringify(res.body).includes('INJECTED-DELUXE-TOKEN'), false)
  })

  void it('24. neither unknown key names nor values of the request are logged', async () => {
    const logged: string[] = []
    const record = (...args: unknown[]) => { logged.push(args.map((arg) => typeof arg === 'string' ? arg : JSON.stringify(arg)).join(' ')) }
    const spies = [
      ...(['log', 'info', 'warn', 'error', 'debug'] as const).map((method) => mock.method(console, method, record)),
      ...(['info', 'warn', 'error', 'debug', 'verbose'] as const).map((method) => mock.method(logger, method, record))
    ]
    try {
      await register({ LOGLEAK_KEY_NAME: 'LOGLEAK_VALUE', role: 'LOGLEAK_ROLE', totpSecret: 'LOGLEAK_TOTP', deluxeToken: 'LOGLEAK_DELUXE' })
    } finally {
      spies.forEach((spy) => { spy.mock.restore() })
    }
    assert.equal(logged.join('\n').includes('LOGLEAK'), false)
  })
})

void describe('privileged attributes cannot be changed through /api/Users/:id', () => {
  async function registerAndLogin () {
    const { credentials } = await register()
    const { token } = await login(app, credentials)
    const user = await storedUser(credentials.email)
    return { credentials, user, headers: { ...jsonHeader, Authorization: `Bearer ${token}` } }
  }
  const privilegedUpdate = { role: 'admin', deluxeToken: 'x', totpSecret: 'JBSWY3DPEHPK3PXP', isActive: false }
  const expectUnchanged = async (email: string) => {
    const user = await storedUser(email)
    assert.deepEqual([user.role, user.deluxeToken, user.totpSecret, user.isActive], ['customer', '', '', true])
  }

  void it('17. PUT /api/Users/:id is rejected, even for the account owner', async () => {
    const { credentials, user, headers } = await registerAndLogin()
    const res = await request(app).put(`/api/Users/${user.id}`).set(headers).send(privilegedUpdate)
    assert.equal(res.status, 401)
    await expectUnchanged(credentials.email)
  })

  void it('18. DELETE /api/Users/:id is rejected, even for the account owner', async () => {
    const { credentials, user, headers } = await registerAndLogin()
    const res = await request(app).delete(`/api/Users/${user.id}`).set(headers)
    assert.equal(res.status, 401)
    await expectUnchanged(credentials.email)
  })

  void it('19. PATCH /api/Users/:id does not change the stored user', async () => {
    const { credentials, user, headers } = await registerAndLogin()
    await request(app).patch(`/api/Users/${user.id}`).set(headers).send(privilegedUpdate)
    await expectUnchanged(credentials.email)
  })

  void it('20. POST /api/Users/:id does not change the stored user', async () => {
    const { credentials, user, headers } = await registerAndLogin()
    await request(app).post(`/api/Users/${user.id}`).set(headers).send(privilegedUpdate)
    await expectUnchanged(credentials.email)
  })
})

void describe('existing registration flows and challenges', () => {
  void it('21. OAuth-style registration (email, password, passwordRepeat) and login keep working', async () => {
    const email = 'oauth.user@example.com'
    const password = Buffer.from(email.split('').reverse().join('')).toString('base64')
    const res = await request(app).post('/api/Users').set(jsonHeader).send({ email, password, passwordRepeat: password })
    assert.equal(res.status, 201)
    const loginRes = await request(app).post('/rest/user/login').set(jsonHeader).send({ email, password, oauth: true })
    assert.equal(loginRes.status, 200)
    assert.ok(loginRes.body.authentication.token)
  })

  void it('22. the frontend registration payload including securityQuestion and securityAnswer is still accepted', async () => {
    const { res, credentials } = await register({
      securityQuestion: { id: 1, question: 'Your eldest siblings middle name?' },
      securityAnswer: 'Jane'
    })
    assert.equal(res.status, 201)
    assert.equal((await storedUser(credentials.email)).role, 'customer')
  })

  void it('22. registration without passwordRepeat (Repetitive Registration) still works and is not rejected', async () => {
    challenges.passwordRepeatChallenge.solved = false
    const res = await request(app).post('/api/Users').set(jsonHeader).send(newCredentials())
    assert.equal(res.status, 201)
    assert.equal(challenges.passwordRepeatChallenge.solved, true)
  })

  void it('Admin Registration is defined, unavailable on Hardened and not solved by a rejected admin role', async () => {
    challenges.registerAdminChallenge.solved = false
    const { res } = await register({ role: 'admin' })
    assert.equal(res.status, 201)
    assert.equal(challenges.registerAdminChallenge.solved, false)

    const challengeList = await request(app).get('/api/Challenges')
    assert.equal(challengeList.status, 200)
    const registerAdmin = challengeList.body.data.find((challenge: { key: string }) => challenge.key === 'registerAdminChallenge')
    assert.ok(registerAdmin, 'the challenge definition must not be removed')
    assert.equal(registerAdmin.disabledEnv, 'Hardened')
    assert.equal(registerAdmin.solved, false)
  })
})
