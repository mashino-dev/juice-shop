/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/*
 * Defensive tests for the "unauthenticated account takeover via the forgot-password security-answer flow" finding.
 *
 * Scope of this change: the security answer can no longer be planted by anonymous callers
 * (POST /api/SecurityAnswers is denied, the answer is stored server-side during registration)
 * and the security-answer based Forgot Password feature is unavailable (reset-password never changes a password,
 * security-question never discloses anything).
 *
 * Out of scope (tracked as separate findings): revocation of already issued sessions/JWTs after a password change.
 * There is intentionally no test for that here, because no password can be changed through this flow anymore.
 */

import { describe, it, before, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import logger from '../../lib/logger'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
const domain = () => config.get<string>('application.domain')
let sequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

afterEach(() => {
  mock.restoreAll()
})

function newEmail () {
  sequence++
  return `fp.hardening.${sequence}@example.com`
}

async function register (body: Record<string, unknown> = {}) {
  const email = newEmail()
  const password = 'Passw0rd-' + sequence
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email, password, passwordRepeat: password, ...body })
  return { res, email, password, id: res.body?.data?.id as number }
}

async function answersOf (userId: number) {
  return await SecurityAnswerModel.findAll({ where: { UserId: userId } })
}

const snapshot = (res: request.Response) => ({ status: res.status, text: res.text })

const hardenedResetChallenges = [
  'resetPasswordJimChallenge',
  'resetPasswordBenderChallenge',
  'resetPasswordBjoernChallenge',
  'resetPasswordBjoernOwaspChallenge',
  'resetPasswordMortyChallenge',
  'resetPasswordUvoginChallenge',
  'geoStalkingMetaChallenge',
  'geoStalkingVisualChallenge'
]

void describe('POST /api/SecurityAnswers from outside', () => {
  void it('1. is rejected for unauthenticated callers', async () => {
    const victim = await register()
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({ UserId: victim.id, SecurityQuestionId: 1, answer: 'attacker' })

    assert.equal(res.status, 401)
    assert.equal((await answersOf(victim.id)).length, 0)
  })

  void it('2. is rejected even for authenticated callers', async () => {
    const attacker = await register()
    const { token } = await login(app, { email: attacker.email, password: attacker.password })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
      .send({ SecurityQuestionId: 1, answer: 'own answer' })

    assert.equal(res.status, 401)
    assert.equal((await answersOf(attacker.id)).length, 0)
  })

  void it('3. cannot create an answer for a client supplied UserId', async () => {
    const victim = await register()
    const attacker = await register()
    const { token } = await login(app, { email: attacker.email, password: attacker.password })

    for (const headers of [jsonHeader, { ...jsonHeader, Authorization: 'Bearer ' + token }]) {
      const res = await request(app)
        .post('/api/SecurityAnswers')
        .set(headers)
        .send({ UserId: victim.id, SecurityQuestionId: 1, answer: 'planted' })
      assert.ok([401, 403].includes(res.status), `unexpected status ${res.status}`)
    }
    assert.equal((await answersOf(victim.id)).length, 0)
  })

  void it('3b. planting an answer for a victim does not enable any password change for the victim', async () => {
    const victim = await register()
    await request(app).post('/api/SecurityAnswers').set(jsonHeader).send({ UserId: victim.id, SecurityQuestionId: 1, answer: 'planted' })
    await request(app).post('/rest/user/reset-password').set(jsonHeader).send({ email: victim.email, answer: 'planted', new: 'pwned-1234', repeat: 'pwned-1234' })

    const attackerLogin = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: victim.email, password: 'pwned-1234' })
    assert.equal(attackerLogin.status, 401)
    const victimLogin = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: victim.email, password: victim.password })
    assert.equal(victimLogin.status, 200)
  })
})

void describe('security answer storage during registration', () => {
  void it('4. stores exactly one answer for the newly created user', async () => {
    const { res, id } = await register({ securityQuestion: { id: 2 }, securityAnswer: 'Rosebud' })
    assert.equal(res.status, 201)

    const answers = await answersOf(id)
    assert.equal(answers.length, 1)
    assert.equal(answers[0].UserId, id)
    assert.equal(answers[0].SecurityQuestionId, 2)
    assert.equal(answers[0].answer, security.hmac('Rosebud'))
  })

  void it('4b. ignores a client supplied UserId or id inside the registration payload', async () => {
    const other = await register()
    const { res, id } = await register({ UserId: other.id, securityQuestion: { id: 1, UserId: other.id }, securityAnswer: 'Jane' })
    assert.equal(res.status, 201)
    assert.equal((await answersOf(id)).length, 1)
    assert.equal((await answersOf(other.id)).length, 0)
  })

  void it('5. registration without question and answer succeeds and creates no answer', async () => {
    for (const extra of [
      {},
      { securityQuestion: null, securityAnswer: null },
      { securityAnswer: 'answer without question' },
      { securityQuestion: { id: 1 } },
      { securityQuestion: { id: 1 }, securityAnswer: '' },
      { securityQuestion: { id: 'x' }, securityAnswer: 'a' }
    ]) {
      const { res, id } = await register(extra)
      assert.equal(res.status, 201, JSON.stringify(extra))
      assert.equal((await answersOf(id)).length, 0, JSON.stringify(extra))
    }
  })

  void it('6. registering while logged in as another user binds the answer to the new user only', async () => {
    const existing = await register()
    const { token } = await login(app, { email: existing.email, password: existing.password })

    const email = newEmail()
    const res = await request(app)
      .post('/api/Users')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
      .send({ email, password: 'Passw0rd-new', passwordRepeat: 'Passw0rd-new', securityQuestion: { id: 3 }, securityAnswer: 'Stale Session' })
    assert.equal(res.status, 201)

    assert.equal((await answersOf(existing.id)).length, 0)
    const answers = await answersOf(res.body.data.id)
    assert.equal(answers.length, 1)
    assert.equal(answers[0].SecurityQuestionId, 3)
  })

  void it('7. leaves no half-created user behind when storing the answer fails', async () => {
    mock.method(SecurityAnswerModel, 'create', async () => { throw new Error('forced answer failure') })
    mock.method(logger, 'error', () => logger)

    const { res, email, password } = await register({ securityQuestion: { id: 1 }, securityAnswer: 'Never Stored' })

    assert.equal(res.status, 500)
    assert.equal(await UserModel.findOne({ where: { email }, paranoid: false }), null)
    mock.restoreAll()
    const loginRes = await request(app).post('/rest/user/login').set(jsonHeader).send({ email, password })
    assert.equal(loginRes.status, 401)
  })

  void it('7b. a failed registration can be retried with the same email', async () => {
    const email = newEmail()
    const payload = { email, password: 'Passw0rd-retry', passwordRepeat: 'Passw0rd-retry', securityQuestion: { id: 1 }, securityAnswer: 'Retry' }
    const failing = mock.method(SecurityAnswerModel, 'create', async () => { throw new Error('forced answer failure') })
    mock.method(logger, 'error', () => logger)
    assert.equal((await request(app).post('/api/Users').set(jsonHeader).send(payload)).status, 500)
    failing.mock.restore()

    const retry = await request(app).post('/api/Users').set(jsonHeader).send(payload)
    assert.equal(retry.status, 201)
    assert.equal((await answersOf(retry.body.data.id)).length, 1)
  })

  void it('18. logs neither secrets, answers, UserIds nor hashes when the compensation also fails', async () => {
    const logged: string[] = []
    mock.method(logger, 'error', (...args: unknown[]) => { logged.push(args.map(String).join(' ')); return logger })
    mock.method(logger, 'warn', (...args: unknown[]) => { logged.push(args.map(String).join(' ')); return logger })
    mock.method(logger, 'info', (...args: unknown[]) => { logged.push(args.map(String).join(' ')); return logger })
    mock.method(SecurityAnswerModel, 'create', async () => { throw new Error('forced answer failure') })
    const destroy = mock.method(UserModel.prototype, 'destroy', async () => { throw new Error('forced compensation failure') })

    const answer = 'Super-Secret-Answer-4711'
    const { res, email, password } = await register({ securityQuestion: { id: 1 }, securityAnswer: answer })
    assert.equal(res.status, 500)
    assert.ok(destroy.mock.callCount() >= 1, 'a compensating delete must have been attempted')

    const joined = logged.join('\n')
    assert.ok(joined.includes('forced answer failure'), 'the answer storage error must be logged')
    assert.ok(joined.includes('forced compensation failure'), 'the compensation error must be logged')
    const leftover = await UserModel.findOne({ where: { email }, paranoid: false })
    for (const secret of [answer, security.hmac(answer), password, security.hash(password), email, 'UserId', String(leftover?.id)]) {
      assert.equal(joined.includes(secret), false, `log output must not contain ${secret === answer ? 'the answer' : 'sensitive values'}`)
    }
    assert.equal(res.text.includes(answer), false)
    assert.equal(res.text.includes(security.hmac(answer)), false)

    mock.restoreAll()
    await UserModel.destroy({ where: { email }, force: true })
  })
})

void describe('GET /rest/user/security-question', () => {
  void it('8. answers identically for existing, unknown, answer-less and malformed lookups', async () => {
    const withAnswer = await register({ securityQuestion: { id: 1 }, securityAnswer: 'Answer' })
    const withoutAnswer = await register()
    const urls = [
      `/rest/user/security-question?email=jim@${domain()}`,
      `/rest/user/security-question?email=${encodeURIComponent(withAnswer.email)}`,
      `/rest/user/security-question?email=${encodeURIComponent(withoutAnswer.email)}`,
      '/rest/user/security-question?email=horst@unknown-us.er',
      `/rest/user/security-question?email=JIM@${domain()}`,
      '/rest/user/security-question',
      '/rest/user/security-question?email=',
      `/rest/user/security-question?email=jim@${domain()}&email=x`,
      '/rest/user/security-question?email[a]=b',
      "/rest/user/security-question?email=';"
    ]
    const responses = []
    for (const url of urls) {
      responses.push(snapshot(await request(app).get(url)))
    }
    for (let i = 1; i < responses.length; i++) {
      assert.deepEqual(responses[i], responses[0], `response for ${urls[i]} differs from ${urls[0]}`)
    }
    assert.equal(responses[0].status, 404, 'a fixed 404 is expected')
  })

  void it('9. never returns a question, an email address, an id or any user data', async () => {
    const res = await request(app).get(`/rest/user/security-question?email=jim@${domain()}`)
    const text = res.text.toLowerCase()
    assert.equal(text.includes('siblings'), false)
    assert.equal(text.includes('jim@'), false)
    assert.equal(text.includes('"question"'), false)
    assert.equal(text.includes('"id"'), false)
    assert.equal(text.includes('securityquestion'), false)
    assert.equal(/[a-f0-9]{32}/.test(text), false)
  })
})

void describe('POST /rest/user/reset-password', () => {
  void it('10. does not change the password even for the correct answer', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email: `jim@${domain()}`, answer: 'Samuel', new: 'changed-by-attacker', repeat: 'changed-by-attacker' })
    assert.notEqual(res.status, 200)

    assert.equal((await request(app).post('/rest/user/login').set(jsonHeader).send({ email: `jim@${domain()}`, password: 'changed-by-attacker' })).status, 401)
    assert.equal((await request(app).post('/rest/user/login').set(jsonHeader).send({ email: `jim@${domain()}`, password: 'ncc-1701' })).status, 200)
    assert.equal(challenges.resetPasswordJimChallenge.solved, false)
  })

  void it('10b. does not change the password for a registered user with their own answer', async () => {
    const user = await register({ securityQuestion: { id: 1 }, securityAnswer: 'My Own Answer' })
    await request(app).post('/rest/user/reset-password').set(jsonHeader).send({ email: user.email, answer: 'My Own Answer', new: 'new-password-1', repeat: 'new-password-1' })

    assert.equal((await request(app).post('/rest/user/login').set(jsonHeader).send({ email: user.email, password: 'new-password-1' })).status, 401)
    assert.equal((await request(app).post('/rest/user/login').set(jsonHeader).send({ email: user.email, password: user.password })).status, 200)
  })

  void it('11. responds identically for existing, unknown, correct, wrong and malformed requests', async () => {
    const withAnswer = await register({ securityQuestion: { id: 1 }, securityAnswer: 'Known Answer' })
    const withoutAnswer = await register()
    const bodies: Array<Record<string, unknown> | undefined> = [
      { email: `jim@${domain()}`, answer: 'Samuel', new: 'abcdef', repeat: 'abcdef' },
      { email: `jim@${domain()}`, answer: 'wrong', new: 'abcdef', repeat: 'abcdef' },
      { email: withAnswer.email, answer: 'Known Answer', new: 'abcdef', repeat: 'abcdef' },
      { email: withoutAnswer.email, answer: 'anything', new: 'abcdef', repeat: 'abcdef' },
      { email: 'nobody@unknown-us.er', answer: 'anything', new: 'abcdef', repeat: 'abcdef' },
      { email: `JIM@${domain()}`, answer: 'Samuel', new: 'abcdef', repeat: 'abcdef' },
      { email: [`jim@${domain()}`, 'x'], answer: 'Samuel', new: 'abcdef', repeat: 'abcdef' },
      { email: `jim@${domain()}`, answer: ['Samuel'], new: 'abcdef', repeat: 'abcdef' },
      { email: `jim@${domain()}`, answer: 'Samuel', repeat: 'abcdef' },
      { email: `jim@${domain()}`, answer: 'Samuel', new: 'abcdef', repeat: 'different' },
      { answer: 'Samuel', new: 'abcdef', repeat: 'abcdef' },
      { email: `jim@${domain()}`, new: 'abcdef', repeat: 'abcdef' },
      undefined
    ]
    const responses = []
    for (const body of bodies) {
      const req = request(app).post('/rest/user/reset-password').set(jsonHeader)
      responses.push(snapshot(body ? await req.send(body) : await req))
    }
    for (let i = 1; i < responses.length; i++) {
      assert.deepEqual(responses[i], responses[0], `response for request #${i} differs from request #0`)
    }
    assert.notEqual(responses[0].status, 200)
    assert.notEqual(responses[0].status, 500)
  })

  void it('12. never returns a user object, an email address or a password hash', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email: `jim@${domain()}`, answer: 'Samuel', new: 'abcdef', repeat: 'abcdef' })
    const text = res.text.toLowerCase()
    assert.equal(text.includes('"user"'), false)
    assert.equal(text.includes('"password"'), false)
    assert.equal(text.includes('jim@'), false)
    assert.equal(text.includes('"email"'), false)
    assert.equal(text.includes('"id"'), false)
    assert.equal(/[a-f0-9]{32}/.test(text), false)
    assert.equal(security.hash('abcdef') && text.includes(security.hash('abcdef')), false)
  })

  void it('18b. does not log answers or passwords while rejecting reset attempts', async () => {
    const logged: string[] = []
    for (const level of ['error', 'warn', 'info', 'debug'] as const) {
      mock.method(logger, level, (...args: unknown[]) => { logged.push(args.map(String).join(' ')); return logger })
    }
    await request(app).post('/rest/user/reset-password').set(jsonHeader).send({ email: `jim@${domain()}`, answer: 'Samuel', new: 'Secret-Pass-1', repeat: 'Secret-Pass-1' })
    await request(app).get(`/rest/user/security-question?email=jim@${domain()}`)
    const joined = logged.join('\n')
    for (const secret of ['Samuel', 'Secret-Pass-1', security.hash('Secret-Pass-1'), security.hmac('Samuel')]) {
      assert.equal(joined.includes(secret), false)
    }
  })
})

void describe('challenges depending on the security answer flow', () => {
  void it('16. are defined but unavailable on Hardened and stay unsolved', async () => {
    const res = await request(app).get('/api/Challenges')
    assert.equal(res.status, 200)
    for (const key of hardenedResetChallenges) {
      const challenge = res.body.data.find((c: { key: string }) => c.key === key)
      assert.ok(challenge, `${key} must not be removed`)
      assert.equal(challenge.disabledEnv, 'Hardened', `${key} must be disabled on Hardened`)
      assert.equal(challenge.solved, false, `${key} must not be solved`)
      assert.deepEqual(utils.getChallengeEnablementStatus((challenges as Record<string, any>)[key]), { enabled: false, disabledBecause: 'Hardened' })
    }
  })
})

void describe('existing flows that must keep working', () => {
  void it('14. regular registration and login still work', async () => {
    const { res, email, password } = await register({ securityQuestion: { id: 1 }, securityAnswer: 'Regular' })
    assert.equal(res.status, 201)
    const loginRes = await request(app).post('/rest/user/login').set(jsonHeader).send({ email, password })
    assert.equal(loginRes.status, 200)
    assert.ok(loginRes.body.authentication.token)

    const seeded = await login(app, { email: `jim@${domain()}`, password: 'ncc-1701' })
    assert.ok(seeded.token)
  })

  void it('15. /dataerasure still finds the answer stored during registration', async () => {
    const { email, password } = await register({ securityQuestion: { id: 1 }, securityAnswer: 'Erasure' })
    const { token } = await login(app, { email, password })
    const res = await request(app).get('/dataerasure/').set({ Cookie: 'token=' + token })
    assert.equal(res.status, 200)
    assert.ok(res.text.includes(email))
    assert.ok(res.text.includes('Your eldest siblings middle name?'))
  })

  void it('15b. /dataerasure still reports a missing answer for users registered without one', async () => {
    const { email, password } = await register()
    const { token } = await login(app, { email, password })
    const res = await request(app).get('/dataerasure/').set({ Cookie: 'token=' + token })
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: No answer found!'))
  })
})
