/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/*
 * Defensive regression tests for the finding "Passkey login issues a full session even when the
 * WebAuthn assertion fails signature verification". All users and keys are generated at runtime and
 * assertion messages never contain any secret, token, signature or challenge value.
 */

import crypto from 'node:crypto'
import path from 'node:path'
import { describe, it, before, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import { buildAssertion, buildAttestation, flipBit, type VictimCredential } from './helpers/passkey'
import { loadStaticUserData } from '../../data/staticData'
import { PasskeyModel } from '../../models/passkey'
import { BasketModel } from '../../models/basket'
import { UserModel } from '../../models/user'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'

// The library offers no public hook to force `verified: false`, but it routes the result of the
// signature check through this stubbable seam (see verifySignature.js).
const verifySignatureModule = require(path.join(path.dirname(require.resolve('@simplewebauthn/server')), 'helpers', 'verifySignature.js'))

const jsonHeader: Record<string, string> = { 'content-type': 'application/json', host: 'localhost:3000' }
const bearer = (token: string) => ({ Authorization: 'Bearer ' + token, ...jsonHeader })
const SENTINEL = 'synthetic-' + crypto.randomBytes(8).toString('hex')

let app: Express
let signCount = 1000

interface Owner {
  id: number
  email: string
  token: string
  credential: VictimCredential
}

const sessionCount = () => Object.keys(security.authenticatedUsers.tokenMap).length
const storedCounter = async (credential: VictimCredential) => (await PasskeyModel.findOne({ where: { credentialID: credential.credentialID } }))?.counter

async function newOwner (): Promise<Owner> {
  const email = `pk-sig-${crypto.randomBytes(6).toString('hex')}@example.test`
  const password = 'Aa1!' + crypto.randomBytes(12).toString('base64url')
  await register(app, { email, password })
  const { token } = await login(app, { email, password })
  const id = (await UserModel.findOne({ where: { email } }))?.id as number

  const options = await request(app).get('/rest/passkey/register-options').set(bearer(token))
  const credentialID = isoBase64URL.fromBuffer(crypto.randomBytes(32))
  const forged = buildAttestation(credentialID, options.body.options.challenge)
  const registered = await request(app)
    .post('/rest/passkey/register-verify')
    .set(bearer(token))
    .send({ attestation: forged.attestation, regToken: options.body.regToken })
  assert.equal(registered.status, 200)
  return { id, email, token, credential: { credentialID, publicKeyCose: forged.publicKey, privateKeyPem: forged.privateKeyPem } }
}

async function loginOptions (email?: string) {
  const res = await request(app).post('/rest/passkey/login-options').set(jsonHeader).send(email ? { email } : {})
  return { challenge: res.body.options.challenge as string, authToken: res.body.authToken as string }
}

const loginVerify = (body: object) => request(app).post('/rest/passkey/login-verify').set(jsonHeader).send(body)

async function signedAssertion (owner: Owner, options: Partial<Parameters<typeof buildAssertion>[2]> = {}) {
  const { challenge, authToken } = await loginOptions(owner.email)
  const counter = ++signCount
  return { counter, authToken, assertion: buildAssertion(owner.credential, challenge, { tamper: false, counter, ...options }) }
}

// A rejected login must leave nothing behind: empty body (so no token and no internals), no new
// session, unchanged counter and no basket for the user.
async function assertRejectedWithoutSideEffects (owner: Owner, run: () => Promise<request.Response>) {
  await BasketModel.destroy({ where: { UserId: owner.id } })
  const sessionsBefore = sessionCount()
  const tokenBefore = security.authenticatedUsers.tokenOf(await UserModel.findByPk(owner.id) as UserModel)
  const counterBefore = await storedCounter(owner.credential)

  const res = await run()

  assert.equal(res.status, 401)
  assert.equal(res.text, '', 'response body must be empty')
  assert.equal(res.body?.authentication, undefined, 'a session was returned')
  assert.equal(sessionCount(), sessionsBefore, 'authenticatedUsers changed')
  assert.equal(security.authenticatedUsers.tokenOf(await UserModel.findByPk(owner.id) as UserModel), tokenBefore, 'session of the user changed')
  assert.equal(await storedCounter(owner.credential), counterBefore, 'counter changed')
  assert.equal(await BasketModel.count({ where: { UserId: owner.id } }), 0, 'a basket was created')
}

before(async () => {
  app = (await createTestApp()).app
}, { timeout: 60000 })

afterEach(() => { mock.restoreAll() })

void describe('passkey login-verify signature gate', () => {
  void it('signs in a genuine assertion, stores the new counter and issues a session', async () => {
    const owner = await newOwner()
    challenges.passkeySignatureChallenge.solved = false
    const { assertion, authToken, counter } = await signedAssertion(owner)

    const res = await loginVerify({ assertion, authToken })

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(res.body.authentication.umail, owner.email)
    assert.equal(await storedCounter(owner.credential), counter)
    assert.equal(challenges.passkeySignatureChallenge.solved, false)
  })

  void it('rejects an assertion signed with a different key', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner, { tamper: true })

    await assertRejectedWithoutSideEffects(owner, () => loginVerify({ assertion, authToken }))
  })

  void it('rejects an assertion whose signature has a single flipped bit', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner)
    // The last byte belongs to the DER-encoded `s` integer, so the signature stays well-formed.
    assertion.response.signature = flipBit(assertion.response.signature, -1)

    await assertRejectedWithoutSideEffects(owner, () => loginVerify({ assertion, authToken }))
  })

  void it('rejects when the library reports verified=false for an otherwise valid assertion', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner)
    mock.method(verifySignatureModule._verifySignatureInternals, 'stubThis', () => Promise.resolve(false))

    await assertRejectedWithoutSideEffects(owner, () => loginVerify({ assertion, authToken }))
  })

  void it('does not solve passkeySignatureChallenge for a failed assertion against the seeded passkey-user', async () => {
    const seeded = (await loadStaticUserData()).find(({ key }) => key === 'passkeyUser')?.passkeys?.[0]
    assert.ok(seeded)
    const { challenge, authToken } = await loginOptions()
    const credential = { credentialID: seeded.credentialID, publicKeyCose: seeded.publicKey, privateKeyPem: '' }
    // Signed with a throwaway key, never with the seeded passkey's own key.
    const assertion = buildAssertion(credential, challenge, { tamper: true, counter: ++signCount })
    challenges.passkeySignatureChallenge.solved = false
    const sessionsBefore = sessionCount()

    const res = await loginVerify({ assertion, authToken })

    assert.equal(res.status, 401)
    assert.equal(res.text, '')
    assert.equal(sessionCount(), sessionsBefore)
    assert.equal(challenges.passkeySignatureChallenge.solved, false)
  })

  void it('keeps passkeySignatureChallenge defined but unavailable on Hardened', async () => {
    assert.ok(challenges.passkeySignatureChallenge)
    assert.equal(challenges.passkeySignatureChallenge.disabledEnv, 'Hardened')
    assert.deepEqual(utils.getChallengeEnablementStatus(challenges.passkeySignatureChallenge), { enabled: false, disabledBecause: 'Hardened' })
  })
})

void describe('passkey login-verify verification exceptions', () => {
  void it('answers 401 without body, session or logged values when the library throws', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner)
    mock.method(verifySignatureModule._verifySignatureInternals, 'stubThis', () => { throw new Error(SENTINEL) })
    const output: string[] = []
    const stdout = process.stdout.write.bind(process.stdout)
    const stderr = process.stderr.write.bind(process.stderr)
    mock.method(process.stdout, 'write', (chunk: any, ...rest: any[]) => { output.push(String(chunk)); return stdout(chunk, ...rest) })
    mock.method(process.stderr, 'write', (chunk: any, ...rest: any[]) => { output.push(String(chunk)); return stderr(chunk, ...rest) })

    await assertRejectedWithoutSideEffects(owner, () => loginVerify({ assertion, authToken }))

    mock.restoreAll()
    assert.ok(!output.some((line) => line.includes(SENTINEL)), 'the error message was logged')
  })

  void it('answers 401 with an empty body for a signature the library cannot parse, without stack or paths', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner)
    // 0x30 (SEQUENCE) -> 0x31: the library cannot parse the DER signature and throws.
    assertion.response.signature = flipBit(assertion.response.signature, 0)

    await assertRejectedWithoutSideEffects(owner, () => loginVerify({ assertion, authToken }))
  })

  void it('answers 401 with an empty body for a different origin, a wrong challenge and a replayed counter', async () => {
    const owner = await newOwner()
    const first = await signedAssertion(owner)
    await loginVerify({ assertion: first.assertion, authToken: first.authToken }).expect(200)
    const cases = {
      'different origin': () => signedAssertion(owner, { origin: 'http://evil.example:3000' }),
      'wrong challenge': async () => {
        const { authToken } = await loginOptions(owner.email)
        const wrong = buildAssertion(owner.credential, isoBase64URL.fromBuffer(crypto.randomBytes(32)), { tamper: false, counter: ++signCount })
        return { assertion: wrong, authToken }
      },
      'replayed counter': async () => {
        const { challenge, authToken } = await loginOptions(owner.email)
        return { assertion: buildAssertion(owner.credential, challenge, { tamper: false, counter: first.counter }), authToken }
      }
    }
    for (const [name, craft] of Object.entries(cases)) {
      const { assertion, authToken } = await craft()

      await assertRejectedWithoutSideEffects(owner, () => loginVerify({ assertion, authToken }))
      assert.ok(true, name)
    }
  })

  void it('does not solve passkeySignatureChallenge when the library throws', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner)
    challenges.passkeySignatureChallenge.solved = false
    mock.method(verifySignatureModule._verifySignatureInternals, 'stubThis', () => { throw new Error(SENTINEL) })

    const res = await loginVerify({ assertion, authToken })

    assert.equal(res.status, 401)
    assert.equal(challenges.passkeySignatureChallenge.solved, false)
  })
})

void describe('passkey login-verify persistence failures', () => {
  void it('issues no session and no JWT when passkey.save() fails', async () => {
    const owner = await newOwner()
    const { assertion, authToken } = await signedAssertion(owner)
    await BasketModel.destroy({ where: { UserId: owner.id } })
    const sessionsBefore = sessionCount()
    const counterBefore = await storedCounter(owner.credential)
    mock.method(PasskeyModel.prototype, 'save', () => Promise.reject(new Error(SENTINEL)))

    const res = await loginVerify({ assertion, authToken })

    assert.notEqual(res.status, 200)
    assert.equal(res.body?.authentication, undefined)
    assert.ok(!res.text.includes('"token"'))
    assert.equal(sessionCount(), sessionsBefore)
    assert.equal(await BasketModel.count({ where: { UserId: owner.id } }), 0)
    mock.restoreAll()
    assert.equal(await storedCounter(owner.credential), counterBefore)
  })

  void it('stores the counter before the session is issued, and only for a verified assertion', async () => {
    const owner = await newOwner()
    const calls: string[] = []
    const originalSave = PasskeyModel.prototype.save
    mock.method(PasskeyModel.prototype, 'save', async function (this: PasskeyModel, ...args: any[]) {
      calls.push('save')
      return await originalSave.apply(this, args as any)
    })
    const originalPut = security.authenticatedUsers.put
    mock.method(security.authenticatedUsers, 'put', function (this: any, ...args: any[]) {
      calls.push('session')
      return originalPut.apply(this, args as any)
    })
    const rejected = await signedAssertion(owner, { tamper: true })
    await loginVerify({ assertion: rejected.assertion, authToken: rejected.authToken }).expect(401)
    assert.deepEqual(calls, [])

    const accepted = await signedAssertion(owner)
    await loginVerify({ assertion: accepted.assertion, authToken: accepted.authToken }).expect(200)

    assert.deepEqual(calls, ['save', 'session'])
    assert.equal(await storedCounter(owner.credential), accepted.counter)
  })
})

void describe('passkey registration and sign-in stay intact', () => {
  void it('registers a passkey, lists it and signs in with it', async () => {
    const owner = await newOwner()

    const listed = await request(app).get('/rest/passkey/credentials').set(bearer(owner.token))
    const { assertion, authToken } = await signedAssertion(owner)
    const res = await loginVerify({ assertion, authToken })

    assert.equal(listed.status, 200)
    assert.ok(listed.body.data.some((c: { credentialID: string }) => c.credentialID === owner.credential.credentialID))
    assert.equal(res.status, 200)
    assert.equal(res.body.authentication.umail, owner.email)
  })
})
