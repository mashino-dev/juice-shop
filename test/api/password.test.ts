/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/change-password', () => {
  void it('GET password change for newly created user with recognized token as Authorization header', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kuni@be.rt',
        password: 'kunigunde'
      })
      .expect(201)

    const { token } = await login(app, { email: 'kuni@be.rt', password: 'kunigunde' })

    const res = await request(app)
      .get('/rest/user/change-password?current=kunigunde&new=foo&repeat=foo')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
  })

  void it('GET password change with passing wrong current password', async () => {
    const { token } = await login(app, {
      email: 'bjoern@' + config.get<string>('application.domain'),
      password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
    })

    const res = await request(app)
      .get('/rest/user/change-password?current=definetely_wrong&new=blubb&repeat=blubb')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))
  })

  void it('GET password change without passing any passwords', async () => {
    const res = await request(app)
      .get('/rest/user/change-password')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty'))
  })

  void it('GET password change with passing wrong repeated password', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=bar')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match'))
  })

  void it('GET password change without passing an authorization token', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=foo')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET password change with passing unrecognized authorization token', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=foo')
      .set({ Authorization: 'Bearer unknown' })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET password change for Bender without current password using GET request', async () => {
    const { token } = await login(app, {
      email: 'bender@' + config.get<string>('application.domain'),
      password: 'OhG0dPlease1nsertLiquor!'
    })

    const res = await request(app)
      .get('/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
  })
})

void describe('/rest/user/reset-password (security answer based Forgot Password is unavailable on Hardened)', () => {
  const resetAttempts: Array<{ name: string, email: string, answer: string, challenge: keyof typeof challenges }> = [
    { name: 'Jim', email: 'jim@' + config.get<string>('application.domain'), answer: 'Samuel', challenge: 'resetPasswordJimChallenge' },
    { name: 'Bender', email: 'bender@' + config.get<string>('application.domain'), answer: 'Stop\'n\'Drop', challenge: 'resetPasswordBenderChallenge' },
    { name: 'Bjoern\u00b4s internal account', email: 'bjoern@' + config.get<string>('application.domain'), answer: 'West-2082', challenge: 'resetPasswordBjoernChallenge' },
    { name: 'Bjoern\u00b4s OWASP account', email: 'bjoern@owasp.org', answer: 'Zaya', challenge: 'resetPasswordBjoernOwaspChallenge' },
    { name: 'Morty', email: 'morty@' + config.get<string>('application.domain'), answer: '5N0wb41L', challenge: 'resetPasswordMortyChallenge' },
    { name: 'Uvogin', email: 'uvogin@' + config.get<string>('application.domain'), answer: 'Silence of the Lambs', challenge: 'resetPasswordUvoginChallenge' }
  ]

  for (const { name, email, answer, challenge } of resetAttempts) {
    void it(`POST password reset for ${name} with the correct answer is refused and solves nothing`, async () => {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json' })
        .send({ email, answer, new: 'not-going-to-be-set', repeat: 'not-going-to-be-set' })

      assert.equal(res.status, 404)
      assert.equal(res.body.user, undefined)
      assert.equal(challenges[challenge].solved, false)
    })
  }

  void it('POST password reset with wrong answer gets the same refusal as a correct answer', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: '25436',
        new: '12345',
        repeat: '12345'
      })

    assert.equal(res.status, 404)
    assert.ok(res.text.includes('not available'))
  })

  void it('POST password reset without any data gets the same refusal instead of an error page', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')

    assert.equal(res.status, 404)
    assert.ok(res.text.includes('not available'))
    assert.ok(!res.text.includes('Blocked illegal activity'))
  })
})
