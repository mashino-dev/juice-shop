/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import type { Challenge } from '@juice-shop/data/types'
import { extractRegistrationSecurityAnswer, registrationFields, restrictRegistrationFields, storeRegistrationSecurityAnswer } from '../../routes/userRegistration'
import * as verify from '../../routes/verify'

void describe('userRegistration', () => {
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = { json: mock.fn(), status: mock.fn(() => res), send: mock.fn() }
    next = mock.fn()
    save = () => ({ then () { } })
  })

  const run = (body: unknown) => {
    const req: any = { body }
    restrictRegistrationFields()(req, res, next)
    return req
  }

  void it('allows exactly email, password and passwordRepeat', () => {
    assert.deepEqual([...registrationFields], ['email', 'password', 'passwordRepeat'])
  })

  void it('keeps allowed fields, drops everything else and sets the customer role on the server', () => {
    const req = run({
      email: 'a@b.c',
      password: 'secret',
      passwordRepeat: 'secret',
      role: 'admin',
      deluxeToken: 'x',
      totpSecret: 'y',
      isActive: false,
      id: 1,
      securityAnswer: 'z',
      unknown: true
    })
    assert.deepEqual(req.body, { email: 'a@b.c', password: 'secret', passwordRepeat: 'secret', role: 'customer' })
    assert.equal(next.mock.callCount(), 1)
  })

  void it('does not modify the submitted object and returns a new one', () => {
    const submitted = { email: 'a@b.c', password: 'secret', role: 'admin' }
    const req = run(submitted)
    assert.notEqual(req.body, submitted)
    assert.equal(submitted.role, 'admin')
  })

  void it('ignores inherited properties', () => {
    const req = run(Object.create({ email: 'inherited@b.c', password: 'inherited' }))
    assert.deepEqual(req.body, { role: 'customer' })
  })

  for (const [name, body] of [
    ['null', null],
    ['undefined', undefined],
    ['an array', ['role', 'admin']],
    ['a string', 'role=admin'],
    ['a number', 42],
    ['a boolean', true]
  ] as Array<[string, unknown]>) {
    void it(`does not throw for a body that is ${name}`, () => {
      const req = run(body)
      assert.equal(req.body.role, 'customer')
      assert.equal(Object.prototype.hasOwnProperty.call(req.body, 'email'), false)
      assert.equal(next.mock.callCount(), 1)
    })
  }

  void describe('followed by the registration challenge checks', () => {
    beforeEach(() => {
      challenges.registerAdminChallenge = { solved: false, save } as unknown as Challenge
      challenges.passwordRepeatChallenge = { solved: false, save } as unknown as Challenge
      challenges.emptyUserRegistration = { solved: false, save } as unknown as Challenge
    })

    const chain = (body: unknown) => {
      const req: any = { body }
      restrictRegistrationFields()(req, res, next)
      verify.registerAdminChallenge()(req, res, next)
      verify.passwordRepeatChallenge()(req, res, next)
      verify.emptyUserRegistration()(req, res, next)
    }

    void it('Admin Registration is not solved by a requested admin role', () => {
      chain({ email: 'a@b.c', password: 'secret', passwordRepeat: 'secret', role: 'admin' })
      assert.equal(challenges.registerAdminChallenge.solved, false)
    })

    void it('Repetitive Registration is still solved by a differing passwordRepeat', () => {
      chain({ email: 'a@b.c', password: 'secret', passwordRepeat: 'other' })
      assert.equal(challenges.passwordRepeatChallenge.solved, true)
    })

    void it('Empty User Registration is still solved by empty email and password', () => {
      chain({ email: '', password: '', passwordRepeat: '' })
      assert.equal(challenges.emptyUserRegistration.solved, true)
    })
  })

  void describe('security answer submitted with the registration', () => {
    void it('is extracted from a positive integer question id and a non-empty answer', () => {
      assert.deepEqual(
        extractRegistrationSecurityAnswer({ securityQuestion: { id: 3, question: 'Q?' }, securityAnswer: 'A' }),
        { SecurityQuestionId: 3, answer: 'A' })
    })

    for (const [name, body] of [
      ['no question and answer', {}],
      ['null question and answer', { securityQuestion: null, securityAnswer: null }],
      ['an answer without question', { securityAnswer: 'A' }],
      ['a question without answer', { securityQuestion: { id: 1 } }],
      ['an empty answer', { securityQuestion: { id: 1 }, securityAnswer: '' }],
      ['a non-string answer', { securityQuestion: { id: 1 }, securityAnswer: ['A'] }],
      ['a string question id', { securityQuestion: { id: '1' }, securityAnswer: 'A' }],
      ['a fractional question id', { securityQuestion: { id: 1.5 }, securityAnswer: 'A' }],
      ['a zero question id', { securityQuestion: { id: 0 }, securityAnswer: 'A' }],
      ['a negative question id', { securityQuestion: { id: -1 }, securityAnswer: 'A' }],
      ['a question that is not an object', { securityQuestion: 1, securityAnswer: 'A' }],
      ['inherited properties only', Object.create({ securityQuestion: { id: 1 }, securityAnswer: 'A' })]
    ] as Array<[string, Record<string, unknown>]>) {
      void it(`is not extracted for ${name}`, () => {
        assert.equal(extractRegistrationSecurityAnswer(body), undefined)
      })
    }

    void it('never takes a UserId from the payload and is not part of the body that reaches the model', () => {
      const req: any = { body: { email: 'a@b.c', password: 'secret', UserId: 99, securityQuestion: { id: 1, UserId: 98 }, securityAnswer: 'A' } }
      restrictRegistrationFields()(req, res, next)
      assert.deepEqual(req.body, { email: 'a@b.c', password: 'secret', role: 'customer' })
      assert.deepEqual(extractRegistrationSecurityAnswer({ securityQuestion: { id: 1, UserId: 98 }, securityAnswer: 'A' }), { SecurityQuestionId: 1, answer: 'A' })
    })

    void it('is not stored by the finale hook for a request that did not submit one', async () => {
      const context: any = { instance: { id: 1 }, continue: 'continue', error: mock.fn() }
      const result = await storeRegistrationSecurityAnswer()({} as any, res, context)
      assert.equal(result, 'continue')
      assert.equal(context.error.mock.callCount(), 0)
    })
  })
})
