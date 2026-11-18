/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import type { Challenge } from '@juice-shop/data/types'
import { registrationFields, restrictRegistrationFields } from '../../routes/userRegistration'
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
})
