/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import logger from '../../lib/logger'
import * as models from '../../models/index'
import { createTestApp } from './helpers/setup'

// Assertions in this file compare booleans on purpose, so that a failing test never prints
// credentials, the canary value, response bodies or log lines into the test output.

let app: Express
const domain = config.get<string>('application.domain')
const email = `sqli-regression-${crypto.randomUUID()}@${domain}`
const password = crypto.randomBytes(16).toString('hex')

const INTERNALS = /SELECT|SQLITE|SequelizeDatabaseError|sqlite_master|CREATE TABLE|\.ts:\d+|\.js:\d+|node_modules|\/home\/|\/tmp\/|\n\s+at /i

const leaksInternals = (text: string, secret?: string) =>
  INTERNALS.test(text) || text.includes(process.cwd()) || (secret !== undefined && text.includes(secret))

const login = async (body: object) => await request(app).post('/rest/user/login').set('content-type', 'application/json').send(body)
const search = async (q?: string) => await request(app).get('/rest/products/search').query(q === undefined ? {} : { q })

const databaseError = (name: string, withParent: boolean) => {
  const error: any = new Error('SQLITE_ERROR: no such table: Internal')
  error.name = name
  error.sql = 'SELECT * FROM Internal WHERE value = canary'
  if (withParent) error.parent = Object.assign(new Error('SQLITE_ERROR: no such table: Internal'), { sql: error.sql })
  return error
}

const failQueriesStartingWith = (prefix: string, error: Error) => {
  const original = models.sequelize.query.bind(models.sequelize)
  mock.method(models.sequelize, 'query', async (...args: any[]) => {
    if (typeof args[0] === 'string' && args[0].startsWith(prefix)) throw error
    return await original(args[0], args[1])
  })
}

before(async () => {
  app = (await createTestApp()).app
  const res = await request(app).post('/api/Users').set('content-type', 'application/json')
    .send({ email, password, passwordRepeat: password, securityQuestion: { id: 1 }, securityAnswer: crypto.randomUUID() })
  assert.equal(res.status, 201)
}, { timeout: 60000 })

afterEach(() => { mock.restoreAll() })

void describe('POST /rest/user/login SQL injection regression', () => {
  void it('logs in with valid credentials', async () => {
    const res = await login({ email, password })
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(res.body.authentication.umail === email, true)
  })

  void it('rejects a wrong password with 401', async () => {
    const res = await login({ email, password: password + 'x' })
    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  for (const [index, payload] of ["' or 1=1--", `${email}'--`, "') or ('1'='1", "'; select 1--", "\\' or 1=1--"].entries()) {
    void it(`does not authenticate with SQL metacharacters in the email (variant ${index + 1})`, async () => {
      const res = await login({ email: payload, password: 'irrelevant' })
      assert.equal(res.status, 401)
      assert.equal(res.body.authentication, undefined)
    })
  }

  void it('does not authenticate with SQL metacharacters in the password', async () => {
    const res = await login({ email, password: "' or '1'='1" })
    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  for (const [name, value] of [['number', 123], ['boolean', true], ['null', null], ['array', ['a', 'b']], ['object', { a: 1 }]] as Array<[string, unknown]>) {
    void it(`handles a non-string email (${name}) as empty without a server error`, async () => {
      const res = await login({ email: value, password })
      assert.equal(res.status, 401)
    })

    void it(`handles a non-string password (${name}) as empty without a server error`, async () => {
      const res = await login({ email, password: value })
      assert.equal(res.status, 401)
    })
  }

  void it('returns a generic 500, leaks nothing and logs a diagnosable entry on database errors', async () => {
    const canary = `canary-${crypto.randomUUID()}`
    failQueriesStartingWith('SELECT * FROM Users WHERE', databaseError('SequelizeDatabaseError', true))
    const logged = mock.method(logger, 'error', () => logger)

    for (const accept of ['text/html', 'application/json']) {
      const res = await request(app).post('/rest/user/login').set('Accept', accept).set('content-type', 'application/json').send({ email: canary, password: canary })
      assert.equal(res.status, 500)
      assert.equal(res.body.error === 'Internal Server Error', true)
      assert.equal(leaksInternals(res.text, canary), false)
    }

    const lines = logged.mock.calls.map((call) => String(call.arguments[0]))
    assert.equal(lines.length >= 2, true)
    assert.equal(lines.every((line) => line.includes('SequelizeDatabaseError')), true)
    assert.equal(lines.some((line) => line.includes(canary) || /SELECT|SQLITE/.test(line)), false)
  })
})

void describe('GET /rest/products/search SQL injection regression', () => {
  void it('finds products by name and by description', async () => {
    const byName = await search('apple')
    assert.equal(byName.status, 200)
    assert.equal(byName.body.data.some((product: any) => product.name.toLowerCase().includes('apple')), true)

    const all = (await search('')).body.data
    const withDescription = all.find((product: any) => typeof product.description === 'string' && product.description.length > 20)
    assert.notEqual(withDescription, undefined)
    const byDescription = await search(withDescription.description.slice(5, 20))
    assert.equal(byDescription.status, 200)
    assert.equal(byDescription.body.data.some((product: any) => product.id === withDescription.id), true)
  })

  void it('keeps returning all products for an empty, missing or "undefined" query', async () => {
    const all = (await request(app).get('/api/Products')).body.data.length
    assert.equal((await search('')).body.data.length, all)
    assert.equal((await search()).body.data.length, all)
    assert.equal((await search('undefined')).body.data.length, all)
  })

  for (const [index, q] of ['日本語', "it's", 'a"b', 'a;b', '100% juice', '%', 'under_score', '_', 'back\\slash', '\\', ':criteria', '🍎', '-- comment', '/* c */'].entries()) {
    void it(`does not fail for quotes, symbols, wildcards and non-ASCII text (variant ${index + 1})`, async () => {
      const res = await search(q)
      assert.equal(res.status, 200)
      assert.equal(Array.isArray(res.body.data), true)
    })
  }

  void it('keeps "%" and "_" working as LIKE wildcards', async () => {
    const all = (await request(app).get('/api/Products')).body.data.length
    assert.equal((await search('%')).body.data.length, all)
    assert.equal((await search('_')).body.data.length, all)
  })

  void it('limits the search criteria to 200 characters', async () => {
    const original = models.sequelize.query.bind(models.sequelize)
    const spy = mock.method(models.sequelize, 'query', async (...args: any[]) => await original(args[0], args[1]))
    const res = await search('a'.repeat(500))
    assert.equal(res.status, 200)
    const call = spy.mock.calls.find((c: any) => String(c.arguments[0]).includes('FROM Products WHERE'))
    assert.notEqual(call, undefined)
    assert.equal((call?.arguments[1] as any).bind.criteria.length, 202)
  })

  void it('binds the criteria instead of concatenating it into the SQL statement', async () => {
    const original = models.sequelize.query.bind(models.sequelize)
    const canary = `canary${crypto.randomUUID().replace(/-/g, '')}`
    const spy = mock.method(models.sequelize, 'query', async (...args: any[]) => await original(args[0], args[1]))
    const res = await search(canary)
    assert.equal(res.status, 200)
    const call = spy.mock.calls.find((c: any) => String(c.arguments[0]).includes('FROM Products WHERE'))
    assert.notEqual(call, undefined)
    assert.equal(String(call?.arguments[0]).includes(canary), false)
    assert.equal((call?.arguments[1] as any).replacements, undefined)
    assert.equal((call?.arguments[1] as any).bind.criteria.includes(canary), true)
  })

  for (const [index, q] of ["')) union select id,email,password from users--", "') union select sql from sqlite_master--", "' or 1=1--"].entries()) {
    void it(`does not return other tables or schema information for SQL metacharacters (variant ${index + 1})`, async () => {
      const res = await search(q)
      assert.equal(res.status, 200)
      assert.equal(res.body.data.length, 0)
      assert.equal(/CREATE TABLE|sqlite_master|"password"|"totpSecret"/.test(res.text), false)
    })
  }

  void it('handles non-string query values as empty without a server error', async () => {
    const all = (await request(app).get('/api/Products')).body.data.length
    for (const url of ['/rest/products/search?q=apple&q=juice', '/rest/products/search?q[]=apple', '/rest/products/search?q[a]=b']) {
      const res = await request(app).get(url)
      assert.equal(res.status, 200)
      assert.equal(res.body.data.length, all)
    }
  })

  void it('returns a generic 500, leaks nothing and logs a diagnosable entry on database errors', async () => {
    const canary = `canary-${crypto.randomUUID()}`
    failQueriesStartingWith('SELECT * FROM Products WHERE', databaseError('SequelizeDatabaseError', true))
    const logged = mock.method(logger, 'error', () => logger)

    for (const accept of ['text/html', 'application/json']) {
      const res = await request(app).get('/rest/products/search').query({ q: canary }).set('Accept', accept)
      assert.equal(res.status, 500)
      assert.equal(res.body.error === 'Internal Server Error', true)
      assert.equal(leaksInternals(res.text, canary), false)
    }

    const lines = logged.mock.calls.map((call) => String(call.arguments[0]))
    assert.equal(lines.length >= 2, true)
    assert.equal(lines.every((line) => line.includes('SequelizeDatabaseError')), true)
    assert.equal(lines.some((line) => line.includes(canary) || /SELECT|SQLITE/.test(line)), false)
  })
})
