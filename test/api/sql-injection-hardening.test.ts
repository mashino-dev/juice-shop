/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/*
 * Defensive regression tests for the finding "Unauthenticated SQL injection via string-interpolated queries
 * in login and product search". All users, passwords and canary values are generated at runtime. Assertions
 * compare booleans, status codes and counts only, so a failing assertion never prints a password, a canary
 * value or a response body.
 */

import crypto from 'node:crypto'
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import config from 'config'
import sqlite3 from 'sqlite3'
import { generateSecret, generateSync } from 'otplib'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as utils from '../../lib/utils'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
import * as models from '../../models/index'
import logger from '../../lib/logger'
import { searchProducts } from '../../routes/search'

const jsonHeader = { 'content-type': 'application/json' }
const domain = config.get<string>('application.domain')
const GENERIC_ERROR = { status: 'error', message: 'Internal Server Error' }
const LEAK_PATTERN = /SQLITE|Sequelize|\sat\s.+:\d+:\d+|\/routes\/|\/node_modules\/|\.ts:\d+|\.js:\d+/i

let app: Express

const rnd = () => crypto.randomBytes(8).toString('hex')
const randomPassword = () => 'Aa1!' + crypto.randomBytes(12).toString('base64url')
const randomEmail = () => `sqli-${rnd()}@${domain}`

interface CapturedStatement { sql: string, params: unknown }
const statements: CapturedStatement[] = []
const queryCalls: Array<{ sql: string, options: any }> = []
const originalSqliteMethods: Record<string, any> = {}
let originalQuery: (sql: any, options?: any) => Promise<any>

function sqlOf (sql: unknown): string {
  return typeof sql === 'string' ? sql : (sql as { query?: string })?.query ?? ''
}

function selectsFrom (table: string): CapturedStatement[] {
  return statements.filter((s) => new RegExp(`FROM\\s+\`?${table}\`?`, 'i').test(s.sql) && /^\s*select/i.test(s.sql))
}

function leaks (value: unknown, canaries: string[] = []): boolean {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value) ?? ''
  return LEAK_PATTERN.test(serialized) || canaries.some((canary) => serialized.includes(canary))
}

async function postLogin (body: unknown, raw?: string, contentType = 'application/json') {
  return await request(app).post('/rest/user/login').set('content-type', contentType).send(raw ?? JSON.stringify(body))
}

const hasToken = (res: request.Response) => typeof res.body?.authentication?.token === 'string'

async function withFailingQuery<T> (tablePattern: RegExp, run: () => Promise<T>, canary: string): Promise<{ result: T, log: string }> {
  const messages: string[] = []
  const originalError = logger.error
  const spiedQuery = (models.sequelize as any).query
  ;(logger as any).error = (...args: unknown[]) => { messages.push(args.map((arg) => String(arg)).join(' ')); return logger }
  ;(models.sequelize as any).query = async (sql: unknown, ...rest: any[]) => {
    if (tablePattern.test(sqlOf(sql))) {
      const parent = Object.assign(new Error(`SQLITE_ERROR: ${canary} SECRETSQL`), { code: 'SQLITE_ERROR', sql: `SELECT ${canary} SECRETSQL` })
      throw Object.assign(new Error(`${canary} SECRETSQL`), { name: 'SequelizeDatabaseError', parent, sql: `SELECT ${canary} SECRETSQL` })
    }
    return await spiedQuery(sql, ...rest)
  }
  try {
    const result = await run()
    return { result, log: messages.join('\n') }
  } finally {
    ;(models.sequelize as any).query = spiedQuery
    ;(logger as any).error = originalError
  }
}

before(async () => {
  for (const method of ['all', 'run', 'get', 'each']) {
    const original = (sqlite3.Database.prototype as any)[method]
    originalSqliteMethods[method] = original
    ;(sqlite3.Database.prototype as any)[method] = function (sql: unknown, ...args: any[]) {
      statements.push({ sql: String(sql), params: args.filter((arg) => typeof arg !== 'function')[0] })
      return original.call(this, sql, ...args)
    }
  }
  const result = await createTestApp()
  app = result.app
  originalQuery = models.sequelize.query.bind(models.sequelize)
  ;(models.sequelize as any).query = async (sql: unknown, options?: any) => {
    queryCalls.push({ sql: sqlOf(sql), options })
    return await originalQuery(sql as any, options)
  }
}, { timeout: 60000 })

after(() => {
  if (originalQuery !== undefined) (models.sequelize as any).query = originalQuery
  for (const [method, original] of Object.entries(originalSqliteMethods)) {
    ;(sqlite3.Database.prototype as any)[method] = original
  }
})

void describe('POST /rest/user/login: regular behaviour', () => {
  void it('logs in with correct credentials and keeps the password hash out of the JWT', async () => {
    const email = randomEmail()
    const password = randomPassword()
    await register(app, { email, password })
    const res = await postLogin({ email, password })
    assert.equal(res.status, 200)
    assert.equal(hasToken(res), true)
    const payload = JSON.parse(Buffer.from(res.body.authentication.token.split('.')[1], 'base64url').toString())
    assert.equal(payload.data.email === email, true)
    assert.equal('password' in payload.data, false)
  })

  void it('rejects a wrong password and an unknown email with 401 and no token', async () => {
    const email = randomEmail()
    const password = randomPassword()
    await register(app, { email, password })
    const wrong = await postLogin({ email, password: randomPassword() })
    assert.equal(wrong.status, 401)
    assert.equal(hasToken(wrong), false)
    const unknown = await postLogin({ email: randomEmail(), password })
    assert.equal(unknown.status, 401)
    assert.equal(hasToken(unknown), false)
  })

  void it('rejects a logically deleted user with 401', async () => {
    const email = randomEmail()
    const password = randomPassword()
    await register(app, { email, password })
    assert.equal((await postLogin({ email, password })).status, 200)
    const user = await UserModel.findOne({ where: { email } })
    await user?.destroy()
    const res = await postLogin({ email, password })
    assert.equal(res.status, 401)
    assert.equal(hasToken(res), false)
  })

  void it('registers and logs in with Japanese, emoji, quote and backslash characters in the password', async () => {
    const email = randomEmail()
    const password = `パス🔑"'\\%_:criteria-${rnd()}`
    await register(app, { email, password })
    const res = await postLogin({ email, password })
    assert.equal(res.status, 200)
    assert.equal(hasToken(res), true)
    const wrong = await postLogin({ email, password: password + 'x' })
    assert.equal(wrong.status, 401)
  })

  void it('keeps a password containing a NUL character usable (it is only hashed, never part of the SQL)', async () => {
    const email = randomEmail()
    const password = `nul\u0000-${rnd()}`
    await register(app, { email, password })
    const res = await postLogin({ email, password })
    assert.equal(res.status, 200)
    assert.equal(hasToken(res), true)
    const truncated = await postLogin({ email, password: 'nul' })
    assert.equal(truncated.status, 401)
  })

  void it('still requires the TOTP token for users with 2FA enabled', async () => {
    const email = randomEmail()
    const password = randomPassword()
    const totpSecret = generateSecret()
    await register(app, { email, password, totpSecret })
    const res = await postLogin({ email, password })
    assert.equal(res.status, 401)
    assert.equal(res.body.status, 'totp_token_required')
    assert.equal(typeof res.body.data.tmpToken, 'string')
    assert.equal(hasToken(res), false)
    const second = await request(app).post('/rest/2fa/verify').set(jsonHeader).send({ tmpToken: res.body.data.tmpToken, totpToken: generateSync({ secret: totpSecret }) })
    assert.equal(second.status, 200)
    assert.equal(hasToken(second), true)
    const full = await login(app, { email, password, totpSecret })
    assert.equal(typeof full.token, 'string')
  })
})

void describe('POST /rest/user/login: SQL injection payloads are rejected', () => {
  const adminEmail = `admin@${domain}`
  const payloads: Array<[string, () => string]> = [
    ['comment syntax after a known email', () => `${knownEmail}'--`],
    ['OR condition', () => "' OR 1=1--"],
    ['OR condition with parenthesis', () => "') OR 1=1--"],
    ['comment syntax after the admin email', () => `${adminEmail}'--`],
    ['UNION with a forged row', () => `' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@${domain}' as 'email', '12345' as 'password', 'accounting' as 'role', '' as deluxeToken, '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--`],
    ['backslash and quote', () => `${knownEmail}\\'--`]
  ]
  let knownEmail = ''

  before(async () => {
    knownEmail = randomEmail()
    await register(app, { email: knownEmail, password: randomPassword() })
  })

  for (const [name, payload] of payloads) {
    void it(`rejects: ${name}`, async () => {
      const res = await postLogin({ email: payload(), password: randomPassword() })
      assert.equal(res.status, 401)
      assert.equal(hasToken(res), false)
      assert.equal(leaks(res.text), false)
      const withoutPassword = await postLogin({ email: payload() })
      assert.equal(withoutPassword.status, 401)
      assert.equal(hasToken(withoutPassword), false)
    })
  }

  void it('does not solve any login SQL injection challenge', async () => {
    for (const key of ['loginAdminChallenge', 'loginJimChallenge', 'loginBenderChallenge', 'ghostLoginChallenge', 'ephemeralAccountantChallenge']) {
      assert.equal((challenges as Record<string, any>)[key].solved, false, `${key} must stay unsolved`)
    }
  })

  void it('treats metacharacters in the password as part of an ordinary hash input', async () => {
    const res = await postLogin({ email: knownEmail, password: "' OR '1'='1" })
    assert.equal(res.status, 401)
    assert.equal(hasToken(res), false)
  })
})

void describe('POST /rest/user/login: non-string input', () => {
  const email = randomEmail()
  const password = randomPassword()
  const otherEmail = randomEmail()

  before(async () => {
    await register(app, { email, password })
  })

  const nonStrings: Record<string, unknown> = {
    number: 1,
    zero: 0,
    true: true,
    false: false,
    null: null,
    emptyArray: [],
    arrayWithValidValue: [email],
    arrayWithValidAndOther: [email, otherEmail],
    nestedArray: [[email]],
    emptyObject: {},
    object: { a: 1 },
    operatorLookingObject: { $ne: 'x' },
    symbolLookingObject: { '[Op.ne]': 'x' },
    likeObject: { like: '%' }
  }

  for (const [name, value] of Object.entries(nonStrings)) {
    void it(`email as ${name} is rejected with 401 before any user lookup`, async () => {
      const before = selectsFrom('Users').length
      const res = await postLogin({ email: value, password })
      assert.equal(res.status, 401)
      assert.equal(hasToken(res), false)
      assert.equal(leaks(res.text), false)
      assert.equal(selectsFrom('Users').length - before, 0, 'no user query may be executed')
    })

    void it(`password as ${name} is rejected with 401 before any user lookup`, async () => {
      const before = selectsFrom('Users').length
      const res = await postLogin({ email, password: value })
      assert.equal(res.status, 401)
      assert.equal(hasToken(res), false)
      assert.equal(leaks(res.text), false)
      assert.equal(selectsFrom('Users').length - before, 0, 'no user query may be executed')
    })
  }

  void it('missing email and password are rejected with 401', async () => {
    const res = await postLogin({})
    assert.equal(res.status, 401)
    assert.equal(hasToken(res), false)
  })

  void it('an email containing a NUL character is rejected with 401 and not with 500', async () => {
    const before = selectsFrom('Users').length
    const res = await postLogin({ email: `${email}\u0000`, password })
    assert.equal(res.status, 401)
    assert.equal(hasToken(res), false)
    assert.equal(selectsFrom('Users').length - before, 0)
  })

  void it('a JSON null body and a text body are rejected with 401 and not with 500', async () => {
    const jsonNull = await postLogin(null, 'null')
    assert.equal(jsonNull.status, 401)
    const text = await postLogin(null, `email=${email}&password=${password}`, 'text/plain')
    assert.equal(text.status, 401)
    assert.equal(hasToken(text), false)
  })

  void it('special characters in the email never produce a server error', async () => {
    const unexpected: string[] = []
    const chars: string[] = []
    for (let code = 0; code < 0x80; code++) chars.push(String.fromCharCode(code))
    chars.push('\ud800', '\u{1F511}', 'ʼ', '＇')
    for (const ch of chars) {
      for (const candidate of [`a${ch}b@${domain}`, `'${ch}`]) {
        const res = await postLogin({ email: candidate, password })
        if (res.status !== 401 || hasToken(res)) unexpected.push(`U+${ch.charCodeAt(0).toString(16)}`)
      }
    }
    assert.equal(unexpected.length, 0, `${unexpected.length} unexpected responses`)
  })
})

void describe('POST /rest/user/login: query construction and error handling', () => {
  void it('passes the email as ORM condition and keeps the password hash column out of the result', async () => {
    const email = randomEmail()
    const password = randomPassword()
    await register(app, { email, password })
    const canary = `cnry${rnd()}`
    statements.length = 0
    await postLogin({ email: `${canary}@${domain}`, password })
    const selects = selectsFrom('Users')
    assert.equal(selects.length, 1)
    assert.equal(/deletedAt`?\s+IS\s+NULL/i.test(selects[0].sql), true, 'soft deleted users stay excluded')
    assert.equal(/SELECT\s+\*/i.test(selects[0].sql), false, 'no SELECT * on Users')
    assert.equal(/password/i.test(selects[0].sql.split(/\sFROM\s/i)[0]), false, 'the password column is not selected')
  })

  void it('answers a database error with the fixed JSON and leaks nothing into the response or the log', async () => {
    const email = randomEmail()
    const password = randomPassword()
    await register(app, { email, password })
    const canary = `cnry${rnd()}`
    const { result, log } = await withFailingQuery(/Users/, async () => await postLogin({ email, password }), canary)
    assert.equal(result.status, 500)
    assert.deepEqual(result.body, GENERIC_ERROR)
    assert.equal(leaks(result.text, [canary, 'SECRETSQL', email, password]), false)
    assert.equal(log.includes('Login query failed: SequelizeDatabaseError'), true)
    assert.equal(leaks(log.replace('Login query failed: SequelizeDatabaseError', ''), [canary, 'SECRETSQL', email, password]), false)
  })
})

const searchPaths = {
  all: '/rest/products/search?q=',
  q: (value: string) => '/rest/products/search?q=' + encodeURIComponent(value)
}

async function allProducts (): Promise<Array<{ id: number, name: string, description: string }>> {
  const res = await request(app).get('/api/Products')
  return res.body.data
}

const expectedIds = (products: Array<{ id: number, name: string, description: string }>, needle: string) =>
  products.filter((p) => `${p.name}\n${p.description}`.toLowerCase().includes(needle.toLowerCase())).map((p) => p.id).sort()

const idsOf = (res: request.Response): number[] => (res.body.data as Array<{ id: number }>).map((p) => p.id).sort()

void describe('GET /rest/products/search: regular behaviour', () => {
  let products: Array<{ id: number, name: string, description: string }>
  before(async () => { products = await allProducts() })

  void it('finds products by name', async () => {
    const name = products[0].name
    const res = await request(app).get(searchPaths.q(name))
    assert.equal(res.status, 200)
    assert.equal(idsOf(res).includes(products[0].id), true)
  })

  void it('finds products by description', async () => {
    const product = products.find((p) => /[A-Za-z]{8,}/.test(p.description) && !p.name.toLowerCase().includes((p.description.match(/[A-Za-z]{8,}/) as RegExpMatchArray)[0].toLowerCase()))
    const word = (product?.description.match(/[A-Za-z]{8,}/) as RegExpMatchArray)[0]
    const res = await request(app).get(searchPaths.q(word))
    assert.equal(res.status, 200)
    assert.equal(idsOf(res).includes((product as { id: number }).id), true)
  })

  void it('returns all products for an empty search, a missing parameter and the string undefined', async () => {
    for (const url of [searchPaths.all, '/rest/products/search', '/rest/products/search?q=undefined']) {
      const res = await request(app).get(url)
      assert.equal(res.status, 200)
      assert.equal(res.body.data.length, products.length)
    }
  })

  void it('keeps % and _ as LIKE wildcards', async () => {
    const name = products[0].name
    const percent = await request(app).get(searchPaths.q('%'))
    assert.equal(percent.body.data.length, products.length)
    const underscore = await request(app).get(searchPaths.q('_'))
    assert.equal(underscore.body.data.length, products.length)
    const middlePercent = await request(app).get(searchPaths.q(name.slice(0, 2) + '%' + name.slice(3, 6)))
    assert.equal(idsOf(middlePercent).includes(products[0].id), true)
    const middleUnderscore = await request(app).get(searchPaths.q(name.slice(0, 2) + '_' + name.slice(3, 6)))
    assert.equal(idsOf(middleUnderscore).includes(products[0].id), true)
  })

  void it('treats backslash as an ordinary character (no ESCAPE clause)', async () => {
    const res = await request(app).get(searchPaths.q('\\'))
    assert.equal(res.status, 200)
    assert.deepEqual(idsOf(res), expectedIds(products, '\\'))
    const backslashPercent = await request(app).get(searchPaths.q('\\%'))
    assert.equal(backslashPercent.status, 200)
    assert.deepEqual(idsOf(backslashPercent), expectedIds(products, '\\'))
  })

  void it('handles Japanese, emoji, quotes, :criteria and NUL as plain search text without error', async () => {
    const cases = ['りんごジュース', '🍎🔑', "it's", '"quoted"', "'", ':criteria', '$criteria', 'ap\u0000ple', '?', '$1', ':1']
    for (const needle of cases) {
      const res = await request(app).get(searchPaths.q(needle))
      assert.equal(res.status, 200, 'status')
      assert.equal(Array.isArray(res.body.data), true)
      assert.equal(leaks(res.text), false)
      if (!needle.includes('\u0000')) {
        assert.deepEqual(idsOf(res), expectedIds(products, needle), 'result matches a literal search')
      }
    }
  })

  void it('uses at most 200 characters of the search condition', async () => {
    const name = products[0].name
    const q200 = name + '%'.repeat(200 - name.length)
    assert.equal(q200.length, 200)
    const exact = await request(app).get(searchPaths.q(q200))
    assert.equal(idsOf(exact).includes(products[0].id), true)
    const q201 = q200 + 'X'
    const truncated = await request(app).get(searchPaths.q(q201))
    assert.equal(truncated.status, 200)
    assert.equal(idsOf(truncated).includes(products[0].id), true, 'the 201st character is cut off')
    const q300 = q200 + 'Y'.repeat(100)
    const longer = await request(app).get(searchPaths.q(q300))
    assert.deepEqual(idsOf(longer), idsOf(exact))
    statements.length = 0
    await request(app).get(searchPaths.q('a'.repeat(5000)))
    const bound = selectsFrom('Products').filter((s) => s.sql.includes('$criteria')).map((s) => Object.values(s.params as Record<string, unknown>)[0])
    assert.equal(bound.length > 0 && bound.every((value) => typeof value === 'string' && value.length === 202), true, 'bound value is %<200 chars>%')
  })
})

void describe('GET /rest/products/search: SQL injection payloads', () => {
  const christmasName = config.get<Array<{ name: string, useForChristmasSpecialChallenge?: boolean }>>('products').find((p) => p.useForChristmasSpecialChallenge)?.name ?? ''
  const payloads: Record<string, string> = {
    'UNION with user columns': "')) union select id,email,password,'4','5','6','7','8','9','10' from users--",
    'UNION with required columns': "')) union select id,'2','3',email,password,'6','7','8','9','10' from users--",
    'UNION with totp secret': "')) union select id,'2','3',email,totpSecret,'6','7','8','9','10' from users--",
    'UNION with all columns': "')) union select * from users--",
    'UNION with sqlite_master': "')) union select sql,'2','3','4','5','6','7','8','9','10' from sqlite_master--",
    'comment out the deleted filter': "'))--",
    'comment out the deleted filter after a product name': `${christmasName}'))--`,
    'always true condition': "' OR 1=1--",
    'stacked query': "'; DROP TABLE Products;--",
    'syntax breaking quote': "';"
  }

  for (const [name, payload] of Object.entries(payloads)) {
    void it(`does not expose other data: ${name}`, async () => {
      const users = await UserModel.findAll()
      const emails = users.map((u) => u.email)
      const [hashRows]: any = await originalQuery('SELECT password FROM Users')
      const hashes: string[] = hashRows.map((row: { password: string }) => row.password)
      const products = await allProducts()
      const res = await request(app).get(searchPaths.q(payload))
      assert.equal(res.status, 200)
      assert.equal(Array.isArray(res.body.data), true)
      assert.equal(res.body.data.length <= products.length, true, 'no rows beyond the visible products')
      assert.equal(emails.some((email) => res.text.includes(email)), false, 'no user email in the response')
      assert.equal(hashes.some((hash) => res.text.includes(hash)), false, 'no password hash in the response')
      assert.equal(res.text.includes('CREATE TABLE'), false, 'no schema in the response')
      assert.equal(leaks(res.text), false)
      assert.equal(res.body.data.length, 0, 'literal payload matches no product')
    })
  }

  void it('does not solve the SQL injection search challenges and keeps the Products table intact', async () => {
    await new Promise((resolve) => setTimeout(resolve, 300))
    for (const key of ['unionSqlInjectionChallenge', 'dbSchemaChallenge', 'christmasSpecialChallenge']) {
      assert.equal((challenges as Record<string, any>)[key].solved, false, `${key} must stay unsolved`)
    }
    const res = await request(app).get(searchPaths.all)
    assert.equal(res.body.data.length, (await allProducts()).length)
  })
})

void describe('GET /rest/products/search: non-string input', () => {
  const rejected: Record<string, string> = {
    'array (q[])': '/rest/products/search?q[]=apple',
    'array (repeated q)': '/rest/products/search?q=apple&q=juice',
    'empty array': '/rest/products/search?q[]=',
    'long array': '/rest/products/search?q[]=' + 'a'.repeat(300),
    object: '/rest/products/search?q[a]=b',
    'nested object': '/rest/products/search?q[a][b]=c',
    'object with length': '/rest/products/search?q[length]=1',
    'object with substring': '/rest/products/search?q[length]=300&q[substring]=x',
    'object with toString': '/rest/products/search?q[toString]=x'
  }

  for (const [name, url] of Object.entries(rejected)) {
    void it(`answers ${name} with 400 and runs no product query`, async () => {
      const before = selectsFrom('Products').length
      const res = await request(app).get(url)
      assert.equal(res.status, 400)
      assert.equal(res.body.status, 'error')
      assert.equal(leaks(res.text), false)
      assert.equal(selectsFrom('Products').length - before, 0)
    })
  }

  void it('answers number, boolean and null with 400 (handler level) and runs no query', async () => {
    for (const value of [123, 0, true, false, null, NaN]) {
      let statusCode = 0
      let body: any
      const res: any = {
        status (code: number) { statusCode = code; return res },
        json (payload: unknown) { body = payload; return res },
        send (payload: unknown) { body = payload; return res }
      }
      const before = queryCalls.length
      await searchProducts()({ query: { q: value }, __: (text: string) => text } as any, res)
      assert.equal(statusCode, 400, 'status')
      assert.equal(body?.status, 'error')
      assert.equal(queryCalls.length - before, 0)
    }
  })
})

void describe('GET /rest/products/search: query construction and error handling', () => {
  void it('passes the search text only as SQLite bind parameter and does not use replacements', async () => {
    const canary = `cnry${rnd()}`
    statements.length = 0
    queryCalls.length = 0
    const res = await request(app).get(searchPaths.q(canary))
    assert.equal(res.status, 200)
    const selects = selectsFrom('Products')
    assert.equal(selects.length > 0, true)
    assert.equal(selects.some((s) => s.sql.includes(canary)), false, 'canary is not part of the SQL text')
    assert.equal(selects.some((s) => JSON.stringify(s.params).includes(canary)), true, 'canary is part of the bind parameters')
    const productQuery = queryCalls.find((call) => /FROM Products/i.test(call.sql))
    assert.equal(productQuery !== undefined, true)
    assert.equal(productQuery?.options?.replacements === undefined, true, 'replacements are not used')
    assert.equal(typeof productQuery?.options?.bind?.criteria, 'string')
    assert.equal(/\$criteria/.test(productQuery?.sql ?? ''), true)
    assert.equal((productQuery?.sql.match(/\$criteria/g) ?? []).length, 2, 'name and description share one bind parameter')
  })

  void it('does not use replacements or string interpolation in the route source', () => {
    const source = fs.readFileSync(path.resolve('routes/search.ts'), 'utf8')
    assert.equal(/replacements/.test(source), false)
    assert.equal(/LIKE\s+'%\$\{/.test(source), false)
  })

  void it('answers a database error with the fixed JSON and leaks nothing into the response or the log', async () => {
    const canary = `cnry${rnd()}`
    const { result, log } = await withFailingQuery(/FROM\s+Products/i, async () => await request(app).get(searchPaths.q(canary)), canary)
    assert.equal(result.status, 500)
    assert.deepEqual(result.body, GENERIC_ERROR)
    assert.equal(leaks(result.text, [canary, 'SECRETSQL']), false)
    assert.equal(log.includes('Product search failed: SequelizeDatabaseError'), true)
    assert.equal(leaks(log.replace('Product search failed: SequelizeDatabaseError', ''), [canary, 'SECRETSQL']), false)
  })
})

void describe('challenges that depended on SQL injection', () => {
  const hardened = ['loginAdminChallenge', 'loginJimChallenge', 'loginBenderChallenge', 'ghostLoginChallenge', 'ephemeralAccountantChallenge', 'unionSqlInjectionChallenge', 'dbSchemaChallenge', 'twoFactorAuthUnsafeSecretStorageChallenge']

  void it('are defined but unavailable on Hardened and unsolved', async () => {
    const res = await request(app).get('/api/Challenges')
    for (const key of hardened) {
      const challenge = res.body.data.find((c: { key: string }) => c.key === key)
      assert.equal(challenge !== undefined, true, `${key} must not be removed`)
      assert.equal(challenge.disabledEnv, 'Hardened', `${key} must be Hardened`)
      assert.equal(challenge.solved, false, `${key} must be unsolved`)
      assert.deepEqual(utils.getChallengeEnablementStatus((challenges as Record<string, any>)[key]), { enabled: false, disabledBecause: 'Hardened' })
    }
  })

  void it('are no tutorial challenges, so restrictToTutorialsFirst can never dead-end', async () => {
    const res = await request(app).get('/api/Challenges')
    for (const key of ['loginAdminChallenge', 'loginJimChallenge', 'loginBenderChallenge']) {
      const challenge = res.body.data.find((c: { key: string }) => c.key === key)
      assert.equal(challenge.tutorialOrder, null, `${key} has no tutorial order`)
      assert.equal(challenge.tags?.includes('Tutorial') ?? false, false, `${key} has no Tutorial tag`)
    }
    const unsolvableTutorial = res.body.data.filter((c: { tutorialOrder: number | null, disabledEnv: string | null }) => c.tutorialOrder !== null && c.disabledEnv !== null && c.disabledEnv !== undefined)
    assert.equal(unsolvableTutorial.length, 0, 'every tutorial challenge must stay available')
  })

  void it('leaves changePasswordBenderChallenge available', async () => {
    assert.equal(utils.isChallengeEnabled(challenges.changePasswordBenderChallenge), true)
  })
})
