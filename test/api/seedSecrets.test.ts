/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import request from 'supertest'
import config from 'config'
import { generateSecret } from 'otplib'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { ChallengeModel } from '../../models/challenge'
import * as security from '../../lib/insecurity'

// Every secret in this file is generated at runtime. Secret values are only compared with boolean assertions
// so that a failing test never prints a secret.
const randomSecret = () => crypto.randomBytes(32).toString('hex')

const SECRET_VARIABLES = [
  'ADMIN_INITIAL_PASSWORD', 'BJOERN_GOOGLE_INITIAL_PASSWORD', 'SUPPORT_INITIAL_PASSWORD', 'JANNIK_INITIAL_PASSWORD',
  'TIMO_INITIAL_PASSWORD', 'TIMO_TOTP_SECRET', 'BJOERN_INITIAL_PASSWORD', 'TESTING_INITIAL_PASSWORD', 'CLOUD_ADMIN_INITIAL_PASSWORD'
]

const domain = config.get<string>('application.domain')
const ADMIN_EMAILS = {
  admin: `admin@${domain}`,
  bjoernGoogle: 'bjoern.kimminich@gmail.com',
  support: `support@${domain}`,
  jannik: `J12934@${domain}`,
  timo: `wurstbrot@${domain}`,
  bjoern: `bjoern@${domain}`,
  LetUsTest: `testing@${domain}`,
  cloudAdmin: `cloud-admin@${domain}`
}

interface ProbeResult {
  started: boolean
  issues?: Array<{ variable: string, reason: string }> | string
  adminCount?: number
  securityAnswersOfAdmins?: number
  distinctAdminPasswordHashes?: number
}

async function runProbe (env: Record<string, string>): Promise<{ result: ProbeResult, output: string }> {
  const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !SECRET_VARIABLES.some(variable => name === variable || name === `${variable}_FILE`)))
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', 'test/api/helpers/seed-probe.ts'], {
      env: { ...cleanEnv, ...env, NODE_ENV: 'test' }
    })
    let output = ''
    child.stdout.on('data', chunk => { output += String(chunk) })
    child.stderr.on('data', chunk => { output += String(chunk) })
    child.on('error', reject)
    child.on('close', () => {
      const line = output.split('\n').reverse().find(candidate => candidate.startsWith('{'))
      try {
        resolve({ result: JSON.parse(line ?? '{}'), output })
      } catch (err) {
        reject(err)
      }
    })
  })
}

void describe('seed secrets (hardened mode, the default)', () => {
  const secrets = {
    admin: randomSecret(),
    support: randomSecret(),
    totp: generateSecret()
  }
  const savedEnv: Record<string, string | undefined> = {}
  let app: Express

  before(async () => {
    for (const variable of SECRET_VARIABLES) {
      savedEnv[variable] = process.env[variable]
      delete process.env[variable]
      savedEnv[`${variable}_FILE`] = process.env[`${variable}_FILE`]
      delete process.env[`${variable}_FILE`]
    }
    process.env.ADMIN_INITIAL_PASSWORD = secrets.admin
    process.env.SUPPORT_INITIAL_PASSWORD = secrets.support
    process.env.TIMO_TOTP_SECRET = secrets.totp
    const result = await createTestApp()
    app = result.app
  }, { timeout: 60000 })

  after(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  })

  void it('should seed the admin account with the externally supplied secret', async () => {
    const admin = await UserModel.findOne({ where: { email: ADMIN_EMAILS.admin } })
    assert.ok(admin?.password === security.hash(secrets.admin))
  })

  void it('should seed an optional admin account with its externally supplied secret', async () => {
    const support = await UserModel.findOne({ where: { email: ADMIN_EMAILS.support } })
    assert.ok(support?.password === security.hash(secrets.support))
  })

  void it('should seed all eight accounts with admin privileges', async () => {
    const admins = await UserModel.findAll({ where: { role: 'admin' } })
    assert.deepEqual(admins.map(user => user.email).sort(), Object.values(ADMIN_EMAILS).sort())
  })

  void it('should lock the remaining admin accounts with distinct random values', async () => {
    const admins = await UserModel.findAll({ where: { role: 'admin' } })
    assert.equal(new Set(admins.map(user => user.password)).size, admins.length)
    const external = [security.hash(secrets.admin), security.hash(secrets.support)]
    const locked = admins.filter(user => user.email !== ADMIN_EMAILS.admin && user.email !== ADMIN_EMAILS.support)
    assert.equal(locked.length, 6)
    assert.ok(locked.every(user => !external.includes(user.password)))
  })

  void it('should use the external TOTP secret for wurstbrot and no TOTP secret for the other admin accounts', async () => {
    const admins = await UserModel.findAll({ where: { role: 'admin' } })
    for (const user of admins) {
      if (user.email === ADMIN_EMAILS.timo) {
        assert.ok(user.totpSecret === secrets.totp)
      } else {
        assert.equal(user.totpSecret, '')
      }
    }
  })

  void it('should not create a security answer for any account with admin privileges', async () => {
    const admins = await UserModel.findAll({ where: { role: 'admin' } })
    const count = await SecurityAnswerModel.count({ where: { UserId: admins.map(user => user.id) } })
    assert.equal(count, 0)
  })

  void it('should mark the challenges that depend on removed fixed admin credentials as unavailable', async () => {
    const keys = ['weakPasswordChallenge', 'loginSupportChallenge', 'dlpPasswordSprayingChallenge', 'oauthUserPasswordChallenge', 'exposedCredentialsChallenge', 'resetPasswordBjoernChallenge']
    const unavailable = await ChallengeModel.findAll({ where: { key: keys } })
    assert.equal(unavailable.length, keys.length)
    assert.ok(unavailable.every(challenge => challenge.disabledEnv === 'Hardened'))
  })

  void it('should keep the challenges that do not depend on fixed admin credentials available', async () => {
    const available = await ChallengeModel.findAll({ where: { key: ['loginAdminChallenge', 'iacLeakedKeyChallenge', 'twoFactorAuthUnsafeSecretStorageChallenge', 'loginRapperChallenge', 'loginAmyChallenge'] } })
    assert.equal(available.length, 5)
    assert.ok(available.every(challenge => challenge.disabledEnv === null))
  })

  void it('should not allow resetting the password of an admin account via the security question', async () => {
    for (const email of Object.values(ADMIN_EMAILS)) {
      const before = (await UserModel.findOne({ where: { email } }))?.password
      const newPassword = randomSecret()
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json' })
        .send({ email, answer: randomSecret(), new: newPassword, repeat: newPassword })
      assert.equal(res.status, 401, `reset for ${email} was not rejected`)
      const after = (await UserModel.findOne({ where: { email } }))?.password
      assert.ok(after === before && after !== security.hash(newPassword), `password of ${email} changed`)
    }
  })
})

void describe('seed secrets (startup behavior)', () => {
  void it('should refuse to start in hardened mode without ADMIN_INITIAL_PASSWORD', async () => {
    const { result, output } = await runProbe({})
    assert.equal(result.started, false)
    assert.deepEqual(result.issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'missing' }])
    assert.ok(!output.includes('Could not insert User'))
  })

  void it('should refuse to start if ADMIN_INITIAL_PASSWORD and ADMIN_INITIAL_PASSWORD_FILE are both set', async () => {
    const { result } = await runProbe({ ADMIN_INITIAL_PASSWORD: randomSecret(), ADMIN_INITIAL_PASSWORD_FILE: '/dev/null' })
    assert.equal(result.started, false)
    assert.deepEqual(result.issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'conflict' }])
  })

  void it('should refuse to start with a too short ADMIN_INITIAL_PASSWORD without echoing it', async () => {
    const tooShort = crypto.randomBytes(4).toString('hex')
    const { result, output } = await runProbe({ ADMIN_INITIAL_PASSWORD: tooShort })
    assert.equal(result.started, false)
    assert.deepEqual(result.issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'too_short' }])
    assert.ok(!output.includes(tooShort))
  })

  void it('should start in training mode without any secret and keep all admin accounts locked and without security answers', async () => {
    const { result } = await runProbe({ NODE_CONFIG: JSON.stringify({ security: { mode: 'training' } }) })
    assert.equal(result.started, true)
    assert.equal(result.adminCount, 8)
    assert.equal(result.securityAnswersOfAdmins, 0)
    assert.equal(result.distinctAdminPasswordHashes, 8)
  })

  void it('should still validate supplied secrets in training mode', async () => {
    const { result } = await runProbe({ NODE_CONFIG: JSON.stringify({ security: { mode: 'training' } }), SUPPORT_INITIAL_PASSWORD: 'tiny' })
    assert.equal(result.started, false)
    assert.deepEqual(result.issues, [{ variable: 'SUPPORT_INITIAL_PASSWORD', reason: 'too_short' }])
  })
})
