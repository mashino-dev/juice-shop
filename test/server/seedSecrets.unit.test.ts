/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { inspect } from 'node:util'
import config from 'config'
import logger from '../../lib/logger'
import {
  SeedSecretError,
  checkPassword,
  checkTotpSecret,
  clearPreparedSeedSecrets,
  generateEphemeralPassword,
  getSeedSecret,
  prepareSeedSecrets,
  readSecret,
  resolveSeedSecrets,
  type SeedUserInput
} from '../../lib/startup/seedSecrets'

// All secret values in this file are generated at test runtime. Assertions that involve secret values
// use boolean checks only, so that a failing test never prints a secret.
const randomSecret = () => crypto.randomBytes(32).toString('hex')

const users: SeedUserInput[] = [
  { key: 'admin', email: 'admin', role: 'admin', passwordSecretName: 'ADMIN_INITIAL_PASSWORD' },
  { key: 'support', email: 'support', role: 'admin', passwordSecretName: 'SUPPORT_INITIAL_PASSWORD' },
  { key: 'timo', email: 'wurstbrot', role: 'admin', passwordSecretName: 'TIMO_INITIAL_PASSWORD', totpSecretName: 'TIMO_TOTP_SECRET' },
  { key: 'jim', email: 'jim', role: 'customer' }
]

const byVariable = (a: { variable: string }, b: { variable: string }) => a.variable.localeCompare(b.variable)

function issuesOf (action: () => unknown): Array<{ variable: string, reason: string }> {
  try {
    action()
  } catch (err) {
    assert.ok(err instanceof SeedSecretError)
    return [...err.issues]
  }
  assert.fail('expected a SeedSecretError')
}

void describe('seedSecrets', () => {
  let tmpDir: string
  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seed-secrets-test-'))
  })
  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })
  afterEach(() => {
    clearPreparedSeedSecrets()
    mock.restoreAll()
  })

  const writeSecretFile = (content: string, name = crypto.randomBytes(6).toString('hex')) => {
    const file = path.join(tmpDir, name)
    fs.writeFileSync(file, content, { mode: 0o600 })
    return file
  }

  void describe('configuration', () => {
    void it('should default to the hardened security mode', () => {
      assert.equal(config.get('security.mode'), 'hardened')
    })
  })

  void describe('readSecret', () => {
    void it('should return undefined if neither variable is set', () => {
      assert.equal(readSecret('ADMIN_INITIAL_PASSWORD', {}), undefined)
    })

    void it('should read and trim the environment variable', () => {
      const secret = randomSecret()
      assert.ok(readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD: ` ${secret}\n` }) === secret)
    })

    void it('should read and trim the secret file', () => {
      const secret = randomSecret()
      const file = writeSecretFile(`${secret}\n`)
      assert.ok(readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: file }) === secret)
    })

    void it('should reject NAME and NAME_FILE being set at the same time', () => {
      const file = writeSecretFile(randomSecret())
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD: randomSecret(), ADMIN_INITIAL_PASSWORD_FILE: file }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'conflict' }])
    })

    void it('should reject NAME_FILE even if NAME is set to an empty string', () => {
      const file = writeSecretFile(randomSecret())
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD: '', ADMIN_INITIAL_PASSWORD_FILE: file }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'conflict' }])
    })

    void it('should reject a secret file that does not exist', () => {
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: path.join(tmpDir, 'does-not-exist') }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD_FILE', reason: 'file_unreadable' }])
    })

    void it('should reject an empty secret file path', () => {
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: '  ' }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD_FILE', reason: 'file_unreadable' }])
    })

    void it('should reject a directory as secret file', () => {
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: tmpDir }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD_FILE', reason: 'file_not_regular' }])
    })

    void it('should reject an oversized secret file', () => {
      const file = writeSecretFile('x'.repeat(5000))
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: file }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD_FILE', reason: 'file_too_large' }])
    })

    void it('should reject a secret file without read permission', (t) => {
      if (process.platform === 'win32' || process.getuid?.() === 0) {
        t.skip('file permissions are not enforced for this user or platform')
        return
      }
      const file = writeSecretFile(randomSecret())
      fs.chmodSync(file, 0o000)
      const issues = issuesOf(() => readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: file }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD_FILE', reason: 'file_unreadable' }])
    })

    void it('should not expose the secret file path in the error', () => {
      const missing = path.join(tmpDir, 'path-must-not-leak')
      try {
        readSecret('ADMIN_INITIAL_PASSWORD', { ADMIN_INITIAL_PASSWORD_FILE: missing })
        assert.fail('expected an error')
      } catch (err) {
        assert.ok(err instanceof SeedSecretError)
        assert.ok(!err.message.includes('path-must-not-leak'))
      }
    })
  })

  void describe('checkPassword', () => {
    void it('should accept a long random value', () => {
      assert.equal(checkPassword(randomSecret(), ['admin']).ok, true)
    })

    void it('should trim the value', () => {
      const secret = randomSecret()
      const result = checkPassword(`  ${secret}  `)
      assert.ok(result.ok && result.value === secret)
    })

    void it('should reject empty values', () => {
      assert.deepEqual(checkPassword(''), { ok: false, reason: 'empty' })
      assert.deepEqual(checkPassword('   \n'), { ok: false, reason: 'empty' })
    })

    void it('should reject values that are too short', () => {
      assert.deepEqual(checkPassword(crypto.randomBytes(7).toString('hex')), { ok: false, reason: 'too_short' })
    })

    void it('should reject values that are too long', () => {
      assert.deepEqual(checkPassword(crypto.randomBytes(200).toString('hex')), { ok: false, reason: 'too_long' })
    })

    void it('should reject values with too few distinct characters', () => {
      assert.deepEqual(checkPassword('ab'.repeat(20)), { ok: false, reason: 'too_few_distinct_characters' })
    })

    void it('should reject values with control characters', () => {
      assert.deepEqual(checkPassword(`${randomSecret()}\n${randomSecret()}`), { ok: false, reason: 'invalid_characters' })
    })

    void it('should reject unresolved template placeholders', () => {
      // eslint-disable-next-line no-template-curly-in-string
      assert.deepEqual(checkPassword('${ADMIN_PASSWORD_FROM_CI_VARIABLE}'), { ok: false, reason: 'unresolved_template' })
      assert.deepEqual(checkPassword('<your-admin-password-here>'), { ok: false, reason: 'unresolved_template' })
    })

    void it('should reject values that contain the account identifier', () => {
      assert.deepEqual(checkPassword(`${randomSecret()}Admin`, ['admin']), { ok: false, reason: 'contains_account_identifier' })
    })
  })

  void describe('checkTotpSecret', () => {
    void it('should accept a generated Base32 secret and normalize its case', () => {
      const result = checkTotpSecret(` ${resolveSeedSecrets(users, { mode: 'training', env: {} }).get('timo')?.totpSecret?.toLowerCase() ?? ''} `)
      assert.equal(result.ok, true)
    })

    void it('should reject empty and non-Base32 values', () => {
      assert.deepEqual(checkTotpSecret(' '), { ok: false, reason: 'empty' })
      assert.deepEqual(checkTotpSecret('0189'.repeat(8)), { ok: false, reason: 'invalid_base32' })
    })

    void it('should reject a Base32 string with an impossible length', () => {
      assert.deepEqual(checkTotpSecret('ABCDEFGH'.repeat(3) + 'A'), { ok: false, reason: 'invalid_base32' })
    })

    void it('should reject secrets that are too short', () => {
      assert.deepEqual(checkTotpSecret('ABCDEFGHIJKLMNOP'), { ok: false, reason: 'too_short' })
    })
  })

  void describe('resolveSeedSecrets', () => {
    void it('should fail closed in hardened mode if the admin secret is missing', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'hardened', env: {} }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'missing' }])
    })

    void it('should use the configured (hardened by default) mode if none is passed', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { env: {} }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'missing' }])
    })

    void it('should fail closed in hardened mode if the admin account is not part of the seed data', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users.filter(user => user.key !== 'admin'), { mode: 'hardened', env: {} }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'missing' }])
    })

    void it('should fail closed for an empty admin secret instead of falling back', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: '' } }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'empty' }])
    })

    void it('should fail closed for a too short admin secret', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: crypto.randomBytes(4).toString('hex') } }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'too_short' }])
    })

    void it('should fail closed if NAME and NAME_FILE are both set', () => {
      const file = writeSecretFile(randomSecret())
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: randomSecret(), ADMIN_INITIAL_PASSWORD_FILE: file } }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD', reason: 'conflict' }])
    })

    void it('should fail closed for an unreadable admin secret file', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD_FILE: path.join(tmpDir, 'does-not-exist') } }))
      assert.deepEqual(issues, [{ variable: 'ADMIN_INITIAL_PASSWORD_FILE', reason: 'file_unreadable' }])
    })

    void it('should report all problems at once, listing only variable names', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'hardened', env: { SUPPORT_INITIAL_PASSWORD: 'tiny', TIMO_TOTP_SECRET: '!!!' } }))
      assert.deepEqual(issues.sort(byVariable), [
        { variable: 'ADMIN_INITIAL_PASSWORD', reason: 'missing' },
        { variable: 'SUPPORT_INITIAL_PASSWORD', reason: 'too_short' },
        { variable: 'TIMO_TOTP_SECRET', reason: 'invalid_base32' }
      ])
    })

    void it('should not replace an invalid optional secret with a random value', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'training', env: { SUPPORT_INITIAL_PASSWORD: 'tiny' } }))
      assert.deepEqual(issues, [{ variable: 'SUPPORT_INITIAL_PASSWORD', reason: 'too_short' }])
    })

    void it('should seed the admin from an external secret and lock the other accounts with random values', () => {
      const adminSecret = randomSecret()
      const resolved = resolveSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: adminSecret } })
      assert.ok(resolved.get('admin')?.password === adminSecret)
      assert.equal(resolved.get('admin')?.source, 'external')
      assert.equal(resolved.get('support')?.source, 'ephemeral')
      assert.equal(resolved.get('timo')?.source, 'ephemeral')
      assert.equal(resolved.get('timo')?.totpSource, 'ephemeral')
      assert.equal(checkTotpSecret(resolved.get('timo')?.totpSecret ?? '').ok, true)
      assert.ok(resolved.get('support')?.password !== adminSecret)
      assert.ok(resolved.get('support')?.password !== resolved.get('timo')?.password)
      assert.equal(resolved.has('jim'), false)
    })

    void it('should read secrets from files and from environment variables side by side', () => {
      const adminSecret = randomSecret()
      const supportSecret = randomSecret()
      const totp = resolveSeedSecrets(users, { mode: 'training', env: {} }).get('timo')?.totpSecret ?? ''
      const resolved = resolveSeedSecrets(users, {
        mode: 'hardened',
        env: {
          ADMIN_INITIAL_PASSWORD_FILE: writeSecretFile(`${adminSecret}\n`),
          SUPPORT_INITIAL_PASSWORD: supportSecret,
          TIMO_TOTP_SECRET_FILE: writeSecretFile(totp)
        }
      })
      assert.ok(resolved.get('admin')?.password === adminSecret)
      assert.ok(resolved.get('support')?.password === supportSecret)
      assert.ok(resolved.get('timo')?.totpSecret === totp)
      assert.equal(resolved.get('timo')?.totpSource, 'external')
    })

    void it('should start in training mode without secrets and lock the admin with a random value', () => {
      const first = resolveSeedSecrets(users, { mode: 'training', env: {} })
      const second = resolveSeedSecrets(users, { mode: 'training', env: {} })
      assert.equal(first.get('admin')?.source, 'ephemeral')
      assert.ok((first.get('admin')?.password.length ?? 0) >= 32)
      assert.ok(first.get('admin')?.password !== second.get('admin')?.password)
    })

    void it('should reject an unknown security mode', () => {
      const issues = issuesOf(() => resolveSeedSecrets(users, { mode: 'lenient' as any, env: {} }))
      assert.deepEqual(issues, [{ variable: 'security.mode', reason: 'invalid_security_mode' }])
    })

    void it('should reject a static credential on an admin seed account', () => {
      const withStatic: SeedUserInput[] = [
        { ...users[0], password: randomSecret() },
        { ...users[1], securityQuestion: { id: 1, answer: randomSecret() } },
        { ...users[2], totpSecret: randomSecret() }
      ]
      const issues = issuesOf(() => resolveSeedSecrets(withStatic, { mode: 'training', env: {} }))
      assert.deepEqual(issues, [
        { variable: 'admin.password', reason: 'static_credential_present' },
        { variable: 'support.securityQuestion', reason: 'static_credential_present' },
        { variable: 'timo.totpSecret', reason: 'static_credential_present' }
      ])
    })

    void it('should reject an admin seed account without a secret reference', () => {
      const issues = issuesOf(() => resolveSeedSecrets([{ key: 'root', email: 'root', role: 'admin' }], { mode: 'training', env: {} }))
      assert.deepEqual(issues, [{ variable: 'root.passwordSecretName', reason: 'secret_name_missing' }])
    })

    void it('should reject invalid and duplicate secret names', () => {
      const bad: SeedUserInput[] = [
        { key: 'a', email: 'a', role: 'admin', passwordSecretName: 'lower_case' },
        { key: 'b', email: 'b', role: 'admin', passwordSecretName: 'SOME_SECRET' },
        { key: 'c', email: 'c', role: 'admin', passwordSecretName: 'SOME_SECRET' },
        { key: 'd', email: 'd', role: 'admin', passwordSecretName: 'FOO_FILE' }
      ]
      const issues = issuesOf(() => resolveSeedSecrets(bad, { mode: 'training', env: {} }))
      assert.deepEqual(issues.sort(byVariable), [
        { variable: 'SOME_SECRET', reason: 'duplicate_secret_name' },
        { variable: 'a.secretName', reason: 'invalid_secret_name' },
        { variable: 'd.secretName', reason: 'invalid_secret_name' }
      ].sort(byVariable))
    })

    void it('should generate unique ephemeral passwords', () => {
      const first = generateEphemeralPassword()
      const second = generateEphemeralPassword()
      assert.ok(first !== second)
    })
  })

  void describe('prepareSeedSecrets and getSeedSecret', () => {
    void it('should refuse to hand out secrets before they are prepared', () => {
      assert.throws(() => getSeedSecret('admin'), /have not been prepared/)
    })

    void it('should provide the prepared secrets', () => {
      const adminSecret = randomSecret()
      prepareSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: adminSecret } })
      assert.ok(getSeedSecret('admin')?.password === adminSecret)
      assert.equal(getSeedSecret('jim'), undefined)
    })

    void it('should discard earlier preparations if a later preparation fails', () => {
      prepareSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: randomSecret() } })
      assert.throws(() => { prepareSeedSecrets(users, { mode: 'hardened', env: {} }) }, SeedSecretError)
      assert.throws(() => getSeedSecret('admin'), /have not been prepared/)
    })

    void it('should never write secret values to the log or into errors', () => {
      const adminSecret = randomSecret()
      const supportSecret = 'x'.repeat(3)
      const calls: string[] = []
      for (const level of ['info', 'warn', 'error', 'debug'] as const) {
        mock.method(logger, level, (...args: unknown[]) => { calls.push(args.map(arg => inspect(arg, { depth: 5 })).join(' ')) })
      }
      prepareSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: adminSecret } })
      prepareSeedSecrets(users, { mode: 'training', env: {} })
      let errorText = ''
      try {
        prepareSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: adminSecret, SUPPORT_INITIAL_PASSWORD: supportSecret } })
      } catch (err) {
        errorText = String((err as Error).stack) + JSON.stringify(err)
      }
      const output = calls.join('\n') + errorText
      assert.ok(calls.length > 0)
      assert.ok(errorText.includes('SUPPORT_INITIAL_PASSWORD'))
      assert.ok(!output.includes(adminSecret))
      assert.ok(!output.includes(supportSecret))
    })

    void it('should not reveal values through JSON serialization or inspection', () => {
      const adminSecret = randomSecret()
      prepareSeedSecrets(users, { mode: 'hardened', env: { ADMIN_INITIAL_PASSWORD: adminSecret } })
      const secret = getSeedSecret('admin')
      assert.ok(!JSON.stringify(secret).includes(adminSecret))
      assert.ok(!inspect(secret, { showHidden: true, depth: 5 }).includes(adminSecret))
      assert.ok(!JSON.stringify({ secret }).includes(adminSecret))
    })
  })
})
