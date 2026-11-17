/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'
import { checkPassword, checkTotpSecret } from '../../lib/startup/seedSecrets'
import { seedSecretVariables } from '../helpers/seedCredentials'

const ADMIN_SEED_KEYS = ['admin', 'bjoernGoogle', 'support', 'jannik', 'timo', 'bjoern', 'LetUsTest', 'cloudAdmin']

void describe('static seed users', () => {
  let users: StaticUser[]
  let admins: StaticUser[]

  before(async () => {
    users = await loadStaticUserData()
    admins = users.filter(user => user.role === 'admin')
  })

  void it('should contain exactly the eight known seed accounts with admin privileges', () => {
    assert.deepEqual(admins.map(user => user.key).sort(), [...ADMIN_SEED_KEYS].sort())
  })

  void it('should not contain a fixed password for any account with admin privileges', () => {
    assert.deepEqual(admins.filter(user => 'password' in user), [])
  })

  void it('should not contain a fixed TOTP secret for any account with admin privileges', () => {
    assert.deepEqual(admins.filter(user => 'totpSecret' in user), [])
  })

  void it('should not contain a fixed security answer for any account with admin privileges', () => {
    assert.deepEqual(admins.filter(user => 'securityQuestion' in user), [])
  })

  void it('should reference an external secret for the password of every account with admin privileges', () => {
    for (const user of admins) {
      assert.match(user.passwordSecretName ?? '', /^[A-Z][A-Z0-9_]*_INITIAL_PASSWORD$/, `${user.key} has no valid passwordSecretName`)
    }
  })

  void it('should only reference an external TOTP secret for the account that uses two-factor authentication', () => {
    const withTotp = users.filter(user => user.totpSecretName !== undefined)
    assert.deepEqual(withTotp.map(user => [user.key, user.totpSecretName]), [['timo', 'TIMO_TOTP_SECRET']])
  })

  void it('should use a unique secret name per account', () => {
    const names = users.flatMap(user => [user.passwordSecretName, user.totpSecretName]).filter(name => name !== undefined)
    assert.equal(new Set(names).size, names.length)
    assert.ok(names.every(name => !name.endsWith('_FILE')))
  })

  void it('should give every seed account either a fixed password or a secret reference, never both', () => {
    for (const user of users) {
      assert.ok((user.password !== undefined) !== (user.passwordSecretName !== undefined), `${user.key} must have exactly one password source`)
    }
  })

  void it('should require the admin account to be seeded from ADMIN_INITIAL_PASSWORD', () => {
    assert.equal(users.find(user => user.key === 'admin')?.passwordSecretName, 'ADMIN_INITIAL_PASSWORD')
  })

  void it('should be fully covered by the secret variables that the test helpers know', () => {
    const known = seedSecretVariables()
    const passwordNames = users.map(user => user.passwordSecretName).filter(name => name !== undefined)
    const totpNames = users.map(user => user.totpSecretName).filter(name => name !== undefined)
    assert.deepEqual([...passwordNames].sort(), [...known.passwords].sort())
    assert.deepEqual([...totpNames].sort(), [...known.totpSecrets].sort())
  })

  void it('should get valid random secrets for every seed secret from the API test environment', async () => {
    const saved = { ...process.env }
    const known = seedSecretVariables()
    for (const name of [...known.passwords, ...known.totpSecrets]) delete process.env[name]
    try {
      await import('../api/helpers/test-env.mjs?fresh=' + Date.now().toString())
      for (const name of known.passwords) {
        assert.ok(checkPassword(process.env[name] ?? '').ok, `${name} was not generated as a valid password`)
      }
      for (const name of known.totpSecrets) {
        assert.ok(checkTotpSecret(process.env[name] ?? '').ok, `${name} was not generated as a valid TOTP secret`)
      }
      assert.equal(new Set(known.passwords.map(name => process.env[name])).size, known.passwords.length)
    } finally {
      for (const name of [...known.passwords, ...known.totpSecrets]) {
        if (saved[name] === undefined) delete process.env[name]
        else process.env[name] = saved[name]
      }
    }
  })
})
