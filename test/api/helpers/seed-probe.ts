/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Child process used by test/api/seedSecrets.test.ts to start the application with a given environment.
// It reports booleans, counts and variable names only and never prints a secret value.
import { createApp } from '../../../server'
import { UserModel } from '../../../models/user'
import { SecurityAnswerModel } from '../../../models/securityAnswer'
import { SeedSecretError } from '../../../lib/startup/seedSecrets'

async function probe () {
  try {
    await createApp({ inMemoryDb: true })
  } catch (err) {
    if (err instanceof SeedSecretError) {
      return { started: false, issues: err.issues }
    }
    return { started: false, issues: 'unexpected error' }
  }
  const admins = await UserModel.findAll({ where: { role: 'admin' } })
  const adminIds = admins.map(admin => admin.id)
  return {
    started: true,
    adminCount: admins.length,
    securityAnswersOfAdmins: await SecurityAnswerModel.count({ where: { UserId: adminIds } }),
    distinctAdminPasswordHashes: new Set(admins.map(admin => admin.password)).size
  }
}

probe()
  .then(result => { console.log(JSON.stringify(result)); process.exit(0) })
  .catch(() => { console.log(JSON.stringify({ started: false, issues: 'unexpected error' })); process.exit(0) })
