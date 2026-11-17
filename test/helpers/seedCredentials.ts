/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { readSecret } from '../../lib/startup/seedSecrets'

export type SeedAccount = 'admin' | 'bjoernGoogle' | 'support' | 'jannik' | 'timo' | 'bjoern' | 'LetUsTest' | 'cloudAdmin'

export interface SeedCredential {
  email: string
  password: string
  totpSecret?: string
}

// Names of the secrets the application is seeded with. The values are generated at test runtime
// (see test/api/helpers/test-env.mjs and lib/scripts/generateTestSecrets.ts) and are never part of the repository.
const ACCOUNTS: Record<SeedAccount, { email: (domain: string) => string, passwordVariable: string, totpVariable?: string }> = {
  admin: { email: domain => `admin@${domain}`, passwordVariable: 'ADMIN_INITIAL_PASSWORD' },
  bjoernGoogle: { email: () => 'bjoern.kimminich@gmail.com', passwordVariable: 'BJOERN_GOOGLE_INITIAL_PASSWORD' },
  support: { email: domain => `support@${domain}`, passwordVariable: 'SUPPORT_INITIAL_PASSWORD' },
  jannik: { email: domain => `J12934@${domain}`, passwordVariable: 'JANNIK_INITIAL_PASSWORD' },
  timo: { email: domain => `wurstbrot@${domain}`, passwordVariable: 'TIMO_INITIAL_PASSWORD', totpVariable: 'TIMO_TOTP_SECRET' },
  bjoern: { email: domain => `bjoern@${domain}`, passwordVariable: 'BJOERN_INITIAL_PASSWORD' },
  LetUsTest: { email: domain => `testing@${domain}`, passwordVariable: 'TESTING_INITIAL_PASSWORD' },
  cloudAdmin: { email: domain => `cloud-admin@${domain}`, passwordVariable: 'CLOUD_ADMIN_INITIAL_PASSWORD' }
}

function required (variable: string, env: NodeJS.ProcessEnv): string {
  const value = readSecret(variable, env)
  if (value === undefined || value === '') {
    throw new Error(`Test secret ${variable} is not set. Run the tests via the npm scripts or provide ${variable} or ${variable}_FILE.`)
  }
  return value
}

/** Credentials of a seeded admin account, as supplied to the application for this test run. */
export function seedCredential (account: SeedAccount, env: NodeJS.ProcessEnv = process.env): SeedCredential {
  const definition = ACCOUNTS[account]
  const credential: SeedCredential = {
    email: definition.email(config.get<string>('application.domain')),
    password: required(definition.passwordVariable, env)
  }
  if (definition.totpVariable !== undefined) {
    credential.totpSecret = required(definition.totpVariable, env)
  }
  return credential
}

/** All secret variables the seeded admin accounts are supplied with. */
export function seedSecretVariables (): { passwords: string[], totpSecrets: string[] } {
  const accounts = Object.values(ACCOUNTS)
  return {
    passwords: accounts.map(account => account.passwordVariable),
    totpSecrets: accounts.flatMap(account => account.totpVariable === undefined ? [] : [account.totpVariable])
  }
}

export function isSeedAccount (value: string): value is SeedAccount {
  return Object.prototype.hasOwnProperty.call(ACCOUNTS, value)
}
