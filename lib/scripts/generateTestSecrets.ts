/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script for CI: creates random seed secrets as files (mode 0600) in the given, preferably temporary, directory.
// Only "<NAME>_FILE=<path>" lines are printed, never a secret value, so the output is safe to append to $GITHUB_ENV.
// Example: node --import tsx lib/scripts/generateTestSecrets.ts "$(mktemp -d)" >> "$GITHUB_ENV"

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { generateSecret } from 'otplib'
import { seedSecretVariables } from '../../test/helpers/seedCredentials'

const directory = process.argv[2]
if (!directory) {
  console.error('Usage: generateTestSecrets.ts <target directory>')
  process.exit(1)
}

fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
const { passwords, totpSecrets } = seedSecretVariables()
const lines: string[] = []
for (const [names, generate] of [[passwords, () => crypto.randomBytes(32).toString('hex')], [totpSecrets, () => generateSecret()]] as const) {
  for (const name of names) {
    const file = path.resolve(directory, name.toLowerCase())
    fs.writeFileSync(file, generate(), { mode: 0o600 })
    lines.push(`${name}_FILE=${file}`)
  }
}
console.log(lines.join('\n'))
