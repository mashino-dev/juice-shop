/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

async function app () {
  const { default: validateDependencies } = await import('./lib/startup/validateDependenciesBasic')
  await validateDependencies()

  const server = await import('./server')
  try {
    await server.start()
  } catch (err) {
    const { SeedSecretError } = await import('./lib/startup/seedSecrets')
    if (err instanceof SeedSecretError) {
      const { default: logger } = await import('./lib/logger')
      logger.error(`${err.message}. Provide the secrets via <NAME> or <NAME>_FILE, or set security.mode to "training". Exiting.`)
      process.exit(1)
    }
    throw err
  }
}

app()
  .catch(err => {
    throw err
  })
