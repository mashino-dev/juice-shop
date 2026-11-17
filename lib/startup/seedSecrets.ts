/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import { inspect } from 'node:util'
import config from 'config'
import { generateSecret } from 'otplib'
import logger from '../logger'
import type { SecurityConfig } from '../config.schema'
import type { ChallengeKey } from '../../models/challenge'

export type SecurityMode = SecurityConfig['mode']

export type SeedSecretIssueReason =
  | 'conflict'
  | 'missing'
  | 'file_unreadable'
  | 'file_not_regular'
  | 'file_too_large'
  | 'empty'
  | 'too_short'
  | 'too_long'
  | 'too_few_distinct_characters'
  | 'invalid_characters'
  | 'unresolved_template'
  | 'contains_account_identifier'
  | 'invalid_base32'
  | 'static_credential_present'
  | 'secret_name_missing'
  | 'invalid_secret_name'
  | 'duplicate_secret_name'
  | 'invalid_security_mode'

export interface SeedSecretIssue {
  variable: string
  reason: SeedSecretIssueReason
}

/**
 * Carries only variable names and reason codes. It must never carry a secret value
 * or a file path, so that it is safe to log and to show in test output.
 */
export class SeedSecretError extends Error {
  readonly issues: readonly SeedSecretIssue[]

  constructor (issues: SeedSecretIssue[]) {
    super('Seed secret validation failed: ' + issues.map(({ variable, reason }) => `${variable} (${reason})`).join(', '))
    this.name = 'SeedSecretError'
    this.issues = issues
  }
}

/** Seed accounts that must be provided from outside in 'hardened' mode, mapped to their secret variable. */
export const REQUIRED_SEED_SECRETS: Readonly<Record<string, string>> = Object.freeze({
  admin: 'ADMIN_INITIAL_PASSWORD'
})

/**
 * Challenges that can only be solved with a fixed credential (password or security answer) of an
 * admin seed account. Those credentials are not shipped anymore, so these challenges are marked as unavailable.
 */
export const CHALLENGES_UNAVAILABLE_WITHOUT_FIXED_ADMIN_CREDENTIALS: readonly ChallengeKey[] = Object.freeze([
  'weakPasswordChallenge',
  'loginSupportChallenge',
  'dlpPasswordSprayingChallenge',
  'oauthUserPasswordChallenge',
  'exposedCredentialsChallenge',
  'resetPasswordBjoernChallenge'
])
export const UNAVAILABLE_CHALLENGE_ENVIRONMENT = 'Hardened'

export const MIN_PASSWORD_LENGTH = 16
export const MAX_PASSWORD_LENGTH = 256
export const MIN_DISTINCT_CHARACTERS = 8
export const MIN_TOTP_SECRET_LENGTH = 26
export const MAX_SECRET_FILE_BYTES = 4096

const SECRET_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/
const SECURITY_MODES: readonly SecurityMode[] = ['hardened', 'training']

/** Minimal shape of a static seed user that is needed for secret resolution. */
export interface SeedUserInput {
  key: string
  email: string
  role: string
  password?: string
  totpSecret?: string
  securityQuestion?: unknown
  passwordSecretName?: string
  totpSecretName?: string
}

export type SeedSecretSource = 'external' | 'ephemeral'

/**
 * Holds a resolved secret. The values are kept private and are excluded from
 * JSON serialization and util.inspect so they do not leak into logs by accident.
 */
export class ResolvedSeedSecret {
  readonly source: SeedSecretSource
  readonly totpSource?: SeedSecretSource
  readonly #password: string
  readonly #totpSecret?: string

  constructor (password: string, source: SeedSecretSource, totpSecret?: string, totpSource?: SeedSecretSource) {
    this.#password = password
    this.source = source
    this.#totpSecret = totpSecret
    this.totpSource = totpSource
  }

  get password (): string {
    return this.#password
  }

  get totpSecret (): string | undefined {
    return this.#totpSecret
  }

  toJSON () {
    return { source: this.source, totpSource: this.totpSource }
  }

  [inspect.custom] () {
    return `ResolvedSeedSecret { source: '${this.source}' }`
  }
}

type Check<T> = { ok: true, value: T } | { ok: false, reason: SeedSecretIssueReason }

function distinctCharacters (value: string): number {
  return new Set(value).size
}

export function generateEphemeralPassword (): string {
  return crypto.randomBytes(32).toString('base64url')
}

export function generateEphemeralTotpSecret (): string {
  return generateSecret()
}

function readSecretFile (variable: string, filePath: string): string {
  const fail = (reason: SeedSecretIssueReason) => new SeedSecretError([{ variable, reason }])
  if (filePath.trim() === '') throw fail('file_unreadable')
  let stats: fs.Stats
  try {
    stats = fs.statSync(filePath)
  } catch {
    throw fail('file_unreadable')
  }
  if (!stats.isFile()) throw fail('file_not_regular')
  if (stats.size > MAX_SECRET_FILE_BYTES) throw fail('file_too_large')
  try {
    return fs.readFileSync(filePath, 'utf8')
  } catch {
    throw fail('file_unreadable')
  }
}

/**
 * Reads a secret from `<name>_FILE` (preferred) or from the environment variable `<name>`.
 * Setting both is ambiguous and rejected. Returns `undefined` if neither is set.
 * The returned value is trimmed. Errors never contain the value or the file path.
 */
export function readSecret (name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const filePath = env[`${name}_FILE`]
  const direct = env[name]
  if (filePath !== undefined && direct !== undefined) {
    throw new SeedSecretError([{ variable: name, reason: 'conflict' }])
  }
  if (filePath !== undefined) {
    return readSecretFile(`${name}_FILE`, filePath).trim()
  }
  return direct?.trim()
}

/**
 * Structural plausibility checks only. This is deliberately not a list of forbidden values.
 * `identifiers` are account identifiers (key, email) that must not be part of the password.
 */
export function checkPassword (value: string, identifiers: string[] = []): Check<string> {
  const trimmed = value.trim()
  if (trimmed === '') return { ok: false, reason: 'empty' }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return { ok: false, reason: 'invalid_characters' }
  if (/\$\{[^}]*\}/.test(trimmed) || /^<[A-Za-z0-9_ -]+>$/.test(trimmed) || /^\{\{.*\}\}$/.test(trimmed)) {
    return { ok: false, reason: 'unresolved_template' }
  }
  if (trimmed.length > MAX_PASSWORD_LENGTH) return { ok: false, reason: 'too_long' }
  if (trimmed.length < MIN_PASSWORD_LENGTH) return { ok: false, reason: 'too_short' }
  if (distinctCharacters(trimmed) < MIN_DISTINCT_CHARACTERS) return { ok: false, reason: 'too_few_distinct_characters' }
  const lowerCased = trimmed.toLowerCase()
  if (identifiers.some(identifier => identifier.length >= 3 && lowerCased.includes(identifier.toLowerCase()))) {
    return { ok: false, reason: 'contains_account_identifier' }
  }
  return { ok: true, value: trimmed }
}

export function checkTotpSecret (value: string): Check<string> {
  const normalized = value.trim().toUpperCase()
  if (normalized === '') return { ok: false, reason: 'empty' }
  if (!/^[A-Z2-7]+$/.test(normalized) || [1, 3, 6].includes(normalized.length % 8)) {
    return { ok: false, reason: 'invalid_base32' }
  }
  if (normalized.length < MIN_TOTP_SECRET_LENGTH) return { ok: false, reason: 'too_short' }
  if (distinctCharacters(normalized) < MIN_DISTINCT_CHARACTERS) return { ok: false, reason: 'too_few_distinct_characters' }
  return { ok: true, value: normalized }
}

function collectIssues (action: () => void): SeedSecretIssue[] {
  try {
    action()
    return []
  } catch (err) {
    if (err instanceof SeedSecretError) return [...err.issues]
    throw err
  }
}

function checkSecretNames (users: SeedUserInput[]): SeedSecretIssue[] {
  const issues: SeedSecretIssue[] = []
  const seen = new Set<string>()
  for (const user of users) {
    for (const name of [user.passwordSecretName, user.totpSecretName]) {
      if (name === undefined) continue
      if (!SECRET_NAME_PATTERN.test(name) || name.endsWith('_FILE')) {
        issues.push({ variable: `${user.key}.secretName`, reason: 'invalid_secret_name' })
      } else if (seen.has(name)) {
        issues.push({ variable: name, reason: 'duplicate_secret_name' })
      }
      seen.add(name)
    }
  }
  return issues
}

function checkStaticData (users: SeedUserInput[]): SeedSecretIssue[] {
  const issues: SeedSecretIssue[] = []
  for (const user of users) {
    const privileged = user.role === 'admin'
    if (privileged && user.passwordSecretName === undefined) {
      issues.push({ variable: `${user.key}.passwordSecretName`, reason: 'secret_name_missing' })
    }
    if (privileged || user.passwordSecretName !== undefined) {
      if (user.password !== undefined) issues.push({ variable: `${user.key}.password`, reason: 'static_credential_present' })
    }
    if (privileged || user.totpSecretName !== undefined) {
      if (user.totpSecret !== undefined) issues.push({ variable: `${user.key}.totpSecret`, reason: 'static_credential_present' })
    }
    if (privileged && user.securityQuestion !== undefined) {
      issues.push({ variable: `${user.key}.securityQuestion`, reason: 'static_credential_present' })
    }
  }
  return issues
}

/**
 * Resolves the passwords (and optional TOTP secrets) of all seed users that reference an external secret.
 * Throws a SeedSecretError that lists every problem (variable names and reason codes only).
 * - external value present: it is validated and used, an invalid value is never replaced silently
 * - external value absent and not required: a cryptographically random value is generated, which locks the account
 * - external value absent and required (admin, 'hardened' mode only): startup must not continue
 */
export function resolveSeedSecrets (
  users: SeedUserInput[],
  options: { mode?: SecurityMode, env?: NodeJS.ProcessEnv } = {}
): Map<string, ResolvedSeedSecret> {
  const env = options.env ?? process.env
  const issues: SeedSecretIssue[] = []

  let mode: SecurityMode | undefined = options.mode
  if (mode === undefined) {
    try {
      mode = config.get<SecurityMode>('security.mode')
    } catch {
      mode = undefined
    }
  }
  if (mode === undefined || !SECURITY_MODES.includes(mode)) {
    throw new SeedSecretError([{ variable: 'security.mode', reason: 'invalid_security_mode' }])
  }

  issues.push(...checkStaticData(users), ...checkSecretNames(users))

  if (mode === 'hardened') {
    for (const [key, variable] of Object.entries(REQUIRED_SEED_SECRETS)) {
      if (!users.some(user => user.key === key)) issues.push({ variable, reason: 'missing' })
    }
  }

  const resolved = new Map<string, ResolvedSeedSecret>()
  for (const user of users) {
    if (user.passwordSecretName === undefined) continue
    const identifiers = [user.key, user.email, user.email.split('@')[0]]
    const requiredVariable = REQUIRED_SEED_SECRETS[user.key]
    let password: string | undefined
    let passwordSource: SeedSecretSource = 'external'
    let totpSecret: string | undefined
    let totpSource: SeedSecretSource | undefined
    let valid = true

    const passwordIssues = collectIssues(() => {
      const raw = readSecret(user.passwordSecretName as string, env)
      if (raw === undefined) return
      const check = checkPassword(raw, identifiers)
      if (!check.ok) throw new SeedSecretError([{ variable: user.passwordSecretName as string, reason: check.reason }])
      password = check.value
    })
    issues.push(...passwordIssues)
    valid = passwordIssues.length === 0
    if (valid && password === undefined) {
      if (mode === 'hardened' && requiredVariable !== undefined) {
        issues.push({ variable: user.passwordSecretName, reason: 'missing' })
        valid = false
      } else {
        password = generateEphemeralPassword()
        passwordSource = 'ephemeral'
      }
    }

    if (user.totpSecretName !== undefined) {
      const totpIssues = collectIssues(() => {
        const raw = readSecret(user.totpSecretName as string, env)
        if (raw === undefined) return
        const check = checkTotpSecret(raw)
        if (!check.ok) throw new SeedSecretError([{ variable: user.totpSecretName as string, reason: check.reason }])
        totpSecret = check.value
        totpSource = 'external'
      })
      issues.push(...totpIssues)
      valid = valid && totpIssues.length === 0
      if (totpIssues.length === 0 && totpSecret === undefined) {
        totpSecret = generateEphemeralTotpSecret()
        totpSource = 'ephemeral'
      }
    }

    if (valid && password !== undefined) {
      resolved.set(user.key, new ResolvedSeedSecret(password, passwordSource, totpSecret, totpSource))
    }
  }

  if (issues.length > 0) throw new SeedSecretError(issues)
  return resolved
}

let preparedSecrets: Map<string, ResolvedSeedSecret> | undefined

/**
 * Must run before the database is seeded. Throws a SeedSecretError if the secrets are not acceptable.
 * Logs only account keys and the secret source, never any value.
 */
export function prepareSeedSecrets (users: SeedUserInput[], options: { mode?: SecurityMode, env?: NodeJS.ProcessEnv } = {}): void {
  preparedSecrets = undefined
  const resolved = resolveSeedSecrets(users, options)
  preparedSecrets = resolved
  const mode = options.mode ?? config.get<SecurityMode>('security.mode')
  logger.info(`Seed secrets prepared in ${mode} mode: ` + [...resolved.entries()].map(([key, secret]) => `${key}=${secret.source}`).join(', '))
  if (resolved.get('admin')?.source === 'ephemeral') {
    logger.warn('Seed account "admin" has no external secret and cannot be used to log in (training mode)')
  }
}

export function getSeedSecret (key: string): ResolvedSeedSecret | undefined {
  if (preparedSecrets === undefined) {
    throw new Error('Seed secrets have not been prepared before seeding the database')
  }
  return preparedSecrets.get(key)
}

export function clearPreparedSeedSecrets (): void {
  preparedSecrets = undefined
}
