/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

export const passwordRecoveryUnavailableMessage = 'Password recovery via security question is not available in this environment.'

/**
 * Security answer based Forgot Password is unavailable on Hardened.
 *
 * The handler deliberately ignores the request completely (no body, query, header or database access), so
 * the response is identical for existing and unknown accounts, correct and wrong answers and malformed input.
 * It never changes a password and never returns a question, an account, a user object or a password hash.
 */
export function passwordRecoveryUnavailable () {
  return (_req: Request, res: Response) => {
    res.status(404).type('text/plain').send(passwordRecoveryUnavailableMessage)
  }
}
