/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

/* Fields an anonymous caller may supply when registering a new account (allowlist) */
export const registrationFields = ['email', 'password', 'passwordRepeat'] as const

/**
 * Reduces the body of an anonymous `POST /api/Users` to the allowlisted fields before the generated
 * finale endpoint passes it to `UserModel.create`. Everything else (role, deluxeToken, totpSecret,
 * isActive, id, timestamps, unknown keys, ...) is dropped without being logged, and the role is always
 * assigned by the server.
 */
export function restrictRegistrationFields () {
  return (req: Request, res: Response, next: NextFunction) => {
    const submitted: Record<string, unknown> = (req.body !== null && typeof req.body === 'object') ? req.body : {}
    const allowed: Record<string, unknown> = {}
    for (const field of registrationFields) {
      if (Object.prototype.hasOwnProperty.call(submitted, field)) {
        allowed[field] = submitted[field]
      }
    }
    allowed.role = security.roles.customer
    req.body = allowed
    next()
  }
}
