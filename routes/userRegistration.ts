/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import logger from '../lib/logger'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { SecurityQuestionModel } from '../models/securityQuestion'

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
    const securityAnswer = extractRegistrationSecurityAnswer(submitted)
    if (securityAnswer !== undefined) {
      pendingSecurityAnswers.set(req, securityAnswer)
    }
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

export interface RegistrationSecurityAnswer {
  SecurityQuestionId: number
  answer: string
}

/* Security answers submitted along with a registration, keyed by request. Never part of the body that reaches the model. */
const pendingSecurityAnswers = new WeakMap<object, RegistrationSecurityAnswer>()

/**
 * Reads the optional security question and answer of the registration payload. Only a positive integer question id and
 * a non-empty string answer are accepted; anything else means the user registers without security answer.
 * A client supplied UserId (top level or nested) is never read.
 */
export function extractRegistrationSecurityAnswer (submitted: Record<string, unknown>): RegistrationSecurityAnswer | undefined {
  const own = (field: string) => Object.prototype.hasOwnProperty.call(submitted, field) ? submitted[field] : undefined
  const question = own('securityQuestion')
  const answer = own('securityAnswer')
  if (question === null || typeof question !== 'object' || typeof answer !== 'string' || answer.length === 0) {
    return undefined
  }
  const id = (question as Record<string, unknown>).id
  if (typeof id !== 'number' || !Number.isSafeInteger(id) || id < 1) {
    return undefined
  }
  return { SecurityQuestionId: id, answer }
}

/**
 * finale hook (create.write.after): stores the security answer for the user that was just created by this very request.
 * The UserId always comes from the created instance. If the answer cannot be stored, the half-created user is physically
 * deleted again (finale does not share a transaction between the milestones) and the registration fails.
 * Errors are logged without any value (no answer, hash, password, email or UserId).
 */
export function storeRegistrationSecurityAnswer () {
  return async (req: Request, _res: Response, context: { instance: { id: number, destroy: (options: { force: boolean }) => Promise<unknown> }, continue: any, error: (status: number, message: string) => any }) => {
    const pending = pendingSecurityAnswers.get(req)
    pendingSecurityAnswers.delete(req)
    if (pending === undefined) {
      return context.continue
    }
    try {
      const question = await SecurityQuestionModel.findByPk(pending.SecurityQuestionId)
      if (question !== null) {
        await SecurityAnswerModel.create({ UserId: context.instance.id, SecurityQuestionId: question.id, answer: pending.answer })
      }
      return context.continue
    } catch (storeError: unknown) {
      logger.error(`Could not store security answer during registration: ${utils.getErrorMessage(storeError)}`)
      try {
        await context.instance.destroy({ force: true })
      } catch (compensationError: unknown) {
        logger.error(`Could not remove incompletely registered user: ${utils.getErrorMessage(compensationError)}`)
      }
      return context.error(500, 'Registration failed')
    }
  }
}
