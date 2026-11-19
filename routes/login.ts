/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response } from 'express'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { type User } from '../data/types'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// vuln-code-snippet start loginAdminChallenge loginBenderChallenge loginJimChallenge
export function login () {
  function afterLogin (user: User, res: Response) {
    verifyPostLoginChallenges(user) // vuln-code-snippet hide-line
    BasketModel.findOrCreate({ where: { UserId: user.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const authenticatedUser = { data: user, bid: basket.id } // keep track of original basket
        const token = security.authorize(authenticatedUser)
        security.authenticatedUsers.put(token, authenticatedUser)
        res.json({ authentication: { token, bid: basket.id, umail: user.email } })
      }).catch((error: Error) => {
        failLogin(error, res)
      })
  }

  return (req: Request, res: Response) => {
    req.body ??= {} // vuln-code-snippet hide-line
    verifyPreLoginChallenges(req) // vuln-code-snippet hide-line
    const { email, password } = req.body // vuln-code-snippet hide-line
    if (typeof email !== 'string' || typeof password !== 'string' || email.includes('\0')) { // vuln-code-snippet hide-line
      res.status(401).send(res.__('Invalid email or password.')) // vuln-code-snippet hide-line
      return // vuln-code-snippet hide-line
    } // vuln-code-snippet hide-line
    UserModel.findOne({ where: { email, password: security.hash(password) } }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
      .then((authenticatedUser) => { // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          afterLogin(user.data, res)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        failLogin(error, res)
      })
  }
  // vuln-code-snippet end loginAdminChallenge loginBenderChallenge loginJimChallenge

  function failLogin (error: Error, res: Response) {
    logger.error(`Login query failed: ${error.name}`)
    res.status(500).json({ status: 'error', message: 'Internal Server Error' })
  }

  function verifyPreLoginChallenges (req: Request) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => { return req.body.email === 'admin@' + config.get<string>('application.domain') && req.body.password === 'admin123' })
    challengeUtils.solveIf(challenges.loginSupportChallenge, () => { return req.body.email === 'support@' + config.get<string>('application.domain') && req.body.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P' })
    challengeUtils.solveIf(challenges.loginRapperChallenge, () => { return req.body.email === 'mc.safesearch@' + config.get<string>('application.domain') && req.body.password === 'Mr. N00dles' })
    challengeUtils.solveIf(challenges.loginAmyChallenge, () => { return req.body.email === 'amy@' + config.get<string>('application.domain') && req.body.password === 'K1f.....................' })
    challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => { return req.body.email === 'J12934@' + config.get<string>('application.domain') && req.body.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB' })
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return req.body.email === 'bjoern.kimminich@gmail.com' && req.body.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    challengeUtils.solveIf(challenges.exposedCredentialsChallenge, () => { return req.body.email === 'testing@' + config.get<string>('application.domain') && req.body.password === 'IamUsedForTesting' })
  }

  function verifyPostLoginChallenges (user: User) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => { return user.id === users.admin.id })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => { return user.id === users.jim.id })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => { return user.id === users.bender.id })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => { return user.id === users.chris.id })
    if (challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) && user.email === 'acc0unt4nt@' + config.get<string>('application.domain') && user.role === 'accounting') {
      UserModel.count({ where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') } }).then((count: number) => {
        if (count === 0) {
          challengeUtils.solve(challenges.ephemeralAccountantChallenge)
        }
      }).catch(() => {
        throw new Error('Unable to verify challenges! Try again')
      })
    }
  }
}
