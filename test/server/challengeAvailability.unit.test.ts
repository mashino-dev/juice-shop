/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import fs from 'node:fs'
import { load } from 'js-yaml'
import type { ChallengeModel } from '@juice-shop/models/challenge'
import * as utils from '../../lib/utils'

const challenges = load(fs.readFileSync(path.resolve(__dirname, '../../data/static/challenges.yml'), 'utf8')) as any[]
const find = (key: string) => challenges.find((challenge) => challenge.key === key)

const sqlInjectionDependentChallenges = [
  'loginAdminChallenge',
  'loginBenderChallenge',
  'loginJimChallenge',
  'ghostLoginChallenge',
  'ephemeralAccountantChallenge',
  'unionSqlInjectionChallenge',
  'dbSchemaChallenge',
  'twoFactorAuthUnsafeSecretStorageChallenge'
]
const formerTutorialChallenges = ['loginAdminChallenge', 'loginBenderChallenge', 'loginJimChallenge']
const challengesWithoutSqlInjectionDependency = ['christmasSpecialChallenge', 'dlpPastebinDataLeakChallenge']

void describe('Availability of challenges that depended on SQL Injection', () => {
  for (const key of sqlInjectionDependentChallenges) {
    void it(`${key} is defined and marked as unavailable on Hardened for every safety mode`, () => {
      const challenge = find(key)
      assert.notEqual(challenge, undefined)
      assert.deepEqual(challenge.disabledEnv, ['Hardened'])
      for (const safetyMode of ['enabled', 'disabled', 'auto'] as const) {
        const status = utils.getChallengeEnablementStatus({ disabledEnv: challenge.disabledEnv.join(';') } as unknown as ChallengeModel, safetyMode)
        assert.deepEqual(status, { enabled: false, disabledBecause: 'Hardened' })
      }
    })
  }

  for (const key of formerTutorialChallenges) {
    void it(`${key} is no longer part of the tutorial mode`, () => {
      const challenge = find(key)
      assert.equal(challenge.tutorial, undefined)
      assert.equal(challenge.tags?.includes('Tutorial') ?? false, false)
    })
  }

  for (const key of challengesWithoutSqlInjectionDependency) {
    void it(`${key} stays available because it can be solved without SQL Injection`, () => {
      assert.equal(find(key).disabledEnv, undefined)
    })
  }
})
