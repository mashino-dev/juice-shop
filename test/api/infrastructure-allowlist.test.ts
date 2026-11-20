/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import {
  TempFixtures,
  rawGet,
  socketGet,
  captureOutput,
  leaksStackOrPath,
  sameAsReference,
  randomId,
  type RawResponse
} from './helpers/public-files'
import * as security from '../../lib/insecurity'
import logger from '../../lib/logger'
import { challenges } from '../../data/datacache'

// networking.tf is intentionally absent: until the legacy TLS key literal is removed from it (PR 2) it must not be served
const ALLOWED_FILES = [
  'Dockerfile',
  'docker-compose.yml',
  'terraform/main.tf',
  'terraform/outputs.tf',
  'terraform/variables.tf'
]

let app: Express
let customerToken: string
let adminToken: string
let reference: RawResponse
const fixtures = new TempFixtures()
const bearer = (token: string): Record<string, string> => ({ Authorization: 'Bearer ' + token })

before(async () => {
  const result = await createTestApp()
  app = result.app

  const email = `infra-${randomId()}@example.test`
  const password = 'Pw-' + randomId() + randomId()
  await register(app, { email, password })
  customerToken = (await login(app, { email, password })).token
  adminToken = security.authorize({ data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } })

  // regular files that exist on disk but must never be served
  const t = 'infrastructure/terraform/'
  fixtures.file(`${t}${fixtures.name('.tfstate')}`)
  fixtures.file(`${t}${fixtures.name('.tfstate.backup')}`)
  fixtures.file(`${t}${fixtures.name('.tfvars')}`)
  fixtures.file(`${t}${fixtures.name('.pem')}`)
  fixtures.file(`${t}${fixtures.name('.key')}`)
  fixtures.file(`${t}${fixtures.name('.crt')}`)
  fixtures.file(`${t}${fixtures.name('.tf.bak')}`)
  fixtures.file(`${t}${fixtures.name('.tf~')}`)
  fixtures.file(`${t}${fixtures.name('-unknown.tf')}`)
  fixtures.file(`${t}.${fixtures.name('-hidden.tf')}`)
  fixtures.file(`infrastructure/.${fixtures.name('-dir')}/main.tf`)
  fixtures.file(`infrastructure/${fixtures.name('-unknown.txt')}`)
  fixtures.file(`infrastructure/${fixtures.name('.yml')}`)
  fixtures.symlink(`${t}${fixtures.name('-inside-link.tf')}`, 'main.tf')
  fixtures.symlink(`${t}${fixtures.name('-outside-link.tf')}`, fixtures.outsideFile())

  reference = await rawGet(app, `/infrastructure/zz-nonexistent-${randomId()}`)
}, { timeout: 60000 })

after(() => {
  fixtures.cleanup()
})

void describe('/infrastructure allowlist', () => {
  void describe('allowed fixtures', () => {
    for (const file of ALLOWED_FILES) {
      void it(`GET /infrastructure/${file} is served anonymously`, async () => {
        const res = await rawGet(app, `/infrastructure/${file}`)
        assert.equal(res.status, 200)
        assert.ok(res.headers['content-type']?.includes('text/plain'))
        assert.ok(res.body.length > 0)
        assert.equal(res.text.includes('vuln-code-snippet'), false)
        assert.equal(/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(res.text), false)
      })
    }

    void it('serves the same allowed files to a registered customer and to an admin token', async () => {
      for (const file of ALLOWED_FILES) {
        const anonymous = await rawGet(app, `/infrastructure/${file}`)
        const customer = await rawGet(app, `/infrastructure/${file}`, bearer(customerToken))
        const admin = await rawGet(app, `/infrastructure/${file}`, bearer(adminToken))
        assert.equal(customer.status, 200)
        assert.equal(admin.status, 200)
        assert.equal(customer.text === anonymous.text && admin.text === anonymous.text, true)
      }
    })

    void it('keeps the docker-compose fixture content needed by the "Vulnerable Infrastructure" challenge', async () => {
      const res = await rawGet(app, '/infrastructure/docker-compose.yml')
      assert.equal(res.text.includes('mongo:4.4.29'), true)
    })
  })

  void describe('directory listing', () => {
    void it('lists exactly the allowed files and nothing else', async () => {
      const root = await rawGet(app, '/infrastructure/', { Accept: 'application/json' })
      const terraform = await rawGet(app, '/infrastructure/terraform/', { Accept: 'application/json' })
      assert.equal(root.status, 200)
      assert.equal(terraform.status, 200)
      const listed = [
        ...(JSON.parse(root.text) as string[]).map((name) => name),
        ...(JSON.parse(terraform.text) as string[]).map((name) => `terraform/${name}`)
      ].filter((entry) => entry !== 'terraform').sort()
      assert.deepEqual(listed, [...ALLOWED_FILES].sort())
    })

    void it('does not reveal README.md, networking.tf, temporary fixtures, dotfiles or symlinks in the HTML listing', async () => {
      const root = await rawGet(app, '/infrastructure/')
      const terraform = await rawGet(app, '/infrastructure/terraform/')
      const html = root.text + terraform.text
      assert.equal(html.includes('README'), false)
      assert.equal(html.includes('networking'), false)
      assert.equal(html.includes(fixtures.id), false)
      assert.equal(html.includes('.tfstate'), false)
      assert.equal(html.includes('.tfvars'), false)
      assert.equal(html.includes('.pem'), false)
      assert.equal(html.includes(fixtures.canary), false)
    })

    void it('answers directory listings with the same content for anonymous, customer and admin', async () => {
      const anonymous = await rawGet(app, '/infrastructure/terraform/', { Accept: 'application/json' })
      const customer = await rawGet(app, '/infrastructure/terraform/', { Accept: 'application/json', ...bearer(customerToken) })
      const admin = await rawGet(app, '/infrastructure/terraform/', { Accept: 'application/json', ...bearer(adminToken) })
      assert.equal(customer.text === anonymous.text && admin.text === anonymous.text, true)
    })
  })

  void describe('everything outside the allowlist is an identical fixed 404', () => {
    const blocked: Array<[string, () => string]> = [
      ['.tfstate', () => `/infrastructure/terraform/${fixtures.name('.tfstate')}`],
      ['.tfstate.backup', () => `/infrastructure/terraform/${fixtures.name('.tfstate.backup')}`],
      ['.tfvars', () => `/infrastructure/terraform/${fixtures.name('.tfvars')}`],
      ['.pem', () => `/infrastructure/terraform/${fixtures.name('.pem')}`],
      ['.key', () => `/infrastructure/terraform/${fixtures.name('.key')}`],
      ['.crt', () => `/infrastructure/terraform/${fixtures.name('.crt')}`],
      ['.bak', () => `/infrastructure/terraform/${fixtures.name('.tf.bak')}`],
      ['trailing ~', () => `/infrastructure/terraform/${fixtures.name('.tf~')}`],
      ['unknown regular .tf file', () => `/infrastructure/terraform/${fixtures.name('-unknown.tf')}`],
      ['unknown regular .txt file', () => `/infrastructure/${fixtures.name('-unknown.txt')}`],
      ['unknown regular .yml file', () => `/infrastructure/${fixtures.name('.yml')}`],
      ['dotfile', () => `/infrastructure/terraform/.${fixtures.name('-hidden.tf')}`],
      ['file inside a dot-directory', () => `/infrastructure/.${fixtures.name('-dir')}/main.tf`],
      ['dot-directory itself', () => `/infrastructure/.${fixtures.name('-dir')}/`],
      ['README.md', () => '/infrastructure/README.md'],
      ['networking.tf (still embeds the legacy TLS key literal)', () => '/infrastructure/terraform/networking.tf'],
      ['symlink inside the root', () => `/infrastructure/terraform/${fixtures.name('-inside-link.tf')}`],
      ['symlink to a file outside the root', () => `/infrastructure/terraform/${fixtures.name('-outside-link.tf')}`],
      ['..', () => '/infrastructure/../lib/insecurity.ts'],
      ['.. inside the path', () => '/infrastructure/terraform/../../lib/insecurity.ts'],
      ['URL-encoded ..', () => '/infrastructure/%2e%2e/lib/insecurity.ts'],
      ['URL-encoded ../', () => '/infrastructure/..%2flib/insecurity.ts'],
      ['URL-encoded traversal into encryptionkeys', () => '/infrastructure/terraform/%2e%2e/%2e%2e/encryptionkeys/jwt.pub'],
      ['double-encoded ..', () => '/infrastructure/%252e%252e/lib/insecurity.ts'],
      ['double-encoded /', () => '/infrastructure/terraform%252f..%252f..%252flib/insecurity.ts'],
      ['double-encoded allowed name', () => '/infrastructure/%2544ockerfile'],
      ['absolute path (double slash)', () => '/infrastructure//etc/passwd'],
      ['absolute path (encoded slash)', () => '/infrastructure/%2fetc%2fpasswd'],
      ['absolute path to an allowed file', () => `/infrastructure/${process.cwd()}/infrastructure/Dockerfile`],
      ['backslash', () => '/infrastructure/terraform%5cmain.tf'],
      ['backslash traversal', () => '/infrastructure/..%5clib%5cinsecurity.ts'],
      ['NUL byte after an allowed name', () => '/infrastructure/Dockerfile%00.txt'],
      ['NUL byte before an extension', () => '/infrastructure/terraform/main.tf%00.png'],
      ['NUL byte only', () => '/infrastructure/%00'],
      ['dot segment', () => '/infrastructure/./Dockerfile'],
      ['other case of an allowed name', () => '/infrastructure/DOCKERFILE'],
      ['allowed name with trailing slash', () => '/infrastructure/Dockerfile/'],
      ['allowed file under another directory', () => '/infrastructure/terraform/Dockerfile'],
      ['directory that is not allowed', () => '/infrastructure/terraform/modules/'],
      ['malformed percent-encoding', () => '/infrastructure/%E0%A4%A']
    ]

    for (const [label, url] of blocked) {
      void it(`GET ${label} returns the fixed 404`, async () => {
        const res = await rawGet(app, url())
        assert.equal(res.status, 404)
        assert.equal(sameAsReference(res, reference), true)
        assert.equal(res.text.includes(fixtures.canary), false)
        assert.equal(leaksStackOrPath(res.text, [fixtures.id, 'insecurity', 'passwd', 'terraform']), false)
      })
    }

    void it('returns 404 for a raw (unencoded) backslash in the request line', async () => {
      for (const raw of ['/infrastructure/terraform\\main.tf', '/infrastructure/\\Dockerfile', '/infrastructure/..\\lib\\insecurity.ts']) {
        const res = await socketGet(app, raw)
        assert.equal(res.status, 404)
        assert.equal(sameAsReference(res, reference), true)
      }
    })

    void it('resolves duplicate slashes (collapsed app-wide) only to the allowed fixture itself', async () => {
      const same = await socketGet(app, '/infrastructure/terraform//main.tf')
      const plain = await rawGet(app, '/infrastructure/terraform/main.tf')
      assert.equal(same.status, 200)
      assert.equal(same.text, plain.text)
      const other = await socketGet(app, '/infrastructure/terraform//zz-nothing.tf')
      assert.equal(other.status, 404)
    })

    void it('returns 404 for non-GET methods on allowed files', async () => {
      const post = await request(app).post('/infrastructure/Dockerfile').send({})
      const put = await request(app).put('/infrastructure/terraform/main.tf').send({})
      const del = await request(app).delete('/infrastructure/Dockerfile')
      assert.deepEqual([post.status, put.status, del.status], [404, 404, 404])
    })

    void it('returns 404 to admin and customer tokens as well', async () => {
      for (const token of [customerToken, adminToken]) {
        for (const url of [
          `/infrastructure/terraform/${fixtures.name('.tfstate')}`,
          `/infrastructure/terraform/${fixtures.name('.pem')}`,
          `/infrastructure/terraform/${fixtures.name('-outside-link.tf')}`,
          '/infrastructure/README.md',
          '/infrastructure/../lib/insecurity.ts'
        ]) {
          const res = await rawGet(app, url, bearer(token))
          assert.equal(res.status, 404)
          assert.equal(sameAsReference(res, reference), true)
        }
      }
    })

    void it('does not leak the content of a symlink target', async () => {
      const res = await rawGet(app, `/infrastructure/terraform/${fixtures.name('-outside-link.tf')}`)
      assert.equal(res.body.includes(fixtures.canary), false)
    })

    void it('treats an allowed fixture that is no longer a regular file as not found', async () => {
      const dir = fixtures.dir('infrastructure/terraform/zz-swap-' + fixtures.id)
      assert.ok(fs.existsSync(dir))
      const res = await rawGet(app, `/infrastructure/terraform/zz-swap-${fixtures.id}/`)
      assert.equal(res.status, 404)
    })
  })

  void describe('logging', () => {
    void it('the capture used below sees application log output', async () => {
      const output = await captureOutput(async () => { logger.error('capture-self-check-' + fixtures.id) })
      assert.equal(output.includes('capture-self-check-' + fixtures.id), true)
    })

    void it('does not write requested paths, canaries or key material to the application output', async () => {
      const marker = 'zz-log-marker-' + fixtures.id
      const output = await captureOutput(async () => {
        for (const url of [
          `/infrastructure/terraform/${fixtures.name('.pem')}`,
          `/infrastructure/terraform/${fixtures.name('.tfstate')}`,
          `/infrastructure/terraform/${fixtures.name('-outside-link.tf')}`,
          `/infrastructure/${marker}`,
          '/infrastructure/../lib/insecurity.ts',
          '/infrastructure/%2e%2e/%2e%2e/etc/passwd',
          '/infrastructure/Dockerfile%00.txt'
        ]) {
          await rawGet(app, url)
        }
      })
      assert.equal(output.includes(marker), false)
      assert.equal(output.includes(fixtures.id), false)
      assert.equal(output.includes(fixtures.canary), false)
      assert.equal(output.includes('PRIVATE KEY'), false)
      assert.equal(output.includes(process.cwd()), false)
      assert.equal(output.includes('insecurity'), false)
    })
  })

  void describe('challenges', () => {
    void it('"misplacedIacFiles" is solved by an allowed fixture', async () => {
      for (const file of ['Dockerfile', 'docker-compose.yml', 'terraform/main.tf']) {
        challenges.misplacedIacFiles.solved = false
        const res = await rawGet(app, `/infrastructure/${file}`)
        assert.equal(res.status, 200)
        assert.equal(challenges.misplacedIacFiles.solved, true)
      }
    })

    void it('"misplacedIacFiles" is not solved by files that are not allowed fixtures', async () => {
      for (const url of [
        '/infrastructure/zz-nonexistent.tf',
        `/infrastructure/terraform/${fixtures.name('-unknown.tf')}`,
        '/infrastructure/terraform/Dockerfile',
        '/infrastructure/other/docker-compose.yml'
      ]) {
        challenges.misplacedIacFiles.solved = false
        await rawGet(app, url)
        assert.equal(challenges.misplacedIacFiles.solved, false)
      }
    })

    void it('does not solve unrelated access-control challenges via /infrastructure URLs', async () => {
      const keys = ['scoreBoardChallenge', 'adminSectionChallenge', 'securityPolicyChallenge', 'extraLanguageChallenge', 'accessLogDisclosureChallenge'] as const
      for (const key of keys) challenges[key].solved = false
      for (const url of [
        '/infrastructure/1px.png',
        '/infrastructure/19px.png',
        '/infrastructure/security.txt',
        '/infrastructure/tlh_AA.json',
        '/infrastructure/access.log'
      ]) {
        await rawGet(app, url)
      }
      for (const key of keys) assert.equal(challenges[key].solved, false)
    })

    void it('"vulnerableDockerImageChallenge" is solved by reporting the version found in the allowed docker-compose fixture', async () => {
      const compose = await rawGet(app, '/infrastructure/docker-compose.yml')
      const image = /image:\s*(mongo):(\d+\.\d+\.\d+)/.exec(compose.text)
      assert.ok(image)
      challenges.vulnerableDockerImageChallenge.solved = false
      const res = await request(app)
        .post('/api/Complaints')
        .set({ Authorization: 'Bearer ' + customerToken, 'content-type': 'application/json' })
        .send({ message: `The infrastructure uses ${image[1]} ${image[2]} which is end-of-life.` })
      assert.equal(res.status, 201)
      assert.equal(challenges.vulnerableDockerImageChallenge.solved, true)
    })
  })
})
