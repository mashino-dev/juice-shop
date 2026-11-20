/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
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

// jwt.pub is public and is replaced by a derived public key in PR 2; premium.key is the deliberate artifact of the "Premium Paywall" challenge
const ALLOWED_FILES = ['jwt.pub', 'premium.key']

let app: Express
let customerToken: string
let adminToken: string
let reference: RawResponse
const fixtures = new TempFixtures()
const bearer = (token: string): Record<string, string> => ({ Authorization: 'Bearer ' + token })
const createdLegacyKey: string[] = []

before(async () => {
  const result = await createTestApp()
  app = result.app

  const email = `keys-${randomId()}@example.test`
  const password = 'Pw-' + randomId() + randomId()
  await register(app, { email, password })
  customerToken = (await login(app, { email, password })).token
  adminToken = security.authorize({ data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } })

  const e = 'encryptionkeys/'
  fixtures.file(`${e}${fixtures.name('.key')}`)
  fixtures.file(`${e}${fixtures.name('.pem')}`)
  fixtures.file(`${e}${fixtures.name('-pkcs8.key')}`)
  fixtures.file(`${e}${fixtures.name('-openssh')}`)
  fixtures.file(`${e}${fixtures.name('.bak')}`)
  fixtures.file(`${e}${fixtures.name('.pub~')}`)
  fixtures.file(`${e}${fixtures.name('.txt')}`)
  fixtures.file(`${e}.${fixtures.name('-hidden')}`)
  fixtures.file(`${e}${fixtures.name('-dir')}/inner.txt`)
  fixtures.symlink(`${e}${fixtures.name('-inside-link.pub')}`, 'jwt.pub')
  fixtures.symlink(`${e}${fixtures.name('-outside-link.pub')}`, fixtures.outsideFile())
  // the file name the legacy default location would use; only created when it does not exist
  if (!fs.existsSync('encryptionkeys/jwt.key')) {
    createdLegacyKey.push(fixtures.file(`${e}jwt.key`))
  }

  reference = await rawGet(app, `/encryptionkeys/zz-nonexistent-${randomId()}`)
}, { timeout: 60000 })

after(() => {
  fixtures.cleanup()
})

void describe('/encryptionkeys allowlist', () => {
  void describe('allowed public files', () => {
    for (const file of ALLOWED_FILES) {
      void it(`GET /encryptionkeys/${file} is served, byte-identical, anonymously`, async () => {
        const res = await rawGet(app, `/encryptionkeys/${file}`)
        assert.equal(res.status, 200)
        assert.equal(res.body.equals(fs.readFileSync(`encryptionkeys/${file}`)), true)
      })
    }

    void it('serves the same files to a registered customer and to an admin token', async () => {
      for (const file of ALLOWED_FILES) {
        const anonymous = await rawGet(app, `/encryptionkeys/${file}`)
        const customer = await rawGet(app, `/encryptionkeys/${file}`, bearer(customerToken))
        const admin = await rawGet(app, `/encryptionkeys/${file}`, bearer(adminToken))
        assert.equal(customer.body.equals(anonymous.body) && admin.body.equals(anonymous.body), true)
      }
    })

    void it('only publishes a public key and no private key material', async () => {
      const pub = await rawGet(app, '/encryptionkeys/jwt.pub')
      const premium = await rawGet(app, '/encryptionkeys/premium.key')
      assert.equal(pub.text.includes('PRIVATE'), false)
      assert.equal(/-----BEGIN [A-Z ]*-----/.test(premium.text), false)
    })

    void it('ignores a query string on allowed files', async () => {
      const res = await rawGet(app, '/encryptionkeys/jwt.pub?download=1')
      assert.equal(res.status, 200)
    })
  })

  void describe('everything outside the allowlist is an identical fixed 404', () => {
    const blocked: Array<[string, () => string]> = [
      ['directory (no trailing slash)', () => '/encryptionkeys'],
      ['directory (trailing slash)', () => '/encryptionkeys/'],
      ['unknown file', () => '/encryptionkeys/doesnotexist.md'],
      ['.key file', () => `/encryptionkeys/${fixtures.name('.key')}`],
      ['PKCS#8 style .key file', () => `/encryptionkeys/${fixtures.name('-pkcs8.key')}`],
      ['jwt.key (legacy default location)', () => '/encryptionkeys/jwt.key'],
      ['.pem file', () => `/encryptionkeys/${fixtures.name('.pem')}`],
      ['OpenSSH style file without extension', () => `/encryptionkeys/${fixtures.name('-openssh')}`],
      ['backup file', () => `/encryptionkeys/${fixtures.name('.bak')}`],
      ['trailing ~ of a public key name', () => `/encryptionkeys/${fixtures.name('.pub~')}`],
      ['unknown regular .txt file', () => `/encryptionkeys/${fixtures.name('.txt')}`],
      ['jwt.pub backup', () => '/encryptionkeys/jwt.pub.bak'],
      ['jwt.pub with trailing ~', () => '/encryptionkeys/jwt.pub~'],
      ['dotfile', () => `/encryptionkeys/.${fixtures.name('-hidden')}`],
      ['.gitkeep style dotfile', () => '/encryptionkeys/.gitkeep'],
      ['symlink to an allowed file', () => `/encryptionkeys/${fixtures.name('-inside-link.pub')}`],
      ['symlink to a file outside the folder', () => `/encryptionkeys/${fixtures.name('-outside-link.pub')}`],
      ['sub-directory', () => `/encryptionkeys/${fixtures.name('-dir')}`],
      ['file inside a sub-directory', () => `/encryptionkeys/${fixtures.name('-dir')}/inner.txt`],
      ['allowed name inside a sub-directory', () => '/encryptionkeys/sub/jwt.pub'],
      ['..', () => '/encryptionkeys/../package.json'],
      ['.. to the key itself', () => '/encryptionkeys/../encryptionkeys/jwt.pub'],
      ['URL-encoded ..', () => '/encryptionkeys/%2e%2e/package.json'],
      ['URL-encoded ../', () => '/encryptionkeys/..%2fpackage.json'],
      ['double-encoded ../', () => '/encryptionkeys/%252e%252e%252fpackage.json'],
      ['double-encoded allowed name', () => '/encryptionkeys/jwt%252epub'],
      ['encoded slash with NUL (legacy probe)', () => '/encryptionkeys/%2fetc%2fos-release%2500.md'],
      ['absolute path (encoded slash)', () => '/encryptionkeys/%2fetc%2fpasswd'],
      ['absolute path (double slash)', () => '/encryptionkeys//etc/passwd'],
      ['backslash', () => '/encryptionkeys/..%5cpackage.json'],
      ['backslash before an allowed name', () => '/encryptionkeys/%5cjwt.pub'],
      ['NUL byte after an allowed name', () => '/encryptionkeys/jwt.pub%00.md'],
      ['NUL byte only', () => '/encryptionkeys/%00'],
      ['other case of an allowed name', () => '/encryptionkeys/JWT.PUB'],
      ['allowed name with trailing slash', () => '/encryptionkeys/premium.key/'],
      ['dot segment', () => '/encryptionkeys/./premium.key'],
      ['malformed percent-encoding', () => '/encryptionkeys/%E0%A4%A']
    ]

    for (const [label, url] of blocked) {
      void it(`GET ${label} returns the fixed 404`, async () => {
        const res = await rawGet(app, url())
        assert.equal(res.status, 404)
        assert.equal(sameAsReference(res, reference), true)
        assert.equal(res.text.includes(fixtures.canary), false)
        assert.equal(leaksStackOrPath(res.text, [fixtures.id, 'package.json', 'passwd', 'os-release', 'encryptionkeys']), false)
      })
    }

    void it('returns 404 for a raw (unencoded) backslash in the request line', async () => {
      for (const raw of ['/encryptionkeys/\\jwt.pub', '/encryptionkeys/..\\package.json']) {
        const res = await socketGet(app, raw)
        assert.equal(res.status, 404)
        assert.equal(sameAsReference(res, reference), true)
      }
    })

    void it('does not provide a directory listing in any representation', async () => {
      for (const accept of ['text/html', 'application/json', 'text/plain']) {
        for (const url of ['/encryptionkeys', '/encryptionkeys/']) {
          const res = await rawGet(app, url, { Accept: accept })
          assert.equal(res.status, 404)
          assert.equal(res.text.includes('listing directory'), false)
          assert.equal(res.text.includes('premium'), false)
          assert.equal(res.text.includes('jwt'), false)
        }
      }
    })

    void it('returns 404 to customer and admin tokens as well', async () => {
      for (const token of [customerToken, adminToken]) {
        for (const url of ['/encryptionkeys/', `/encryptionkeys/${fixtures.name('.key')}`, '/encryptionkeys/jwt.key', '/encryptionkeys/../package.json']) {
          const res = await rawGet(app, url, bearer(token))
          assert.equal(res.status, 404)
          assert.equal(sameAsReference(res, reference), true)
        }
      }
    })

    void it('returns 404 for non-GET methods on allowed files', async () => {
      const { default: request } = await import('supertest')
      const post = await request(app).post('/encryptionkeys/jwt.pub').send({})
      const del = await request(app).delete('/encryptionkeys/premium.key')
      assert.deepEqual([post.status, del.status], [404, 404])
    })

    void it('does not expose the content of blocked files or symlink targets', async () => {
      for (const url of [
        `/encryptionkeys/${fixtures.name('.key')}`,
        `/encryptionkeys/${fixtures.name('.pem')}`,
        `/encryptionkeys/${fixtures.name('-inside-link.pub')}`,
        `/encryptionkeys/${fixtures.name('-outside-link.pub')}`,
        '/encryptionkeys/jwt.key'
      ]) {
        const res = await rawGet(app, url)
        assert.equal(res.body.includes(fixtures.canary), false)
      }
    })
  })

  void describe('logging', () => {
    void it('does not write requested paths, canaries or key material to the application output', async () => {
      const marker = 'zz-log-marker-' + fixtures.id
      const output = await captureOutput(async () => {
        for (const url of [
          `/encryptionkeys/${fixtures.name('.key')}`,
          `/encryptionkeys/${fixtures.name('.pem')}`,
          `/encryptionkeys/${marker}`,
          '/encryptionkeys/jwt.key',
          '/encryptionkeys/../package.json',
          '/encryptionkeys/%2fetc%2fos-release%2500.md',
          '/encryptionkeys/jwt.pub%00.md'
        ]) {
          await rawGet(app, url)
        }
      })
      assert.equal(output.includes(marker), false)
      assert.equal(output.includes(fixtures.id), false)
      assert.equal(output.includes(fixtures.canary), false)
      assert.equal(output.includes('PRIVATE KEY'), false)
      assert.equal(output.includes(process.cwd()), false)
      assert.equal(output.includes('File names cannot contain'), false)
    })
  })
})
