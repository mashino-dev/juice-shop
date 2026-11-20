/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import express from 'express'
import request from 'supertest'
import { serveKeyFiles, KEY_FILES } from '../../routes/keyServer'
import { publicFilesErrorHandler } from '../../lib/publicFiles'

void describe('keyServer', () => {
  let tmp: string
  let app: express.Express
  let reference: request.Response

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-keyserver-'))
    const root = path.join(tmp, 'keys')
    const outside = path.join(tmp, 'outside')
    fs.mkdirSync(root)
    fs.mkdirSync(path.join(root, 'sub'))
    fs.mkdirSync(outside)
    fs.writeFileSync(path.join(root, 'public.pub'), 'public-content')
    fs.writeFileSync(path.join(root, 'other.txt'), 'other-content')
    fs.writeFileSync(path.join(root, 'sub', 'public.pub'), 'nested-content')
    fs.writeFileSync(path.join(outside, 'target.txt'), 'outside-content')
    fs.symlinkSync(path.join(outside, 'target.txt'), path.join(root, 'linked.pub'))
    fs.writeFileSync(path.join(root, 'swapped.pub'), 'will-be-replaced')
    fs.rmSync(path.join(root, 'swapped.pub'))
    fs.symlinkSync(path.join(outside, 'target.txt'), path.join(root, 'swapped.pub'))

    app = express()
    app.use('/keys', serveKeyFiles({ root, files: ['public.pub', 'swapped.pub', 'linked.pub'] }), publicFilesErrorHandler)
    reference = await request(app).get('/keys/never-existed')
  })

  after(() => {
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  void it('only allows the exactly named public files of the shop', () => {
    assert.deepEqual([...KEY_FILES].sort(), ['jwt.pub', 'premium.key'])
  })

  void it('serves an allowed regular file from the configured folder', async () => {
    const res = await request(app).get('/keys/public.pub').buffer(true).parse((response, callback) => {
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => chunks.push(chunk))
      response.on('end', () => callback(null, Buffer.concat(chunks)))
    })
    assert.equal(res.status, 200)
    assert.equal((res.body as Buffer).toString('utf8'), 'public-content')
  })

  void it('answers every other request with the identical fixed 404', async () => {
    for (const url of [
      '/keys', '/keys/', '/keys/other.txt', '/keys/sub/public.pub', '/keys/sub', '/keys/linked.pub', '/keys/swapped.pub',
      '/keys/../outside/target.txt', '/keys/%2e%2e/outside/target.txt', '/keys/..%2foutside%2ftarget.txt', '/keys/%252e%252e',
      '/keys/public.pub%00.txt', '/keys/public.pub/', '/keys/PUBLIC.PUB', '/keys/.hidden', '/keys/%5cpublic.pub'
    ]) {
      const res = await request(app).get(url)
      assert.equal(res.status, 404)
      assert.equal(res.text, reference.text)
      assert.equal(res.headers['content-type'], reference.headers['content-type'])
      assert.equal(res.headers['content-length'], reference.headers['content-length'])
      assert.equal(res.text.includes('outside-content'), false)
    }
  })

  void it('answers non-GET requests with the fixed 404', async () => {
    const res = await request(app).post('/keys/public.pub').send({})
    assert.equal(res.status, 404)
    assert.equal(res.text, reference.text)
  })

  void it('never passes errors on to the global error handler', async () => {
    let reachedErrorHandler = false
    const guarded = express()
    guarded.use('/keys', serveKeyFiles({ root: path.join(tmp, 'does-not-exist'), files: ['public.pub'] }))
    guarded.use((err: unknown, req: express.Request, res: express.Response, next: express.NextFunction) => {
      reachedErrorHandler = true
      next(err)
    })
    const res = await request(guarded).get('/keys/public.pub')
    assert.equal(res.status, 404)
    assert.equal(reachedErrorHandler, false)
  })
})
