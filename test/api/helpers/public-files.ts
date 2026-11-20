/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import logger from '../../../lib/logger'

export interface RawResponse {
  status: number
  headers: Record<string, string | undefined>
  body: Buffer
  text: string
}

export const randomId = () => crypto.randomBytes(5).toString('hex')

/** Temporary fixtures created inside the served folders. Names are random, contents are random canaries (never key material). */
export class TempFixtures {
  private readonly created: string[] = []
  readonly id = randomId()
  readonly canary = 'CANARY' + crypto.randomBytes(8).toString('hex')
  readonly outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-public-files-'))

  constructor () {
    process.on('exit', () => this.cleanup())
  }

  name (suffix: string) {
    return `zz-${this.id}${suffix}`
  }

  file (relative: string, content = this.canary) {
    const target = path.resolve(relative)
    const firstCreated = fs.mkdirSync(path.dirname(target), { recursive: true })
    if (firstCreated) this.created.push(firstCreated)
    fs.writeFileSync(target, content)
    this.created.push(target)
    return target
  }

  dir (relative: string) {
    const target = path.resolve(relative)
    const firstCreated = fs.mkdirSync(target, { recursive: true })
    if (firstCreated) this.created.push(firstCreated)
    return target
  }

  symlink (relative: string, target: string) {
    const link = path.resolve(relative)
    fs.symlinkSync(target, link)
    this.created.push(link)
    return link
  }

  outsideFile (content = this.canary) {
    const target = path.join(this.outsideDir, 'outside.txt')
    fs.writeFileSync(target, content)
    return target
  }

  cleanup () {
    for (const entry of this.created.splice(0).reverse()) {
      fs.rmSync(entry, { recursive: true, force: true })
    }
    fs.rmSync(this.outsideDir, { recursive: true, force: true })
  }
}

export async function rawGet (app: Express, url: string, headers: Record<string, string> = {}): Promise<RawResponse> {
  const res = await request(app)
    .get(url)
    .set(headers)
    .redirects(0)
    .buffer(true)
    .parse((response, callback) => {
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => chunks.push(chunk))
      response.on('end', () => callback(null, Buffer.concat(chunks)))
    })
  const body = Buffer.isBuffer(res.body) ? res.body : Buffer.alloc(0)
  return { status: res.status, headers: res.headers as Record<string, string | undefined>, body, text: body.toString('utf8') }
}

/**
 * Captures what the application emits while `action` runs: the winston logger, console.* and stderr.
 * stdout is deliberately not intercepted because the test runner reports its own results there.
 */
export async function captureOutput (action: () => Promise<void>): Promise<string> {
  const chunks: string[] = []
  const record = (...args: unknown[]) => { chunks.push(args.map((arg) => typeof arg === 'string' ? arg : JSON.stringify(arg)).join(' ')) }
  const restorers: Array<() => void> = []
  const loggerRecord = logger as unknown as Record<string, unknown>
  for (const level of ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly', 'log']) {
    const original = loggerRecord[level]
    loggerRecord[level] = (...args: unknown[]) => { record(...args); return logger }
    restorers.push(() => { loggerRecord[level] = original })
  }
  const consoleRecord = console as unknown as Record<string, unknown>
  for (const method of ['log', 'info', 'warn', 'error', 'debug']) {
    const original = consoleRecord[method]
    consoleRecord[method] = record
    restorers.push(() => { consoleRecord[method] = original })
  }
  const stderr = process.stderr.write.bind(process.stderr)
  process.stderr.write = ((chunk: unknown) => { record(String(chunk)); return true }) as typeof process.stderr.write
  restorers.push(() => { process.stderr.write = stderr })
  try {
    await action()
  } finally {
    restorers.forEach((restore) => restore())
  }
  return chunks.join('\n')
}

export const leaksStackOrPath = (text: string, extraMarkers: string[] = []) =>
  /\n\s+at\s+\S+.*\(.*:\d+:\d+\)/.test(text) ||
  /\bat\s+\S+\s+\(.*:\d+:\d+\)/.test(text) ||
  text.includes(process.cwd()) ||
  text.includes('node_modules') ||
  /\/home\/|\/Users\/|[A-Z]:\\/.test(text) ||
  extraMarkers.some((marker) => marker !== '' && text.includes(marker))

/** A non-existing path is the reference every blocked path has to look identical to. */
export function sameAsReference (res: RawResponse, reference: RawResponse) {
  return res.status === reference.status &&
    res.text === reference.text &&
    res.headers['content-type'] === reference.headers['content-type'] &&
    res.headers['content-length'] === reference.headers['content-length'] &&
    res.headers.etag === reference.headers.etag &&
    res.headers['content-disposition'] === reference.headers['content-disposition'] &&
    res.headers.location === reference.headers.location
}

/** Sends the request line exactly as given (no client-side URL normalisation), e.g. for raw backslashes. */
export async function socketGet (app: Express, rawPath: string): Promise<RawResponse> {
  const server = http.createServer(app).listen(0, '127.0.0.1')
  await new Promise((resolve) => server.once('listening', resolve))
  try {
    const { port } = server.address() as { port: number }
    return await new Promise<RawResponse>((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: rawPath }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          const body = Buffer.concat(chunks)
          resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string | undefined>, body, text: body.toString('utf8') })
        })
      }).on('error', reject)
    })
  } finally {
    server.close()
  }
}
