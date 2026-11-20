/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response } from 'express'
import { normalizePublicPath, openPublicFile, sendNotFound } from '../lib/publicFiles'

const MAX_FILE_BYTES = 64 * 1024

/**
 * Exact names of the files that may be downloaded from /encryptionkeys:
 * - jwt.pub: public key of the JWT signature (to be replaced by a key derived from the runtime key in a later change)
 * - premium.key: deliberately exposed key of the "Premium Paywall" challenge
 */
export const KEY_FILES: readonly string[] = Object.freeze(['jwt.pub', 'premium.key'])

interface KeyServerOptions {
  root?: string
  files?: readonly string[]
}

export function serveKeyFiles (options: KeyServerOptions = {}) {
  const root = options.root ?? path.resolve('encryptionkeys')
  const allowed = new Set(options.files ?? KEY_FILES)

  const serve = async (req: Request, res: Response) => {
    const requested = req.method === 'GET' || req.method === 'HEAD' ? normalizePublicPath(req.path) : null
    if (requested === null || requested.trailingSlash || !allowed.has(requested.relative)) {
      return sendNotFound(res)
    }
    const handle = await openPublicFile(root, requested.relative)
    if (handle === null) {
      return sendNotFound(res)
    }
    try {
      const { size } = await handle.stat()
      if (size > MAX_FILE_BYTES) return sendNotFound(res)
      const content = await handle.readFile()
      res.type(path.extname(requested.relative)).send(content)
    } catch {
      if (!res.headersSent) sendNotFound(res)
    } finally {
      await handle.close().catch(() => undefined)
    }
  }

  return (req: Request, res: Response) => {
    void serve(req, res).catch(() => {
      if (!res.headersSent) sendNotFound(res)
    })
  }
}
