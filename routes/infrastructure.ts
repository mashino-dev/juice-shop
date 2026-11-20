/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { customizeTerraformContent } from '../lib/terraformCustomization'
import { normalizePublicPath, parentDirectories, openPublicFile, isPublicDirectory, sendNotFound } from '../lib/publicFiles'

const MAX_FILE_BYTES = 256 * 1024

/**
 * Exact relative paths of the training fixtures that may be downloaded from /infrastructure. Nothing else below the
 * folder is ever served or listed, whatever its name or type.
 * terraform/networking.tf is deliberately not part of the list as long as it embeds the legacy TLS key literal.
 */
export const INFRASTRUCTURE_FILES: readonly string[] = Object.freeze([
  'Dockerfile',
  'docker-compose.yml',
  'terraform/main.tf',
  'terraform/outputs.tf',
  'terraform/variables.tf'
])

interface InfrastructureOptions {
  root?: string
  files?: readonly string[]
}

const settings = (options: InfrastructureOptions) => {
  const files = options.files ?? INFRASTRUCTURE_FILES
  return { root: options.root ?? path.resolve('infrastructure'), files: new Set(files), directories: parentDirectories(files) }
}

const isReadRequest = (req: Request) => req.method === 'GET' || req.method === 'HEAD'

/** Lets only allowed fixtures and the directories leading to them pass; everything else gets the fixed 404. */
export function infrastructureGuard (options: InfrastructureOptions = {}) {
  const { root, files, directories } = settings(options)
  return (req: Request, res: Response, next: NextFunction) => {
    const requested = isReadRequest(req) ? normalizePublicPath(req.path) : null
    if (requested === null) return sendNotFound(res)
    const check = async (): Promise<boolean> => {
      if (files.has(requested.relative)) {
        if (requested.trailingSlash) return false
        const handle = await openPublicFile(root, requested.relative)
        await handle?.close()
        return handle !== null
      }
      return directories.has(requested.relative) && await isPublicDirectory(root, requested.relative)
    }
    check().then((allowed) => allowed ? next() : sendNotFound(res), () => sendNotFound(res))
  }
}

/** serve-index filter: shows only allowed fixtures (regular files) and the directories leading to them. */
export function infrastructureListingFilter (options: InfrastructureOptions = {}) {
  const { root, files, directories } = settings(options)
  return (filename: string, _index: number, _files: unknown[], dir: string) => {
    const relative = path.posix.join(path.relative(root, dir).split(path.sep).join('/'), filename)
    try {
      const stats = fs.lstatSync(path.join(dir, filename))
      return (files.has(relative) && stats.isFile()) || (directories.has(relative) && stats.isDirectory())
    } catch {
      return false
    }
  }
}

/** Sends an allowed fixture; the code snippet markers of the coding challenges are removed from the content. */
export function serveInfrastructureFile (options: InfrastructureOptions = {}) {
  const { root, files } = settings(options)
  const serve = async (req: Request, res: Response) => {
    const requested = isReadRequest(req) ? normalizePublicPath(req.path) : null
    if (requested === null || requested.trailingSlash || !files.has(requested.relative)) return sendNotFound(res)
    const handle = await openPublicFile(root, requested.relative)
    if (handle === null) return sendNotFound(res)
    try {
      const { size } = await handle.stat()
      if (size > MAX_FILE_BYTES) return sendNotFound(res)
      const data = await handle.readFile('utf8')
      const cleaned = data.split('\n').filter(line => !line.trim().match(/^#\s*vuln-code-snippet\s/)).map(line => line.replace(/\s*#\s*vuln-code-snippet\s.*$/, '')).join('\n')
      res.type('text/plain').send(requested.relative.endsWith('.tf') ? customizeTerraformContent(cleaned) : cleaned)
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
