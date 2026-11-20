/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const MAX_PATH_LENGTH = 512

export interface PublicPath {
  relative: string
  trailingSlash: boolean
}

/**
 * Turns a raw request path (as seen below the mount point) into a relative, slash separated path. The path is URL-decoded
 * exactly once; anything that could address something other than a plain, visible entry below the root yields `null`.
 */
export function normalizePublicPath (rawPath: string): PublicPath | null {
  if (typeof rawPath !== 'string' || rawPath.length > MAX_PATH_LENGTH || rawPath.includes('\\')) return null
  let decoded: string
  try {
    decoded = decodeURIComponent(rawPath)
  } catch {
    return null
  }
  // eslint-disable-next-line no-control-regex
  if (decoded.includes('%') || decoded.includes('\\') || /[\u0000-\u001f\u007f]/.test(decoded)) return null
  if (decoded === '' || decoded === '/') return { relative: '', trailingSlash: true }
  if (!decoded.startsWith('/')) return null
  let body = decoded.slice(1)
  const trailingSlash = body.endsWith('/')
  if (trailingSlash) body = body.slice(0, -1)
  const segments = body.split('/')
  if (segments.some((segment) => segment === '' || segment.startsWith('.') || segment.includes(':'))) return null
  return { relative: segments.join('/'), trailingSlash }
}

/** All directories (including the root, `''`) that contain allowed files and may therefore be listed. */
export function parentDirectories (files: readonly string[]): Set<string> {
  const directories = new Set<string>([''])
  for (const file of files) {
    const segments = file.split('/').slice(0, -1)
    for (let i = 1; i <= segments.length; i++) {
      directories.add(segments.slice(0, i).join('/'))
    }
  }
  return directories
}

const resolveInsideRoot = async (root: string, relative: string): Promise<string | null> => {
  const segments = relative.split('/')
  if (relative !== '' && segments.some((segment) => segment === '' || segment === '.' || segment === '..')) return null
  let rootReal: string
  try {
    rootReal = await fs.promises.realpath(root)
  } catch {
    return null
  }
  const target = path.join(rootReal, ...segments)
  let real: string
  try {
    real = await fs.promises.realpath(target)
  } catch {
    return null
  }
  // a different real path means a symlink somewhere in the chain (or an aliased spelling of the name)
  if (real !== target) return null
  if (real !== rootReal && !real.startsWith(rootReal.endsWith(path.sep) ? rootReal : rootReal + path.sep)) return null
  return real
}

/** Opens `relative` below `root` if, and only if, it is a regular file reachable without passing a symlink. */
export async function openPublicFile (root: string, relative: string): Promise<fs.promises.FileHandle | null> {
  if (relative === '') return null
  const real = await resolveInsideRoot(root, relative)
  if (real === null) return null
  let handle: fs.promises.FileHandle | undefined
  try {
    handle = await fs.promises.open(real, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0))
    const [opened, linked] = await Promise.all([handle.stat(), fs.promises.lstat(real)])
    if (!opened.isFile() || !linked.isFile() || opened.ino !== linked.ino || opened.dev !== linked.dev) {
      await handle.close()
      return null
    }
    return handle
  } catch {
    await handle?.close().catch(() => undefined)
    return null
  }
}

/** True if `relative` below `root` is a real directory reachable without passing a symlink. */
export async function isPublicDirectory (root: string, relative: string): Promise<boolean> {
  const real = await resolveInsideRoot(root, relative)
  if (real === null) return false
  try {
    return (await fs.promises.lstat(real)).isDirectory()
  } catch {
    return false
  }
}

/** The one and only negative answer of the public file routes: it does not depend on the request or on what exists. */
export function sendNotFound (res: Response) {
  res.status(404).type('text/plain').send('Not Found')
}

/** Keeps errors of a public file route (e.g. from serve-index or malformed URLs) away from the global error handler. */
export function publicFilesErrorHandler (err: unknown, req: Request, res: Response, next: NextFunction) {
  if (res.headersSent) return next(err)
  sendNotFound(res)
}
