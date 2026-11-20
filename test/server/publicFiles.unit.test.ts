/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { normalizePublicPath, openPublicFile, isPublicDirectory, parentDirectories } from '../../lib/publicFiles'

void describe('publicFiles', () => {
  void describe('normalizePublicPath', () => {
    const valid: Array<[string, string, boolean]> = [
      ['', '', true],
      ['/', '', true],
      ['/Dockerfile', 'Dockerfile', false],
      ['/terraform', 'terraform', false],
      ['/terraform/', 'terraform', true],
      ['/terraform/main.tf', 'terraform/main.tf', false],
      ['/docker-compose.yml', 'docker-compose.yml', false],
      ['/jwt.pub', 'jwt.pub', false],
      ['/terraform%2fmain.tf', 'terraform/main.tf', false]
    ]
    for (const [raw, relative, trailingSlash] of valid) {
      void it(`accepts "${raw}"`, () => {
        assert.deepEqual(normalizePublicPath(raw), { relative, trailingSlash })
      })
    }

    const invalid = [
      '/..', '/../x', '/a/../b', '/%2e%2e', '/%2e%2e/x', '/..%2fx', '/%2E%2E%2Fx', '/.', '/./x', '/a/./b',
      '/.hidden', '/a/.hidden', '/.hidden/x', '/a/.hidden/x', '/.git/config',
      '//etc/passwd', '/a//b', '/%2fetc%2fpasswd', '/%2f%2fetc',
      '/a\\b', '/a%5cb', '/..%5cx', '/%5cetc',
      '/%00', '/a%00.txt', '/a.txt%00',
      '/%252e%252e', '/%252f', '/a%2520b', '/%25',
      '/%E0%A4%A', '/%', '/%zz',
      '/C:/windows', '/a:b',
      '/' + 'a'.repeat(600),
      '/a\u0001b', '/a\u007fb', '/a\nb'
    ]
    for (const raw of invalid) {
      void it(`rejects ${JSON.stringify(raw.length > 40 ? raw.slice(0, 40) + '...' : raw)}`, () => {
        assert.equal(normalizePublicPath(raw), null)
      })
    }

    void it('rejects non-string input', () => {
      assert.equal(normalizePublicPath(undefined as unknown as string), null)
      assert.equal(normalizePublicPath(null as unknown as string), null)
    })
  })

  void describe('parentDirectories', () => {
    void it('derives the listable directories from the allowed files', () => {
      assert.deepEqual([...parentDirectories(['Dockerfile', 'terraform/main.tf', 'a/b/c.txt'])].sort(), ['', 'a', 'a/b', 'terraform'])
    })
  })

  void describe('openPublicFile / isPublicDirectory', () => {
    let tmp: string
    let root: string
    let outside: string

    before(() => {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-publicfiles-'))
      root = path.join(tmp, 'root')
      outside = path.join(tmp, 'outside')
      fs.mkdirSync(path.join(root, 'sub'), { recursive: true })
      fs.mkdirSync(outside)
      fs.writeFileSync(path.join(root, 'regular.txt'), 'regular')
      fs.writeFileSync(path.join(root, 'sub', 'nested.txt'), 'nested')
      fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside')
      fs.writeFileSync(path.join(outside, 'nested.txt'), 'outside-nested')
      fs.symlinkSync(path.join(root, 'regular.txt'), path.join(root, 'link-inside.txt'))
      fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'link-outside.txt'))
      fs.symlinkSync('regular.txt', path.join(root, 'link-relative.txt'))
      fs.mkdirSync(path.join(root, 'directory.txt'))
      fs.symlinkSync(outside, path.join(root, 'linked-dir'))
    })

    after(() => {
      fs.rmSync(tmp, { recursive: true, force: true })
    })

    const read = async (relative: string) => {
      const handle = await openPublicFile(root, relative)
      if (handle === null) return null
      try {
        return (await handle.readFile('utf8'))
      } finally {
        await handle.close()
      }
    }

    void it('opens regular files', async () => {
      assert.equal(await read('regular.txt'), 'regular')
      assert.equal(await read('sub/nested.txt'), 'nested')
    })

    void it('rejects symlinks to files inside and outside of the root', async () => {
      assert.equal(await read('link-inside.txt'), null)
      assert.equal(await read('link-outside.txt'), null)
      assert.equal(await read('link-relative.txt'), null)
    })

    void it('rejects files reached through a symlinked directory', async () => {
      assert.equal(await read('linked-dir/secret.txt'), null)
      assert.equal(await read('linked-dir/nested.txt'), null)
    })

    void it('rejects directories, missing files and traversal attempts', async () => {
      assert.equal(await read('directory.txt'), null)
      assert.equal(await read('missing.txt'), null)
      assert.equal(await read('../outside/secret.txt'), null)
      assert.equal(await read('sub/../regular.txt'), null)
      assert.equal(await read(''), null)
    })

    void it('works when the configured root itself is reached through a symlink', async () => {
      const linkedRoot = path.join(tmp, 'linked-root')
      fs.symlinkSync(root, linkedRoot)
      const handle = await openPublicFile(linkedRoot, 'regular.txt')
      assert.notEqual(handle, null)
      await handle?.close()
    })

    void it('returns null for a root that does not exist', async () => {
      assert.equal(await openPublicFile(path.join(tmp, 'nope'), 'regular.txt'), null)
    })

    void it('accepts only real directories inside the root', async () => {
      assert.equal(await isPublicDirectory(root, ''), true)
      assert.equal(await isPublicDirectory(root, 'sub'), true)
      assert.equal(await isPublicDirectory(root, 'linked-dir'), false)
      assert.equal(await isPublicDirectory(root, 'regular.txt'), false)
      assert.equal(await isPublicDirectory(root, 'missing'), false)
      assert.equal(await isPublicDirectory(root, '../outside'), false)
    })
  })
})
