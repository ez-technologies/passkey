// @vitest-environment node
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

// The published manifest is the repository root's package.json; this folder's is for development.
const root = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))
const dev = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

describe('published package.json', () => {
  it('depends on the same @simplewebauthn/browser as development', () => {
    expect(root.dependencies).toEqual(dev.dependencies)
  })

  it('points at files the build makes', () => {
    for (const entry of Object.values(root.exports) as Record<string, string>[]) {
      for (const file of Object.values(entry)) expect(file).toMatch(/^\.\/client\/dist\/[a-z]+\.(js|d\.ts)$/)
    }
    expect(root.files).toEqual(['client/dist'])
  })
})
