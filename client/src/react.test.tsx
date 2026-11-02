import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@simplewebauthn/browser', () => ({
  browserSupportsWebAuthn: () => true,
  startRegistration: vi.fn(async () => ({ id: 'new' })),
  startAuthentication: vi.fn(async () => ({ id: 'cred' })),
}))

import { ErrorCodes } from './index.js'
import { usePasskey } from './react.js'
import { fakeFetch } from './test-helpers.js'

const user = { id: 'u1', name: 'ada', displayName: 'Ada' }
const info = { user, confirmedAt: 'a', expiresAt: 'b', hasPasskey: true }
const signedOut = () => ({ status: 401, body: { code: ErrorCodes.sessionRequired } })
const signedIn = () => ({ status: 200, body: info })

beforeEach(() => vi.clearAllMocks())

describe('usePasskey', () => {
  it('loads the session, signs in and out', async () => {
    const f = fakeFetch({
      'GET /auth/passkey/session': [signedOut, signedIn, signedOut],
      'POST /auth/passkey/login/begin': () => ({ status: 200, body: { challengeId: 'c', options: {} } }),
      'POST /auth/passkey/login/finish': () => ({ status: 200, body: { user } }),
      'POST /auth/passkey/logout': () => ({ status: 204 }),
    })
    const { result } = renderHook(() => usePasskey({ fetch: f.fetch }))
    expect(result.current.status).toBe('loading')
    await waitFor(() => expect(result.current.status).toBe('signed-out'))

    let ok = false
    await act(async () => {
      ok = await result.current.signIn()
    })
    expect(ok).toBe(true)
    expect(result.current.status).toBe('signed-in')
    expect(result.current.user).toEqual(user)

    await act(async () => {
      await result.current.signOut()
    })
    expect(result.current.status).toBe('signed-out')
    expect(result.current.user).toBeNull()
  })

  it('shows a locked session and unlocks it with confirm', async () => {
    const f = fakeFetch({
      'GET /auth/passkey/session': [() => ({ status: 401, body: { code: ErrorCodes.reconfirmRequired } }), signedIn],
      'POST /auth/passkey/confirm/begin': () => ({ status: 200, body: { challengeId: 'c', options: {} } }),
      'POST /auth/passkey/confirm/finish': () => ({ status: 200, body: {} }),
    })
    const { result } = renderHook(() => usePasskey({ fetch: f.fetch }))
    await waitFor(() => expect(result.current.status).toBe('locked'))
    await act(async () => {
      await result.current.confirm()
    })
    expect(result.current.status).toBe('signed-in')
  })

  it('keeps the error of a failed action and resolves false', async () => {
    const f = fakeFetch({
      'GET /auth/passkey/session': signedOut,
      'POST /auth/passkey/code': () => ({ status: 401, body: { code: ErrorCodes.invalidCode, error: 'that code is not valid' } }),
    })
    const { result } = renderHook(() => usePasskey({ fetch: f.fetch }))
    await waitFor(() => expect(result.current.status).toBe('signed-out'))
    let ok = true
    await act(async () => {
      ok = await result.current.redeemCode('nope')
    })
    expect(ok).toBe(false)
    expect((result.current.error as { code: string }).code).toBe(ErrorCodes.invalidCode)
    expect(result.current.busy).toBe(false)
  })
})
