import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@simplewebauthn/browser', () => ({
  browserSupportsWebAuthn: vi.fn(() => true),
  startRegistration: vi.fn(async () => ({ id: 'new-cred', type: 'public-key' })),
  startAuthentication: vi.fn(async () => ({ id: 'cred', type: 'public-key' })),
}))

import * as browser from '@simplewebauthn/browser'
import {
  ErrorCodes,
  PasskeyError,
  confirm,
  createPasskeyClient,
  errorCode,
  fetchWithConfirmation,
  getSession,
  isSupported,
  needsConfirmation,
  redeemCode,
  register,
  signIn,
  signOut,
  withConfirmation,
} from './index.js'
import { fakeFetch } from './test-helpers.js'

const begin = (options: unknown) => () => ({ status: 200, body: { challengeId: 'ch1', options } })
const user = { id: 'u1', name: 'ada', displayName: 'Ada' }

beforeEach(() => vi.clearAllMocks())

describe('register', () => {
  it('begins, runs the prompt with the options and finishes', async () => {
    const f = fakeFetch({
      'POST /auth/passkey/register/begin': begin({ challenge: 'abc' }),
      'POST /auth/passkey/register/finish': () => ({ status: 200, body: { user, signedIn: true } }),
    })
    const out = await register({ fetch: f.fetch, name: 'ada', displayName: 'Ada', passkeyName: 'Laptop' })
    expect(out).toEqual({ user, signedIn: true })
    expect(browser.startRegistration).toHaveBeenCalledWith({ optionsJSON: { challenge: 'abc' } })
    expect(f.calls[0].body).toEqual({ name: 'ada', displayName: 'Ada' })
    expect(f.calls[1].body).toEqual({ challengeId: 'ch1', credential: { id: 'new-cred', type: 'public-key' }, passkeyName: 'Laptop' })
    expect(f.calls[0].credentials).toBe('same-origin')
    expect(f.calls[0].headers['Content-Type']).toBe('application/json')
  })

  it('turns a closed prompt into a "cancelled" error and does not finish', async () => {
    vi.mocked(browser.startRegistration).mockRejectedValueOnce(Object.assign(new Error('closed'), { name: 'NotAllowedError' }))
    const f = fakeFetch({ 'POST /auth/passkey/register/begin': begin({}) })
    const err = await register({ fetch: f.fetch }).catch((e) => e)
    expect(err).toBeInstanceOf(PasskeyError)
    expect(errorCode(err)).toBe('cancelled')
    expect(f.calls).toHaveLength(1)
  })

  it('passes a server refusal on as a PasskeyError with its code and action', async () => {
    const f = fakeFetch({
      'POST /auth/passkey/register/begin': () => ({
        status: 403,
        body: { error: 'confirm it is you to do this', code: ErrorCodes.confirmationRequired, action: 'passkey.add' },
      }),
    })
    const err = (await register({ fetch: f.fetch }).catch((e) => e)) as PasskeyError
    expect(err.status).toBe(403)
    expect(err.code).toBe(ErrorCodes.confirmationRequired)
    expect(err.action).toBe('passkey.add')
    expect(err.message).toBe('confirm it is you to do this')
    expect(needsConfirmation(err)).toBe(true)
  })
})

describe('signIn, confirm, signOut, codes', () => {
  it('signs in', async () => {
    const f = fakeFetch({
      'POST /auth/passkey/login/begin': begin({ challenge: 'xyz' }),
      'POST /auth/passkey/login/finish': () => ({ status: 200, body: { user } }),
    })
    expect(await signIn({ fetch: f.fetch })).toEqual({ user })
    expect(browser.startAuthentication).toHaveBeenCalledWith({ optionsJSON: { challenge: 'xyz' } })
    expect(f.calls[1].body).toEqual({ challengeId: 'ch1', credential: { id: 'cred', type: 'public-key' } })
  })

  it('confirms', async () => {
    const f = fakeFetch({
      'POST /auth/passkey/confirm/begin': begin({ allowCredentials: [{ id: 'cred' }] }),
      'POST /auth/passkey/confirm/finish': () => ({ status: 200, body: { confirmedAt: 'now' } }),
    })
    await confirm({ fetch: f.fetch })
    expect(f.calls.map((c) => c.url)).toEqual(['/auth/passkey/confirm/begin', '/auth/passkey/confirm/finish'])
  })

  it('signs out (204) and redeems a code', async () => {
    const f = fakeFetch({
      'POST /auth/passkey/logout': () => ({ status: 204 }),
      'POST /auth/passkey/code': () => ({ status: 200, body: { user } }),
    })
    await expect(signOut({ fetch: f.fetch })).resolves.toBeUndefined()
    expect(await redeemCode('abcde-12345', { fetch: f.fetch })).toEqual({ user })
    expect(f.calls[1].body).toEqual({ code: 'abcde-12345' })
  })

  it('uses baseUrl, credentials and headers', async () => {
    const f = fakeFetch({ 'POST https://api.example.com/auth/logout': () => ({ status: 204 }) })
    await signOut({ fetch: f.fetch, baseUrl: 'https://api.example.com/auth/', credentials: 'include', headers: { 'X-CSRF': 't' } })
    expect(f.calls[0].credentials).toBe('include')
    expect(f.calls[0].headers['X-CSRF']).toBe('t')
  })

  it('reports a non-JSON failure with its status', async () => {
    const fetchFn = (async () => new Response('bad gateway', { status: 502 })) as typeof fetch
    const err = (await signOut({ fetch: fetchFn }).catch((e) => e)) as PasskeyError
    expect(err.status).toBe(502)
    expect(err.code).toBeUndefined()
  })

  it('isSupported asks the browser', () => {
    expect(isSupported()).toBe(true)
  })
})

describe('getSession', () => {
  it('maps the answers to states', async () => {
    const info = { user, confirmedAt: 'a', expiresAt: 'b', hasPasskey: true }
    const f = fakeFetch({
      'GET /auth/passkey/session': [
        () => ({ status: 200, body: info }),
        () => ({ status: 401, body: { code: ErrorCodes.sessionRequired } }),
        () => ({ status: 401, body: { code: ErrorCodes.reconfirmRequired } }),
        () => ({ status: 500, body: { error: 'something went wrong' } }),
      ],
    })
    expect(await getSession({ fetch: f.fetch })).toEqual({ status: 'signed-in', session: info })
    expect(await getSession({ fetch: f.fetch })).toEqual({ status: 'signed-out' })
    expect(await getSession({ fetch: f.fetch })).toEqual({ status: 'locked' })
    await expect(getSession({ fetch: f.fetch })).rejects.toBeInstanceOf(PasskeyError)
  })
})

describe('step-up helpers', () => {
  const confirmRoutes = {
    'POST /auth/passkey/confirm/begin': begin({}),
    'POST /auth/passkey/confirm/finish': () => ({ status: 200, body: {} }),
  }

  it('withConfirmation confirms and retries once', async () => {
    const f = fakeFetch(confirmRoutes)
    const action = vi
      .fn()
      .mockRejectedValueOnce(new PasskeyError('x', 403, { code: ErrorCodes.confirmationRequired, action: 'member.approve' }))
      .mockResolvedValueOnce('done')
    expect(await withConfirmation(action, { fetch: f.fetch })).toBe('done')
    expect(action).toHaveBeenCalledTimes(2)
    expect(browser.startAuthentication).toHaveBeenCalledTimes(1)
  })

  it('withConfirmation passes other errors through without a prompt', async () => {
    const action = vi.fn().mockRejectedValue(new Error('network'))
    await expect(withConfirmation(action)).rejects.toThrow('network')
    expect(browser.startAuthentication).not.toHaveBeenCalled()
  })

  it('fetchWithConfirmation retries after an idle lock', async () => {
    const f = fakeFetch({
      ...confirmRoutes,
      'POST /api/approve': [
        () => ({ status: 401, body: { code: ErrorCodes.reconfirmRequired } }),
        () => ({ status: 204 }),
      ],
    })
    const res = await fetchWithConfirmation('/api/approve', { method: 'POST' }, { fetch: f.fetch })
    expect(res.status).toBe(204)
    expect(f.calls.map((c) => c.url)).toEqual(['/api/approve', '/auth/passkey/confirm/begin', '/auth/passkey/confirm/finish', '/api/approve'])
  })

  it('fetchWithConfirmation returns other failures as they are', async () => {
    const f = fakeFetch({ 'GET /api/x': () => ({ status: 401, body: { code: ErrorCodes.sessionRequired } }) })
    const res = await fetchWithConfirmation('/api/x', undefined, { fetch: f.fetch })
    expect(res.status).toBe(401)
    expect(f.calls).toHaveLength(1)
  })
})

describe('createPasskeyClient', () => {
  it('binds the options', async () => {
    const f = fakeFetch({
      'POST /auth/login/begin': begin({}),
      'POST /auth/login/finish': () => ({ status: 200, body: { user } }),
      'GET /auth/credentials': () => ({ status: 200, body: [] }),
      'DELETE /auth/credentials/a%2Fb': () => ({ status: 204 }),
    })
    const client = createPasskeyClient({ baseUrl: '/auth', fetch: f.fetch })
    expect(await client.signIn()).toEqual({ user })
    expect(await client.listPasskeys()).toEqual([])
    await client.removePasskey('a/b')
    expect(f.calls.map((c) => c.url)).toEqual(['/auth/login/begin', '/auth/login/finish', '/auth/credentials', '/auth/credentials/a%2Fb'])
  })
})
