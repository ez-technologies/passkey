/**
 * Passkey sign-in for the browser: the client of the Go package github.com/ez-technologies/passkey
 * (its ginpasskey routes). Every function talks JSON to `baseUrl` (default `/auth/passkey`) with
 * the session cookie, and runs the passkey prompt with @simplewebauthn/browser.
 */
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser'

/** The stable error codes the server answers with. */
export const ErrorCodes = {
  /** No session, or it ended: show sign-in. */
  sessionRequired: 'passkey.session_required',
  /** The session was idle too long: call confirm(), then go on. */
  reconfirmRequired: 'passkey.reconfirm_required',
  /** A sensitive action needs a fresh confirmation: call confirm(), then retry. */
  confirmationRequired: 'passkey.confirmation_required',
  /** The passkey was not accepted. */
  rejected: 'passkey.rejected',
  /** The ceremony took too long or was used already: start again. */
  challengeExpired: 'passkey.challenge_expired',
  /** The one-time code is wrong, used or expired. */
  invalidCode: 'passkey.invalid_code',
  /** The request could not be read. */
  badRequest: 'passkey.bad_request',
} as const

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes]

/** A person, as the server knows them. */
export interface PasskeyUser {
  id: string
  name: string
  displayName: string
}

/** The signed-in session. */
export interface SessionInfo {
  user: PasskeyUser
  /** When the person last proved it was them (ISO time). */
  confirmedAt: string
  /** When the session ends (ISO time). */
  expiresAt: string
  /** False for a session started with a one-time code by someone with no passkey yet. */
  hasPasskey: boolean
}

/** Where the session stands: signed in, signed out, or locked until confirm(). */
export type SessionState =
  | { status: 'signed-in'; session: SessionInfo }
  | { status: 'signed-out' }
  | { status: 'locked' }

/** One passkey of the signed-in person. */
export interface PasskeyInfo {
  id: string
  name: string
  createdAt: string
  lastUsedAt: string
  /** True for the passkey that started this session. */
  current: boolean
}

/** An error the server answered, or the passkey prompt raised. */
export class PasskeyError extends Error {
  /** The server's code (see ErrorCodes), or "cancelled" when the person closed the prompt. */
  readonly code: string | undefined
  /** The HTTP status, or 0 when the error did not come from the server. */
  readonly status: number
  /** For confirmation_required: the sensitive action that asked for it. */
  readonly action: string | undefined
  /** The whole answer of the server. */
  readonly data: Record<string, unknown>

  constructor(message: string, status: number, data: Record<string, unknown> = {}, code?: string) {
    super(message)
    this.name = 'PasskeyError'
    this.status = status
    this.data = data
    this.code = code ?? (typeof data.code === 'string' ? data.code : undefined)
    this.action = typeof data.action === 'string' ? data.action : undefined
  }
}

/** Options every function takes. */
export interface ClientOptions {
  /** Where the routes are mounted. Default "/auth/passkey". */
  baseUrl?: string
  /** The fetch to use. Default the global fetch. */
  fetch?: typeof fetch
  /** Credentials mode of the requests. Default "same-origin"; "include" for an API on another origin. */
  credentials?: RequestCredentials
  /** Extra headers on every request (a CSRF token, for instance). */
  headers?: Record<string, string>
}

/** What register() may send. */
export interface RegisterOptions extends ClientOptions {
  /** Account name for a sign-up (ignored when signed in). */
  name?: string
  /** Name shown for a sign-up (ignored when signed in). */
  displayName?: string
  /** A label for the passkey, such as "Laptop". */
  passkeyName?: string
}

/** The code of an error, if it has one. */
export function errorCode(err: unknown): string | undefined {
  return err instanceof PasskeyError ? err.code : undefined
}

/** Whether the error asks for confirm(): an idle lock or a sensitive action. */
export function needsConfirmation(err: unknown): boolean {
  const code = errorCode(err)
  return code === ErrorCodes.reconfirmRequired || code === ErrorCodes.confirmationRequired
}

/** Whether this browser can use passkeys at all. */
export function isSupported(): boolean {
  return browserSupportsWebAuthn()
}

async function call<T>(path: string, opts: ClientOptions, method = 'POST', body?: unknown): Promise<T> {
  const doFetch = opts.fetch ?? fetch
  const base = (opts.baseUrl ?? '/auth/passkey').replace(/\/$/, '')
  const res = await doFetch(base + path, {
    method,
    credentials: opts.credentials ?? 'same-origin',
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...opts.headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 204) return undefined as T
  let data: Record<string, unknown> = {}
  try {
    data = (await res.json()) as Record<string, unknown>
  } catch {
    // not JSON: keep the status
  }
  if (!res.ok) {
    throw new PasskeyError(typeof data.error === 'string' ? data.error : `request failed (${res.status})`, res.status, data)
  }
  return data as T
}

interface Begin<T> {
  challengeId: string
  options: T
}

/** Runs the browser prompt; a closed prompt becomes PasskeyError with code "cancelled". */
async function prompt<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run()
  } catch (err) {
    if (err instanceof Error && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
      throw new PasskeyError(err.message, 0, {}, 'cancelled')
    }
    throw err
  }
}

/**
 * Makes a passkey. Signed out, this is a sign-up: the server makes the account (from name and
 * displayName) and signs the person in. Signed in, it adds a passkey to the account.
 */
export async function register(opts: RegisterOptions = {}): Promise<{ user: PasskeyUser; signedIn: boolean }> {
  const begin = await call<Begin<PublicKeyCredentialCreationOptionsJSON>>('/register/begin', opts, 'POST', {
    name: opts.name,
    displayName: opts.displayName,
  })
  const credential = await prompt(() => startRegistration({ optionsJSON: begin.options }))
  return call('/register/finish', opts, 'POST', {
    challengeId: begin.challengeId,
    credential,
    passkeyName: opts.passkeyName,
  })
}

/** Signs in with a passkey; the device offers the accounts it has. */
export async function signIn(opts: ClientOptions = {}): Promise<{ user: PasskeyUser }> {
  const begin = await call<Begin<PublicKeyCredentialRequestOptionsJSON>>('/login/begin', opts)
  const credential = await prompt(() => startAuthentication({ optionsJSON: begin.options }))
  return call('/login/finish', opts, 'POST', { challengeId: begin.challengeId, credential })
}

/**
 * Confirms it is still the same person (step-up): unlocks an idle session, and makes the session
 * fresh for sensitive actions. The device asks only for the fingerprint, face or PIN.
 */
export async function confirm(opts: ClientOptions = {}): Promise<void> {
  const begin = await call<Begin<PublicKeyCredentialRequestOptionsJSON>>('/confirm/begin', opts)
  const credential = await prompt(() => startAuthentication({ optionsJSON: begin.options }))
  await call('/confirm/finish', opts, 'POST', { challengeId: begin.challengeId, credential })
}

/** Signs out of this browser. */
export async function signOut(opts: ClientOptions = {}): Promise<void> {
  await call('/logout', opts)
}

/** Signs in with a one-time code (dashes, spaces and case do not matter). */
export async function redeemCode(code: string, opts: ClientOptions = {}): Promise<{ user: PasskeyUser }> {
  return call('/code', opts, 'POST', { code })
}

/** Where the session stands. Other errors (the network, the server) are thrown. */
export async function getSession(opts: ClientOptions = {}): Promise<SessionState> {
  try {
    const session = await call<SessionInfo>('/session', opts, 'GET')
    return { status: 'signed-in', session }
  } catch (err) {
    if (errorCode(err) === ErrorCodes.sessionRequired) return { status: 'signed-out' }
    if (errorCode(err) === ErrorCodes.reconfirmRequired) return { status: 'locked' }
    throw err
  }
}

/** The signed-in person's passkeys. */
export async function listPasskeys(opts: ClientOptions = {}): Promise<PasskeyInfo[]> {
  return call('/credentials', opts, 'GET')
}

/** Removes one of the signed-in person's passkeys. */
export async function removePasskey(id: string, opts: ClientOptions = {}): Promise<void> {
  await call('/credentials/' + encodeURIComponent(id), opts, 'DELETE')
}

/**
 * Runs action; when it fails because a confirmation is needed (an idle lock or a sensitive action),
 * asks for confirm() and runs it once more. Throw PasskeyError from action for this to work, or use
 * fetchWithConfirmation.
 */
export async function withConfirmation<T>(action: () => Promise<T>, opts: ClientOptions = {}): Promise<T> {
  try {
    return await action()
  } catch (err) {
    if (!needsConfirmation(err)) throw err
    await confirm(opts)
    return action()
  }
}

/** Reads a fetch Response that failed into a PasskeyError (null when it did not fail). */
export async function responseError(res: Response): Promise<PasskeyError | null> {
  if (res.ok) return null
  let data: Record<string, unknown> = {}
  try {
    data = (await res.clone().json()) as Record<string, unknown>
  } catch {
    // not JSON
  }
  return new PasskeyError(typeof data.error === 'string' ? data.error : `request failed (${res.status})`, res.status, data)
}

/**
 * fetch for your own API: when the answer says a confirmation is needed, asks for confirm() and
 * sends the request once more. Other answers, failed or not, are returned as they are.
 */
export async function fetchWithConfirmation(input: RequestInfo | URL, init?: RequestInit, opts: ClientOptions = {}): Promise<Response> {
  const doFetch = opts.fetch ?? fetch
  const res = await doFetch(input, init)
  if (res.status !== 401 && res.status !== 403) return res
  const err = await responseError(res)
  if (!needsConfirmation(err)) return res
  await confirm(opts)
  return doFetch(input, init)
}

/** All the functions with the options bound once. */
export interface PasskeyClient {
  register(opts?: Omit<RegisterOptions, keyof ClientOptions>): Promise<{ user: PasskeyUser; signedIn: boolean }>
  signIn(): Promise<{ user: PasskeyUser }>
  confirm(): Promise<void>
  signOut(): Promise<void>
  redeemCode(code: string): Promise<{ user: PasskeyUser }>
  getSession(): Promise<SessionState>
  listPasskeys(): Promise<PasskeyInfo[]>
  removePasskey(id: string): Promise<void>
  withConfirmation<T>(action: () => Promise<T>): Promise<T>
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
}

/** A client with its options bound: `const passkey = createPasskeyClient({ baseUrl: '/auth' })`. */
export function createPasskeyClient(options: ClientOptions = {}): PasskeyClient {
  return {
    register: (o = {}) => register({ ...options, ...o }),
    signIn: () => signIn(options),
    confirm: () => confirm(options),
    signOut: () => signOut(options),
    redeemCode: (code) => redeemCode(code, options),
    getSession: () => getSession(options),
    listPasskeys: () => listPasskeys(options),
    removePasskey: (id) => removePasskey(id, options),
    withConfirmation: (action) => withConfirmation(action, options),
    fetch: (input, init) => fetchWithConfirmation(input, init, options),
  }
}
