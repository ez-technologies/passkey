import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import {
  createPasskeyClient,
  type ClientOptions,
  type PasskeyClient,
  type PasskeyUser,
  type RegisterOptions,
  type SessionInfo,
} from './index.js'

/** Where the hook's session stands. */
export type PasskeyStatus = 'loading' | 'signed-out' | 'signed-in' | 'locked'

/** What usePasskey returns. */
export interface UsePasskey {
  status: PasskeyStatus
  session: SessionInfo | null
  user: PasskeyUser | null
  /** The last error of an action (cleared when the next one starts). */
  error: unknown
  /** True while an action runs. */
  busy: boolean
  /** Each action resolves to true when it worked; on failure it stores `error` and resolves to false. */
  register(opts?: Omit<RegisterOptions, keyof ClientOptions>): Promise<boolean>
  signIn(): Promise<boolean>
  confirm(): Promise<boolean>
  signOut(): Promise<boolean>
  redeemCode(code: string): Promise<boolean>
  /** Reads the session again. */
  refresh(): Promise<void>
  /** Runs action, asking for confirm() when the server says it needs one. Errors are thrown. */
  withConfirmation<T>(action: () => Promise<T>): Promise<T>
  /** fetch that asks for confirm() when the server says it needs one. */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
  /** The underlying client. */
  client: PasskeyClient
}

/**
 * The session and the passkey actions for a React app. The options are read once, on the first
 * render.
 */
export function usePasskey(options: ClientOptions = {}): UsePasskey {
  const optionsRef = useRef(options)
  const client = useMemo(() => createPasskeyClient(optionsRef.current), [])
  const [status, setStatus] = useState<PasskeyStatus>('loading')
  const [session, setSession] = useState<SessionInfo | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const state = await client.getSession()
      setStatus(state.status)
      setSession(state.status === 'signed-in' ? state.session : null)
    } catch (err) {
      setError(err)
      setStatus('signed-out')
      setSession(null)
    }
  }, [client])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const run = useCallback(
    async (action: () => Promise<unknown>): Promise<boolean> => {
      setBusy(true)
      setError(null)
      try {
        await action()
        await refresh()
        return true
      } catch (err) {
        setError(err)
        return false
      } finally {
        setBusy(false)
      }
    },
    [refresh],
  )

  const withConfirmation = useCallback(
    async <T,>(action: () => Promise<T>): Promise<T> => {
      try {
        return await client.withConfirmation(action)
      } finally {
        await refresh()
      }
    },
    [client, refresh],
  )

  return {
    status,
    session,
    user: session?.user ?? null,
    error,
    busy,
    register: (opts) => run(() => client.register(opts)),
    signIn: () => run(() => client.signIn()),
    confirm: () => run(() => client.confirm()),
    signOut: () => run(() => client.signOut()),
    redeemCode: (code) => run(() => client.redeemCode(code)),
    refresh,
    withConfirmation,
    fetch: client.fetch,
    client,
  }
}
