import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPasskeyClient, } from './index.js';
/**
 * The session and the passkey actions for a React app. The options are read once, on the first
 * render.
 */
export function usePasskey(options = {}) {
    const optionsRef = useRef(options);
    const client = useMemo(() => createPasskeyClient(optionsRef.current), []);
    const [status, setStatus] = useState('loading');
    const [session, setSession] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const refresh = useCallback(async () => {
        try {
            const state = await client.getSession();
            setStatus(state.status);
            setSession(state.status === 'signed-in' ? state.session : null);
        }
        catch (err) {
            setError(err);
            setStatus('signed-out');
            setSession(null);
        }
    }, [client]);
    useEffect(() => {
        void refresh();
    }, [refresh]);
    const run = useCallback(async (action) => {
        setBusy(true);
        setError(null);
        try {
            await action();
            await refresh();
            return true;
        }
        catch (err) {
            setError(err);
            return false;
        }
        finally {
            setBusy(false);
        }
    }, [refresh]);
    const withConfirmation = useCallback(async (action) => {
        try {
            return await client.withConfirmation(action);
        }
        finally {
            await refresh();
        }
    }, [client, refresh]);
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
    };
}
//# sourceMappingURL=react.js.map