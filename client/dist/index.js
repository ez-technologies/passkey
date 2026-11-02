/**
 * Passkey sign-in for the browser: the client of the Go package github.com/ez-technologies/passkey
 * (its ginpasskey routes). Every function talks JSON to `baseUrl` (default `/auth/passkey`) with
 * the session cookie, and runs the passkey prompt with @simplewebauthn/browser.
 */
import { browserSupportsWebAuthn, startAuthentication, startRegistration, } from '@simplewebauthn/browser';
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
};
/** An error the server answered, or the passkey prompt raised. */
export class PasskeyError extends Error {
    /** The server's code (see ErrorCodes), or "cancelled" when the person closed the prompt. */
    code;
    /** The HTTP status, or 0 when the error did not come from the server. */
    status;
    /** For confirmation_required: the sensitive action that asked for it. */
    action;
    /** The whole answer of the server. */
    data;
    constructor(message, status, data = {}, code) {
        super(message);
        this.name = 'PasskeyError';
        this.status = status;
        this.data = data;
        this.code = code ?? (typeof data.code === 'string' ? data.code : undefined);
        this.action = typeof data.action === 'string' ? data.action : undefined;
    }
}
/** The code of an error, if it has one. */
export function errorCode(err) {
    return err instanceof PasskeyError ? err.code : undefined;
}
/** Whether the error asks for confirm(): an idle lock or a sensitive action. */
export function needsConfirmation(err) {
    const code = errorCode(err);
    return code === ErrorCodes.reconfirmRequired || code === ErrorCodes.confirmationRequired;
}
/** Whether this browser can use passkeys at all. */
export function isSupported() {
    return browserSupportsWebAuthn();
}
async function call(path, opts, method = 'POST', body) {
    const doFetch = opts.fetch ?? fetch;
    const base = (opts.baseUrl ?? '/auth/passkey').replace(/\/$/, '');
    const res = await doFetch(base + path, {
        method,
        credentials: opts.credentials ?? 'same-origin',
        headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...opts.headers },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 204)
        return undefined;
    let data = {};
    try {
        data = (await res.json());
    }
    catch {
        // not JSON: keep the status
    }
    if (!res.ok) {
        throw new PasskeyError(typeof data.error === 'string' ? data.error : `request failed (${res.status})`, res.status, data);
    }
    return data;
}
/** Runs the browser prompt; a closed prompt becomes PasskeyError with code "cancelled". */
async function prompt(run) {
    try {
        return await run();
    }
    catch (err) {
        if (err instanceof Error && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
            throw new PasskeyError(err.message, 0, {}, 'cancelled');
        }
        throw err;
    }
}
/**
 * Makes a passkey. Signed out, this is a sign-up: the server makes the account (from name and
 * displayName) and signs the person in. Signed in, it adds a passkey to the account.
 */
export async function register(opts = {}) {
    const begin = await call('/register/begin', opts, 'POST', {
        name: opts.name,
        displayName: opts.displayName,
    });
    const credential = await prompt(() => startRegistration({ optionsJSON: begin.options }));
    return call('/register/finish', opts, 'POST', {
        challengeId: begin.challengeId,
        credential,
        passkeyName: opts.passkeyName,
    });
}
/** Signs in with a passkey; the device offers the accounts it has. */
export async function signIn(opts = {}) {
    const begin = await call('/login/begin', opts);
    const credential = await prompt(() => startAuthentication({ optionsJSON: begin.options }));
    return call('/login/finish', opts, 'POST', { challengeId: begin.challengeId, credential });
}
/**
 * Confirms it is still the same person (step-up): unlocks an idle session, and makes the session
 * fresh for sensitive actions. The device asks only for the fingerprint, face or PIN.
 */
export async function confirm(opts = {}) {
    const begin = await call('/confirm/begin', opts);
    const credential = await prompt(() => startAuthentication({ optionsJSON: begin.options }));
    await call('/confirm/finish', opts, 'POST', { challengeId: begin.challengeId, credential });
}
/** Signs out of this browser. */
export async function signOut(opts = {}) {
    await call('/logout', opts);
}
/** Signs in with a one-time code (dashes, spaces and case do not matter). */
export async function redeemCode(code, opts = {}) {
    return call('/code', opts, 'POST', { code });
}
/** Where the session stands. Other errors (the network, the server) are thrown. */
export async function getSession(opts = {}) {
    try {
        const session = await call('/session', opts, 'GET');
        return { status: 'signed-in', session };
    }
    catch (err) {
        if (errorCode(err) === ErrorCodes.sessionRequired)
            return { status: 'signed-out' };
        if (errorCode(err) === ErrorCodes.reconfirmRequired)
            return { status: 'locked' };
        throw err;
    }
}
/** The signed-in person's passkeys. */
export async function listPasskeys(opts = {}) {
    return call('/credentials', opts, 'GET');
}
/** Removes one of the signed-in person's passkeys. */
export async function removePasskey(id, opts = {}) {
    await call('/credentials/' + encodeURIComponent(id), opts, 'DELETE');
}
/**
 * Runs action; when it fails because a confirmation is needed (an idle lock or a sensitive action),
 * asks for confirm() and runs it once more. Throw PasskeyError from action for this to work, or use
 * fetchWithConfirmation.
 */
export async function withConfirmation(action, opts = {}) {
    try {
        return await action();
    }
    catch (err) {
        if (!needsConfirmation(err))
            throw err;
        await confirm(opts);
        return action();
    }
}
/** Reads a fetch Response that failed into a PasskeyError (null when it did not fail). */
export async function responseError(res) {
    if (res.ok)
        return null;
    let data = {};
    try {
        data = (await res.clone().json());
    }
    catch {
        // not JSON
    }
    return new PasskeyError(typeof data.error === 'string' ? data.error : `request failed (${res.status})`, res.status, data);
}
/**
 * fetch for your own API: when the answer says a confirmation is needed, asks for confirm() and
 * sends the request once more. Other answers, failed or not, are returned as they are.
 */
export async function fetchWithConfirmation(input, init, opts = {}) {
    const doFetch = opts.fetch ?? fetch;
    const res = await doFetch(input, init);
    if (res.status !== 401 && res.status !== 403)
        return res;
    const err = await responseError(res);
    if (!needsConfirmation(err))
        return res;
    await confirm(opts);
    return doFetch(input, init);
}
/** A client with its options bound: `const passkey = createPasskeyClient({ baseUrl: '/auth' })`. */
export function createPasskeyClient(options = {}) {
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
    };
}
//# sourceMappingURL=index.js.map