/** The stable error codes the server answers with. */
export declare const ErrorCodes: {
    /** No session, or it ended: show sign-in. */
    readonly sessionRequired: 'passkey.session_required';
    /** The session was idle too long: call confirm(), then go on. */
    readonly reconfirmRequired: 'passkey.reconfirm_required';
    /** A sensitive action needs a fresh confirmation: call confirm(), then retry. */
    readonly confirmationRequired: 'passkey.confirmation_required';
    /** The passkey was not accepted. */
    readonly rejected: 'passkey.rejected';
    /** The ceremony took too long or was used already: start again. */
    readonly challengeExpired: 'passkey.challenge_expired';
    /** The one-time code is wrong, used or expired. */
    readonly invalidCode: 'passkey.invalid_code';
    /** The request could not be read. */
    readonly badRequest: 'passkey.bad_request';
};
export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
/** A person, as the server knows them. */
export interface PasskeyUser {
    id: string;
    name: string;
    displayName: string;
}
/** The signed-in session. */
export interface SessionInfo {
    user: PasskeyUser;
    /** When the person last proved it was them (ISO time). */
    confirmedAt: string;
    /** When the session ends (ISO time). */
    expiresAt: string;
    /** False for a session started with a one-time code by someone with no passkey yet. */
    hasPasskey: boolean;
}
/** Where the session stands: signed in, signed out, or locked until confirm(). */
export type SessionState = {
    status: 'signed-in';
    session: SessionInfo;
} | {
    status: 'signed-out';
} | {
    status: 'locked';
};
/** One passkey of the signed-in person. */
export interface PasskeyInfo {
    id: string;
    name: string;
    createdAt: string;
    lastUsedAt: string;
    /** True for the passkey that started this session. */
    current: boolean;
}
/** An error the server answered, or the passkey prompt raised. */
export declare class PasskeyError extends Error {
    /** The server's code (see ErrorCodes), or "cancelled" when the person closed the prompt. */
    readonly code: string | undefined;
    /** The HTTP status, or 0 when the error did not come from the server. */
    readonly status: number;
    /** For confirmation_required: the sensitive action that asked for it. */
    readonly action: string | undefined;
    /** The whole answer of the server. */
    readonly data: Record<string, unknown>;
    constructor(message: string, status: number, data?: Record<string, unknown>, code?: string);
}
/** Options every function takes. */
export interface ClientOptions {
    /** Where the routes are mounted. Default "/auth/passkey". */
    baseUrl?: string;
    /** The fetch to use. Default the global fetch. */
    fetch?: typeof fetch;
    /** Credentials mode of the requests. Default "same-origin"; "include" for an API on another origin. */
    credentials?: RequestCredentials;
    /** Extra headers on every request (a CSRF token, for instance). */
    headers?: Record<string, string>;
}
/** What register() may send. */
export interface RegisterOptions extends ClientOptions {
    /** Account name for a sign-up (ignored when signed in). */
    name?: string;
    /** Name shown for a sign-up (ignored when signed in). */
    displayName?: string;
    /** A label for the passkey, such as "Laptop". */
    passkeyName?: string;
}
/** The code of an error, if it has one. */
export declare function errorCode(err: unknown): string | undefined;
/** Whether the error asks for confirm(): an idle lock or a sensitive action. */
export declare function needsConfirmation(err: unknown): boolean;
/** Whether this browser can use passkeys at all. */
export declare function isSupported(): boolean;
/**
 * Makes a passkey. Signed out, this is a sign-up: the server makes the account (from name and
 * displayName) and signs the person in. Signed in, it adds a passkey to the account.
 */
export declare function register(opts?: RegisterOptions): Promise<{
    user: PasskeyUser;
    signedIn: boolean;
}>;
/** Signs in with a passkey; the device offers the accounts it has. */
export declare function signIn(opts?: ClientOptions): Promise<{
    user: PasskeyUser;
}>;
/**
 * Confirms it is still the same person (step-up): unlocks an idle session, and makes the session
 * fresh for sensitive actions. The device asks only for the fingerprint, face or PIN.
 */
export declare function confirm(opts?: ClientOptions): Promise<void>;
/** Signs out of this browser. */
export declare function signOut(opts?: ClientOptions): Promise<void>;
/** Signs in with a one-time code (dashes, spaces and case do not matter). */
export declare function redeemCode(code: string, opts?: ClientOptions): Promise<{
    user: PasskeyUser;
}>;
/** Where the session stands. Other errors (the network, the server) are thrown. */
export declare function getSession(opts?: ClientOptions): Promise<SessionState>;
/** The signed-in person's passkeys. */
export declare function listPasskeys(opts?: ClientOptions): Promise<PasskeyInfo[]>;
/** Removes one of the signed-in person's passkeys. */
export declare function removePasskey(id: string, opts?: ClientOptions): Promise<void>;
/**
 * Runs action; when it fails because a confirmation is needed (an idle lock or a sensitive action),
 * asks for confirm() and runs it once more. Throw PasskeyError from action for this to work, or use
 * fetchWithConfirmation.
 */
export declare function withConfirmation<T>(action: () => Promise<T>, opts?: ClientOptions): Promise<T>;
/** Reads a fetch Response that failed into a PasskeyError (null when it did not fail). */
export declare function responseError(res: Response): Promise<PasskeyError | null>;
/**
 * fetch for your own API: when the answer says a confirmation is needed, asks for confirm() and
 * sends the request once more. Other answers, failed or not, are returned as they are.
 */
export declare function fetchWithConfirmation(input: RequestInfo | URL, init?: RequestInit, opts?: ClientOptions): Promise<Response>;
/** All the functions with the options bound once. */
export interface PasskeyClient {
    register(opts?: Omit<RegisterOptions, keyof ClientOptions>): Promise<{
        user: PasskeyUser;
        signedIn: boolean;
    }>;
    signIn(): Promise<{
        user: PasskeyUser;
    }>;
    confirm(): Promise<void>;
    signOut(): Promise<void>;
    redeemCode(code: string): Promise<{
        user: PasskeyUser;
    }>;
    getSession(): Promise<SessionState>;
    listPasskeys(): Promise<PasskeyInfo[]>;
    removePasskey(id: string): Promise<void>;
    withConfirmation<T>(action: () => Promise<T>): Promise<T>;
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}
/** A client with its options bound: `const passkey = createPasskeyClient({ baseUrl: '/auth' })`. */
export declare function createPasskeyClient(options?: ClientOptions): PasskeyClient;
//# sourceMappingURL=index.d.ts.map