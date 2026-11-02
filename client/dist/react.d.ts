import { type ClientOptions, type PasskeyClient, type PasskeyUser, type RegisterOptions, type SessionInfo } from './index.js';
/** Where the hook's session stands. */
export type PasskeyStatus = 'loading' | 'signed-out' | 'signed-in' | 'locked';
/** What usePasskey returns. */
export interface UsePasskey {
    status: PasskeyStatus;
    session: SessionInfo | null;
    user: PasskeyUser | null;
    /** The last error of an action (cleared when the next one starts). */
    error: unknown;
    /** True while an action runs. */
    busy: boolean;
    /** Each action resolves to true when it worked; on failure it stores `error` and resolves to false. */
    register(opts?: Omit<RegisterOptions, keyof ClientOptions>): Promise<boolean>;
    signIn(): Promise<boolean>;
    confirm(): Promise<boolean>;
    signOut(): Promise<boolean>;
    redeemCode(code: string): Promise<boolean>;
    /** Reads the session again. */
    refresh(): Promise<void>;
    /** Runs action, asking for confirm() when the server says it needs one. Errors are thrown. */
    withConfirmation<T>(action: () => Promise<T>): Promise<T>;
    /** fetch that asks for confirm() when the server says it needs one. */
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
    /** The underlying client. */
    client: PasskeyClient;
}
/**
 * The session and the passkey actions for a React app. The options are read once, on the first
 * render.
 */
export declare function usePasskey(options?: ClientOptions): UsePasskey;
//# sourceMappingURL=react.d.ts.map