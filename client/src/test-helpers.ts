// Shared by the tests: a fetch that answers from a table of routes.
export type Route = (body: unknown) => { status: number; body?: unknown }

export function fakeFetch(routes: Record<string, Route | Route[]>) {
  const calls: { url: string; method: string; body: unknown; credentials?: RequestCredentials; headers: Record<string, string> }[] = []
  const fn = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input)
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ url, method, body, credentials: init.credentials, headers: (init.headers ?? {}) as Record<string, string> })
    let route = routes[`${method} ${url}`]
    if (Array.isArray(route)) route = route.length > 1 ? route.shift()! : route[0]
    if (!route) return new Response(JSON.stringify({ error: 'no route' }), { status: 404 })
    const out = route(body)
    if (out.status === 204) return new Response(null, { status: 204 })
    return new Response(JSON.stringify(out.body ?? {}), { status: out.status, headers: { 'Content-Type': 'application/json' } })
  }
  return { fetch: fn as typeof fetch, calls }
}
