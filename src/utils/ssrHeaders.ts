import type { IncomingHttpHeaders } from 'http';

/**
 * Build the header set to forward on SSR loopback calls into the seerr API.
 *
 * The cookie carries the session for already-signed-in users. The
 * `x-auth-*` headers carry the upstream forward-auth identity (the
 * conventional name for headers set by Caddy's `forward_auth`,
 * Authelia, etc.). Forwarding them lets the headerAuth middleware
 * sign the user in on the very first SSR render — without this, the
 * SSR loopback hits `/me` with no credentials and the user is
 * redirected to `/login` even though Caddy already authenticated
 * them upstream.
 *
 * Note: the loopback peer is the local Node process, so the trusted-
 * proxy CIDR list must include loopback (127.0.0.1/32, ::1/128) for
 * the middleware to honor these headers.
 */
export function ssrApiHeaders(
  reqHeaders: IncomingHttpHeaders | undefined
): Record<string, string> | undefined {
  if (!reqHeaders) return undefined;

  const out: Record<string, string> = {};

  const cookie = reqHeaders.cookie;
  if (cookie) {
    out.cookie = Array.isArray(cookie) ? cookie.join('; ') : cookie;
  }

  for (const [name, value] of Object.entries(reqHeaders)) {
    if (value === undefined) continue;
    if (!name.toLowerCase().startsWith('x-auth-')) continue;
    out[name] = Array.isArray(value) ? value[0] : value;
  }

  return Object.keys(out).length > 0 ? out : undefined;
}
