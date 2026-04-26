import type {
  HeaderAuthRoleMapping,
  HeaderAuthSettings,
} from '@server/lib/settings';
import { isIPv4, isIPv6 } from 'net';

export interface ForwardAuthIdentity {
  externalId: string;
  username?: string;
  email?: string;
  roles: string[];
}

/**
 * Strip the IPv4-mapped-IPv6 prefix (`::ffff:`) Node attaches to remote
 * addresses on dual-stack sockets, so callers can match `127.0.0.1/32`
 * even when `req.socket.remoteAddress` reports `::ffff:127.0.0.1`.
 */
export function normalizeIp(ip: string): string {
  if (ip.startsWith('::ffff:') && isIPv4(ip.slice(7))) {
    return ip.slice(7);
  }
  return ip;
}

interface ParsedCidr {
  family: 4 | 6;
  base: bigint;
  prefix: number;
  mask: bigint;
}

function ipToBigInt(ip: string, family: 4 | 6): bigint | null {
  if (family === 4) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let acc = 0n;
    for (const p of parts) {
      const n = Number(p);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      acc = (acc << 8n) | BigInt(n);
    }
    return acc;
  }

  // IPv6: expand `::` and parse 8 hextets.
  const [head, tail] = ip.split('::', 2) as [string, string | undefined];
  const headParts = head ? head.split(':') : [];
  const tailParts = tail !== undefined ? (tail ? tail.split(':') : []) : null;
  let parts: string[];
  if (tailParts === null) {
    if (headParts.length !== 8) return null;
    parts = headParts;
  } else {
    const fillCount = 8 - headParts.length - tailParts.length;
    if (fillCount < 0) return null;
    parts = [
      ...headParts,
      ...new Array<string>(fillCount).fill('0'),
      ...tailParts,
    ];
  }
  let acc = 0n;
  for (const p of parts) {
    if (p.length === 0 || p.length > 4) return null;
    const n = parseInt(p, 16);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) return null;
    acc = (acc << 16n) | BigInt(n);
  }
  return acc;
}

export function parseCidr(cidr: string): ParsedCidr | null {
  const trimmed = cidr.trim();
  if (!trimmed) return null;

  const slashIdx = trimmed.indexOf('/');
  const ipPart = slashIdx === -1 ? trimmed : trimmed.slice(0, slashIdx);
  const prefixPart = slashIdx === -1 ? null : trimmed.slice(slashIdx + 1);

  const normalized = normalizeIp(ipPart);
  let family: 4 | 6;
  if (isIPv4(normalized)) family = 4;
  else if (isIPv6(normalized)) family = 6;
  else return null;

  const totalBits = family === 4 ? 32 : 128;
  let prefix: number;
  if (prefixPart === null) {
    prefix = totalBits;
  } else {
    const parsed = Number(prefixPart);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > totalBits) {
      return null;
    }
    prefix = parsed;
  }

  const base = ipToBigInt(normalized, family);
  if (base === null) return null;

  const hostBits = BigInt(totalBits - prefix);
  const mask =
    prefix === 0
      ? 0n
      : ((1n << BigInt(totalBits)) - 1n) ^ ((1n << hostBits) - 1n);

  return { family, base: base & mask, prefix, mask };
}

export function ipMatchesCidr(ip: string, cidr: string): boolean {
  const parsed = parseCidr(cidr);
  if (!parsed) return false;

  const normalized = normalizeIp(ip);
  let family: 4 | 6;
  if (isIPv4(normalized)) family = 4;
  else if (isIPv6(normalized)) family = 6;
  else return false;

  if (family !== parsed.family) return false;

  const value = ipToBigInt(normalized, family);
  if (value === null) return false;

  return (value & parsed.mask) === parsed.base;
}

export function isTrustedProxy(
  remoteAddress: string | undefined | null,
  trustedProxies: string[]
): boolean {
  if (!remoteAddress || trustedProxies.length === 0) return false;
  return trustedProxies.some((cidr) => ipMatchesCidr(remoteAddress, cidr));
}

export function parseRoles(
  headerValue: string | undefined | null,
  separator: string
): string[] {
  if (!headerValue) return [];
  const sep = separator || ',';
  const seen = new Set<string>();
  const result: string[] = [];
  for (const raw of headerValue.split(sep)) {
    const trimmed = raw.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

export function computePermissions(
  roles: string[],
  mapping: HeaderAuthRoleMapping[],
  adminRoles: string[]
): number {
  const roleSet = new Set(roles);
  if (adminRoles.some((r) => roleSet.has(r))) {
    // Permission.ADMIN is a single bit; any other bits would be redundant.
    return 2;
  }
  let perms = 0;
  for (const entry of mapping) {
    if (roleSet.has(entry.role)) {
      perms |= entry.permissions;
    }
  }
  return perms;
}

function readHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  if (!name) return undefined;
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0];
  return value;
}

export function extractIdentity(
  headers: Record<string, string | string[] | undefined>,
  config: HeaderAuthSettings
): ForwardAuthIdentity | null {
  const externalId = readHeader(headers, config.userHeader)?.trim();
  if (!externalId) return null;

  const username =
    readHeader(headers, config.usernameHeader)?.trim() || undefined;
  const email =
    readHeader(headers, config.emailHeader)?.trim().toLowerCase() || undefined;
  const roles = parseRoles(
    readHeader(headers, config.rolesHeader),
    config.rolesSeparator
  );

  return { externalId, username, email, roles };
}
