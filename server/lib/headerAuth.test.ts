import {
  computePermissions,
  extractIdentity,
  ipMatchesCidr,
  isTrustedProxy,
  normalizeIp,
  parseCidr,
  parseRoles,
} from '@server/lib/headerAuth';
import { Permission } from '@server/lib/permissions';
import type { HeaderAuthSettings } from '@server/lib/settings';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

const baseConfig: HeaderAuthSettings = {
  enabled: true,
  userHeader: 'x-auth-user',
  usernameHeader: 'x-auth-username',
  emailHeader: 'x-auth-email',
  rolesHeader: 'x-auth-roles',
  rolesSeparator: ',',
  adminRoles: [],
  roleMapping: [],
  trustedProxies: [],
  syncPermissions: true,
};

describe('normalizeIp', () => {
  it('strips IPv4-mapped IPv6 prefix', () => {
    assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
    assert.equal(normalizeIp('::ffff:10.20.30.40'), '10.20.30.40');
  });

  it('passes through real IPv6 addresses', () => {
    assert.equal(normalizeIp('::1'), '::1');
    assert.equal(normalizeIp('2001:db8::1'), '2001:db8::1');
  });

  it('passes through real IPv4 addresses', () => {
    assert.equal(normalizeIp('127.0.0.1'), '127.0.0.1');
  });
});

describe('parseCidr', () => {
  it('parses bare IPv4 as /32', () => {
    const parsed = parseCidr('10.0.0.1');
    assert.ok(parsed);
    assert.equal(parsed.family, 4);
    assert.equal(parsed.prefix, 32);
  });

  it('parses bare IPv6 as /128', () => {
    const parsed = parseCidr('::1');
    assert.ok(parsed);
    assert.equal(parsed.family, 6);
    assert.equal(parsed.prefix, 128);
  });

  it('parses IPv4 CIDR', () => {
    const parsed = parseCidr('10.0.0.0/24');
    assert.ok(parsed);
    assert.equal(parsed.prefix, 24);
  });

  it('rejects malformed input', () => {
    assert.equal(parseCidr(''), null);
    assert.equal(parseCidr('not-an-ip'), null);
    assert.equal(parseCidr('10.0.0.1/33'), null);
    assert.equal(parseCidr('10.0.0.1/-1'), null);
    assert.equal(parseCidr('::1/129'), null);
  });
});

describe('ipMatchesCidr', () => {
  it('matches exact IPv4', () => {
    assert.equal(ipMatchesCidr('127.0.0.1', '127.0.0.1/32'), true);
    assert.equal(ipMatchesCidr('127.0.0.2', '127.0.0.1/32'), false);
  });

  it('matches inside an IPv4 subnet', () => {
    assert.equal(ipMatchesCidr('10.0.0.50', '10.0.0.0/24'), true);
    assert.equal(ipMatchesCidr('10.0.1.1', '10.0.0.0/24'), false);
  });

  it('matches IPv6', () => {
    assert.equal(ipMatchesCidr('::1', '::1/128'), true);
    assert.equal(ipMatchesCidr('::2', '::1/128'), false);
    assert.equal(ipMatchesCidr('2001:db8::5', '2001:db8::/32'), true);
  });

  it('treats IPv4-mapped IPv6 as IPv4', () => {
    assert.equal(ipMatchesCidr('::ffff:127.0.0.1', '127.0.0.1/32'), true);
    assert.equal(ipMatchesCidr('::ffff:10.0.0.5', '10.0.0.0/24'), true);
  });

  it('does not cross address families', () => {
    assert.equal(ipMatchesCidr('::1', '10.0.0.0/24'), false);
    assert.equal(ipMatchesCidr('10.0.0.1', '::1/128'), false);
  });
});

describe('isTrustedProxy', () => {
  it('returns false when the remote address is missing', () => {
    assert.equal(isTrustedProxy(undefined, ['127.0.0.1/32']), false);
  });

  it('returns true when any CIDR matches', () => {
    assert.equal(
      isTrustedProxy('10.0.0.5', ['10.0.0.0/24', '192.168.0.0/16']),
      true
    );
  });

  it('returns false when no CIDR matches and address is not loopback', () => {
    assert.equal(isTrustedProxy('192.168.1.1', ['10.0.0.0/24']), false);
  });

  it('always trusts IPv4 loopback even with empty list', () => {
    assert.equal(isTrustedProxy('127.0.0.1', []), true);
    assert.equal(isTrustedProxy('127.0.0.5', []), true);
  });

  it('always trusts IPv6 loopback even with empty list', () => {
    assert.equal(isTrustedProxy('::1', []), true);
  });

  it('always trusts IPv4-mapped IPv6 loopback', () => {
    assert.equal(isTrustedProxy('::ffff:127.0.0.1', []), true);
  });
});

describe('parseRoles', () => {
  it('returns an empty list for missing/empty input', () => {
    assert.deepEqual(parseRoles(undefined, ','), []);
    assert.deepEqual(parseRoles('', ','), []);
  });

  it('splits, trims, and de-duplicates', () => {
    assert.deepEqual(parseRoles(' admin , user, admin ,  ', ','), [
      'admin',
      'user',
    ]);
  });

  it('respects custom separators', () => {
    assert.deepEqual(parseRoles('admin|user|guest', '|'), [
      'admin',
      'user',
      'guest',
    ]);
  });
});

describe('computePermissions', () => {
  it('returns 0 when no roles map', () => {
    assert.equal(computePermissions(['nope'], [], []), 0);
  });

  it('returns ADMIN for any matching admin role', () => {
    assert.equal(
      computePermissions(['ops'], [], ['ops', 'platform']),
      Permission.ADMIN
    );
  });

  it('combines bitmask permissions across matching roles', () => {
    const perms = computePermissions(
      ['requesters', 'voters'],
      [
        { role: 'requesters', permissions: Permission.REQUEST },
        { role: 'voters', permissions: Permission.VOTE },
        { role: 'unrelated', permissions: Permission.MANAGE_USERS },
      ],
      []
    );
    assert.equal(perms, Permission.REQUEST | Permission.VOTE);
  });

  it('admin override beats role mapping', () => {
    const perms = computePermissions(
      ['ops', 'requesters'],
      [{ role: 'requesters', permissions: Permission.REQUEST }],
      ['ops']
    );
    assert.equal(perms, Permission.ADMIN);
  });
});

describe('extractIdentity', () => {
  it('returns null when the user header is absent', () => {
    assert.equal(extractIdentity({}, baseConfig), null);
  });

  it('reads all four headers, lowercases email, parses roles', () => {
    const id = extractIdentity(
      {
        'x-auth-user': '42',
        'x-auth-username': 'alice',
        'x-auth-email': 'Alice@Example.COM',
        'x-auth-roles': 'admin, user',
      },
      baseConfig
    );
    assert.deepEqual(id, {
      externalId: '42',
      username: 'alice',
      email: 'alice@example.com',
      roles: ['admin', 'user'],
    });
  });

  it('handles array-valued headers by taking the first', () => {
    const id = extractIdentity(
      {
        'x-auth-user': ['42', 'shouldnt-be-used'],
        'x-auth-roles': 'admin',
      },
      baseConfig
    );
    assert.equal(id?.externalId, '42');
  });

  it('returns null on whitespace-only user header', () => {
    assert.equal(extractIdentity({ 'x-auth-user': '   ' }, baseConfig), null);
  });
});
