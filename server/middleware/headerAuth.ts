import { UserType } from '@server/constants/user';
import { getRepository } from '@server/datasource';
import { User } from '@server/entity/User';
import {
  computePermissions,
  extractIdentity,
  isTrustedProxy,
} from '@server/lib/headerAuth';
import { Permission } from '@server/lib/permissions';
import { getSettings } from '@server/lib/settings';
import logger from '@server/logger';
import gravatarUrl from 'gravatar-url';

const GENERIC_AVATAR = '';

// Track peers we've already warned about so we don't flood the log when
// the same client makes many requests. Bounded to keep memory in check.
const warnedUntrustedPeers = new Set<string>();
const MAX_WARNED_PEERS = 50;

export const headerAuth: Middleware = async (req, _res, next) => {
  const settings = getSettings();
  const config = settings.main.headerAuth;

  if (!config.enabled) {
    return next();
  }

  // Trust gate: only honor auth headers when the direct TCP peer is in
  // the configured trusted-proxy list. We deliberately use
  // `req.socket.remoteAddress` rather than `req.ip`, because `req.ip`
  // is influenced by `X-Forwarded-For` and would let an attacker who
  // can reach the port forge their apparent source address.
  const peer = req.socket?.remoteAddress ?? undefined;
  const userHeaderName = config.userHeader.toLowerCase();
  const userHeaderValue = req.headers[userHeaderName];
  logger.debug('Forward-auth middleware fired', {
    label: 'Header Auth',
    path: req.path,
    peer,
    hasUserHeader:
      typeof userHeaderValue === 'string' && userHeaderValue.length > 0,
  });
  if (!isTrustedProxy(peer, config.trustedProxies)) {
    // Diagnostic: if the request actually carried the user header,
    // the operator probably *meant* for it to be honored — surface a
    // one-shot warning so misconfiguration is visible in the logs.
    const hadAuthHeader =
      typeof userHeaderValue === 'string' && userHeaderValue.trim().length > 0;
    if (hadAuthHeader && peer && !warnedUntrustedPeers.has(peer)) {
      if (warnedUntrustedPeers.size >= MAX_WARNED_PEERS) {
        warnedUntrustedPeers.clear();
      }
      warnedUntrustedPeers.add(peer);
      logger.warn(
        'Ignoring forward-auth headers from untrusted peer; add this address to Trusted Proxies in Settings → Users → Forward Auth (note: SSR loopback requires 127.0.0.1/32 and ::1/128)',
        {
          label: 'Header Auth',
          peer,
          path: req.path,
        }
      );
    }
    return next();
  }

  const identity = extractIdentity(
    req.headers as Record<string, string | string[] | undefined>,
    config
  );
  if (!identity) {
    return next();
  }

  const userRepository = getRepository(User);
  const headerPermissions = computePermissions(
    identity.roles,
    config.roleMapping,
    config.adminRoles
  );

  try {
    let user: User | null = null;

    // Lookup order: email (preferred — stable identifier), then username.
    if (identity.email) {
      user = await userRepository.findOne({
        where: { email: identity.email },
      });
    }
    if (!user && identity.username) {
      user = await userRepository.findOne({
        where: { username: identity.username },
      });
    }

    if (!user) {
      const totalUsers = await userRepository.count();
      const isFirstUser = totalUsers === 0;

      // First user always gets admin (matches Plex/Jellyfin behavior).
      // Otherwise grant whatever the role mapping computed; if the
      // mapping yields zero, fall back to defaultPermissions so the
      // account isn't completely inert.
      const permissions = isFirstUser
        ? Permission.ADMIN
        : headerPermissions || settings.main.defaultPermissions;

      const email = identity.email ?? `${identity.externalId}@local`;
      user = new User({
        email,
        username: identity.username ?? identity.externalId,
        permissions,
        userType: UserType.HEADER_AUTH,
        avatar: identity.email
          ? gravatarUrl(identity.email, { default: 'mm', size: 200 })
          : GENERIC_AVATAR,
        plexToken: '',
      });
      await userRepository.save(user);

      logger.info('Provisioned new user via forward auth', {
        label: 'Header Auth',
        userId: user.id,
        username: user.username,
        email: user.email,
      });
    } else if (
      config.syncPermissions &&
      user.permissions !== headerPermissions
    ) {
      user.permissions = headerPermissions;
      await userRepository.save(user);
    }

    req.session!.userId = user.id;
    logger.debug('Forward-auth set session userId', {
      label: 'Header Auth',
      userId: user.id,
      sessionId: req.sessionID,
      path: req.path,
    });
  } catch (e) {
    logger.error('Failed to process forward-auth headers', {
      label: 'Header Auth',
      message: (e as Error).message,
    });
  }

  return next();
};

export default headerAuth;
