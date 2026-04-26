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
  if (!isTrustedProxy(peer, config.trustedProxies)) {
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
  } catch (e) {
    logger.error('Failed to process forward-auth headers', {
      label: 'Header Auth',
      message: (e as Error).message,
    });
  }

  return next();
};

export default headerAuth;
