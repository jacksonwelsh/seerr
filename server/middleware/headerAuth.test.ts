import { UserType } from '@server/constants/user';
import { getRepository } from '@server/datasource';
import { User } from '@server/entity/User';
import { Permission } from '@server/lib/permissions';
import { getSettings } from '@server/lib/settings';
import { checkUser } from '@server/middleware/auth';
import { headerAuth } from '@server/middleware/headerAuth';
import { setupTestDb } from '@server/test/db';
import type { Express } from 'express';
import express from 'express';
import session from 'express-session';
import assert from 'node:assert/strict';
import { before, beforeEach, describe, it } from 'node:test';
import request from 'supertest';

let app: Express;

function createApp(): Express {
  const app = express();
  app.use(express.json());
  app.use(
    session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(headerAuth);
  app.use(checkUser);
  // A minimal "who am I" route to observe the resulting authenticated state.
  app.get('/whoami', (req, res) => {
    if (!req.user) {
      res.status(401).json({ status: 401 });
      return;
    }
    res.status(200).json({
      id: req.user.id,
      email: req.user.email,
      username: req.user.username,
      permissions: req.user.permissions,
      userType: req.user.userType,
    });
  });
  return app;
}

function resetHeaderAuthSettings() {
  const settings = getSettings();
  settings.main.headerAuth = {
    enabled: false,
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
}

before(() => {
  app = createApp();
});

setupTestDb();

beforeEach(() => {
  resetHeaderAuthSettings();
});

describe('headerAuth middleware — no-op cases', () => {
  it('does nothing when disabled, even with valid headers from a trusted source', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = false;
    // Even loopback in the trusted list should not matter when disabled.
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'admin@seerr.dev')
      .set('x-auth-email', 'admin@seerr.dev');

    assert.equal(res.status, 401);
  });

  it('trusts loopback peers even when the trusted-proxy list is empty', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = [];
    settings.main.headerAuth.syncPermissions = false;

    // Supertest connects from loopback, which is implicitly trusted.
    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'admin')
      .set('x-auth-email', 'admin@seerr.dev');

    assert.equal(res.status, 200);
    assert.equal(res.body.email, 'admin@seerr.dev');
  });

  it('does nothing when the user header is missing', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-email', 'admin@seerr.dev');

    assert.equal(res.status, 401);
  });
});

describe('headerAuth middleware — find-or-create', () => {
  it('signs in an existing user found by email', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    // Disable sync so that the existing user's seeded permissions are
    // preserved — this test only exercises the find-by-email path.
    settings.main.headerAuth.syncPermissions = false;

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'whatever-id')
      .set('x-auth-email', 'admin@seerr.dev');

    assert.equal(res.status, 200);
    assert.equal(res.body.email, 'admin@seerr.dev');
    // Existing admin user has Permission.ADMIN (bit value 2).
    assert.equal(res.body.permissions, Permission.ADMIN);
    // userType should not be silently overwritten on existing users.
    assert.equal(res.body.userType, UserType.PLEX);
  });

  it('provisions a new user when none exists for the supplied identity', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    settings.main.headerAuth.roleMapping = [
      { role: 'requester', permissions: Permission.REQUEST },
    ];

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'fresh-id')
      .set('x-auth-username', 'fresh')
      .set('x-auth-email', 'fresh@example.com')
      .set('x-auth-roles', 'requester');

    assert.equal(res.status, 200);
    assert.equal(res.body.email, 'fresh@example.com');
    assert.equal(res.body.username, 'fresh');
    assert.equal(res.body.userType, UserType.HEADER_AUTH);
    assert.equal(res.body.permissions, Permission.REQUEST);

    const userRepository = getRepository(User);
    const persisted = await userRepository.findOneOrFail({
      where: { email: 'fresh@example.com' },
    });
    assert.equal(persisted.userType, UserType.HEADER_AUTH);
  });

  it('falls back to defaultPermissions for new users when no role mapping matches', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    settings.main.defaultPermissions = Permission.VOTE;

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'novel-id')
      .set('x-auth-email', 'novel@example.com')
      .set('x-auth-roles', 'role-with-no-mapping');

    assert.equal(res.status, 200);
    assert.equal(res.body.permissions, Permission.VOTE);
  });
});

describe('headerAuth middleware — role mapping & sync', () => {
  it('grants ADMIN when the user carries an admin role', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    settings.main.headerAuth.adminRoles = ['ops'];
    settings.main.headerAuth.roleMapping = [
      { role: 'requester', permissions: Permission.REQUEST },
    ];

    // Pre-existing non-admin user; admin role should bump them to ADMIN
    // when syncPermissions is on (default).
    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'friend-id')
      .set('x-auth-email', 'friend@seerr.dev')
      .set('x-auth-roles', 'ops, requester');

    assert.equal(res.status, 200);
    assert.equal(res.body.permissions, Permission.ADMIN);
  });

  it('combines bitmask permissions across matching roles', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    settings.main.headerAuth.roleMapping = [
      { role: 'r1', permissions: Permission.REQUEST },
      { role: 'r2', permissions: Permission.VOTE },
      { role: 'r3', permissions: Permission.MANAGE_USERS },
    ];

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'friend-id')
      .set('x-auth-email', 'friend@seerr.dev')
      .set('x-auth-roles', 'r1,r2');

    assert.equal(res.status, 200);
    assert.equal(res.body.permissions, Permission.REQUEST | Permission.VOTE);
  });

  it('overwrites existing permissions when syncPermissions is true', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    settings.main.headerAuth.syncPermissions = true;
    settings.main.headerAuth.roleMapping = [
      { role: 'requester', permissions: Permission.REQUEST },
    ];

    // friend@ starts at Permission.REQUEST (32) per the seed; replace with VOTE
    // to verify the next request realigns to whatever the headers say.
    const userRepository = getRepository(User);
    const friend = await userRepository.findOneOrFail({
      where: { email: 'friend@seerr.dev' },
    });
    friend.permissions = Permission.VOTE;
    await userRepository.save(friend);

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'friend-id')
      .set('x-auth-email', 'friend@seerr.dev')
      .set('x-auth-roles', 'requester');

    assert.equal(res.status, 200);
    assert.equal(res.body.permissions, Permission.REQUEST);

    const refreshed = await userRepository.findOneOrFail({
      where: { email: 'friend@seerr.dev' },
    });
    assert.equal(refreshed.permissions, Permission.REQUEST);
  });

  it('preserves existing permissions when syncPermissions is false', async () => {
    const settings = getSettings();
    settings.main.headerAuth.enabled = true;
    settings.main.headerAuth.trustedProxies = ['127.0.0.1/32', '::1/128'];
    settings.main.headerAuth.syncPermissions = false;
    settings.main.headerAuth.roleMapping = [
      { role: 'requester', permissions: Permission.REQUEST },
    ];

    const userRepository = getRepository(User);
    const friend = await userRepository.findOneOrFail({
      where: { email: 'friend@seerr.dev' },
    });
    friend.permissions = Permission.MANAGE_USERS;
    await userRepository.save(friend);

    const res = await request(app)
      .get('/whoami')
      .set('x-auth-user', 'friend-id')
      .set('x-auth-email', 'friend@seerr.dev')
      .set('x-auth-roles', 'requester');

    assert.equal(res.status, 200);
    assert.equal(res.body.permissions, Permission.MANAGE_USERS);
  });
});
