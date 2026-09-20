import pino from 'pino';
import { createApp } from './app.js';
import { env } from './config/env.js';
import { AuditLog } from './auth/AuditLog.js';
import { AuthService } from './auth/AuthService.js';
import { OwnerRepository } from './auth/OwnerRepository.js';
import { createPool } from './db/pool.js';
import { ensureSchema } from './db/schema.js';
import { PlatformClient } from './platform/PlatformClient.js';

const logger = pino({ level: env.LOG_LEVEL, redact: { paths: ['password', 'passwordHash', 'token', 'authorization'], censor: '[REDACTED]' } });

async function start() {
  const db = createPool({ host: env.DB_HOST, port: env.DB_PORT, database: env.DB_NAME, user: env.DB_USER, password: env.DB_PASSWORD });
  await ensureSchema(db);
  const owners = new OwnerRepository(db);
  const auth = new AuthService(owners, env.JWT_SECRET, env.JWT_EXPIRES_IN, env.BCRYPT_ROUNDS);
  await auth.ensureFirstOwner(env.OWNER_USERNAME, env.OWNER_PASSWORD, (msg) => logger.info(msg));
  const platform = new PlatformClient(env.WAFEER_API_URL, env.PLATFORM_API_KEY);
  const app = createApp(
    { auth, owners, audit: new AuditLog(db), platform },
    { corsOrigins: env.CORS_ORIGIN.split(',').map((s) => s.trim()).filter(Boolean), logger },
  );
  app.listen(env.PORT, () => logger.info(`Wafeer dashboard API listening on port ${env.PORT}`));
}

start().catch((error) => {
  logger.error({ errorMessage: error instanceof Error ? error.message : String(error) }, 'Failed to start dashboard server');
  process.exitCode = 1;
});
