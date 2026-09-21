import cors from 'cors';
import express, { type Express } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pino from 'pino';
import { errorHandler } from './http/middleware/common.js';
import { createRoutes, type RouteDeps } from './http/routes.js';

/** يبني تطبيق Express بلا إقلاع (للاختبارات والخادم معاً). */
export function createApp(deps: RouteDeps, options: { corsOrigins: string[]; logger: pino.Logger }): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(helmet());
  app.use(cors({ origin: true, credentials: true }));
  app.use(express.json({ limit: '1mb' }));
  app.use(rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));
  app.use('/api', createRoutes(deps));
  app.use(errorHandler(options.logger));
  return app;
}
