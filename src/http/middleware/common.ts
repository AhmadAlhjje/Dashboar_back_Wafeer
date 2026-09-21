import { MulterError } from 'multer';
import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError, type ZodTypeAny } from 'zod';
import type pino from 'pino';
import { AppError } from '../../errors.js';
import type { AuthService, OwnerToken } from '../../auth/AuthService.js';

declare module 'express-serve-static-core' {
  interface Request {
    owner?: OwnerToken;
  }
}

export const asyncRoute =
  (handler: RequestHandler): RequestHandler =>
  (req, res, next) =>
    Promise.resolve(handler(req, res, next)).catch(next);

export const validate =
  (schema: ZodTypeAny): RequestHandler =>
  (req, _res, next) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      next(error);
    }
  };

/** مصادقة المالك: `Authorization: Bearer <token>`. */
export const requireOwner =
  (auth: AuthService): RequestHandler =>
  (req, _res, next) => {
    const value = req.header('authorization');
    if (!value?.startsWith('Bearer ')) return next(new AppError('UNAUTHENTICATED', 'Authentication required', 401));
    try {
      req.owner = auth.verify(value.slice(7));
      next();
    } catch (error) {
      next(error);
    }
  };

export const errorHandler =
  (logger: pino.Logger): ErrorRequestHandler =>
  (error, req, res, _next) => {
    if (error instanceof ZodError)
      return void res.status(422).json({ success: false, error: { code: 'VALIDATION_ERROR', message: 'Invalid request', details: error.flatten() } });
    if (error instanceof AppError)
      return void res.status(error.status).json({ success: false, error: { code: error.code, message: error.message, details: error.details } });
    // multer: ملف أكبر من الحدّ (لوغو المكتب) ⇒ 413 برسالة واضحة بدل 500
    if (error instanceof MulterError)
      return void res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 422).json({
        success: false,
        error: {
          code: error.code === 'LIMIT_FILE_SIZE' ? 'FILE_TOO_LARGE' : 'INVALID_UPLOAD',
          message: error.code === 'LIMIT_FILE_SIZE' ? 'حجم الصورة يتجاوز الحدّ المسموح (20MB)' : 'ملف الرفع غير صالح',
          details: { code: error.code },
        },
      });
    logger.error({ path: req.path, errorMessage: error instanceof Error ? error.message : String(error) }, 'unhandled error');
    res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Internal server error', details: null } });
  };
