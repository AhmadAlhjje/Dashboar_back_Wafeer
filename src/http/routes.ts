import { Router } from 'express';
import multer from 'multer';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import type { AuthService } from '../auth/AuthService.js';
import type { AuditLog } from '../auth/AuditLog.js';
import { safeOwner, type OwnerRepository } from '../auth/OwnerRepository.js';
import type { PlatformClient } from '../platform/PlatformClient.js';
import { AppError } from '../errors.js';
import { asyncRoute, requireOwner, validate } from './middleware/common.js';

const nullableText = (max: number) => z.string().trim().max(max).nullable().optional();
const dateOrNull = z.union([z.string().datetime({ offset: true }), z.string().regex(/^\d{4}-\d{2}-\d{2}$/), z.null()]).optional();

export const loginSchema = z.object({ username: z.string().trim().min(1).max(100), password: z.string().min(1).max(200) }).strict();
export const changePasswordSchema = z.object({ currentPassword: z.string().min(1).max(200), newPassword: z.string().min(8).max(200) }).strict();
export const createOwnerSchema = z.object({
  username: z.string().trim().min(3).max(100).regex(/^[A-Za-z0-9_.-]+$/),
  displayName: z.string().trim().min(2).max(150),
  password: z.string().min(8).max(200),
});
export const createOfficeSchema = z.object({
  name: z.string().trim().min(2).max(150),
  phone: nullableText(30),
  address: nullableText(255),
  notes: nullableText(2000),
  expiresAt: dateOrNull,
  message: nullableText(500),
  admin: z.object({
    fullName: z.string().trim().min(2).max(150),
    password: z.string().min(8).max(128),
    phone: nullableText(30),
    email: z.string().trim().email().max(150).nullable().optional(),
  }),
});
export const updateOfficeSchema = z.object({
  name: z.string().trim().min(2).max(150).optional(),
  phone: nullableText(30),
  address: nullableText(255),
  notes: nullableText(2000),
});
export const licenseSchema = z.object({
  status: z.enum(['ACTIVE', 'SUSPENDED', 'EXPIRED']),
  expiresAt: dateOrNull,
  message: nullableText(500),
});
export const createOfficeAdminSchema = z.object({
  fullName: z.string().trim().min(2).max(150),
  password: z.string().min(8).max(128),
  phone: nullableText(30),
  email: z.string().trim().email().max(150).nullable().optional(),
  role: z.enum(['ADMIN', 'MANAGER', 'ACCOUNTANT', 'EMPLOYEE', 'VIEWER']).optional(),
});
export const passwordSchema = z.object({ password: z.string().min(8).max(128) });

export interface RouteDeps {
  auth: AuthService;
  owners: OwnerRepository;
  audit: AuditLog;
  platform: PlatformClient;
}

/** كل مسارات اللوحة تحت `/api`؛ ما عدا الدخول والصحة تحتاج توكن المالك. كل تغيير يُدوَّن في سجل العمليات. */
export function createRoutes(deps: RouteDeps): Router {
  const router = Router();
  const owner = requireOwner(deps.auth);
  const record = (req: { owner?: { ownerId: string; username: string }; ip?: string }, action: string, extra: Record<string, unknown> = {}) =>
    deps.audit.record({ ownerId: req.owner?.ownerId ?? null, ownerUsername: req.owner?.username ?? '-', action, ip: req.ip ?? null, ...extra });

  router.get(
    '/health',
    asyncRoute(async (_req, res) => {
      res.json({ success: true, data: { status: 'ok', wafeer: await deps.platform.reachable() } });
    }),
  );

  // ── المالك ─────────────────────────────────────────────────────────────
  router.post(
    '/auth/login',
    rateLimit({ windowMs: 15 * 60_000, limit: 20, standardHeaders: true, legacyHeaders: false }),
    validate(loginSchema),
    asyncRoute(async (req, res) => {
      const result = await deps.auth.login(req.body.username, req.body.password);
      await deps.audit.record({ ownerId: result.owner.id, ownerUsername: result.owner.username, action: 'owner.login', ip: req.ip ?? null });
      res.json({ success: true, data: result });
    }),
  );
  router.get(
    '/auth/me',
    owner,
    asyncRoute(async (req, res) => {
      const me = await deps.owners.findById(req.owner!.ownerId);
      if (!me || !me.isActive) throw new AppError('UNAUTHENTICATED', 'Owner not found', 401);
      res.json({ success: true, data: safeOwner(me) });
    }),
  );
  router.patch(
    '/auth/me/password',
    owner,
    validate(changePasswordSchema),
    asyncRoute(async (req, res) => {
      await deps.auth.changePassword(req.owner!.ownerId, req.body.currentPassword, req.body.newPassword);
      await record(req, 'owner.password_changed');
      res.json({ success: true, data: { changed: true } });
    }),
  );

  // ── نظرة عامة ──────────────────────────────────────────────────────────
  router.get(
    '/overview',
    owner,
    asyncRoute(async (_req, res) => {
      const [overview, recent] = await Promise.all([deps.platform.overview(), deps.audit.recent(10)]);
      res.json({ success: true, data: { ...overview, recentAudit: recent } });
    }),
  );

  // ── المكاتب ────────────────────────────────────────────────────────────
  router.get(
    '/offices',
    owner,
    asyncRoute(async (_req, res) => {
      res.json({ success: true, data: await deps.platform.listOffices() });
    }),
  );
  router.post(
    '/offices',
    owner,
    validate(createOfficeSchema),
    asyncRoute(async (req, res) => {
      const office = await deps.platform.createOffice(req.body);
      await record(req, 'office.created', { officeId: office.id, officeCode: office.code, target: office.name, details: { admin: req.body.admin.fullName } });
      // بيانات التسليم تُعرض مرة واحدة في اللوحة؛ كلمة المرور لا تُخزَّن هنا ولا تُدوَّن.
      res.status(201).json({ success: true, data: { office, credentials: { officeCode: office.code, fullName: req.body.admin.fullName } } });
    }),
  );
  router.get(
    '/offices/:id',
    owner,
    asyncRoute(async (req, res) => {
      const [office, admins, audit] = await Promise.all([
        deps.platform.getOffice(req.params.id),
        deps.platform.listAdmins(req.params.id),
        deps.audit.recent(20, req.params.id),
      ]);
      res.json({ success: true, data: { office, admins, audit } });
    }),
  );
  router.patch(
    '/offices/:id',
    owner,
    validate(updateOfficeSchema),
    asyncRoute(async (req, res) => {
      const office = await deps.platform.updateOffice(req.params.id, req.body);
      await record(req, 'office.updated', { officeId: office.id, officeCode: office.code, target: office.name, details: req.body });
      res.json({ success: true, data: office });
    }),
  );
  router.put(
    '/offices/:id/license',
    owner,
    validate(licenseSchema),
    asyncRoute(async (req, res) => {
      const office = await deps.platform.setLicense(req.params.id, req.body);
      await record(req, `office.license.${req.body.status.toLowerCase()}`, { officeId: office.id, officeCode: office.code, target: office.name, details: req.body });
      res.json({ success: true, data: office });
    }),
  );

  // إعادة توليد كود المكتب (ضاع الكود): يُعرض الجديد مرة واحدة ويُدوَّن.
  router.post(
    '/offices/:id/code',
    owner,
    asyncRoute(async (req, res) => {
      const office = await deps.platform.regenerateCode(req.params.id);
      await record(req, 'office.code_regenerated', { officeId: office.id, officeCode: office.code, target: office.name });
      res.json({ success: true, data: office });
    }),
  );

  // ── لوغو المكتب: يُبدَّل من اللوحة متى شاء المالك (داخل التطبيق يبقى مرة واحدة) ──
  const logoUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024, files: 1 },
    fileFilter: (_req, file, done) =>
      ['image/png', 'image/jpeg', 'image/webp'].includes(file.mimetype)
        ? done(null, true)
        : done(new AppError('INVALID_OFFICE_LOGO', 'الصورة يجب أن تكون PNG أو JPG أو WEBP', 422)),
  }).single('logo');
  router.put(
    '/offices/:id/logo',
    owner,
    (req, res, next) => logoUpload(req, res, (err?: unknown) => (err ? next(err) : next())),
    asyncRoute(async (req, res) => {
      if (!req.file) throw new AppError('VALIDATION_ERROR', 'اختر صورة اللوغو', 422);
      const office = await deps.platform.setOfficeLogo(req.params.id, req.file);
      await record(req, 'office.logo_updated', { officeId: office.id, target: office.name, size: req.file.size, type: req.file.mimetype });
      res.json({ success: true, data: office });
    }),
  );
  router.delete(
    '/offices/:id/logo',
    owner,
    asyncRoute(async (req, res) => {
      const office = await deps.platform.removeOfficeLogo(req.params.id);
      await record(req, 'office.logo_removed', { officeId: office.id, target: office.name });
      res.json({ success: true, data: office });
    }),
  );
  // عرض اللوغو الحالي (يمرّ عبر اللوحة بتوكن المالك؛ v= للتخطي عن التخزين المؤقت)
  router.get(
    '/offices/:id/logo',
    owner,
    asyncRoute(async (req, res) => {
      const office = await deps.platform.getOffice(req.params.id);
      if (!office.logoPath) throw new AppError('NOT_FOUND', 'لا لوغو لهذا المكتب', 404);
      const file = await deps.platform.fetchOfficeLogo(office.logoPath);
      if (!file) throw new AppError('NOT_FOUND', 'ملف اللوغو غير موجود على خادم وفير', 404);
      res.setHeader('content-type', file.contentType);
      res.setHeader('cache-control', 'private, max-age=300');
      res.send(Buffer.from(file.body));
    }),
  );

  // ── إداريو المكتب ──────────────────────────────────────────────────────
  router.get(
    '/offices/:id/admins',
    owner,
    asyncRoute(async (req, res) => {
      res.json({ success: true, data: await deps.platform.listAdmins(req.params.id) });
    }),
  );
  router.post(
    '/offices/:id/admins',
    owner,
    validate(createOfficeAdminSchema),
    asyncRoute(async (req, res) => {
      const admin = await deps.platform.createAdmin(req.params.id, req.body);
      await record(req, 'office.admin.created', { officeId: req.params.id, target: admin.fullName });
      res.status(201).json({ success: true, data: admin });
    }),
  );
  router.put(
    '/offices/:id/admins/:adminId/password',
    owner,
    validate(passwordSchema),
    asyncRoute(async (req, res) => {
      const admin = await deps.platform.resetAdminPassword(req.params.id, req.params.adminId, req.body.password);
      await record(req, 'office.admin.password_reset', { officeId: req.params.id, target: admin.fullName });
      res.json({ success: true, data: admin });
    }),
  );
  router.patch(
    '/offices/:id/admins/:adminId/:action(activate|deactivate)',
    owner,
    asyncRoute(async (req, res) => {
      const active = req.params.action === 'activate';
      const admin = await deps.platform.setAdminActive(req.params.id, req.params.adminId, active);
      await record(req, active ? 'office.admin.activated' : 'office.admin.deactivated', { officeId: req.params.id, target: admin.fullName });
      res.json({ success: true, data: admin });
    }),
  );

  // ── مالكو اللوحة ───────────────────────────────────────────────────────
  router.get(
    '/owners',
    owner,
    asyncRoute(async (_req, res) => {
      res.json({ success: true, data: (await deps.owners.list()).map(safeOwner) });
    }),
  );
  router.post(
    '/owners',
    owner,
    validate(createOwnerSchema),
    asyncRoute(async (req, res) => {
      if (await deps.owners.findByUsername(req.body.username)) throw new AppError('CONFLICT', 'اسم المستخدم مستخدم مسبقاً', 409);
      const created = await deps.owners.create({
        username: req.body.username,
        displayName: req.body.displayName,
        passwordHash: await deps.auth.hash(req.body.password),
      });
      await record(req, 'owner.created', { target: created.username });
      res.status(201).json({ success: true, data: safeOwner(created) });
    }),
  );
  router.patch(
    '/owners/:id/:action(activate|deactivate)',
    owner,
    asyncRoute(async (req, res) => {
      const active = req.params.action === 'activate';
      if (!active && req.params.id === req.owner!.ownerId) throw new AppError('CANNOT_DEACTIVATE_SELF', 'لا يمكنك تعطيل حسابك', 409);
      const updated = await deps.owners.setActive(req.params.id, active);
      if (!updated) throw new AppError('OWNER_NOT_FOUND', 'Owner not found', 404);
      await record(req, active ? 'owner.activated' : 'owner.deactivated', { target: updated.username });
      res.json({ success: true, data: safeOwner(updated) });
    }),
  );

  // ── سجل العمليات ───────────────────────────────────────────────────────
  router.get(
    '/audit',
    owner,
    asyncRoute(async (req, res) => {
      const limit = Math.min(Math.max(Number(req.query.limit ?? 100) || 100, 1), 500);
      const officeId = typeof req.query.officeId === 'string' && req.query.officeId ? req.query.officeId : undefined;
      res.json({ success: true, data: await deps.audit.recent(limit, officeId) });
    }),
  );
  return router;
}
