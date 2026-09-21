import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import pino from 'pino';
import bcrypt from 'bcrypt';
import { createApp } from '../src/app.js';
import { AuthService } from '../src/auth/AuthService.js';
import type { Owner, OwnerRepository } from '../src/auth/OwnerRepository.js';
import type { AuditEntry, AuditLog } from '../src/auth/AuditLog.js';
import { PlatformClient, type Office } from '../src/platform/PlatformClient.js';
import { AppError } from '../src/errors.js';

const SECRET = 's'.repeat(40);

/** مستودع مالكين في الذاكرة. */
function fakeOwners(initial: Owner[] = []): OwnerRepository & { rows: Owner[] } {
  const rows = [...initial];
  return {
    rows,
    count: async () => rows.length,
    findByUsername: async (u: string) => rows.find((o) => o.username === u) ?? null,
    findById: async (id: string) => rows.find((o) => o.id === id) ?? null,
    list: async () => rows,
    create: async (i: { username: string; displayName: string; passwordHash: string }) => {
      const o: Owner = { id: String(rows.length + 1), username: i.username, displayName: i.displayName, passwordHash: i.passwordHash, isActive: true, lastLoginAt: null, createdAt: new Date() };
      rows.push(o);
      return o;
    },
    setActive: async (id: string, isActive: boolean) => {
      const o = rows.find((x) => x.id === id);
      if (o) o.isActive = isActive;
      return o ?? null;
    },
    setPassword: async (id: string, hash: string) => {
      const o = rows.find((x) => x.id === id);
      if (o) o.passwordHash = hash;
    },
    touchLogin: async () => {},
  } as unknown as OwnerRepository & { rows: Owner[] };
}

function fakeAudit(): AuditLog & { entries: AuditEntry[] } {
  const entries: AuditEntry[] = [];
  return {
    entries,
    record: async (e: AuditEntry) => {
      entries.push(e);
    },
    recent: async () => entries.map((e, i) => ({ ...e, id: String(i + 1), createdAt: new Date() })),
  } as unknown as AuditLog & { entries: AuditEntry[] };
}

const office: Office = {
  id: '5',
  code: 'ABCD2345',
  name: 'مكتب حلب',
  status: 'ACTIVE',
  expiresAt: null,
  message: null,
  phone: null,
  address: null,
  notes: null,
  logoPath: null,
  logoUpdatedAt: null,
  createdAt: '2026-09-20T00:00:00.000Z',
  updatedAt: '2026-09-20T00:00:00.000Z',
};

async function harness(ownerPassword = 'owner-pass-123') {
  const owners = fakeOwners([
    { id: '1', username: 'owner', displayName: 'المالك', passwordHash: await bcrypt.hash(ownerPassword, 4), isActive: true, lastLoginAt: null, createdAt: new Date() },
  ]);
  const auth = new AuthService(owners, SECRET, '1h', 4);
  const audit = fakeAudit();
  const platform = {
    overview: vi.fn().mockResolvedValue({ offices: { total: 1, active: 1, suspended: 0, expired: 0 }, movements: { total: 3, today: 1 }, clients: 2, admins: 1 }),
    listOffices: vi.fn().mockResolvedValue([office]),
    getOffice: vi.fn().mockResolvedValue(office),
    createOffice: vi.fn().mockResolvedValue(office),
    updateOffice: vi.fn().mockResolvedValue(office),
    setLicense: vi.fn().mockResolvedValue({ ...office, status: 'SUSPENDED' }),
    regenerateCode: vi.fn().mockResolvedValue({ ...office, code: 'NEWC2DE9' }),
    setOfficeLogo: vi.fn().mockResolvedValue({ ...office, logoPath: 'uploads/offices/office-5-a.png', logoUpdatedAt: '2026-09-21T10:00:00.000Z' }),
    removeOfficeLogo: vi.fn().mockResolvedValue(office),
    fetchOfficeLogo: vi.fn().mockResolvedValue({ body: new Uint8Array([137, 80, 78, 71]).buffer, contentType: 'image/png' }),
    listAdmins: vi.fn().mockResolvedValue([]),
    createAdmin: vi.fn().mockResolvedValue({ id: '9', fullName: 'أحمد', role: 'ADMIN', isActive: true }),
    resetAdminPassword: vi.fn().mockResolvedValue({ id: '9', fullName: 'أحمد' }),
    setAdminActive: vi.fn().mockResolvedValue({ id: '9', fullName: 'أحمد', isActive: false }),
    reachable: vi.fn().mockResolvedValue(true),
  } as unknown as PlatformClient;
  const app = createApp({ auth, owners, audit, platform }, { corsOrigins: ['http://localhost:5173'], logger: pino({ level: 'silent' }) });
  const login = await request(app).post('/api/auth/login').send({ username: 'owner', password: ownerPassword });
  return { app, owners, audit, platform, token: login.body.data?.token as string, login };
}

describe('owner auth', () => {
  it('logs in with valid credentials and rejects bad ones; passwords never appear in responses', async () => {
    const { login, app } = await harness();
    expect(login.status).toBe(200);
    expect(login.body.data.token).toBeTruthy();
    expect(JSON.stringify(login.body)).not.toContain('passwordHash');
    const bad = await request(app).post('/api/auth/login').send({ username: 'owner', password: 'wrong-password' });
    expect(bad.status).toBe(401);
    expect(bad.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('protects every route with the owner token', async () => {
    const { app, token } = await harness();
    expect((await request(app).get('/api/offices')).status).toBe(401);
    expect((await request(app).get('/api/offices').set('authorization', 'Bearer nope')).status).toBe(401);
    expect((await request(app).get('/api/offices').set('authorization', `Bearer ${token}`)).status).toBe(200);
  });

  it('changes the owner password (current must match, new must differ)', async () => {
    const { app, token, owners } = await harness();
    const wrong = await request(app).patch('/api/auth/me/password').set('authorization', `Bearer ${token}`).send({ currentPassword: 'nope-nope-1', newPassword: 'new-password-1' });
    expect(wrong.body.error.code).toBe('INVALID_PASSWORD');
    const same = await request(app).patch('/api/auth/me/password').set('authorization', `Bearer ${token}`).send({ currentPassword: 'owner-pass-123', newPassword: 'owner-pass-123' });
    expect(same.body.error.code).toBe('SAME_PASSWORD');
    const ok = await request(app).patch('/api/auth/me/password').set('authorization', `Bearer ${token}`).send({ currentPassword: 'owner-pass-123', newPassword: 'new-password-1' });
    expect(ok.status).toBe(200);
    expect(await bcrypt.compare('new-password-1', owners.rows[0].passwordHash)).toBe(true);
  });

  it('creates the first owner from env only when none exists', async () => {
    const owners = fakeOwners();
    const auth = new AuthService(owners, SECRET, '1h', 4);
    const log = vi.fn();
    await auth.ensureFirstOwner('owner', 'short', log);
    expect(owners.rows).toHaveLength(0);
    await auth.ensureFirstOwner('owner', 'strong-password-1', log);
    expect(owners.rows).toHaveLength(1);
    await auth.ensureFirstOwner('other', 'strong-password-2', log);
    expect(owners.rows).toHaveLength(1);
  });
});

describe('offices routes', () => {
  it('creates an office through wafeer, returns handover credentials once, and audits without the password', async () => {
    const { app, token, audit, platform } = await harness();
    const res = await request(app)
      .post('/api/offices')
      .set('authorization', `Bearer ${token}`)
      .send({ name: 'مكتب حلب', admin: { fullName: 'أحمد', password: 'secret-123' } });
    expect(res.status).toBe(201);
    expect(res.body.data.credentials).toEqual({ officeCode: 'ABCD2345', fullName: 'أحمد' });
    expect(platform.createOffice).toHaveBeenCalledWith(expect.objectContaining({ name: 'مكتب حلب' }));
    const entry = audit.entries.find((e) => e.action === 'office.created')!;
    expect(entry.officeCode).toBe('ABCD2345');
    expect(JSON.stringify(entry)).not.toContain('secret-123');
  });

  it('validates input (422) and forwards wafeer errors with their code', async () => {
    const { app, token, platform } = await harness();
    const invalid = await request(app).post('/api/offices').set('authorization', `Bearer ${token}`).send({ name: 'x' });
    expect(invalid.status).toBe(422);
    (platform.getOffice as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new AppError('OFFICE_NOT_FOUND', 'Office not found', 404));
    const missing = await request(app).get('/api/offices/404').set('authorization', `Bearer ${token}`);
    expect(missing.status).toBe(404);
    expect(missing.body.error.code).toBe('OFFICE_NOT_FOUND');
  });

  it('sets the license and audits the status change', async () => {
    const { app, token, audit } = await harness();
    const res = await request(app).put('/api/offices/5/license').set('authorization', `Bearer ${token}`).send({ status: 'SUSPENDED', message: 'لم يُسدَّد' });
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('SUSPENDED');
    expect(audit.entries.some((e) => e.action === 'office.license.suspended')).toBe(true);
    const bad = await request(app).put('/api/offices/5/license').set('authorization', `Bearer ${token}`).send({ status: 'PAUSED' });
    expect(bad.status).toBe(422);
  });

  it('regenerates the office code and audits it', async () => {
    const { app, token, audit } = await harness();
    const res = await request(app).post('/api/offices/5/code').set('authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data.code).toBe('NEWC2DE9');
    expect(audit.entries.find((e) => e.action === 'office.code_regenerated')?.officeCode).toBe('NEWC2DE9');
  });

  it('uploads, serves and removes the office logo (any number of times) with audit entries', async () => {
    const { app, token, platform, audit } = await harness();
    const png = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    const up1 = await request(app).put('/api/offices/5/logo').set('Authorization', `Bearer ${token}`).attach('logo', png, { filename: 'logo.png', contentType: 'image/png' });
    expect(up1.status).toBe(200);
    expect(up1.body.data.logoPath).toBe('uploads/offices/office-5-a.png');
    const up2 = await request(app).put('/api/offices/5/logo').set('Authorization', `Bearer ${token}`).attach('logo', png, { filename: 'logo2.png', contentType: 'image/png' });
    expect(up2.status).toBe(200);
    expect((platform.setOfficeLogo as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(2);
    const bad = await request(app).put('/api/offices/5/logo').set('Authorization', `Bearer ${token}`).attach('logo', Buffer.from('x'), { filename: 'x.txt', contentType: 'text/plain' });
    expect(bad.status).toBe(422);
    expect(bad.body.error.code).toBe('INVALID_OFFICE_LOGO');
    const missing = await request(app).put('/api/offices/5/logo').set('Authorization', `Bearer ${token}`);
    expect(missing.status).toBe(422);
    // أكبر من 20MB ⇒ 413 برسالة واضحة (لا 500)
    const huge = await request(app).put('/api/offices/5/logo').set('Authorization', `Bearer ${token}`).attach('logo', Buffer.alloc(20 * 1024 * 1024 + 1, 1), { filename: 'big.png', contentType: 'image/png' });
    expect(huge.status).toBe(413);
    expect(huge.body.error.code).toBe('FILE_TOO_LARGE');
    (platform.getOffice as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ...office, logoPath: 'uploads/offices/office-5-a.png' });
    const img = await request(app).get('/api/offices/5/logo').set('Authorization', `Bearer ${token}`);
    expect(img.status).toBe(200);
    expect(img.headers['content-type']).toContain('image/png');
    const none = await request(app).get('/api/offices/5/logo').set('Authorization', `Bearer ${token}`);
    expect(none.status).toBe(404);
    const del = await request(app).delete('/api/offices/5/logo').set('Authorization', `Bearer ${token}`);
    expect(del.status).toBe(200);
    expect(audit.entries.map((e) => e.action)).toEqual(expect.arrayContaining(['office.logo_updated', 'office.logo_removed']));
    const anon = await request(app).put('/api/offices/5/logo').attach('logo', png, { filename: 'logo.png', contentType: 'image/png' });
    expect(anon.status).toBe(401);
  });

  it('manages office admins and platform owners', async () => {
    const { app, token, owners } = await harness();
    expect((await request(app).post('/api/offices/5/admins').set('authorization', `Bearer ${token}`).send({ fullName: 'أحمد', password: 'secret-123' })).status).toBe(201);
    expect((await request(app).put('/api/offices/5/admins/9/password').set('authorization', `Bearer ${token}`).send({ password: 'secret-456' })).status).toBe(200);
    expect((await request(app).patch('/api/offices/5/admins/9/deactivate').set('authorization', `Bearer ${token}`)).status).toBe(200);
    const created = await request(app).post('/api/owners').set('authorization', `Bearer ${token}`).send({ username: 'second', displayName: 'الثاني', password: 'strong-password-2' });
    expect(created.status).toBe(201);
    expect(owners.rows).toHaveLength(2);
    const dup = await request(app).post('/api/owners').set('authorization', `Bearer ${token}`).send({ username: 'second', displayName: 'xx', password: 'strong-password-2' });
    expect(dup.status).toBe(409);
    const self = await request(app).patch('/api/owners/1/deactivate').set('authorization', `Bearer ${token}`);
    expect(self.body.error.code).toBe('CANNOT_DEACTIVATE_SELF');
    expect((await request(app).patch('/api/owners/2/deactivate').set('authorization', `Bearer ${token}`)).body.data.isActive).toBe(false);
  });

  it('overview merges wafeer stats with recent audit entries', async () => {
    const { app, token } = await harness();
    const res = await request(app).get('/api/overview').set('authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data.offices.total).toBe(1);
    expect(Array.isArray(res.body.data.recentAudit)).toBe(true);
  });
});

describe('PlatformClient', () => {
  const fetchOk = (data: unknown, status = 200) =>
    vi.fn(async () => new Response(JSON.stringify({ success: status < 400, data, ...(status >= 400 ? { error: data } : {}) }), { status }));

  it('sends the platform key and unwraps data', async () => {
    const f = fetchOk([office]);
    const client = new PlatformClient('http://api/api/v1/', 'k'.repeat(32), f as unknown as typeof fetch);
    expect(await client.listOffices()).toEqual([office]);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://api/api/v1/platform/offices');
    expect((init.headers as Record<string, string>)['x-platform-key']).toBe('k'.repeat(32));
  });

  it('maps wafeer errors to AppError with the same code/status, and unreachable servers to 502', async () => {
    const f = fetchOk({ code: 'OFFICE_NOT_FOUND', message: 'Office not found', details: null }, 404);
    const client = new PlatformClient('http://api/api/v1', 'k'.repeat(32), f as unknown as typeof fetch);
    await expect(client.getOffice('1')).rejects.toMatchObject({ code: 'OFFICE_NOT_FOUND', status: 404 });
    const outdated = new PlatformClient('http://api/api/v1', 'k'.repeat(32), vi.fn(async () => new Response('<html>Cannot GET /api/v1/platform/overview</html>', { status: 404 })) as unknown as typeof fetch);
    await expect(outdated.overview()).rejects.toMatchObject({ code: 'WAFEER_OUTDATED', status: 502 });
    const down = new PlatformClient('http://api/api/v1', 'k'.repeat(32), vi.fn(async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch);
    await expect(down.overview()).rejects.toMatchObject({ code: 'WAFEER_UNREACHABLE', status: 502 });
    expect(await down.reachable()).toBe(false);
  });
});
