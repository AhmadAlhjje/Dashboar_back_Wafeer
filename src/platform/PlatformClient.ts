import { AppError } from '../errors.js';

export type LicenseStatus = 'ACTIVE' | 'SUSPENDED' | 'EXPIRED';

export interface OfficeStats {
  officeId: string;
  admins: number;
  activeAdmins: number;
  clients: number;
  movements: number;
  movementsToday: number;
  lastMovementAt: string | null;
}
export interface Office {
  id: string;
  code: string;
  name: string;
  status: LicenseStatus;
  expiresAt: string | null;
  message: string | null;
  phone: string | null;
  address: string | null;
  notes: string | null;
  /** حد الحركات (إضافات فقط؛ null = بلا حد) والعدّاد. */
  movementLimit: number | null;
  movementsUsed: number;
  /** لوغو المكتب من اللوحة: مسار تحت uploads على خادم وفير أو null. */
  logoPath: string | null;
  logoUpdatedAt: string | null;
  createdAt: string;
  updatedAt: string;
  stats?: OfficeStats | null;
  license?: { status: LicenseStatus; expiresAt: string | null; message: string | null; checkedAt: string };
}
export interface OfficeDevice {
  id: string;
  officeId: string;
  label: string | null;
  enrolledBy: string | null;
  lastSeenAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}
export interface OfficeAdmin {
  id: string;
  fullName: string;
  phone: string | null;
  email: string | null;
  role: string;
  permissions: string[] | null;
  isActive: boolean;
}
export interface PlatformOverview {
  offices: { total: number; active: number; suspended: number; expired: number };
  movements: { total: number; today: number };
  clients: number;
  admins: number;
}

type Fetch = typeof fetch;

/**
 * عميل واجهة وفير للمنصّة (`/platform/*` بمفتاح `X-Platform-Key`): مصدر الحقيقة الوحيد للمكاتب
 * وإداريّيها والإحصاءات؛ اللوحة لا تلمس جداول وفير مباشرة. الأخطاء تُعاد بشكلها الموحّد.
 */
/** تلميح عربي بحسب كود خطأ الشبكة — يوجّه المشغّل إلى الإعداد الخاطئ مباشرة. */
const hintFor = (code: string | null): string => {
  switch (code) {
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return 'اسم المضيف في WAFEER_API_URL لا يُحلّ: تأكد أن حاوية وفير تعمل وأن الحاويتين على الشبكة wafeer-net نفسها';
    case 'ECONNREFUSED':
      return 'لا شيء يستمع على هذا العنوان/المنفذ: شغّل خادم وفير أو صحّح المنفذ في WAFEER_API_URL (127.0.0.1 داخل الحاوية يعني الحاوية نفسها)';
    case 'ETIMEDOUT':
    case 'ECONNRESET':
    case 'EHOSTUNREACH':
      return 'الاتصال يُحجب أو ينقطع: راجع الجدار الناري والشبكة بين الحاويتين';
    default:
      return 'تحقق من WAFEER_API_URL وأن خادم وفير يعمل (docker ps / docker compose logs)';
  }
};

export class PlatformClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    // FormData (رفع ملف) يُرسل كما هو ليضع fetch حدود multipart بنفسه؛ غير ذلك JSON.
    const multipart = typeof FormData !== 'undefined' && body instanceof FormData;
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl.replace(/\/+$/, '')}/platform${path}`, {
        method,
        headers: multipart ? { 'x-platform-key': this.apiKey } : { 'content-type': 'application/json', 'x-platform-key': this.apiKey },
        body: body === undefined ? undefined : multipart ? body : JSON.stringify(body),
      });
    } catch (error) {
      // «fetch failed» وحدها لا تفيد: نُظهر السبب الحقيقي (ECONNREFUSED/ENOTFOUND…) والهدف لتشخيص الشبكة.
      let cause = error instanceof Error && error.cause instanceof Error ? error.cause : null;
      // Node يجرّب عدة عناوين (::1 ثم 127.0.0.1) ويجمعها في AggregateError — الكود في أول خطأ داخلي.
      if (cause instanceof AggregateError && cause.errors[0] instanceof Error) cause = cause.errors[0];
      const code = cause && 'code' in cause && typeof cause.code === 'string' ? cause.code : null;
      throw new AppError('WAFEER_UNREACHABLE', 'تعذّر الوصول إلى خادم وفير', 502, {
        reason: code ? `${code}: ${cause?.message ?? ''}`.trim() : error instanceof Error ? error.message : String(error),
        target: this.baseUrl,
        hint: hintFor(code),
      });
    }
    const text = await response.text();
    let json: { success?: boolean; data?: T; error?: { code?: string; message?: string; details?: unknown } } = {};
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      // 404 غير JSON = خادم وفير يعمل بنسخة قديمة لا تعرف مسارات المنصّة (لم يُعد تشغيله بعد التحديث/الهجرة).
      if (response.status === 404)
        throw new AppError('WAFEER_OUTDATED', 'خادم وفير يعمل بنسخة قديمة بلا مسارات المنصّة — شغّل هجرة قاعدة البيانات وأعد تشغيل الباك اند', 502, {
          status: response.status,
        });
      throw new AppError('WAFEER_BAD_RESPONSE', 'ردّ غير مفهوم من خادم وفير', 502, { status: response.status });
    }
    if (!response.ok || json.success === false) {
      const code = json.error?.code ?? `WAFEER_HTTP_${response.status}`;
      throw new AppError(code, json.error?.message ?? 'خطأ من خادم وفير', response.status || 502, json.error?.details ?? null);
    }
    return json.data as T;
  }

  overview(): Promise<PlatformOverview> {
    return this.call('GET', '/overview');
  }
  listOffices(): Promise<Office[]> {
    return this.call('GET', '/offices');
  }
  getOffice(id: string): Promise<Office> {
    return this.call('GET', `/offices/${encodeURIComponent(id)}`);
  }
  createOffice(input: unknown): Promise<Office> {
    return this.call('POST', '/offices', input);
  }
  updateOffice(id: string, patch: unknown): Promise<Office> {
    return this.call('PATCH', `/offices/${encodeURIComponent(id)}`, patch);
  }
  setLicense(id: string, license: unknown): Promise<Office> {
    return this.call('PUT', `/offices/${encodeURIComponent(id)}/license`, license);
  }
  regenerateCode(id: string): Promise<Office> {
    return this.call('POST', `/offices/${encodeURIComponent(id)}/code`);
  }
  /** لوغو المكتب (قرار المستخدم 2026-09-21): يُبدَّل من اللوحة متى شاء المالك. */
  setOfficeLogo(id: string, file: { buffer: Buffer; mimetype: string; originalname: string }): Promise<Office> {
    const form = new FormData();
    form.append('logo', new Blob([new Uint8Array(file.buffer)], { type: file.mimetype }), file.originalname || 'logo');
    return this.call('PUT', `/offices/${encodeURIComponent(id)}/logo`, form);
  }
  removeOfficeLogo(id: string): Promise<Office> {
    return this.call('DELETE', `/offices/${encodeURIComponent(id)}/logo`);
  }
  /** يجلب ملف اللوغو من خادم وفير (خارج /api/v1) لعرضه في اللوحة دون كشف عنوان وفير للمتصفح. */
  async fetchOfficeLogo(logoPath: string): Promise<{ body: ArrayBuffer; contentType: string } | null> {
    const origin = new URL(this.baseUrl).origin;
    const response = await this.fetchImpl(`${origin}/${logoPath.replace(/^\/+/, '')}`);
    if (!response.ok) return null;
    return { body: await response.arrayBuffer(), contentType: response.headers.get('content-type') ?? 'application/octet-stream' };
  }
  /** تصفير عدّاد الحركات المضافة (من اللوحة فقط). */
  resetMovements(officeId: string): Promise<Office> {
    return this.call('POST', `/offices/${encodeURIComponent(officeId)}/movements/reset`);
  }
  listDevices(officeId: string): Promise<OfficeDevice[]> {
    return this.call('GET', `/offices/${encodeURIComponent(officeId)}/devices`);
  }
  revokeDevice(officeId: string, deviceId: string): Promise<OfficeDevice> {
    return this.call('DELETE', `/offices/${encodeURIComponent(officeId)}/devices/${encodeURIComponent(deviceId)}`);
  }
  listAdmins(officeId: string): Promise<OfficeAdmin[]> {
    return this.call('GET', `/offices/${encodeURIComponent(officeId)}/admins`);
  }
  createAdmin(officeId: string, input: unknown): Promise<OfficeAdmin> {
    return this.call('POST', `/offices/${encodeURIComponent(officeId)}/admins`, input);
  }
  resetAdminPassword(officeId: string, adminId: string, password: string): Promise<OfficeAdmin> {
    return this.call('PUT', `/offices/${encodeURIComponent(officeId)}/admins/${encodeURIComponent(adminId)}/password`, { password });
  }
  setAdminActive(officeId: string, adminId: string, active: boolean): Promise<OfficeAdmin> {
    return this.call('PATCH', `/offices/${encodeURIComponent(officeId)}/admins/${encodeURIComponent(adminId)}/${active ? 'activate' : 'deactivate'}`);
  }

  /** فحص الوصول (لصفحة النظرة العامة): true إن أجاب الخادم. */
  async reachable(): Promise<boolean> {
    try {
      await this.overview();
      return true;
    } catch {
      return false;
    }
  }
}
