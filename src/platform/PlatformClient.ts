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
  createdAt: string;
  updatedAt: string;
  stats?: OfficeStats | null;
  license?: { status: LicenseStatus; expiresAt: string | null; message: string | null; checkedAt: string };
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
export class PlatformClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl.replace(/\/+$/, '')}/platform${path}`, {
        method,
        headers: { 'content-type': 'application/json', 'x-platform-key': this.apiKey },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new AppError('WAFEER_UNREACHABLE', 'تعذّر الوصول إلى خادم وفير', 502, {
        reason: error instanceof Error ? error.message : String(error),
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
