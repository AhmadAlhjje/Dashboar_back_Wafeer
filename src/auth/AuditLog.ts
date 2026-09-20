import type { RowDataPacket } from 'mysql2/promise';
import type { Db } from '../db/pool.js';

export interface AuditEntry {
  ownerId: string | null;
  ownerUsername: string;
  action: string;
  officeId?: string | null;
  officeCode?: string | null;
  target?: string | null;
  details?: unknown;
  ip?: string | null;
}

export interface AuditRecord extends AuditEntry {
  id: string;
  createdAt: Date;
}

interface Row extends RowDataPacket {
  id: string;
  owner_id: string | null;
  owner_username: string;
  action: string;
  office_id: string | null;
  office_code: string | null;
  target: string | null;
  details: unknown;
  ip: string | null;
  created_at: Date;
}

const safeJson = (s: string): unknown => {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
};

/** سجل عمليات اللوحة: كل تغيير يُدوَّن مع صاحبه وهدفه — للمراجعة والمساءلة. */
export class AuditLog {
  constructor(private readonly db: Db) {}

  async record(entry: AuditEntry): Promise<void> {
    await this.db.query(
      'INSERT INTO platform_audit_log (owner_id, owner_username, action, office_id, office_code, target, details, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [
        entry.ownerId,
        entry.ownerUsername,
        entry.action,
        entry.officeId ?? null,
        entry.officeCode ?? null,
        entry.target ?? null,
        entry.details === undefined ? null : JSON.stringify(entry.details),
        entry.ip ?? null,
      ],
    );
  }

  async recent(limit = 50, officeId?: string): Promise<AuditRecord[]> {
    const [rows] = officeId
      ? await this.db.query<Row[]>('SELECT * FROM platform_audit_log WHERE office_id = ? ORDER BY id DESC LIMIT ?', [officeId, limit])
      : await this.db.query<Row[]>('SELECT * FROM platform_audit_log ORDER BY id DESC LIMIT ?', [limit]);
    return rows.map((r) => ({
      id: String(r.id),
      ownerId: r.owner_id === null ? null : String(r.owner_id),
      ownerUsername: r.owner_username,
      action: r.action,
      officeId: r.office_id === null ? null : String(r.office_id),
      officeCode: r.office_code,
      target: r.target,
      details: typeof r.details === 'string' ? safeJson(r.details) : r.details,
      ip: r.ip,
      createdAt: r.created_at,
    }));
  }
}
