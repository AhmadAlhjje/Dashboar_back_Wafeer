import type { RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import type { Db } from '../db/pool.js';

export interface Owner {
  id: string;
  username: string;
  displayName: string;
  passwordHash: string;
  isActive: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
}
export type SafeOwner = Omit<Owner, 'passwordHash'>;
export const safeOwner = ({ passwordHash: _h, ...o }: Owner): SafeOwner => o;

interface Row extends RowDataPacket {
  id: string;
  username: string;
  display_name: string;
  password_hash: string;
  is_active: number;
  last_login_at: Date | null;
  created_at: Date;
}
const map = (r: Row): Owner => ({
  id: String(r.id),
  username: r.username,
  displayName: r.display_name,
  passwordHash: r.password_hash,
  isActive: Boolean(r.is_active),
  lastLoginAt: r.last_login_at,
  createdAt: r.created_at,
});

/** مالكو لوحة التحكم. */
export class OwnerRepository {
  constructor(private readonly db: Db) {}

  async count(): Promise<number> {
    const [rows] = await this.db.query<RowDataPacket[]>('SELECT COUNT(*) AS c FROM platform_admins');
    return Number(rows[0]?.c ?? 0);
  }

  async findByUsername(username: string): Promise<Owner | null> {
    const [rows] = await this.db.query<Row[]>('SELECT * FROM platform_admins WHERE username = ? LIMIT 1', [username]);
    return rows[0] ? map(rows[0]) : null;
  }

  async findById(id: string): Promise<Owner | null> {
    const [rows] = await this.db.query<Row[]>('SELECT * FROM platform_admins WHERE id = ? LIMIT 1', [id]);
    return rows[0] ? map(rows[0]) : null;
  }

  async list(): Promise<Owner[]> {
    const [rows] = await this.db.query<Row[]>('SELECT * FROM platform_admins ORDER BY id ASC');
    return rows.map(map);
  }

  async create(input: { username: string; displayName: string; passwordHash: string }): Promise<Owner> {
    const [result] = await this.db.query<ResultSetHeader>(
      'INSERT INTO platform_admins (username, display_name, password_hash) VALUES (?, ?, ?)',
      [input.username, input.displayName, input.passwordHash],
    );
    return (await this.findById(String(result.insertId)))!;
  }

  async setActive(id: string, isActive: boolean): Promise<Owner | null> {
    await this.db.query('UPDATE platform_admins SET is_active = ? WHERE id = ?', [isActive ? 1 : 0, id]);
    return this.findById(id);
  }

  async setPassword(id: string, passwordHash: string): Promise<void> {
    await this.db.query('UPDATE platform_admins SET password_hash = ? WHERE id = ?', [passwordHash, id]);
  }

  async touchLogin(id: string): Promise<void> {
    await this.db.query('UPDATE platform_admins SET last_login_at = NOW() WHERE id = ?', [id]);
  }
}
