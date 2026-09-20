import type { Db } from './pool.js';

/**
 * جداول المنصّة (بادئة `platform_`) في قاعدة وفير نفسها أو قاعدة مستقلة:
 * - `platform_admins`: مالكو لوحة التحكم (مستقلون تماماً عن إداريي المكاتب).
 * - `platform_audit_log`: كل عملية تغيير من اللوحة (من، ماذا، على أي مكتب، التفاصيل).
 * تُنشأ عند الإقلاع إن لم توجد (آمنة للتكرار).
 */
export async function ensureSchema(db: Db): Promise<void> {
  await db.query(`CREATE TABLE IF NOT EXISTS platform_admins (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    last_login_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  await db.query(`CREATE TABLE IF NOT EXISTS platform_audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    owner_id BIGINT UNSIGNED NULL,
    owner_username VARCHAR(100) NOT NULL,
    action VARCHAR(60) NOT NULL,
    office_id BIGINT UNSIGNED NULL,
    office_code VARCHAR(16) NULL,
    target VARCHAR(150) NULL,
    details JSON NULL,
    ip VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created (created_at),
    INDEX idx_audit_office (office_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
}
