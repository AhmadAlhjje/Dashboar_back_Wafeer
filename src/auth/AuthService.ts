import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { AppError } from '../errors.js';
import { safeOwner, type OwnerRepository, type SafeOwner } from './OwnerRepository.js';

export interface OwnerToken {
  ownerId: string;
  username: string;
}

/** مصادقة مالكي اللوحة: bcrypt + JWT. لا تُسجَّل كلمة مرور ولا تُعاد في أي رد. */
export class AuthService {
  constructor(
    private readonly owners: OwnerRepository,
    private readonly secret: string,
    private readonly expiresIn: string,
    private readonly rounds: number,
  ) {}

  hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.rounds);
  }

  async login(username: string, password: string): Promise<{ token: string; owner: SafeOwner }> {
    const owner = await this.owners.findByUsername(username.trim());
    if (!owner?.isActive || !(await bcrypt.compare(password, owner.passwordHash)))
      throw new AppError('INVALID_CREDENTIALS', 'اسم المستخدم أو كلمة المرور غير صحيحة', 401);
    await this.owners.touchLogin(owner.id);
    const payload: OwnerToken = { ownerId: owner.id, username: owner.username };
    const token = jwt.sign(payload, this.secret, { expiresIn: this.expiresIn as jwt.SignOptions['expiresIn'] });
    return { token, owner: safeOwner(owner) };
  }

  verify(token: string): OwnerToken {
    try {
      return jwt.verify(token, this.secret) as OwnerToken;
    } catch {
      throw new AppError('UNAUTHENTICATED', 'Invalid or expired token', 401);
    }
  }

  async changePassword(ownerId: string, currentPassword: string, newPassword: string): Promise<void> {
    const owner = await this.owners.findById(ownerId);
    if (!owner) throw new AppError('UNAUTHENTICATED', 'Owner not found', 401);
    if (!(await bcrypt.compare(currentPassword, owner.passwordHash)))
      throw new AppError('INVALID_PASSWORD', 'كلمة المرور الحالية غير صحيحة', 400);
    if (currentPassword === newPassword) throw new AppError('SAME_PASSWORD', 'كلمة المرور الجديدة مطابقة للحالية', 400);
    await this.owners.setPassword(ownerId, await this.hash(newPassword));
  }

  /** المالك الأول من `.env` إن لم يوجد أي مالك (تثبيت جديد). */
  async ensureFirstOwner(username: string, password: string, log: (msg: string) => void): Promise<void> {
    if ((await this.owners.count()) > 0) return;
    if (!password || password.length < 8) {
      log('no platform owner exists and OWNER_PASSWORD is not set (min 8 chars): set it in .env to create the first owner');
      return;
    }
    await this.owners.create({ username: username.trim(), displayName: username.trim(), passwordHash: await this.hash(password) });
    log(`first platform owner created: ${username}`);
  }
}
