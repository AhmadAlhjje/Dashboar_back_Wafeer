import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  CORS_ORIGIN: z.string().min(1).default('http://localhost:5173'),
  DB_HOST: z.string().min(1),
  DB_PORT: z.coerce.number().int().positive().default(3306),
  DB_NAME: z.string().min(1),
  DB_USER: z.string().min(1),
  DB_PASSWORD: z.string().default(''),
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('12h'),
  BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(15).default(12),
  OWNER_USERNAME: z.string().default('owner'),
  OWNER_PASSWORD: z.string().default(''),
  WAFEER_API_URL: z.string().url(),
  PLATFORM_API_KEY: z.string().min(32),
  LOG_LEVEL: z.string().default('info'),
});

export type Env = z.infer<typeof schema>;
export const env: Env = schema.parse(process.env);
