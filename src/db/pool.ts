import mysql, { type Pool, type PoolOptions } from 'mysql2/promise';

export type Db = Pool;

export function createPool(options: PoolOptions): Db {
  return mysql.createPool({
    waitForConnections: true,
    connectionLimit: 5,
    charset: 'utf8mb4',
    supportBigNumbers: true,
    bigNumberStrings: true,
    ...options,
  });
}
