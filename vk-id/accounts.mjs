import { randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const deriveKey = promisify(scrypt);
const parameters = { N: 131072, r: 8, p: 1, maxmem: 160 * 1024 * 1024 };
const dummySalt = randomBytes(16).toString('hex');

export function defaultAccountFile() {
  const base = process.platform === 'win32'
    ? process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')
    : process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share');
  return join(base, 'topiary-sad', 'accounts.sqlite');
}

export function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  if (email.length > 254) return null;
  const [local, domain, extra] = email.split('@');
  if (extra !== undefined || !local || local.length > 64 || !domain ||
      !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local) ||
      local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
  const labels = domain.split('.');
  if (labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  return email;
}

export function validPassword(value) {
  return typeof value === 'string' && Array.from(value).length >= 15 &&
    Array.from(value).length <= 128 && Buffer.byteLength(value, 'utf8') <= 512;
}

export function openAccounts(filename = ':memory:') {
  if (filename !== ':memory:') {
    filename = resolve(filename);
    const sourceDir = fileURLToPath(new URL('.', import.meta.url));
    const withinSource = relative(sourceDir, filename);
    if (!withinSource.startsWith('..') && !isAbsolute(withinSource)) {
      throw new Error('Базу пользователей нужно хранить вне папки исходников сайта.');
    }
    mkdirSync(dirname(filename), { recursive: true, mode: 0o700 });
  }
  const db = new DatabaseSync(filename);
  if (filename !== ':memory:' && process.platform !== 'win32') chmodSync(filename, 0o600);
  db.exec(`
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    ) STRICT;
  `);
  const find = db.prepare('SELECT id, email, salt, password_hash FROM accounts WHERE email = ?');
  const insert = db.prepare('INSERT INTO accounts (id, email, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(email) DO NOTHING');
  let activeHashes = 0;

  async function hash(password, salt) {
    if (activeHashes >= 2) {
      const error = new Error('Сервер занят. Попробуйте чуть позже.');
      error.status = 503;
      throw error;
    }
    activeHashes++;
    try { return await deriveKey(password, salt, 64, parameters); }
    finally { activeHashes--; }
  }

  return {
    async register(email, password) {
      const salt = randomBytes(16).toString('hex');
      const key = await hash(password, salt);
      const id = randomUUID();
      const result = insert.run(id, email, salt, key.toString('hex'), Date.now());
      return result.changes === 1 ? { id, email } : null;
    },
    async authenticate(email, password) {
      const account = find.get(email);
      // Missing addresses cost the same password derivation as existing accounts.
      const key = await hash(password, account?.salt ?? dummySalt);
      const expected = account ? Buffer.from(account.password_hash, 'hex') : Buffer.alloc(64);
      const matches = expected.length === key.length && timingSafeEqual(key, expected);
      return account && matches ? { id: account.id, email: account.email } : null;
    },
    close() { db.close(); },
  };
}
