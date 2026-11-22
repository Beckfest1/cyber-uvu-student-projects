import 'dotenv/config';
import fs from 'node:fs';
import pg from 'pg';

// `birthdate` is a DATE column. node-postgres parses DATE into a JS Date in the
// server's local timezone, which can shift the day by one. Keep it as a string.
pg.types.setTypeParser(1082, (value) => value);

const {
  DATABASE_URL,
  PGHOST = '127.0.0.1',
  PGPORT = '5544',
  PGUSER,
  PGPASSWORD,
  PGDATABASE,
  PGSSL,
  PGSSLROOTCERT,
} = process.env;

if (!DATABASE_URL && (!PGUSER || !PGPASSWORD || !PGDATABASE)) {
  throw new Error(
    '[db] Missing required database credentials. Set DATABASE_URL or PGUSER, PGPASSWORD, and PGDATABASE in server/.env.',
  );
}

const ssl =
  PGSSL === 'true'
    ? {
        rejectUnauthorized: true,
        ...(PGSSLROOTCERT ? { ca: fs.readFileSync(PGSSLROOTCERT, 'utf8') } : {}),
      }
    : undefined;

export const pool = DATABASE_URL
  ? new pg.Pool({ connectionString: DATABASE_URL, ssl })
  : new pg.Pool({
      host: PGHOST,
      port: Number(PGPORT),
      user: PGUSER,
      password: PGPASSWORD,
      database: PGDATABASE,
      ssl,
    });

pool.on('error', (error) => {
  console.error('[db] unexpected pool error:', error.message);
});

export async function initSchema() {
  // Runtime connects as the least-privilege bm_app role (DML only).
  // Schema creation and migrations are handled separately by bm_admin.
  await pool.query('SELECT 1 FROM birthdays LIMIT 0');
}

export function mapRow(row) {
  return {
    id: row.id,
    firstName: row.first_name,
    lastName: row.last_name,
    birthdate: row.birthdate,
    phone: row.phone,
    email: row.email,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
