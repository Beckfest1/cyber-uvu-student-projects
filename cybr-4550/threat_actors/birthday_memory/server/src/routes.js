import { Router } from 'express';
import { pool, mapRow } from './db.js';
import { validateBirthday } from './validate.js';
import { decorate } from './dates.js';

const router = Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 200;

const SELECT_COLUMNS = `
  id, first_name, last_name, birthdate, phone, email, created_at, updated_at
`;

/** Wraps an async handler so rejected promises reach the error middleware. */
const wrap = (handler) => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

/** Parses bounded pagination parameters to prevent unbounded bulk dumps. */
function parsePagination(query) {
  const rawLimit = Number(query.limit);
  const rawOffset = Number(query.offset);
  const limit =
    Number.isInteger(rawLimit) && rawLimit > 0
      ? Math.min(rawLimit, MAX_LIMIT)
      : DEFAULT_LIMIT;
  const offset =
    Number.isInteger(rawOffset) && rawOffset >= 0 ? rawOffset : 0;
  return { limit, offset };
}

/** Writes structured, PII-free audit logs for state-changing actions. */
function auditLog(req, action, recordId) {
  console.info(
    JSON.stringify({
      event: 'audit',
      timestamp: new Date().toISOString(),
      action,
      recordId,
      method: req.method,
      path: req.originalUrl,
      ip: req.ip,
    }),
  );
}

/** GET /api/birthdays?q=&month=&limit=&offset= — list, optionally filtered. */
router.get(
  '/',
  wrap(async (req, res) => {
    const q = String(req.query.q ?? '').trim().slice(0, 100);
    const month = Number(req.query.month);
    const { limit, offset } = parsePagination(req.query);

    const conditions = [];
    const params = [];

    if (q) {
      params.push(`%${q}%`);
      const p = `$${params.length}`;
      conditions.push(`(
        first_name ILIKE ${p}
        OR last_name ILIKE ${p}
        OR (first_name || ' ' || last_name) ILIKE ${p}
        OR coalesce(email, '') ILIKE ${p}
        OR coalesce(phone, '') ILIKE ${p}
      )`);
    }

    if (Number.isInteger(month) && month >= 1 && month <= 12) {
      params.push(month);
      conditions.push(`EXTRACT(MONTH FROM birthdate) = $${params.length}`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    params.push(limit, offset);
    const limitParam = `$${params.length - 1}`;
    const offsetParam = `$${params.length}`;

    const { rows } = await pool.query(
      `SELECT ${SELECT_COLUMNS}
         FROM birthdays
         ${where}
        ORDER BY EXTRACT(MONTH FROM birthdate),
                 EXTRACT(DAY FROM birthdate),
                 lower(first_name)
        LIMIT ${limitParam} OFFSET ${offsetParam}`,
      params,
    );

    res.set('X-Limit', String(limit));
    res.set('X-Offset', String(offset));
    res.json(rows.map((row) => decorate(mapRow(row))));
  }),
);

/** GET /api/birthdays/upcoming?days=30&limit=100 — soonest celebrations first. */
router.get(
  '/upcoming',
  wrap(async (req, res) => {
    const days = Number(req.query.days);
    const window = Number.isFinite(days) && days > 0 ? Math.min(days, 366) : 30;
    const { limit } = parsePagination(req.query);

    const { rows } = await pool.query(
      `SELECT ${SELECT_COLUMNS} FROM birthdays LIMIT $1`,
      [MAX_LIMIT],
    );

    const upcoming = rows
      .map((row) => decorate(mapRow(row)))
      .filter((entry) => entry.daysUntil <= window)
      .sort((a, b) => a.daysUntil - b.daysUntil || a.firstName.localeCompare(b.firstName))
      .slice(0, limit);

    res.set('X-Limit', String(limit));
    res.json(upcoming);
  }),
);

/** POST /api/birthdays — create a record. */
router.post(
  '/',
  wrap(async (req, res) => {
    const { errors, value } = validateBirthday(req.body);
    if (errors) return res.status(422).json({ errors });

    const { rows } = await pool.query(
      `INSERT INTO birthdays (first_name, last_name, birthdate, phone, email)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING ${SELECT_COLUMNS}`,
      [value.firstName, value.lastName, value.birthdate, value.phone, value.email],
    );

    const created = decorate(mapRow(rows[0]));
    auditLog(req, 'CREATE_BIRTHDAY', created.id);
    res.status(201).json(created);
  }),
);

/** PUT /api/birthdays/:id — replace a record. */
router.put(
  '/:id',
  wrap(async (req, res) => {
    if (!UUID_RE.test(req.params.id)) {
      return res.status(404).json({ error: 'Birthday not found.' });
    }

    const { errors, value } = validateBirthday(req.body);
    if (errors) return res.status(422).json({ errors });

    const { rows } = await pool.query(
      `UPDATE birthdays
          SET first_name = $1,
              last_name  = $2,
              birthdate  = $3,
              phone      = $4,
              email      = $5,
              updated_at = now()
        WHERE id = $6
      RETURNING ${SELECT_COLUMNS}`,
      [
        value.firstName,
        value.lastName,
        value.birthdate,
        value.phone,
        value.email,
        req.params.id,
      ],
    );

    if (rows.length === 0) return res.status(404).json({ error: 'Birthday not found.' });
    const updated = decorate(mapRow(rows[0]));
    auditLog(req, 'UPDATE_BIRTHDAY', updated.id);
    res.json(updated);
  }),
);

/** DELETE /api/birthdays/:id */
router.delete(
  '/:id',
  wrap(async (req, res) => {
    if (!UUID_RE.test(req.params.id)) {
      return res.status(404).json({ error: 'Birthday not found.' });
    }

    const { rowCount } = await pool.query('DELETE FROM birthdays WHERE id = $1', [
      req.params.id,
    ]);

    if (rowCount === 0) return res.status(404).json({ error: 'Birthday not found.' });
    auditLog(req, 'DELETE_BIRTHDAY', req.params.id);
    res.status(204).end();
  }),
);

export default router;
