import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { initSchema, pool } from './db.js';
import birthdaysRouter from './routes.js';

const PORT = Number(process.env.PORT ?? 4000);
const HOST = process.env.HOST ?? '127.0.0.1';
const API_KEY = process.env.API_KEY;

if (!API_KEY || API_KEY.length < 16) {
  throw new Error(
    '[auth] Missing or weak API_KEY. Set a strong API_KEY in server/.env before starting the server.',
  );
}

const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN ?? 'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const app = express();
app.disable('x-powered-by');

// Security headers
app.use(helmet());

// Explicit CORS allowlist
app.use(
  cors({
    origin(origin, callback) {
      // Allow non-browser clients (curl/healthchecks) and explicitly allowlisted origins
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['X-Limit', 'X-Offset'],
  }),
);

// Bounded JSON body parser to prevent large-payload DoS
app.use(express.json({ limit: '16kb' }));

// Rate limiting across all /api routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api', apiLimiter);

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization ?? '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token || !safeEqual(token, API_KEY)) {
    console.warn(
      JSON.stringify({
        event: 'auth_failed',
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.originalUrl,
        ip: req.ip,
      }),
    );
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  return next();
}

// Sanitized health check (no database name or raw error messages leaked)
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (error) {
    console.error('[health] database check failed:', error.message);
    res.status(503).json({ status: 'error' });
  }
});

app.use('/api/birthdays', requireAuth, birthdaysRouter);

// Global error handler
app.use((error, _req, res, _next) => {
  if (error?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request payload is too large.' });
  }
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({ error: 'Invalid JSON payload.' });
  }
  console.error('[api] unhandled error:', error);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

initSchema()
  .then(() => {
    app.listen(PORT, HOST, () => {
      console.log(`[api] listening on http://${HOST}:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('[api] failed to start:', error);
    process.exit(1);
  });
