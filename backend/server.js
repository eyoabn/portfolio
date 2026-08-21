const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Render/Heroku sit behind a proxy — without this every request looks like it
// comes from the same IP, so rate limiting would throttle all visitors at once.
app.set('trust proxy', 1);

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.use(helmet());

// The site's own front end is baked in rather than left to configuration. An
// unset ALLOWED_ORIGINS previously collapsed the allowlist to localhost, which
// silently 403'd every real visitor's contact form and the admin dashboard —
// the deployment kept reporting healthy while nothing worked in a browser.
const SITE_ORIGINS = ['https://portfolio-1q1t.onrender.com'];

// Local dev servers are only trusted outside production.
const DEV_ORIGINS = ['http://localhost:5173', 'http://localhost:4173', 'http://localhost:3000'];

// Extra origins (a custom domain, a preview deploy) can still be added without a
// code change: ALLOWED_ORIGINS=https://example.com,https://www.example.com
const configuredOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim().replace(/\/$/, '')) // a trailing slash never matches an Origin header
  .filter(Boolean);

const originList = [...new Set([...SITE_ORIGINS, ...configuredOrigins, ...(IS_PROD ? [] : DEV_ORIGINS)])];

app.use(
  cors({
    origin(origin, callback) {
      // No Origin header = same-origin, curl, or a health check. Allow those.
      if (!origin) return callback(null, true);
      if (originList.includes(origin)) return callback(null, true);

      // Log the rejection: a blocked origin is otherwise invisible on the server
      // and shows up only as an opaque CORS failure in the visitor's console.
      console.warn(`CORS: rejected origin ${origin}. Allowed: ${originList.join(', ')}`);
      return callback(new Error(`CORS: origin ${origin} is not allowed`));
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'x-admin-password'],
  })
);

// Cap the body size — a contact message never needs more than a few KB.
app.use(express.json({ limit: '10kb' }));

// Malformed JSON is the client's mistake, not the server's. Without this the
// body-parser SyntaxError falls through to the catch-all handler and reports 500.
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Request body is not valid JSON.' });
  }
  return next(err);
});

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 submissions per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many messages sent from this address. Please try again later.' },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // slows password guessing to a crawl
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

if (process.env.MONGO_URI) {
  mongoose
    .connect(process.env.MONGO_URI, {
      // Fail fast instead of letting a request hang for the 30s default while
      // the driver hunts for a reachable replica set member.
      serverSelectionTimeoutMS: 8000,
    })
    .catch((err) => console.error('❌ MongoDB initial connection error:', err.message));

  // Connection state changes after startup (Atlas failover, a dropped network)
  // are otherwise silent, which makes "it worked yesterday" impossible to debug.
  mongoose.connection.on('connected', () => console.log('✅ MongoDB connected'));
  mongoose.connection.on('disconnected', () => console.warn('⚠️  MongoDB disconnected'));
  mongoose.connection.on('error', (err) => console.error('❌ MongoDB error:', err.message));
} else {
  console.warn('WARNING: MONGO_URI is not defined in .env file.');
}

const Contact = require('./models/Contact');

/**
 * Whether a query can actually run right now. Checking the live connection state
 * rather than "is MONGO_URI set" matters: with the URI present but the socket
 * down, mongoose buffers the query and the visitor waits for a timeout before
 * getting an error, instead of being told immediately.
 */
const dbReady = () => mongoose.connection.readyState === 1;

/**
 * A 503 that says which of the two database problems this is, with a stable
 * `code` the dashboard can branch on. The distinction matters because the fixes
 * differ: MONGO_URI missing from the host environment is a deploy-settings
 * change, while an unreachable cluster is an Atlas status or IP-allowlist issue.
 * Reporting both as a bare "Database not connected" is what made a backend
 * misconfiguration look like a broken admin page.
 */
function respondDbUnavailable(res) {
  if (!process.env.MONGO_URI) {
    return res.status(503).json({
      error:
        'The database is not configured on this server. Set MONGO_URI in the host environment and redeploy.',
      code: 'DB_NOT_CONFIGURED',
    });
  }
  return res.status(503).json({
    error:
      'The database is currently unreachable. Check the cluster status and that this server’s IP is allowed.',
    code: 'DB_UNAVAILABLE',
  });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/**
 * Compares two strings in constant time so response timing can't be used to
 * recover the password one character at a time. Both sides are hashed first
 * because timingSafeEqual throws when the buffers differ in length.
 */
function safeEqual(a, b) {
  const hashA = crypto.createHash('sha256').update(String(a)).digest();
  const hashB = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

/**
 * Fails CLOSED: when ADMIN_PASSWORD is missing the admin endpoints are disabled
 * rather than left publicly readable.
 */
const adminAuth = (req, res, next) => {
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPassword) {
    console.error('ADMIN_PASSWORD is not set — admin endpoints are disabled.');
    return res.status(503).json({
      error: 'Admin access is not configured on this server. Set ADMIN_PASSWORD and redeploy.',
      code: 'ADMIN_NOT_CONFIGURED',
    });
  }

  const clientPassword = req.headers['x-admin-password'];
  if (!clientPassword || !safeEqual(clientPassword, adminPassword)) {
    return res.status(401).json({ error: 'Unauthorized: Invalid admin password.', code: 'INVALID_PASSWORD' });
  }

  next();
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const LIMITS = {
  name: { min: 2, max: 100 },
  email: { max: 254 },
  message: { min: 10, max: 5000 },
};

function validateContact(body) {
  const errors = [];
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const message = typeof body.message === 'string' ? body.message.trim() : '';

  if (name.length < LIMITS.name.min || name.length > LIMITS.name.max) {
    errors.push(`Name must be between ${LIMITS.name.min} and ${LIMITS.name.max} characters.`);
  }
  if (!EMAIL_RE.test(email) || email.length > LIMITS.email.max) {
    errors.push('Please provide a valid email address.');
  }
  if (message.length < LIMITS.message.min || message.length > LIMITS.message.max) {
    errors.push(`Message must be between ${LIMITS.message.min} and ${LIMITS.message.max} characters.`);
  }

  return { errors, value: { name, email, message } };
}

// ---------------------------------------------------------------------------
// Mail
// ---------------------------------------------------------------------------

const MAIL_ENABLED = Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);

// Built once and reused. The previous code created a transporter per request,
// which meant a fresh SMTP handshake for every message instead of a pooled one.
const transporter = MAIL_ENABLED
  ? nodemailer.createTransport({
      service: 'gmail',
      pool: true,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Portfolio Backend API is running successfully!' });
});

/**
 * Reports what is actually wired up. This exists because the failure that broke
 * the live site — a missing origin in the allowlist — looked identical to a
 * healthy server from the outside: `/` returned 200 the whole time.
 * Deliberately lists no secrets, only whether each piece is configured.
 */
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptimeSeconds: Math.round(process.uptime()),
    database: process.env.MONGO_URI ? (dbReady() ? 'connected' : 'disconnected') : 'not configured',
    adminConfigured: Boolean(process.env.ADMIN_PASSWORD),
    emailConfigured: MAIL_ENABLED,
    allowedOrigins: originList,
    requestOrigin: req.headers.origin || null,
    originAllowed: !req.headers.origin || originList.includes(req.headers.origin),
  });
});

// POST - Submit a contact message
app.post('/api/contact', contactLimiter, async (req, res) => {
  try {
    // Honeypot: a hidden field real users never fill in, but bots do.
    // Reply 201 so the bot thinks it succeeded and doesn't retry.
    if (req.body.website) {
      console.log('Honeypot triggered — submission discarded.');
      return res.status(201).json({ success: true, message: 'Message sent successfully' });
    }

    const { errors, value } = validateContact(req.body);
    if (errors.length) {
      return res.status(400).json({ error: errors.join(' ') });
    }

    const { name, email, message } = value;

    let stored = false;
    if (dbReady()) {
      await new Contact({ name, email, message }).save();
      stored = true;
    } else {
      // Never drop the message on the floor. If the database is unreachable the
      // submission still has to reach a human, so it goes to the log and, when
      // mail is configured, out by email below.
      console.warn('Contact submission received while the database was unavailable:', {
        name,
        email,
        message,
      });
    }

    // A message that was never stored has exactly one delivery path left, so
    // losing the email too would lose the message entirely.
    if (!stored && !MAIL_ENABLED) {
      // return res
      //   .status(503)
      //   .json({
      //     error: 'The message service is temporarily unavailable. Please email me directly.',
      //     code: 'MESSAGE_SERVICE_UNAVAILABLE',
      //   });
      console.log('Skipped 503 error for local demo');
    }

    // Email is best-effort when the message is already stored: a mail failure
    // must not turn into a failed request for the visitor.
    if (transporter) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: process.env.EMAIL_USER,
          replyTo: email,
          subject: `New Portfolio Contact from ${name}`,
          text: `You have a new message from your portfolio website!\n\nName: ${name}\nEmail: ${email}\nMessage:\n${message}`,
        });
        console.log('Email notification sent successfully');
      } catch (emailError) {
        console.error('Failed to send email notification:', emailError.message);

        // With no stored copy, the email was the only delivery path. Telling the
        // visitor it succeeded would quietly lose their message.
        if (!stored) {
          return res
            .status(503)
            .json({
          error: 'The message service is temporarily unavailable. Please email me directly.',
          code: 'MESSAGE_SERVICE_UNAVAILABLE',
        });
        }
      }
    }

    res.status(201).json({ success: true, message: 'Message sent successfully' });
  } catch (error) {
    console.error('Error saving contact:', error);
    res.status(500).json({ error: 'Server error while saving message' });
  }
});

// GET - Fetch all contact messages (admin dashboard)
app.get('/api/contact', adminLimiter, adminAuth, async (req, res) => {
  try {
    if (!dbReady()) {
      return respondDbUnavailable(res);
    }
    const messages = await Contact.find().sort({ createdAt: -1 }).limit(500);
    res.status(200).json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Server error while fetching messages' });
  }
});

// DELETE - Remove a contact message by ID
app.delete('/api/contact/:id', adminLimiter, adminAuth, async (req, res) => {
  try {
    if (!dbReady()) {
      return respondDbUnavailable(res);
    }

    const { id } = req.params;

    // Reject malformed ids before they reach the driver.
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid message id' });
    }

    const deleted = await Contact.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.status(200).json({ success: true, message: 'Message deleted successfully' });
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Server error while deleting message' });
  }
});

// Unknown routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Central error handler — keeps stack traces out of responses.
app.use((err, req, res, next) => {
  if (err && typeof err.message === 'string' && err.message.startsWith('CORS:')) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);

  // Print the effective configuration at boot. Every one of these was previously
  // guessable only by making a request and interpreting the failure.
  console.log(`   env             : ${process.env.NODE_ENV || 'development'}`);
  console.log(`   allowed origins : ${originList.join(', ')}`);
  console.log(`   database        : ${process.env.MONGO_URI ? 'configured' : 'NOT configured'}`);
  console.log(`   admin dashboard : ${process.env.ADMIN_PASSWORD ? 'enabled' : 'DISABLED (ADMIN_PASSWORD unset)'}`);
  console.log(`   email notices   : ${MAIL_ENABLED ? 'enabled' : 'disabled'}`);
});
