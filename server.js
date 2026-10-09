const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const dns = require("dns").promises;

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

// ============================================================
// LittleBigAdventure Server
// Firebase watchdog + retry + timeout architecture
//
// Browser
//   |
//   v
// LBA Server
//   |
//   +--> Firebase reachable -> normal operation
//   |
//   +--> Firebase offline -> retry -> watchdog recovery
//
// The Render server itself stays online when Firebase is down.
// ============================================================

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

// ============================================================
// CONFIG
// ============================================================

const PORT = Number(process.env.PORT || 10000);

const FIREBASE_RETRIES = Math.max(
  1,
  Number(process.env.FIREBASE_RETRIES || 3)
);

const FIREBASE_TIMEOUT_MS = Math.max(
  1000,
  Number(process.env.FIREBASE_TIMEOUT_MS || 8000)
);

const FIREBASE_RETRY_BASE_MS = Math.max(
  100,
  Number(process.env.FIREBASE_RETRY_BASE_MS || 750)
);

const FIREBASE_WATCHDOG_MS = Math.max(
  5000,
  Number(process.env.FIREBASE_WATCHDOG_MS || 30000)
);

const SESSION_COOKIE = "lba_session";
const SERVICE_NAME = "LittleBigAdventure";

// Public service hostname used for the server information page.
// Render may use multiple/changing public IP addresses, so this page
// resolves the hostname instead of pretending the Node process has a
// permanent public IP.
const PUBLIC_HOSTNAME = String(
  process.env.PUBLIC_HOSTNAME || "littlebigadventure.onrender.com"
).trim();

// ============================================================
// SERVER IP INFORMATION PAGE
// ============================================================

app.get("/server-ip", async (req, res) => {
  try {
    const records = await dns.lookup(PUBLIC_HOSTNAME, { all: true });
    const addresses = [...new Set(records.map(record => record.address))];

    res
      .type("html")
      .send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LittleBigAdventure — Server IP</title>
<style>
body{margin:0;font-family:system-ui,sans-serif;background:#111;color:#fff;display:grid;place-items:center;min-height:100vh}
.card{width:min(720px,90%);padding:28px;border-radius:20px;background:#222;box-shadow:0 20px 60px #0008}
h1{margin-top:0}.ip{font:700 1.5rem ui-monospace,monospace;background:#111;padding:14px;border-radius:12px;margin:10px 0}
small{color:#aaa}.ok{color:#7cff9b}
</style>
</head>
<body>
<main class="card">
<h1>LittleBigAdventure Server IP</h1>
<p class="ok">● Server reachable</p>
<p><strong>SERVER IP ADDRESS</strong></p>
${addresses.map(address => `<div class="ip">${address}</div>`).join("")}
<p><strong>Server hostname</strong></p>
<div class="ip">${PUBLIC_HOSTNAME}</div>
<small>These are the public IP addresses that the Render hostname currently resolves to. Render may use shared or changing ingress addresses; this is not necessarily a unique IP for your individual server instance.</small>
</main>
</body>
</html>`);
  } catch (error) {
    console.error("Server IP lookup failed:", error);
    res.status(503).type("html").send(`<!doctype html>
<html><body style="font-family:system-ui;padding:30px">
<h1>LittleBigAdventure Server</h1>
<p>Server is online, but its public DNS address could not be resolved right now.</p>
<p><strong>Hostname:</strong> ${PUBLIC_HOSTNAME}</p>
</body></html>`);
  }
});

// ============================================================
// SECURITY / TRAFFIC SHIELD
// ============================================================
// This is application-layer protection. Render/Cloudflare should
// still provide upstream volumetric DDoS protection.
//
// The shield:
// - rejects oversized HTTP bodies before parsing them
// - rejects oversized headers
// - limits request duration
// - rate-limits individual IPs
// - detects burst/abuse mode and temporarily blocks offenders
// - keeps health/control endpoints available
// - prefers authenticated/signed session traffic during pressure
// - adds browser/security headers
// - never writes attacker-controlled files to disk
// ============================================================

const MAX_REQUEST_BODY_BYTES = Math.max(
  16 * 1024,
  Number(process.env.MAX_REQUEST_BODY_BYTES || 512 * 1024)
);

const MAX_REQUEST_TIME_MS = Math.max(
  1000,
  Number(process.env.MAX_REQUEST_TIME_MS || 15000)
);

const RATE_WINDOW_MS = Math.max(
  1000,
  Number(process.env.RATE_WINDOW_MS || 10000)
);

const RATE_LIMIT_PER_WINDOW = Math.max(
  20,
  Number(process.env.RATE_LIMIT_PER_WINDOW || 120)
);

const ABUSE_BLOCK_MS = Math.max(
  5000,
  Number(process.env.ABUSE_BLOCK_MS || 60000)
);

const GLOBAL_PRESSURE_WINDOW_MS = 5000;
const GLOBAL_PRESSURE_LIMIT = Math.max(
  200,
  Number(process.env.GLOBAL_PRESSURE_LIMIT || 1000)
);

const MAX_TRACKED_IPS = 10000;

const trafficByIp = new Map();
const blockedIps = new Map();
const authAttemptsByIp = new Map();
const authBlockedIps = new Map();
let globalTraffic = [];

const AUTH_WINDOW_MS = Math.max(60_000, Number(process.env.AUTH_WINDOW_MS || 10 * 60 * 1000));
const AUTH_MAX_ATTEMPTS = Math.max(3, Number(process.env.AUTH_MAX_ATTEMPTS || 8));
const AUTH_BLOCK_MS = Math.max(60_000, Number(process.env.AUTH_BLOCK_MS || 30 * 60 * 1000));
let emergencySafeMode = false;

function requestIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  let ip = forwarded
    ? String(forwarded).split(",")[0].trim()
    : req.socket.remoteAddress || "unknown";

  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (ip === "::1") ip = "127.0.0.1";
  return ip;
}

function hasAuthorizationSignal(req) {
  // IMPORTANT: a header/cookie being present is NOT proof of authentication.
  // Emergency mode therefore never trusts this function for authorization.
  return Boolean(
    req.cookies?.[SESSION_COOKIE] ||
    req.headers.authorization ||
    req.headers["x-firebase-token"]
  );
}

function isStateChangingRequest(req) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(req.method);
}

function isSecurityExempt(req) {
  const pathName = req.path || "";
  return (
    pathName === "/api/status" ||
    pathName === "/api/firebase-test" ||
    pathName === "/control.html" ||
    pathName === "/Control.html" ||
    pathName.startsWith("/api/control/")
  );
}

function pruneTimes(times, now, windowMs) {
  while (times.length && now - times[0] > windowMs) {
    times.shift();
  }
}

function rememberTraffic(ip, now) {
  globalTraffic.push(now);
  pruneTimes(globalTraffic, now, GLOBAL_PRESSURE_WINDOW_MS);

  let entry = trafficByIp.get(ip);
  if (!entry) {
    entry = { times: [], violations: 0, lastSeen: now };
    trafficByIp.set(ip, entry);
  }

  entry.lastSeen = now;
  entry.times.push(now);
  pruneTimes(entry.times, now, RATE_WINDOW_MS);

  if (trafficByIp.size > MAX_TRACKED_IPS) {
    for (const [key, value] of trafficByIp) {
      if (now - value.lastSeen > RATE_WINDOW_MS * 2) {
        trafficByIp.delete(key);
      }
      if (trafficByIp.size <= MAX_TRACKED_IPS) break;
    }
  }

  emergencySafeMode =
    globalTraffic.length >= GLOBAL_PRESSURE_LIMIT;

  return entry;
}

function blockIp(ip, reason) {
  blockedIps.set(ip, {
    until: Date.now() + ABUSE_BLOCK_MS,
    reason
  });
}

function isBlocked(ip) {
  const block = blockedIps.get(ip);
  if (!block) return false;

  if (Date.now() >= block.until) {
    blockedIps.delete(ip);
    return false;
  }

  return true;
}

function authBlocked(ip) {
  const until = authBlockedIps.get(ip);
  if (!until) return false;
  if (Date.now() >= until) {
    authBlockedIps.delete(ip);
    return false;
  }
  return true;
}

function recordAuthAttempt(ip) {
  const now = Date.now();
  let times = authAttemptsByIp.get(ip) || [];
  times = times.filter(t => now - t <= AUTH_WINDOW_MS);
  times.push(now);
  authAttemptsByIp.set(ip, times);

  if (times.length >= AUTH_MAX_ATTEMPTS) {
    authBlockedIps.set(ip, now + AUTH_BLOCK_MS);
    authAttemptsByIp.delete(ip);
    return false;
  }
  return true;
}

function authRateGuard(req, res, next) {
  const ip = requestIp(req);
  if (authBlocked(ip)) {
    return securityReject(res, 429, "Too many authentication attempts. Try again later.");
  }
  if (!recordAuthAttempt(ip)) {
    return securityReject(res, 429, "Too many authentication attempts. Try again later.");
  }
  next();
}

function securityReject(res, status, message) {
  res.status(status);
  res.set("Cache-Control", "no-store");
  return res.json({
    success: false,
    error: message
  });
}

// Security headers. Render normally terminates public HTTPS before
// the Node process, so HSTS is appropriate for the public site.
app.use((req, res, next) => {
  res.set({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-DNS-Prefetch-Control": "off",
    "Cache-Control": "no-store",
    "Content-Security-Policy": process.env.LBA_CSP ||
      "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.googleapis.com; connect-src 'self' https:; font-src 'self' data: https:; media-src 'self' blob: https:; frame-src 'self' https:; upgrade-insecure-requests"
  });
  next();
});

// Public Render traffic should be HTTPS. Render normally terminates TLS
// before Node and forwards x-forwarded-proto=https.
app.use((req, res, next) => {
  const forwardedProto = String(
    req.headers["x-forwarded-proto"] ||
    ""
  ).split(",")[0].trim().toLowerCase();

  const isHttps =
    req.secure ||
    forwardedProto === "https";

  if (!isHttps && process.env.ALLOW_PLAINTEXT_HTTP !== "true") {
    const host = req.get("host");
    if (host) {
      return res.redirect(308, `https://${host}${req.originalUrl}`);
    }
  }

  next();
});

// Request-size + abuse shield runs before body parsing.
app.use((req, res, next) => {
  const now = Date.now();
  const ip = requestIp(req);

  if (isBlocked(ip)) {
    return securityReject(res, 429, "Traffic temporarily blocked");
  }

  const contentLength = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
    blockIp(ip, "oversized request");
    return securityReject(res, 413, "Request body is too large");
  }

  const entry = rememberTraffic(ip, now);

  if (entry.times.length > RATE_LIMIT_PER_WINDOW) {
    entry.violations += 1;
    if (entry.violations >= 3) {
      blockIp(ip, "repeated rate abuse");
    }
    return securityReject(res, 429, "Too many requests");
  }

  // Under extreme pressure, fail closed for state-changing traffic.
  // DO NOT use the mere presence of an Authorization header/cookie as
  // proof of identity: attackers can forge those values. Individual
  // protected routes still perform real Firebase verification.
  if (
    emergencySafeMode &&
    !isSecurityExempt(req) &&
    isStateChangingRequest(req)
  ) {
    return securityReject(
      res,
      503,
      "LBA emergency traffic protection is active"
    );
  }

  req.setTimeout(MAX_REQUEST_TIME_MS, () => {
    try { req.destroy(); } catch (_) {}
  });

  next();
});

// Parse only after the size shield.
app.use(express.json({ limit: `${MAX_REQUEST_BODY_BYTES}b` }));
app.use(express.urlencoded({
  extended: true,
  limit: `${MAX_REQUEST_BODY_BYTES}b`,
  parameterLimit: 100
}));
app.use(cookieParser());

// Periodically clear stale in-memory security state.
setInterval(() => {
  const now = Date.now();
  for (const [ip, block] of blockedIps) {
    if (now >= block.until) blockedIps.delete(ip);
  }
  for (const [ip, entry] of trafficByIp) {
    pruneTimes(entry.times, now, RATE_WINDOW_MS);
    if (!entry.times.length && now - entry.lastSeen > RATE_WINDOW_MS * 2) {
      trafficByIp.delete(ip);
    }
  }
  pruneTimes(globalTraffic, now, GLOBAL_PRESSURE_WINDOW_MS);
  for (const [ip, times] of authAttemptsByIp) {
    const kept = times.filter(t => now - t <= AUTH_WINDOW_MS);
    if (kept.length) authAttemptsByIp.set(ip, kept);
    else authAttemptsByIp.delete(ip);
  }
  for (const [ip, until] of authBlockedIps) {
    if (now >= until) authBlockedIps.delete(ip);
  }
  if (globalTraffic.length < GLOBAL_PRESSURE_LIMIT / 2) {
    emergencySafeMode = false;
  }
}, RATE_WINDOW_MS).unref?.();

// ============================================================
// CONTROL / SERVICE STATE
// ============================================================
//
// Render remains AWAKE in all of these states.
//
// SERVER OFFLINE:
//   - normal site requests have their sockets closed
//   - control.html + control API remain available
//
// FIREBASE OFFLINE:
//   - Firebase reads/writes are refused
//   - Render + website server remain online
//
// MAINTENANCE:
//   - normal visitors are redirected to the external
//     maintenance page
//
// IMPORTANT:
// Render cannot normally see a private LAN address such as
// 192.168.178.69. It sees the public address of the network.
// Therefore CONTROL_ALLOWED_IPS should contain the public IP
// of the administrator network when deployed on Render.
//
// You can set:
//   CONTROL_ALLOWED_IPS=your.public.ip,192.168.178.69
//
// 192.168.178.69 is kept as the requested local fallback,
// but it will only match when the request actually contains
// that address (for example on a local/private deployment).
// ============================================================

const CONTROL_ALLOWED_IPS = String(
  process.env.CONTROL_ALLOWED_IPS ||
  "192.168.178.69"
)
  .split(",")
  .map(value => value.trim())
  .filter(Boolean);

const CONTROL_SECRET =
  process.env.LBA_CONTROL_SECRET || "";

const MAINTENANCE_URL =
  "https://serviceunavailable.neocities.org/Maintenance";

let serverOffline = false;
let firebaseManuallyDisabled = false;
let maintenanceMode = false;



// ============================================================
// FIREBASE STATE
// ============================================================

let firebaseReady = false;
let firebaseChecking = false;
let firebaseLastError = null;
let firebaseLastSuccessfulCheck = null;

let db = null;
let auth = null;

// ============================================================
// LOGGING
// ============================================================

function log(message) {
  console.log(`[LBA] ${message}`);
}

function firebaseLog(message) {
  console.log(`[Firebase] ${message}`);
}

// ============================================================
// TIMEOUT
// ============================================================

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      const timer = setTimeout(() => {
        const error = new Error(
          `${label || "Firebase request"} timed out after ${ms}ms`
        );
        error.code = "firebase-timeout";
        reject(error);
      }, ms);

      // Do not keep Node alive only because of the timeout timer.
      timer.unref?.();
    })
  ]);
}

// ============================================================
// BACKOFF
// ============================================================

function retryDelay(attempt) {
  // 750ms, 1500ms, 3000ms...
  return FIREBASE_RETRY_BASE_MS * Math.pow(2, attempt - 1);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// ENVIRONMENT VALIDATION
// ============================================================

function validateEnvironment() {
  const problems = [];

  if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    problems.push("Missing FIREBASE_SERVICE_ACCOUNT_JSON");
  }

  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const serviceAccount = JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON
      );

      if (!serviceAccount.project_id && !serviceAccount.projectId) {
        problems.push("Firebase service account is missing project_id");
      }

      if (!serviceAccount.client_email && !serviceAccount.clientEmail) {
        problems.push("Firebase service account is missing client_email");
      }

      if (!serviceAccount.private_key && !serviceAccount.privateKey) {
        problems.push("Firebase service account is missing private_key");
      }
    } catch (error) {
      problems.push(
        "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON"
      );
    }
  }

  return problems;
}

// ============================================================
// FIREBASE INITIALIZATION
// ============================================================

function initializeFirebaseOnce() {
  const problems = validateEnvironment();

  if (problems.length) {
    problems.forEach(problem => {
      console.error(`[Firebase] CONFIG ERROR: ${problem}`);
    });

    // Do NOT crash Render.
    firebaseReady = false;
    firebaseLastError = new Error(
      "Firebase configuration is incomplete"
    );

    return false;
  }

  try {
    let firebaseApp;

    if (getApps().length > 0) {
      firebaseApp = getApps()[0];
      log("Firebase app already initialized; reusing it.");
    } else {
      const serviceAccount = JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON
      );

      firebaseApp = initializeApp({
        credential: cert(serviceAccount)
      });

      log("Firebase initialized once.");
    }

    db = getFirestore(firebaseApp);
    auth = getAuth(firebaseApp);

    return true;
  } catch (error) {
    firebaseReady = false;
    firebaseLastError = error;

    console.error(
      "[Firebase] INITIALIZATION ERROR:",
      error.message
    );

    return false;
  }
}

// ============================================================
// FIREBASE RETRY ENGINE
// ============================================================
//
// Every Firebase operation goes through this function.
//
// Attempt 1 -> failed
// wait
// Attempt 2 -> failed
// wait longer
// Attempt 3 -> connected
//
// A failed operation does not crash the Render process.
// ============================================================

async function firebaseRetry(label, operation) {
  if (!db || !auth) {
    const error = new Error("Firebase is not initialized");
    error.code = "firebase-not-initialized";
    throw error;
  }

  let lastError;

  for (let attempt = 1; attempt <= FIREBASE_RETRIES; attempt++) {
    try {
      const result = await withTimeout(
        Promise.resolve().then(operation),
        FIREBASE_TIMEOUT_MS,
        label
      );

      firebaseReady = true;
      firebaseLastError = null;
      firebaseLastSuccessfulCheck = new Date();

      if (!firebaseChecking) {
        firebaseLog(
          `${label}: connected on attempt ${attempt}`
        );
      }

      return result;
    } catch (error) {
      lastError = error;

      firebaseReady = false;
      firebaseLastError = error;

      firebaseLog(
        `${label}: Attempt ${attempt}/${FIREBASE_RETRIES} failed: ${error.message}`
      );

      if (attempt < FIREBASE_RETRIES) {
        const delay = retryDelay(attempt);

        firebaseLog(
          `${label}: retrying in ${delay}ms`
        );

        await sleep(delay);
      }
    }
  }

  throw lastError;
}

// ============================================================
// FIREBASE HEALTH CHECK
// ============================================================

async function checkFirebase(label = "health check") {
  if (firebaseManuallyDisabled) {
    firebaseReady = false;
    return false;
  }

  if (firebaseChecking) {
    return firebaseReady;
  }

  firebaseChecking = true;

  try {
    if (!db || !auth) {
      if (!initializeFirebaseOnce()) {
        return false;
      }
    }

    // A tiny read verifies that the Admin SDK can actually talk
    // to Firestore instead of merely being initialized locally.
    await firebaseRetry(
      label,
      async () => {
        const ref = db.collection("_system").doc("server_health");
        const snapshot = await ref.get();

        return snapshot.exists;
      }
    );

    firebaseReady = true;
    firebaseLastError = null;
    firebaseLastSuccessfulCheck = new Date();

    return true;
  } catch (error) {
    firebaseReady = false;
    firebaseLastError = error;

    firebaseLog(
      `Firebase OFFLINE: ${error.message}`
    );

    return false;
  } finally {
    firebaseChecking = false;
  }
}

// ============================================================
// STARTUP FIREBASE TEST
// ============================================================

async function startupFirebaseTest() {
  log("Testing Firebase before declaring the server ready...");

  const connected = await checkFirebase("startup test");

  if (connected) {
    console.log("Firebase: CONNECTED");
    console.log("Database: READY");
  } else {
    console.log("Firebase: OFFLINE");
    console.log("Database: TEMPORARILY UNAVAILABLE");
    console.log("Server: ONLINE");
    console.log("Watchdog: RECONNECTING");
  }
}

// ============================================================
// WATCHDOG
// ============================================================
//
// This does NOT restart the server.
// It periodically checks Firebase and automatically marks it
// online again when Firebase returns.
// ============================================================

function startFirebaseWatchdog() {
  setInterval(async () => {
    if (firebaseManuallyDisabled) {
      return;
    }

    if (firebaseReady) {
      // A light check keeps the health state current.
      await checkFirebase("watchdog");
      return;
    }

    firebaseLog(
      "Watchdog: Firebase is offline. Attempting recovery..."
    );

    const recovered = await checkFirebase(
      "watchdog recovery"
    );

    if (recovered) {
      console.log("Firebase: CONNECTED");
      console.log("Database: READY");
      console.log("Watchdog: RECOVERY COMPLETE");
    } else {
      console.log("Firebase: STILL OFFLINE");
      console.log("Server: STILL ONLINE");
      console.log("Watchdog: WILL TRY AGAIN");
    }
  }, FIREBASE_WATCHDOG_MS).unref?.();
}

// ============================================================
// CONTROL ACCESS / REQUEST HELPERS
// ============================================================

function getClientIp(req) {
  // Render/reverse proxies normally provide x-forwarded-for.
  // The last trusted proxy address is not used here; the first
  // forwarded value is the original client address in the normal
  // Render proxy setup.
  const forwarded = req.headers["x-forwarded-for"];

  let ip =
    forwarded
      ? String(forwarded).split(",")[0].trim()
      : req.socket.remoteAddress || "";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  if (ip === "::1") {
    ip = "127.0.0.1";
  }

  return ip;
}

function isAllowedControlIp(req) {
  const ip = getClientIp(req);
  return CONTROL_ALLOWED_IPS.includes(ip);
}

function hasControlSecret(req) {
  if (!CONTROL_SECRET || CONTROL_SECRET.length < 32) {
    return false;
  }

  // Never accept secrets in query strings: URLs can leak through logs,
  // browser history, analytics, proxies and referrer headers.
  const supplied = String(req.headers["x-lba-control-secret"] || "");
  const a = Buffer.from(supplied);
  const b = Buffer.from(CONTROL_SECRET);

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isControlRequest(req) {
  const pathName = req.path || "";

  return (
    pathName === "/control.html" ||
    pathName === "/Control.html" ||
    pathName.startsWith("/api/control/")
  );
}

function isAuthorizedControl(req) {
  // IP allowlist is the primary gate.
  // A secret is also accepted for deployments where Render cannot
  // observe the private LAN IP.
  return (
    isAllowedControlIp(req) ||
    hasControlSecret(req)
  );
}

function rejectOfflineConnection(req, res) {
  // Closing the socket instead of returning HTTP 503 is what makes
  // browsers behave like the server cannot be reached.
  try {
    req.socket.destroy();
  } catch (_) {}

  // In case the socket cannot be destroyed immediately.
  if (!res.headersSent) {
    try {
      res.status(503).end();
    } catch (_) {}
  }
}

function controlGuard(req, res, next) {
  if (!isAuthorizedControl(req)) {
    return res.status(403).json({
      success: false,
      error: "Control access denied"
    });
  }

  next();
}

// HARD GATE: every control API endpoint is protected by default.
// Individual routes cannot accidentally forget the guard.
app.use("/api/control", controlGuard);

// This middleware is intentionally before the website/static routes.
// Control requests remain reachable while the LBA server is OFFLINE.
app.use((req, res, next) => {
  if (serverOffline && !isControlRequest(req)) {
    if (!isAuthorizedControl(req)) {
      return rejectOfflineConnection(req, res);
    }
  }

  // Maintenance mode redirects normal visitors but leaves the
  // administrator control panel reachable.
  if (
    maintenanceMode &&
    !isControlRequest(req)
  ) {
    return res.redirect(307, MAINTENANCE_URL);
  }

  next();
});

// ============================================================
// FIREBASE AVAILABILITY MIDDLEWARE
// ============================================================
//
// Privileged Firebase routes do not proceed while Firebase is
// known to be unavailable.
//
// The server itself remains online.
// ============================================================

async function requireFirebase(req, res, next) {
  if (firebaseManuallyDisabled) {
    return res.status(503).json({
      success: false,
      firebase: false,
      firebase_manually_disabled: true,
      error: "Firebase has been disabled by the administrator",
      retrying: false
    });
  }

  if (firebaseReady) {
    return next();
  }

  const recovered = await checkFirebase("request recovery");

  if (!recovered) {
    return res.status(503).json({
      success: false,
      firebase: false,
      error: "Firebase temporarily unavailable",
      retrying: true
    });
  }

  next();
}

// ============================================================
// FIRESTORE HELPERS
// ============================================================

async function readDoc(collection, id) {
  return firebaseRetry(
    `READ ${collection}/${id}`,
    () => db
      .collection(collection)
      .doc(String(id))
      .get()
  );
}

const SAFETY_BACKUP_COLLECTION = "_safety_backups";
const SAFETY_BACKUP_REQUIRED =
  String(process.env.SAFETY_BACKUP_REQUIRED || "true").toLowerCase() !== "false";

async function backupDocumentBeforeChange(collection, id, existingData, action) {
  if (!existingData || collection === SAFETY_BACKUP_COLLECTION) {
    return null;
  }

  return firebaseRetry(
    `BACKUP ${collection}/${id}`,
    async () => {
      const backup = {
        source_collection: collection,
        source_id: String(id),
        action,
        backed_up_at: FieldValue.serverTimestamp(),
        data: existingData
      };

      const ref = await db
        .collection(SAFETY_BACKUP_COLLECTION)
        .add(backup);

      const saved = await ref.get();
      if (!saved.exists) {
        throw new Error(`Safety backup verification failed for ${collection}/${id}`);
      }

      return ref.id;
    }
  );
}

async function writeDocAndVerify(
  collection,
  id,
  data,
  options = {}
) {
  return firebaseRetry(
    `WRITE ${collection}/${id}`,
    async () => {
      const ref = db
        .collection(collection)
        .doc(String(id));

      const existing = await ref.get();

      // Before overwriting existing data, create a recovery copy.
      // If required backup protection fails, the destructive write is refused.
      if (existing.exists && SAFETY_BACKUP_REQUIRED) {
        await backupDocumentBeforeChange(
          collection,
          id,
          existing.data(),
          "before-write"
        );
      }

      await ref.set(data, options);

      const saved = await ref.get();

      if (!saved.exists) {
        const error = new Error(
          `Write verification failed for ${collection}/${id}`
        );

        error.code = "write-verification-failed";
        throw error;
      }

      return saved;
    }
  );
}

async function deleteDocAndVerify(collection, id) {
  return firebaseRetry(
    `DELETE ${collection}/${id}`,
    async () => {
      const ref = db
        .collection(collection)
        .doc(String(id));

      const existing = await ref.get();

      if (existing.exists && SAFETY_BACKUP_REQUIRED) {
        await backupDocumentBeforeChange(
          collection,
          id,
          existing.data(),
          "before-delete"
        );
      }

      await ref.delete();

      const check = await ref.get();

      if (check.exists) {
        const error = new Error(
          `Delete verification failed for ${collection}/${id}`
        );

        error.code = "delete-verification-failed";
        throw error;
      }

      return true;
    }
  );
}

// ============================================================
// DATA HELPERS
// ============================================================

function clean(value, fallback = "") {
  if (value === undefined || value === null) {
    return fallback;
  }

  return String(value).trim();
}

function normalizeUsername(value) {
  return clean(value).toLowerCase();
}

function numberOrZero(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

// ============================================================
// SAFE PUBLIC DATA
// ============================================================

function publicProfile(data, idOverride = null) {
  data = data || {};

  return {
    id: data.user_id ?? idOverride ?? data.uid ?? null,
    user_id: data.user_id ?? idOverride ?? null,
    uid: data.uid || "",
    username:
      clean(data.username) ||
      clean(data.display_name) ||
      "Unknown User",
    display_name:
      clean(data.display_name) ||
      clean(data.username) ||
      "Unknown User",
    bio: clean(data.bio, "No bio"),
    avatar_url: clean(data.avatar_url),
    created_at: data.created_at || null,
    updated_at: data.updated_at || null,
    followers: numberOrZero(data.followers),
    following: numberOrZero(data.following),
    friends: numberOrZero(data.friends)
  };
}

function publicLevel(data, id) {
  data = data || {};

  return {
    id: data.id || data.level_id || id,
    level_id: data.level_id || data.id || id,
    title: clean(
      data.title ||
      data.name,
      "Untitled Adventure"
    ),
    name: clean(
      data.name ||
      data.title,
      "Untitled Adventure"
    ),
    description: clean(
      data.description,
      "No description"
    ),
    thumbnail_url: clean(
      data.thumbnail_url ||
      data.thumbnail
    ),
    creator:
      clean(
        data.creator ||
        data.creator_username ||
        data.username
      ) || "Unknown Creator",
    creator_username:
      clean(
        data.creator_username ||
        data.creator ||
        data.username
      ) || "Unknown Creator",
    creator_user_id:
      data.creator_user_id ??
      data.user_id ??
      data.uid ??
      null,
    creator_uid:
      data.creator_uid ||
      data.uid ||
      "",
    hearts: numberOrZero(data.hearts),
    likes: numberOrZero(data.likes),
    followers: numberOrZero(data.followers),
    plays: numberOrZero(data.plays),
    created_at: data.created_at || null,
    updated_at: data.updated_at || null
  };
}

function publicPost(data, id) {
  data = data || {};

  return {
    id: data.id || data.post_id || id,
    post_id: data.post_id || data.id || id,
    uid: data.uid || "",
    user_id:
      data.user_id ||
      data.profile_user_id ||
      data.uid ||
      null,
    author:
      clean(
        data.author ||
        data.username
      ) || "Unknown User",
    username:
      clean(
        data.username ||
        data.author
      ) || "Unknown User",
    avatar_url: clean(data.avatar_url),
    title: clean(data.title),
    text: clean(
      data.text ||
      data.content,
      "No post"
    ),
    content: clean(
      data.content ||
      data.text,
      "No post"
    ),
    created_at:
      data.created_at ||
      data.date ||
      null,
    updated_at: data.updated_at || null
  };
}

// ============================================================
// AUTH
// ============================================================

async function getCurrentUser(req) {
  if (!auth) {
    return null;
  }

  const session = req.cookies?.[SESSION_COOKIE];

  if (session) {
    try {
      return await firebaseRetry(
        "VERIFY SESSION",
        () => auth.verifySessionCookie(session, true)
      );
    } catch (_) {
      // Try Bearer token below.
    }
  }

  const authorization =
    req.headers.authorization || "";

  const token =
    authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : req.headers["x-firebase-token"];

  if (!token) {
    return null;
  }

  try {
    return await firebaseRetry(
      "VERIFY FIREBASE TOKEN",
      () => auth.verifyIdToken(String(token), true)
    );
  } catch (_) {
    return null;
  }
}

async function requireUser(req, res) {
  const user = await getCurrentUser(req);

  if (!user) {
    res.status(401).json({
      success: false,
      error: "Login required"
    });

    return null;
  }

  return user;
}

async function createSession(res, idToken) {
  const expiresIn = 1000 * 60 * 60 * 24 * 5;

  const sessionCookie = await firebaseRetry(
    "CREATE SESSION",
    () => auth.createSessionCookie(
      idToken,
      { expiresIn }
    )
  );

  res.cookie(
    SESSION_COOKIE,
    sessionCookie,
    {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: expiresIn,
      path: "/"
    }
  );
}

async function signInWithPassword(email, password) {
  const apiKey =
    process.env.FIREBASE_WEB_API_KEY ||
    "AIzaSyAKAvsFCZ840VtMEV7w1t-ie_uil-KWuCk";

  if (!apiKey) {
    throw new Error("Missing FIREBASE_WEB_API_KEY");
  }

  return firebaseRetry(
    "PASSWORD SIGN-IN",
    async () => {
      const response = await withTimeout(
        fetch(
          "https://identitytoolkit.googleapis.com/v1/" +
          "accounts:signInWithPassword?key=" +
          encodeURIComponent(apiKey),
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              email,
              password,
              returnSecureToken: true
            })
          }
        ),
        FIREBASE_TIMEOUT_MS,
        "Firebase Auth sign-in"
      );

      const data = await response.json();

      if (!response.ok) {
        const error = new Error(
          data?.error?.message ||
          "Firebase sign-in failed"
        );

        error.code = "auth-signin-failed";
        throw error;
      }

      return data;
    }
  );
}

// ============================================================
// PROFILE LOOKUP
// ============================================================

async function findProfile(identifier) {
  const value = clean(identifier);

  if (!value) {
    return null;
  }

  // 1. Firebase UID / document ID.
  const direct = await readDoc("profiles", value);

  if (direct.exists) {
    return {
      id: direct.id,
      data: direct.data()
    };
  }

  // 2. Permanent numeric User ID.
  if (/^\d+$/.test(value)) {
    const query = await firebaseRetry(
      `FIND PROFILE USER ID ${value}`,
      () => db
        .collection("profiles")
        .where("user_id", "==", Number(value))
        .limit(1)
        .get()
    );

    if (!query.empty) {
      return {
        id: query.docs[0].id,
        data: query.docs[0].data()
      };
    }
  }

  // 3. Username.
  const usernameQuery = await firebaseRetry(
    `FIND PROFILE USERNAME ${value}`,
    () => db
      .collection("profiles")
      .where(
        "username_lower",
        "==",
        normalizeUsername(value)
      )
      .limit(1)
      .get()
  );

  if (!usernameQuery.empty) {
    return {
      id: usernameQuery.docs[0].id,
      data: usernameQuery.docs[0].data()
    };
  }

  return null;
}

// ============================================================
// CONTROL STATUS
// ============================================================

app.get(
  "/api/control/status",
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    res.json({
      success: true,
      server: {
        online: !serverOffline,
        offline: serverOffline
      },
      render: {
        awake: true
      },
      firebase: {
        online:
          !firebaseManuallyDisabled &&
          firebaseReady,
        manually_disabled:
          firebaseManuallyDisabled
      },
      maintenance: {
        enabled: maintenanceMode,
        url: MAINTENANCE_URL
      },
      control: {
        client_ip: getClientIp(req)
      }
    });
  }
);

// ============================================================
// CONTROL: SERVER OFFLINE / ONLINE
// ============================================================

app.post(
  "/api/control/server/stop",
  (req, res) => {
    serverOffline = true;

    log(
      `CONTROL: LBA server OFFLINE by ${getClientIp(req)}`
    );

    res.json({
      success: true,
      server_online: false,
      render_awake: true,
      message:
        "LBA server is offline. Render remains awake."
    });
  }
);

app.post(
  "/api/control/server/start",
  (req, res) => {
    serverOffline = false;

    log(
      `CONTROL: LBA server ONLINE by ${getClientIp(req)}`
    );

    res.json({
      success: true,
      server_online: true,
      render_awake: true,
      message:
        "LBA server is online again."
    });
  }
);

// ============================================================
// CONTROL: FIREBASE OFFLINE / ONLINE
// ============================================================

app.post(
  "/api/control/firebase/stop",
  (req, res) => {
    firebaseManuallyDisabled = true;
    firebaseReady = false;

    firebaseLog(
      `CONTROL: Firebase manually disabled by ${getClientIp(req)}`
    );

    res.json({
      success: true,
      firebase_online: false,
      manually_disabled: true,
      server_online: !serverOffline
    });
  }
);

app.post(
  "/api/control/firebase/start",
  async (req, res) => {
    firebaseManuallyDisabled = false;

    const connected =
      await checkFirebase(
        "manual Firebase restart"
      );

    firebaseLog(
      `CONTROL: Firebase restart requested by ${getClientIp(req)}`
    );

    if (!connected) {
      return res.status(503).json({
        success: false,
        firebase_online: false,
        manually_disabled: false,
        retrying: true,
        error:
          "Firebase did not reconnect yet"
      });
    }

    res.json({
      success: true,
      firebase_online: true,
      manually_disabled: false
    });
  }
);

// ============================================================
// CONTROL: MAINTENANCE
// ============================================================

app.post(
  "/api/control/maintenance/on",
  (req, res) => {
    maintenanceMode = true;

    log(
      `CONTROL: Maintenance ON by ${getClientIp(req)}`
    );

    res.json({
      success: true,
      maintenance: true,
      url: MAINTENANCE_URL
    });
  }
);

app.post(
  "/api/control/maintenance/off",
  (req, res) => {
    maintenanceMode = false;

    log(
      `CONTROL: Maintenance OFF by ${getClientIp(req)}`
    );

    res.json({
      success: true,
      maintenance: false
    });
  }
);

// ============================================================
// STATUS
// ============================================================

app.get("/api/status", async (req, res) => {
  res.set("Cache-Control", "no-store");

  // Do not hide Firebase outages behind a fake "online".
  if (!firebaseReady) {
    await checkFirebase("status recovery");
  }

  res.json({
    online: !serverOffline,
    server_online: !serverOffline,
    render_awake: true,
    service: SERVICE_NAME,
    firebase:
      !firebaseManuallyDisabled &&
      firebaseReady,
    database:
      !firebaseManuallyDisabled &&
      firebaseReady,
    firebase_manually_disabled:
      firebaseManuallyDisabled,
    maintenance: maintenanceMode,
    maintenance_url: MAINTENANCE_URL,
    firebase_status:
      firebaseManuallyDisabled
        ? "manually_disabled"
        : firebaseReady
          ? "online"
          : "temporarily_unavailable",
    reconnecting:
      !firebaseManuallyDisabled &&
      !firebaseReady,
    last_successful_check:
      firebaseLastSuccessfulCheck,
    retry_attempts: FIREBASE_RETRIES
  });
});

// ============================================================
// FIREBASE TEST
// ============================================================

app.get(
  "/api/firebase-test",
  async (req, res) => {
    const connected =
      await checkFirebase("manual test");

    if (!connected) {
      return res.status(503).json({
        connected: false,
        firestore: false,
        error:
          "Firebase is temporarily unavailable"
      });
    }

    try {
      const before = await readDoc(
        "_system",
        "server_health"
      );

      const saved =
        await writeDocAndVerify(
          "_system",
          "server_health",
          {
            online: true,
            service: SERVICE_NAME,
            checked_at:
              FieldValue.serverTimestamp()
          },
          { merge: true }
        );

      const after = await readDoc(
        "_system",
        "server_health"
      );

      res.json({
        connected: true,
        firestore: true,
        read_before: before.exists,
        write_verified: saved.exists,
        read_after: after.exists,
        data: after.data()
      });
    } catch (error) {
      firebaseReady = false;

      res.status(503).json({
        connected: false,
        firestore: false,
        error:
          "Firebase test failed after retries"
      });
    }
  }
);

// ============================================================
// SIGN UP
// ============================================================

app.post(
  "/api/auth/signup",
  authRateGuard,
  requireFirebase,
  async (req, res) => {
    try {
      const username =
        clean(req.body?.username);

      const password =
        String(req.body?.password || "");

      const confirmPassword =
        String(
          req.body?.confirmPassword || ""
        );

      const email =
        clean(req.body?.email);

      if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) {
        return res.status(400).json({
          success: false,
          error:
            "Username must be 3-30 characters and use letters, numbers, or _"
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be at least 6 characters"
        });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          error:
            "Passwords do not match"
        });
      }

      // Check before creating anything.
      const existing =
        await findProfile(username);

      if (existing) {
        return res.status(409).json({
          success: false,
          error:
            "Username already exists"
        });
      }

      if (!email) {
        return res.status(400).json({
          success: false,
          error:
            "An email is required for the server login system"
        });
      }

      let userRecord;

      try {
        userRecord =
          await firebaseRetry(
            "CREATE AUTH USER",
            () => auth.createUser({
              email,
              password,
              displayName: username
            })
          );
      } catch (error) {
        if (
          String(error.code || "")
            .includes("email-already-exists")
        ) {
          return res.status(409).json({
            success: false,
            error:
              "Email already exists"
          });
        }

        throw error;
      }

      // Allocate numeric ID using a transaction.
      const counterRef =
        db.collection("_system")
          .doc("user_counter");

      const userId =
        await firebaseRetry(
          "ALLOCATE USER ID",
          () => db.runTransaction(
            async transaction => {
              const snapshot =
                await transaction.get(
                  counterRef
                );

              const next =
                Math.max(
                  1,
                  Number(
                    snapshot.exists
                      ? snapshot.data()
                          .next_user_id
                      : 1
                  )
                );

              transaction.set(
                counterRef,
                {
                  next_user_id: next + 1,
                  updated_at:
                    FieldValue.serverTimestamp()
                },
                { merge: true }
              );

              return next;
            }
          )
        );

      const profileData = {
        uid: userRecord.uid,
        user_id: userId,
        username,
        username_lower:
          normalizeUsername(username),
        display_name: username,
        bio: "No bio",
        avatar_url: "",
        email,
        auth_email: email,
        followers: 0,
        following: 0,
        friends: 0,
        created_at:
          FieldValue.serverTimestamp(),
        updated_at:
          FieldValue.serverTimestamp()
      };

      const profile =
        await writeDocAndVerify(
          "profiles",
          userRecord.uid,
          profileData,
          { merge: true }
        );

      const signIn =
        await signInWithPassword(
          email,
          password
        );

      await createSession(
        res,
        signIn.idToken
      );

      res.json({
        success: true,
        user: publicProfile(
          profile.data,
          userId
        )
      });
    } catch (error) {
      console.error(
        "[Auth] Signup error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error:
          "Account creation failed after retries"
      });
    }
  }
);

// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  authRateGuard,
  requireFirebase,
  async (req, res) => {
    try {
      const username =
        clean(req.body?.username);

      const password =
        String(req.body?.password || "");

      if (!username || !password) {
        return res.status(400).json({
          success: false,
          error:
            "Username and password are required"
        });
      }

      const found =
        await findProfile(username);

      if (!found) {
        return res.status(401).json({
          success: false,
          error:
            "Invalid username or password"
        });
      }

      const email =
        found.data.auth_email ||
        found.data.email;

      if (!email) {
        return res.status(500).json({
          success: false,
          error:
            "This account has no login email"
        });
      }

      const signIn =
        await signInWithPassword(
          email,
          password
        );

      await createSession(
        res,
        signIn.idToken
      );

      res.json({
        success: true,
        authenticated: true,
        loggedIn: true,
        user: publicProfile(
          found.data,
          found.data.user_id
        )
      });
    } catch (error) {
      console.error(
        "[Auth] Login error:",
        error.message
      );

      res.status(401).json({
        success: false,
        error:
          "Invalid username or password"
      });
    }
  }
);

// ============================================================
// ME / LOGOUT
// ============================================================

app.get(
  "/api/auth/me",
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    if (!firebaseReady) {
      await checkFirebase("auth recovery");
    }

    if (!firebaseReady) {
      return res.status(503).json({
        authenticated: false,
        loggedIn: false,
        firebase: false
      });
    }

    const user =
      await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({
        authenticated: false,
        loggedIn: false
      });
    }

    const profile =
      await findProfile(user.uid);

    const publicUser = profile
      ? publicProfile(
          profile.data,
          profile.data.user_id
        )
      : {
          uid: user.uid,
          username:
            user.name ||
            user.email ||
            "Unknown User",
          display_name:
            user.name ||
            user.email ||
            "Unknown User"
        };

    res.json({
      authenticated: true,
      loggedIn: true,
      user: publicUser
    });
  }
);

app.post(
  "/api/auth/logout",
  (req, res) => {
    res.clearCookie(
      SESSION_COOKIE,
      {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/"
      }
    );

    res.json({
      success: true,
      loggedOut: true
    });
  }
);

// ============================================================
// PLAYERS
// ============================================================

app.get(
  "/api/players",
  requireFirebase,
  async (req, res) => {
    try {
      const snapshot =
        await firebaseRetry(
          "READ PLAYERS",
          () => db
            .collection("profiles")
            .limit(100)
            .get()
        );

      const players =
        snapshot.docs.map(doc =>
          publicProfile(
            doc.data(),
            doc.data().user_id ||
            doc.id
          )
        );

      players.sort(
        (a, b) =>
          Number(a.user_id || 0) -
          Number(b.user_id || 0)
      );

      res.json({
        players
      });
    } catch (error) {
      console.error("Players read error:", error);
      res.status(503).json({
        players: [],
        error:
          "Players temporarily unavailable"
      });
    }
  }
);

// ============================================================
// PROFILE PAGE API
// ============================================================

async function getProfileContent(profileDocId, data) {
  const uid =
    data.uid || profileDocId;

  const userId =
    data.user_id;

  const levelMap = new Map();

  const levelQueries = [
    ["creator_uid", uid],
    ["uid", uid]
  ];

  if (
    userId !== undefined &&
    userId !== null
  ) {
    levelQueries.push(
      ["creator_user_id", userId]
    );
    levelQueries.push(
      ["user_id", userId]
    );
  }

  for (
    const [field, value]
    of levelQueries
  ) {
    const snapshot =
      await firebaseRetry(
        `PROFILE LEVELS ${field}`,
        () => db
          .collection("levels")
          .where(field, "==", value)
          .limit(100)
          .get()
      );

    snapshot.docs.forEach(doc => {
      levelMap.set(
        doc.id,
        publicLevel(
          doc.data(),
          doc.id
        )
      );
    });
  }

  const names = [
    data.username,
    data.display_name
  ].filter(Boolean);

  for (const username of names) {
    const snapshot =
      await firebaseRetry(
        "PROFILE LEVELS BY CREATOR",
        () => db
          .collection("levels")
          .where("creator", "==", username)
          .limit(100)
          .get()
      );

    snapshot.docs.forEach(doc => {
      levelMap.set(
        doc.id,
        publicLevel(
          doc.data(),
          doc.id
        )
      );
    });
  }

  const postMap = new Map();

  const postQueries = [
    ["uid", uid]
  ];

  if (
    userId !== undefined &&
    userId !== null
  ) {
    postQueries.push(
      ["user_id", userId]
    );
  }

  for (
    const [field, value]
    of postQueries
  ) {
    const snapshot =
      await firebaseRetry(
        `PROFILE POSTS ${field}`,
        () => db
          .collection("posts")
          .where(field, "==", value)
          .limit(100)
          .get()
      );

    snapshot.docs.forEach(doc => {
      postMap.set(
        doc.id,
        publicPost(
          doc.data(),
          doc.id
        )
      );
    });
  }

  for (const username of names) {
    for (
      const field of [
        "author",
        "username"
      ]
    ) {
      const snapshot =
        await firebaseRetry(
          `PROFILE POSTS ${field}`,
          () => db
            .collection("posts")
            .where(field, "==", username)
            .limit(100)
            .get()
        );

      snapshot.docs.forEach(doc => {
        postMap.set(
          doc.id,
          publicPost(
            doc.data(),
            doc.id
          )
        );
      });
    }
  }

  const followers =
    await firebaseRetry(
      "PROFILE FOLLOWERS",
      () => db
        .collection("follows")
        .where(
          "following_uid",
          "==",
          profileDocId
        )
        .limit(500)
        .get()
    );

  const following =
    await firebaseRetry(
      "PROFILE FOLLOWING",
      () => db
        .collection("follows")
        .where(
          "follower_uid",
          "==",
          profileDocId
        )
        .limit(500)
        .get()
    );

  const friends =
    await firebaseRetry(
      "PROFILE FRIENDS",
      () => db
        .collection("friends")
        .where(
          "users",
          "array-contains",
          profileDocId
        )
        .limit(500)
        .get()
    );

  const profile =
    publicProfile(
      data,
      data.user_id || profileDocId
    );

  profile.followers =
    followers.size;

  profile.following =
    following.size;

  profile.friends =
    friends.size;

  return {
    profile,
    levels:
      Array.from(levelMap.values()),
    posts:
      Array.from(postMap.values())
  };
}

async function profileResponse(req, res) {
  try {
    const found =
      await findProfile(
        req.params.id
      );

    if (!found) {
      return res.status(404).json({
        found: false,
        error: "Profile not found"
      });
    }

    const content =
      await getProfileContent(
        found.id,
        found.data
      );

    res.json({
      found: true,
      ...content
    });
  } catch (error) {
    console.error(
      "[Profile] Load error:",
      error.message
    );

    res.status(503).json({
      found: false,
      error:
        "Profile temporarily unavailable"
    });
  }
}

app.get(
  "/api/profiles/:id",
  requireFirebase,
  profileResponse
);

app.get(
  "/api/profile/:id",
  requireFirebase,
  profileResponse
);

// ============================================================
// PROFILE EDIT
// ============================================================

app.post(
  "/api/profile/update",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const profile =
        await findProfile(user.uid);

      if (!profile) {
        return res.status(404).json({
          success: false,
          error: "Profile not found"
        });
      }

      const updates = {};

      if (
        req.body?.display_name !==
        undefined
      ) {
        updates.display_name =
          clean(
            req.body.display_name,
            profile.data.username
          ).slice(0, 40);
      }

      if (
        req.body?.bio !==
        undefined
      ) {
        updates.bio =
          clean(
            req.body.bio
          ).slice(0, 500);
      }

      if (
        req.body?.avatar_url !==
        undefined
      ) {
        updates.avatar_url =
          clean(
            req.body.avatar_url
          ).slice(0, 2000);
      }

      updates.updated_at =
        FieldValue.serverTimestamp();

      const saved =
        await writeDocAndVerify(
          "profiles",
          profile.id,
          updates,
          { merge: true }
        );

      res.json({
        success: true,
        profile:
          publicProfile(
            saved.data,
            saved.data.user_id ||
            profile.id
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Profile update failed"
      });
    }
  }
);

// ============================================================
// PASSWORD UPDATE
// ============================================================

app.post(
  "/api/profile/password",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const password =
        String(
          req.body?.password || ""
        );

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be at least 6 characters"
        });
      }

      await firebaseRetry(
        "UPDATE PASSWORD",
        () => auth.updateUser(
          user.uid,
          { password }
        )
      );

      // Verify the Auth account still exists.
      await firebaseRetry(
        "VERIFY AUTH ACCOUNT",
        () => auth.getUser(
          user.uid
        )
      );

      res.json({
        success: true,
        password_updated: true
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Password update failed"
      });
    }
  }
);

// ============================================================
// LEVEL LOOKUP
// ============================================================

async function findLevel(identifier) {
  const value =
    clean(identifier);

  if (!value) {
    return null;
  }

  // Direct Firestore document ID.
  const direct =
    await readDoc(
      "levels",
      value
    );

  if (direct.exists) {
    return {
      id: direct.id,
      data: direct.data()
    };
  }

  // Common ID fields.
  for (
    const field of [
      "level_id",
      "id",
      "levelId"
    ]
  ) {
    const result =
      await firebaseRetry(
        `FIND LEVEL ${field}`,
        () => db
          .collection("levels")
          .where(
            field,
            "==",
            value
          )
          .limit(1)
          .get()
      );

    if (!result.empty) {
      return {
        id: result.docs[0].id,
        data: result.docs[0].data()
      };
    }

    if (/^\d+$/.test(value)) {
      const numeric =
        await firebaseRetry(
          `FIND LEVEL ${field} NUMBER`,
          () => db
            .collection("levels")
            .where(
              field,
              "==",
              Number(value)
            )
            .limit(1)
            .get()
        );

      if (!numeric.empty) {
        return {
          id: numeric.docs[0].id,
          data:
            numeric.docs[0].data()
        };
      }
    }
  }

  return null;
}

// ============================================================
// LEVELS
// ============================================================

app.get(
  "/api/levels",
  requireFirebase,
  async (req, res) => {
    try {
      const snapshot =
        await firebaseRetry(
          "READ LEVELS",
          () => db
            .collection("levels")
            .limit(100)
            .get()
        );

      const levels =
        snapshot.docs.map(doc =>
          publicLevel(
            doc.data(),
            doc.id
          )
        );

      res.json({
        levels
      });
    } catch (error) {
      console.error(
        "[Levels] List error:",
        error.message
      );

      // Empty collection / temporary failure
      // is represented safely.
      res.status(503).json({
        levels: [],
        firebase: false,
        error:
          "Levels temporarily unavailable"
      });
    }
  }
);

app.get(
  "/api/levels/:id",
  requireFirebase,
  async (req, res) => {
    try {
      const found =
        await findLevel(
          req.params.id
        );

      if (!found) {
        return res.status(404).json({
          found: false,
          level: null,
          error: "Level not found"
        });
      }

      res.json({
        found: true,
        level:
          publicLevel(
            found.data,
            found.id
          )
      });
    } catch (error) {
      console.error(
        "[Levels] Exact load error:",
        error.message
      );

      res.status(503).json({
        found: false,
        level: null,
        error:
          "Level temporarily unavailable"
      });
    }
  }
);

app.post(
  "/api/levels",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const name =
        clean(req.body?.name);

      if (!name) {
        return res.status(400).json({
          success: false,
          error:
            "Level name is required"
        });
      }

      if (name.length > 100) {
        return res.status(400).json({
          success: false,
          error:
            "Level name is too long"
        });
      }

      const profile =
        await findProfile(
          user.uid
        );

      const creator =
        profile?.data?.username ||
        profile?.data?.display_name ||
        user.name ||
        "Unknown Creator";

      const creatorUserId =
        profile?.data?.user_id ??
        user.uid;

      // Generate the ID once and write exactly one document.
      const ref =
        db.collection("levels").doc();

      const levelData = {
        id: ref.id,
        level_id: ref.id,
        title: name,
        name,
        description:
          clean(
            req.body?.description,
            "No description"
          ),
        thumbnail_url:
          clean(
            req.body?.thumbnail_url
          ),
        creator,
        creator_username: creator,
        creator_user_id:
          creatorUserId,
        creator_uid:
          user.uid,
        uid:
          user.uid,
        hearts: 0,
        likes: 0,
        followers: 0,
        plays: 0,
        created_at:
          FieldValue.serverTimestamp(),
        updated_at:
          FieldValue.serverTimestamp()
      };

      const saved =
        await writeDocAndVerify(
          "levels",
          ref.id,
          levelData
        );

      res.json({
        success: true,
        level:
          publicLevel(
            saved.data(),
            saved.id
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Level creation failed"
      });
    }
  }
);

// ============================================================
// POSTS
// ============================================================

async function findPost(identifier) {
  const value =
    clean(identifier);

  if (!value) return null;

  const direct =
    await readDoc(
      "posts",
      value
    );

  if (direct.exists) {
    return {
      id: direct.id,
      data: direct.data()
    };
  }

  for (
    const field of [
      "post_id",
      "id"
    ]
  ) {
    const result =
      await firebaseRetry(
        `FIND POST ${field}`,
        () => db
          .collection("posts")
          .where(
            field,
            "==",
            value
          )
          .limit(1)
          .get()
      );

    if (!result.empty) {
      return {
        id:
          result.docs[0].id,
        data:
          result.docs[0].data()
      };
    }
  }

  return null;
}

async function readReplies(postId) {
  const snapshot =
    await firebaseRetry(
      "READ POST REPLIES",
      () => db
        .collection("post_replies")
        .where(
          "post_id",
          "==",
          String(postId)
        )
        .limit(200)
        .get()
    );

  return snapshot.docs.map(doc => {
    const data = doc.data();

    return {
      id: doc.id,
      user_id:
        data.user_id ||
        data.uid ||
        null,
      uid:
        data.uid || "",
      username:
        clean(
          data.username
        ) || "Unknown User",
      avatar_url:
        clean(
          data.avatar_url
        ),
      text:
        clean(
          data.text ||
          data.content,
          "No reply"
        ),
      created_at:
        data.created_at || null
    };
  });
}

app.get(
  "/api/posts",
  requireFirebase,
  async (req, res) => {
    try {
      const snapshot =
        await firebaseRetry(
          "READ POSTS",
          () => db
            .collection("posts")
            .limit(100)
            .get()
        );

      const posts =
        snapshot.docs.map(doc =>
          publicPost(
            doc.data(),
            doc.id
          )
        );

      res.json({
        posts
      });
    } catch (error) {
      console.error("Posts read error:", error);
      res.status(503).json({
        posts: [],
        error:
          "Posts temporarily unavailable"
      });
    }
  }
);

app.get(
  "/api/posts/:id",
  requireFirebase,
  async (req, res) => {
    try {
      const found =
        await findPost(
          req.params.id
        );

      if (!found) {
        return res.status(404).json({
          found: false,
          post: null,
          replies: [],
          error:
            "Post not found"
        });
      }

      const replies =
        await readReplies(
          found.id
        );

      res.json({
        found: true,
        post:
          publicPost(
            found.data,
            found.id
          ),
        replies
      });
    } catch (error) {
      res.status(503).json({
        found: false,
        post: null,
        replies: [],
        error:
          "Post temporarily unavailable"
      });
    }
  }
);

app.post(
  "/api/posts",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const text =
        clean(
          req.body?.text ||
          req.body?.content
        );

      if (!text) {
        return res.status(400).json({
          success: false,
          error:
            "Post text is required"
        });
      }

      if (text.length > 5000) {
        return res.status(400).json({
          success: false,
          error:
            "Post is too long"
        });
      }

      const profile =
        await findProfile(
          user.uid
        );

      const author =
        profile?.data?.username ||
        profile?.data?.display_name ||
        user.name ||
        "Unknown User";

      const userId =
        profile?.data?.user_id ??
        user.uid;

      const ref =
        db.collection("posts").doc();

      const postData = {
        id: ref.id,
        post_id: ref.id,
        uid: user.uid,
        user_id: userId,
        author,
        username: author,
        avatar_url:
          profile?.data?.avatar_url ||
          "",
        text,
        content: text,
        created_at:
          FieldValue.serverTimestamp(),
        updated_at:
          FieldValue.serverTimestamp()
      };

      const saved =
        await writeDocAndVerify(
          "posts",
          ref.id,
          postData
        );

      res.json({
        success: true,
        post:
          publicPost(
            saved.data(),
            saved.id
          )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Post creation failed"
      });
    }
  }
);

// ============================================================
// REPLIES
// ============================================================

app.post(
  "/api/posts/:id/replies",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const post =
        await findPost(
          req.params.id
        );

      if (!post) {
        return res.status(404).json({
          success: false,
          error:
            "Post not found"
        });
      }

      const text =
        clean(
          req.body?.text ||
          req.body?.content
        );

      if (!text) {
        return res.status(400).json({
          success: false,
          error:
            "Reply text is required"
        });
      }

      if (text.length > 2000) {
        return res.status(400).json({
          success: false,
          error:
            "Reply is too long"
        });
      }

      const profile =
        await findProfile(
          user.uid
        );

      const ref =
        db.collection(
          "post_replies"
        ).doc();

      const replyData = {
        id: ref.id,
        post_id: post.id,
        uid: user.uid,
        user_id:
          profile?.data?.user_id ??
          user.uid,
        username:
          profile?.data?.username ||
          profile?.data?.display_name ||
          user.name ||
          "Unknown User",
        avatar_url:
          profile?.data?.avatar_url ||
          "",
        text,
        content: text,
        created_at:
          FieldValue.serverTimestamp()
      };

      await writeDocAndVerify(
        "post_replies",
        ref.id,
        replyData
      );

      // Read back from Firebase.
      const replies =
        await readReplies(
          post.id
        );

      res.json({
        success: true,
        post_id: post.id,
        replies
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Reply failed after retries"
      });
    }
  }
);

// ============================================================
// FOLLOW
// ============================================================

app.post(
  "/api/profiles/:id/follow",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const target =
        await findProfile(
          req.params.id
        );

      if (!target) {
        return res.status(404).json({
          success: false,
          error:
            "Profile not found"
        });
      }

      if (target.id === user.uid) {
        return res.status(400).json({
          success: false,
          error:
            "You cannot follow yourself"
        });
      }

      const relationshipId =
        `${user.uid}_${target.id}`;

      const existing =
        await readDoc(
          "follows",
          relationshipId
        );

      if (existing.exists) {
        await deleteDocAndVerify(
          "follows",
          relationshipId
        );

        return res.json({
          success: true,
          following: false
        });
      }

      await writeDocAndVerify(
        "follows",
        relationshipId,
        {
          follower_uid:
            user.uid,
          following_uid:
            target.id,
          created_at:
            FieldValue.serverTimestamp()
        }
      );

      res.json({
        success: true,
        following: true
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Follow failed after retries"
      });
    }
  }
);

// ============================================================
// FRIEND
// ============================================================

app.post(
  "/api/profiles/:id/friend",
  requireFirebase,
  async (req, res) => {
    try {
      const user =
        await requireUser(req, res);

      if (!user) return;

      const target =
        await findProfile(
          req.params.id
        );

      if (!target) {
        return res.status(404).json({
          success: false,
          error:
            "Profile not found"
        });
      }

      if (target.id === user.uid) {
        return res.status(400).json({
          success: false,
          error:
            "You cannot friend yourself"
        });
      }

      const users =
        [
          user.uid,
          target.id
        ].sort();

      const relationshipId =
        `${users[0]}_${users[1]}`;

      const existing =
        await readDoc(
          "friends",
          relationshipId
        );

      if (existing.exists) {
        await deleteDocAndVerify(
          "friends",
          relationshipId
        );

        return res.json({
          success: true,
          friends: false
        });
      }

      await writeDocAndVerify(
        "friends",
        relationshipId,
        {
          users,
          created_at:
            FieldValue.serverTimestamp()
        }
      );

      res.json({
        success: true,
        friends: true
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          "Friend action failed after retries"
      });
    }
  }
);

// ============================================================
// GENERIC DATA API — DISABLED
// ============================================================
// A generic collection/id endpoint is intentionally not exposed.
// Firebase Admin bypasses Firestore client security rules, so a
// generic endpoint would turn any authorization mistake into an
// arbitrary database read/write/delete primitive.

app.all("/api/data/:collection/:id", (req, res) => {
  return securityReject(res, 404, "Not Found");
});

// ============================================================
// CONTROL PAGE
// ============================================================
//
// control.html is intentionally served before the normal static
// website handling so it remains reachable in server OFFLINE mode.
// The control API still requires the IP allowlist or secret.

app.get(
  ["/control.html", "/Control.html"],
  controlGuard,
  (req, res) => {
    // control.html itself is PUBLIC and remains reachable even
    // when serverOffline is enabled.
    // The control API endpoints remain protected by controlGuard.
    res.sendFile(
      path.join(__dirname, "control.html")
    );
  }
);

// ============================================================
// PAGE ALIASES
// ============================================================

function sendPage(res, primary, fallback) {
  res.sendFile(
    path.join(__dirname, primary),
    error => {
      if (!error) return;

      res.sendFile(
        path.join(__dirname, fallback)
      );
    }
  );
}

app.get(
  ["/Level.html", "/level.html"],
  (req, res) =>
    sendPage(
      res,
      "Level.html",
      "level.html"
    )
);

app.get(
  ["/Profile.html", "/profile.html"],
  (req, res) =>
    sendPage(
      res,
      "Profile.html",
      "profile.html"
    )
);

app.get(
  ["/Post.html", "/post.html"],
  (req, res) =>
    sendPage(
      res,
      "Post.html",
      "post.html"
    )
);

// ============================================================
// STATIC WEBSITE
// ============================================================

// Never expose server source, environment files, lockfiles, backups,
// service-account files, or other project internals through the static
// file server.
const FORBIDDEN_STATIC_PATHS = [
  /^\/server(?:\.js)?$/i,
  /^\/package(?:-lock)?\.json$/i,
  /^\/\.env(?:\.|$)/i,
  /^\/.*(?:service-account|firebase.*credentials).*\.(?:json|pem|key)$/i,
  /^\/.*\.(?:log|sqlite|db|bak|backup)$/i,
  /^\/_safety_backups(?:\/|$)/i
];

app.use((req, res, next) => {
  if (FORBIDDEN_STATIC_PATHS.some(re => re.test(req.path || ""))) {
    return securityReject(res, 404, "Not Found");
  }
  next();
});

app.use(
  express.static(
    __dirname,
    {
      extensions: ["html"],
      maxAge: 0
    }
  )
);

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "index.html"
    )
  );
});

// ============================================================
// 404
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found"
  });
});

// ============================================================
// PROCESS ERROR HANDLERS
// ============================================================
//
// These stop unexpected promise errors from killing the Render
// process. Individual requests already have their own handlers.
// ============================================================

process.on(
  "unhandledRejection",
  error => {
    console.error(
      "[Process] Unhandled rejection:",
      error
    );
  }
);

process.on(
  "uncaughtException",
  error => {
    console.error(
      "[Process] Uncaught exception:",
      error
    );

    // Do not intentionally process.exit here.
    // Firebase outages and request failures should not kill Render.
  }
);

// ============================================================
// START SERVER
// ============================================================

async function start() {
  // Firebase initialization is attempted once.
  initializeFirebaseOnce();

  // Render becomes reachable even if Firebase is temporarily down.
  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log("========================================");
      console.log(
        `${SERVICE_NAME} server started`
      );
      console.log(`Port: ${PORT}`);
      console.log(
        "Server: ONLINE"
      );
      console.log(
        `Firebase retries: ${FIREBASE_RETRIES}`
      );
      console.log(
        `Firebase timeout: ${FIREBASE_TIMEOUT_MS}ms`
      );
      console.log(
        `Firebase watchdog: ${FIREBASE_WATCHDOG_MS}ms`
      );
      console.log(
        "Firebase write verification: ENABLED"
      );
      console.log("Security headers: ENABLED");
      console.log("Traffic shield: ENABLED");
      console.log(`Max request body: ${MAX_REQUEST_BODY_BYTES} bytes`);
      console.log(`Rate limit: ${RATE_LIMIT_PER_WINDOW}/${RATE_WINDOW_MS}ms per client`);
      console.log("Emergency safe mode: ENABLED");
      console.log("Safety backups: ENABLED");
      console.log(`Safety backup required: ${SAFETY_BACKUP_REQUIRED}`);
      console.log("Application HTTPS: Render TLS termination + HSTS");
      console.log(
        "Control panel: ENABLED"
      );
      console.log(
        `Control allowed IPs: ${CONTROL_ALLOWED_IPS.join(", ")}`
      );
      console.log(
        "Render suspension: DISABLED by design"
      );
      console.log("========================================");
    }
  );

  // Test Firebase after the HTTP server is listening.
  // This means Firebase being down cannot prevent Render from
  // starting the web server.
  await startupFirebaseTest();

  startFirebaseWatchdog();
}

start().catch(error => {
  // Last-resort protection: the web process stays alive.
  console.error(
    "[LBA] Startup protection caught an error:",
    error
  );

  if (!firebaseReady) {
    console.log(
      "Firebase: OFFLINE"
    );
    console.log(
      "Server: ONLINE"
    );
    console.log(
      "Watchdog: RECONNECTING"
    );
  }

  startFirebaseWatchdog();
});
