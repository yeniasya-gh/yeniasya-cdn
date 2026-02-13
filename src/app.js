"use strict";

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const { setTimeout: sleep } = require("timers/promises");
const nodemailer = require("nodemailer");
const axios = require("axios");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 3001;
const AUTH_TOKEN = process.env.AUTH_TOKEN || "";
// Resolve to absolute path so sendFile receives an absolute path.
const STORAGE_ROOT = path.resolve(
  process.env.STORAGE_ROOT || path.join(__dirname, "..", "storage")
);
const TMP_DIR = path.join(STORAGE_ROOT, "_tmp");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const ALLOWED_HEADERS =
  process.env.ALLOWED_HEADERS || "content-type, x-api-key, authorization";
const ALLOWED_METHODS = "GET, POST, OPTIONS";
const VIEW_TOKEN_SECRET = process.env.VIEW_TOKEN_SECRET || "";
const VIEW_TOKEN_TTL_MIN = Number(process.env.VIEW_TOKEN_TTL_MIN || "5");
const FRAME_ANCESTORS = (process.env.ALLOWED_FRAME_ANCESTORS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const FRAME_ANCESTORS_DIRECTIVE =
  FRAME_ANCESTORS.length === 0 ? "'none'" : FRAME_ANCESTORS.join(" ");
const PUBLIC_ROOT = path.join(__dirname, "..", "public");
const MAIL_SETTINGS = {
  host: process.env.MAIL_HOST || "",
  port: Number(process.env.MAIL_PORT || "587"),
  user: process.env.MAIL_USER || "",
  pass: process.env.MAIL_PASS || "",
  from: process.env.MAIL_FROM || "",
  token: process.env.MAIL_API_TOKEN || "",
};
const PAYMENT_RETURN_REDIRECT_URL = process.env.PAYMENT_RETURN_REDIRECT_URL || "";
const PARATIKA_BASE_URL =
  process.env.PARATIKA_BASE_URL || "https://vpos.paratika.com.tr/paratika/api/v2";
const PARATIKA_MERCHANTUSER = process.env.PARATIKA_MERCHANTUSER || "";
const PARATIKA_MERCHANTPASSWORD = process.env.PARATIKA_MERCHANTPASSWORD || "";
const PARATIKA_MERCHANT = process.env.PARATIKA_MERCHANT || "";
const PARATIKA_RETURNURL = process.env.PARATIKA_RETURNURL || "";
const PARATIKA_COOKIE = process.env.PARATIKA_COOKIE || "";
const BUNNY_SETTINGS = {
  cdnUrl: process.env.BUNNY_CDN_URL || "yeniasya.b-cdn.net",
  storageZone: process.env.BUNNY_STORAGE_ZONE || "yeniasya",
  accessKey: process.env.BUNNY_ACCESS_KEY || "",
};
const BUNNY_HTTP_TIMEOUT_MS = Number(process.env.BUNNY_HTTP_TIMEOUT_MS || "20000");
const BUNNY_HTTP_RETRIES = Number(process.env.BUNNY_HTTP_RETRIES || "1");
const BUNNY_HTTP_RETRY_BASE_DELAY_MS = Number(
  process.env.BUNNY_HTTP_RETRY_BASE_DELAY_MS || "400"
);
const BUNNY_STREAM_FIRST_BYTE_TIMEOUT_MS = Number(
  process.env.BUNNY_STREAM_FIRST_BYTE_TIMEOUT_MS || "15000"
);
const BUNNY_STREAM_IDLE_TIMEOUT_MS = Number(process.env.BUNNY_STREAM_IDLE_TIMEOUT_MS || "30000");
const BUNNY_DEBUG = (process.env.BUNNY_DEBUG || "").toLowerCase() === "true";
const ENABLE_BASE64_VIEWER =
  (process.env.ENABLE_BASE64_VIEWER || "").toLowerCase() === "true";
const MAX_BASE64_VIEW_BYTES = Number(process.env.MAX_BASE64_VIEW_BYTES || "5242880");
const HASURA_ENDPOINT = process.env.HASURA_ENDPOINT || "";
const HASURA_ADMIN_SECRET = process.env.HASURA_ADMIN_SECRET || "";
const HASURA_ALLOW_JWTLESS =
  (process.env.HASURA_ALLOW_JWTLESS || "").toLowerCase() === "true";
const JWT_SECRET = process.env.JWT_SECRET || "";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1d";
const JWT_ISSUER = process.env.JWT_ISSUER || "yeniasya";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "yeniasya-app";
const JWT_DEFAULT_ROLE = process.env.JWT_DEFAULT_ROLE || "user";
const JWT_ALLOWED_ROLES = (process.env.JWT_ALLOWED_ROLES || JWT_DEFAULT_ROLE)
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const GUEST_AUTH_USERNAME = process.env.GUEST_AUTH_USERNAME || "yeniasyaguest";
const GUEST_AUTH_PASSWORD =
  process.env.GUEST_AUTH_PASSWORD || "yeniasya.guest.pass.2026";
const REVENUECAT_ENTITLEMENT_ACCESS = {
  "yeniasya pro": { itemType: "newspaper_subscription", itemId: null },
};
const REVENUECAT_API_BASE_URL = (
  process.env.REVENUECAT_API_BASE_URL || "https://api.revenuecat.com/v1"
).replace(/\/+$/, "");
const REVENUECAT_SECRET_API_KEY =
  process.env.REVENUECAT_SECRET_API_KEY || process.env.REVENUECAT_REST_API_KEY || "";
const REVENUECAT_HTTP_TIMEOUT_MS = Number(process.env.REVENUECAT_HTTP_TIMEOUT_MS || "10000");

const bunnyHttp = axios.create({
  baseURL: `https://storage.bunnycdn.com/${BUNNY_SETTINGS.storageZone}`,
  timeout: BUNNY_HTTP_TIMEOUT_MS,
  headers: {
    AccessKey: BUNNY_SETTINGS.accessKey,
  },
  httpsAgent: new https.Agent({
    keepAlive: true,
    keepAliveMsecs: 30_000,
    maxSockets: 64,
    maxFreeSockets: 16,
  }),
});

const isRetryableBunnyError = (err) => {
  const status = err?.response?.status;
  if (Number.isInteger(status)) {
    return [429, 500, 502, 503, 504].includes(status);
  }
  const code = err?.code;
  return [
    "ECONNABORTED",
    "ECONNRESET",
    "EAI_AGAIN",
    "ENOTFOUND",
    "ETIMEDOUT",
    "ECONNREFUSED",
  ].includes(code);
};

const bunnyRequest = async (config, { retries = BUNNY_HTTP_RETRIES } = {}) => {
  let attempt = 0;
  for (;;) {
    const start = process.hrtime.bigint();
    try {
      const response = await bunnyHttp.request({
        ...config,
        validateStatus: () => true,
      });

      const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;
      if (BUNNY_DEBUG) {
        console.log(
          `[bunny] ${config.method || "GET"} ${config.url} -> ${response.status} (${durationMs.toFixed(
            1
          )}ms, attempt ${attempt + 1}/${retries + 1})`
        );
      }

      if (response.status >= 200 && response.status < 300) return response;
      const err = new Error(`BunnyCDN request failed (${response.status})`);
      err.response = response;
      throw err;
    } catch (err) {
      const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;
      const canRetry = attempt < retries && isRetryableBunnyError(err);
      if (BUNNY_DEBUG) {
        console.warn(
          `[bunny] ${config.method || "GET"} ${config.url} failed (${durationMs.toFixed(
            1
          )}ms, attempt ${attempt + 1}/${retries + 1}): ${err?.message}`
        );
      }
      if (!canRetry) throw err;
      const delayMs = BUNNY_HTTP_RETRY_BASE_DELAY_MS * 2 ** attempt;
      attempt += 1;
      await sleep(delayMs);
    }
  }
};

const PUBLIC_TYPES = ["kitap", "gazete", "dergi", "ek", "slider"];
const PRIVATE_TYPES = ["kitap", "gazete", "dergi", "ek"];

const parsePrivatePath = (input) => {
  if (!input) return null;
  const cleaned = String(input).trim();
  // Match /private/type/file OR /type/private/file
  let type, filename;

  const m1 = cleaned.match(/^\/?private\/([a-z0-9_-]+)\/([^/]+)$/i);
  const m2 = cleaned.match(/^\/?([a-z0-9_-]+)\/private\/([^/]+)$/i);

  if (m1) {
    type = m1[1].toLowerCase();
    filename = m1[2];
  } else if (m2) {
    type = m2[1].toLowerCase();
    filename = m2[2];
  } else {
    return null;
  }

  // Basic validation
  if (!type || !filename) return null;

  // Optional: check if type is allowed
  // if (!PRIVATE_TYPES.includes(type)) return null;

  return { type, filename };
};

const logPdfRequest = ({
  req,
  scope,
  route,
  action,
  type,
  filename,
  status,
  outcome,
  message,
  error,
}) => {
  const header = (key) =>
    req && typeof req.get === "function" ? req.get(key) : undefined;
  const payload = {
    ts: new Date().toISOString(),
    scope,
    route,
    action,
    method: req?.method,
    path: req?.originalUrl || req?.url,
    status,
    type,
    filename,
    ip: req?.ip,
    referer: header("referer") || header("origin"),
    ua: header("user-agent"),
    message: message || error?.message,
  };
  const line = `[pdf] ${JSON.stringify(payload)}`;
  if (outcome === "error") {
    if (error?.stack) {
      console.error(line, error.stack);
    } else {
      console.error(line);
    }
  } else {
    console.log(line);
  }
};

const paths = {
  kitap: {
    public: path.join(STORAGE_ROOT, "kitap", "public"),
    private: path.join(STORAGE_ROOT, "kitap", "private"),
  },
  gazete: {
    public: path.join(STORAGE_ROOT, "gazete", "public"),
    private: path.join(STORAGE_ROOT, "gazete", "private"),
  },
  dergi: {
    public: path.join(STORAGE_ROOT, "dergi", "public"),
    private: path.join(STORAGE_ROOT, "dergi", "private"),
  },
  ek: {
    public: path.join(STORAGE_ROOT, "ek", "public"),
    private: path.join(STORAGE_ROOT, "ek", "private"),
  },
  slider: {
    public: path.join(STORAGE_ROOT, "slider", "public"),
  },
};

const app = express();

// Basic request/response logger to surface hung/slow requests.
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${durationMs.toFixed(
        1
      )}ms)`
    );
  });
  next();
});

function ensureDirs() {
  Object.values(paths).forEach((config) => {
    Object.values(config).forEach((dirPath) => {
      fs.mkdirSync(dirPath, { recursive: true });
    });
  });
  fs.mkdirSync(TMP_DIR, { recursive: true });
}

ensureDirs();

const prewarmBunnyConnection = () => {
  if (!BUNNY_SETTINGS.accessKey || !BUNNY_SETTINGS.storageZone) return;
  bunnyHttp
    .get("/", { validateStatus: () => true })
    .catch((err) => console.warn("[bunny] prewarm failed:", err?.message));
};

prewarmBunnyConnection();

const fileFilter = (req, file, cb) => {
  const ok =
    file.mimetype === "application/pdf" ||
    file.mimetype === "image/jpeg" ||
    file.mimetype === "image/png" ||
    file.mimetype === "image/webp";

  if (!ok) {
    return cb(
      new Error("Only pdf, jpg, png, or webp files are allowed for uploads.")
    );
  }

  cb(null, true);
};

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 }, // Increased limit for BunnyCDN uploads
});

const mustHaveEnv = (key, value) => {
  if (value && String(value).trim()) return;
  throw new Error(`Missing required env var: ${key}`);
};

const assertRequiredEnv = () => {
  mustHaveEnv("AUTH_TOKEN", AUTH_TOKEN);
  mustHaveEnv("VIEW_TOKEN_SECRET", VIEW_TOKEN_SECRET);
  mustHaveEnv("HASURA_ENDPOINT", HASURA_ENDPOINT);
  mustHaveEnv("HASURA_ADMIN_SECRET", HASURA_ADMIN_SECRET);
  mustHaveEnv("JWT_SECRET", JWT_SECRET);
};

assertRequiredEnv();

const requireAuth = (req, res, next) => {
  const raw = req.get("x-api-key") || req.get("authorization") || "";
  const token = raw.toLowerCase().startsWith("bearer ")
    ? raw.slice(7)
    : raw;

  if (!token || token !== AUTH_TOKEN) {
    if ((req.path || "").startsWith("/private")) {
      logPdfRequest({
        req,
        scope: "private",
        route: req.path,
        action: "auth-check",
        status: 401,
        outcome: "error",
        message: "Unauthorized request.",
      });
    }
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }

  next();
};

const requireMailAuth = (req, res, next) => {
  const raw = req.get("x-mail-token") || req.get("authorization") || req.get("x-api-key") || "";
  const token = raw.toLowerCase().startsWith("bearer ")
    ? raw.slice(7)
    : raw;
  if (!token || token !== MAIL_SETTINGS.token) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
};

const resolveType = (req, allowedTypes) => {
  const type = (req.body?.type || req.query?.type || "").toLowerCase();
  if (!allowedTypes.includes(type)) {
    return null;
  }
  return type;
};

const normalizeJsonField = (value) => {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return null;
    // Allow pre-encoded JSON strings from x-www-form-urlencoded clients.
    if (/%[0-9A-Fa-f]{2}/.test(trimmed)) {
      try {
        const decoded = decodeURIComponent(trimmed);
        if (decoded) return decoded;
      } catch (err) {
        return trimmed;
      }
    }
    return trimmed;
  }
  try {
    return JSON.stringify(value);
  } catch (err) {
    return null;
  }
};

const formEncode = (payload) =>
  Object.entries(payload)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`
    )
    .join("&");

const buildPayPayload = (body) => {
  const pick = (...keys) => {
    for (const key of keys) {
      const value = body[key];
      if (value !== undefined && value !== null && value !== "") {
        return value;
      }
    }
    return undefined;
  };

  const sessionToken = pick("SESSIONTOKEN", "sessionToken", "token");
  const cardPanRaw = pick("CARDPAN", "cardPan", "pan");
  const cardExpiryRaw = pick("CARDEXPIRY", "cardExpiry");
  const cardExpiryMonth = pick("expiryMonth", "EXPIRYMONTH");
  const cardExpiryYear = pick("expiryYear", "EXPIRYYEAR");
  const cardCvv = pick("CARDCVV", "cardCvv", "cvv");
  const nameOnCard = pick("NAMEONCARD", "nameOnCard", "cardOwner");
  const cardToken = pick("cardToken", "CARDTOKEN");

  const missing = [];
  if (!sessionToken) missing.push("SESSIONTOKEN");
  if (!cardToken && !cardPanRaw) missing.push("CARDPAN");
  if (!cardToken && !cardExpiryRaw && !(cardExpiryMonth && cardExpiryYear))
    missing.push("CARDEXPIRY");
  if (!cardToken && !cardCvv) missing.push("CARDCVV");
  if (!cardToken && !nameOnCard) missing.push("NAMEONCARD");

  if (missing.length) {
    return { ok: false, error: `Missing required fields: ${missing.join(", ")}` };
  }

  const cardPan = cardPanRaw ? String(cardPanRaw).replace(/\s+/g, "") : "";
  let cardExpiry = cardExpiryRaw ? String(cardExpiryRaw) : "";
  if (!cardExpiry && cardExpiryMonth && cardExpiryYear) {
    const month = String(cardExpiryMonth).padStart(2, "0");
    const yearRaw = String(cardExpiryYear);
    const year = yearRaw.length === 4 ? yearRaw.slice(-2) : yearRaw;
    cardExpiry = `${month}${year}`;
  }

  const requestPayload = {
    CARDPAN: cardPan,
    CARDEXPIRY: cardExpiry,
    CARDCVV: cardCvv,
    NAMEONCARD: nameOnCard,
    pan: cardPan,
    cvv: cardCvv,
    cardOwner: nameOnCard,
    expiryMonth: cardExpiry ? cardExpiry.slice(0, 2) : undefined,
    expiryYear: cardExpiry ? `20${cardExpiry.slice(2)}` : undefined,
    cardToken: cardToken,
    installmentCount: pick("installmentCount", "INSTALLMENTCOUNT"),
    saveCard: pick("saveCard", "SAVECARD"),
    cardName: pick("cardName", "CARDNAME"),
    points: pick("points", "POINTS"),
    paymentSystem: pick("paymentSystem", "PAYMENTSYSTEM"),
  };

  return { ok: true, sessionToken, requestPayload };
};

const requestParatikaPay = async (sessionToken, requestPayload) => {
  const endpoint = new URL(PARATIKA_BASE_URL);
  endpoint.pathname = `${endpoint.pathname.replace(
    /\/+$/,
    ""
  )}/post/sale3d/${encodeURIComponent(String(sessionToken))}`;

  const data = formEncode(requestPayload);
  return axios.request({
    method: "post",
    maxBodyLength: Infinity,
    url: endpoint.toString(),
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(PARATIKA_COOKIE ? { Cookie: PARATIKA_COOKIE } : {}),
      Accept: "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      Connection: "keep-alive",
      "User-Agent": "PostmanRuntime/7.36.0",
    },
    data,
  });
};

const requestParatika = (payload, extraHeaders = {}) => {
  const endpoint = new URL(PARATIKA_BASE_URL);
  const body = payload.toString();
  const transport = endpoint.protocol === "http:" ? require("http") : require("https");

  const options = {
    method: "POST",
    hostname: endpoint.hostname,
    port: endpoint.port || (endpoint.protocol === "http:" ? 80 : 443),
    path: endpoint.pathname,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(body),
      ...extraHeaders,
    },
  };

  return new Promise((resolve, reject) => {
    const req = transport.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => {
        data += chunk;
      });
      resp.on("end", () => {
        if (!data) {
          return resolve({ status: resp.statusCode, raw: "" });
        }
        try {
          return resolve({ status: resp.statusCode, data: JSON.parse(data) });
        } catch (err) {
          return resolve({ status: resp.statusCode, raw: data });
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
};

const postLocalJson = (pathName, payload, headers = {}) =>
  new Promise((resolve, reject) => {
    const body = JSON.stringify(payload || {});
    const req = require("http").request(
      {
        method: "POST",
        hostname: "127.0.0.1",
        port: PORT,
        path: pathName,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          ...headers,
        },
      },
      (resp) => {
        let data = "";
        resp.on("data", (chunk) => {
          data += chunk;
        });
        resp.on("end", () => {
          if (!data) {
            return resolve({ status: resp.statusCode, raw: "" });
          }
          try {
            return resolve({ status: resp.statusCode, data: JSON.parse(data) });
          } catch (err) {
            return resolve({ status: resp.statusCode, raw: data });
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });

const smtpHost = (MAIL_SETTINGS.host || "").trim().replace(/\.$/, "");
const mailTransporter = nodemailer.createTransport({
  host: smtpHost,
  port: MAIL_SETTINGS.port,
  secure: MAIL_SETTINGS.port === 465,
  auth: {
    user: MAIL_SETTINGS.user,
    pass: MAIL_SETTINGS.pass,
  },
  tls: {
    // Allow self-signed / mismatched certs (needed for current smtp cert).
    rejectUnauthorized:
      process.env.MAIL_TLS_REJECT_UNAUTHORIZED === "false" ? false : true,
    servername: smtpHost,
  },
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const requestOrigin = req.get("origin");
  const originAllowed =
    ALLOWED_ORIGINS.includes("*") ||
    (requestOrigin && ALLOWED_ORIGINS.includes(requestOrigin));

  if (originAllowed) {
    res.set("Access-Control-Allow-Origin", requestOrigin || "*");
  }
  res.set("Access-Control-Allow-Methods", ALLOWED_METHODS);
  res.set("Access-Control-Allow-Headers", ALLOWED_HEADERS);

  next();
});

app.use(express.static(PUBLIC_ROOT));

app.get("/privacy", (req, res) => {
  return res.sendFile(path.join(PUBLIC_ROOT, "privacy.html"));
});

const buildCorsHeaders = (req) => {
  const requestOrigin = req.get("origin");
  const originAllowed =
    ALLOWED_ORIGINS.includes("*") ||
    (requestOrigin && ALLOWED_ORIGINS.includes(requestOrigin));

  if (!originAllowed) return {};

  return {
    "Access-Control-Allow-Origin": requestOrigin || "*",
    "Access-Control-Allow-Methods": ALLOWED_METHODS,
    "Access-Control-Allow-Headers": ALLOWED_HEADERS,
  };
};

const hasuraRequest = async (query, variables = {}) => {
  const response = await axios.post(
    HASURA_ENDPOINT,
    { query, variables },
    {
      headers: {
        "Content-Type": "application/json",
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
      },
      validateStatus: () => true,
    }
  );

  if (response.status !== 200) {
    throw new Error(`Hasura HTTP ${response.status}`);
  }

  if (response.data?.errors?.length) {
    const msg = response.data.errors[0]?.message || "Hasura error";
    throw new Error(msg);
  }

  return response.data?.data;
};

const buildJwt = (user) => {
  const userId = String(user.id);
  const roles = JWT_ALLOWED_ROLES.includes(JWT_DEFAULT_ROLE)
    ? JWT_ALLOWED_ROLES
    : [JWT_DEFAULT_ROLE, ...JWT_ALLOWED_ROLES];
  const payload = {
    sub: userId,
    name: user.name || undefined,
    email: user.email || undefined,
    "https://hasura.io/jwt/claims": {
      "x-hasura-default-role": JWT_DEFAULT_ROLE,
      "x-hasura-allowed-roles": roles,
      "x-hasura-user-id": userId,
    },
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });

  const decoded = jwt.decode(token);
  const expiresAt =
    decoded && typeof decoded === "object" && decoded.exp
      ? new Date(decoded.exp * 1000).toISOString()
      : null;

  return { token, expiresAt };
};

const normalizeEmail = (value) => String(value || "").trim().toLowerCase();
const hashPassword = (value) =>
  crypto.createHash("sha256").update(String(value || "")).digest("hex");
const normalizeRevenueCatAppUserId = (value) => {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  return normalized || null;
};
const toPositiveIntOrNull = (value) => {
  if (value === undefined || value === null || value === "") return null;
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
};
const toIsoTimestampOrNull = (value) => {
  const normalized = normalizeRevenueCatAppUserId(value);
  if (!normalized) return null;
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
};
const toBool = (value) => {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value === 1;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized === "true" || normalized === "1" || normalized === "yes";
  }
  return false;
};
const verifyJwtToken = (token) =>
  jwt.verify(token, JWT_SECRET, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
const extractJwtUserId = (payload) => {
  const claims = payload?.["https://hasura.io/jwt/claims"] || {};
  const rawId = claims["x-hasura-user-id"] ?? payload?.sub;
  return toPositiveIntOrNull(rawId);
};
const isHasuraVariableTypeMismatch = (err, variableName, expectedType) => {
  const message = String(err?.message || "").toLowerCase();
  const variableKey = String(variableName || "").toLowerCase();
  const expectedKey = String(expectedType || "").toLowerCase();
  if (!message || !variableKey || !expectedKey) return false;
  return (
    message.includes(`variable '${variableKey}'`) &&
    message.includes("is declared as") &&
    message.includes("used where") &&
    message.includes(`'${expectedKey}'`)
  );
};

const requireJwt = (req, res, next) => {
  const raw = req.get("authorization") || "";
  const token = raw.toLowerCase().startsWith("bearer ") ? raw.slice(7) : raw;
  if (!token) {
    return res.status(401).json({ ok: false, error: "Missing token." });
  }
  try {
    const payload = verifyJwtToken(token);
    req.jwt = payload;
    req.jwtToken = token;
    return next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Invalid token." });
  }
};

const optionalJwt = (req, res, next) => {
  if (!HASURA_ALLOW_JWTLESS) {
    return requireJwt(req, res, next);
  }
  const raw = req.get("authorization") || "";
  const token = raw.toLowerCase().startsWith("bearer ") ? raw.slice(7) : raw;
  if (!token) {
    return next();
  }
  try {
    const payload = verifyJwtToken(token);
    req.jwt = payload;
    req.jwtToken = token;
    return next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Invalid token." });
  }
};

const requireRevenueCatAuth = (req, res, next) => {
  const authHeader = req.get("authorization") || "";
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";

  if (bearerToken) {
    try {
      const payload = verifyJwtToken(bearerToken);
      req.jwt = payload;
      req.jwtToken = bearerToken;
      req.revenueCatAuthMode = "jwt";
      return next();
    } catch (err) {
      // fall back to service token validation
    }
  }

  const serviceRaw = req.get("x-api-key") || authHeader || "";
  const serviceToken = serviceRaw.toLowerCase().startsWith("bearer ")
    ? serviceRaw.slice(7).trim()
    : serviceRaw.trim();

  if (serviceToken && serviceToken === AUTH_TOKEN) {
    req.revenueCatAuthMode = "service";
    return next();
  }

  return res.status(401).json({ ok: false, error: "Unauthorized." });
};

const buildHasuraAuthHeaders = (req) => {
  if (req?.jwtToken) {
    return { Authorization: `Bearer ${req.jwtToken}` };
  }
  if (HASURA_ALLOW_JWTLESS && HASURA_ADMIN_SECRET) {
    return { "x-hasura-admin-secret": HASURA_ADMIN_SECRET };
  }
  return {};
};

app.post("/auth/register", async (req, res) => {
  const requestId = crypto.randomUUID();
  const emailForLog = normalizeEmail(req.body?.email);
  console.log(
    `[auth][register][start] id=${requestId} ip=${req.ip} email=${emailForLog}`
  );
  try {
    const name = String(req.body?.name || "").trim();
    const email = normalizeEmail(req.body?.email);
    const phone = req.body?.phone ? String(req.body.phone).trim() : null;
    const password = String(req.body?.password || "");

    if (!name || !email || !password) {
      console.warn(
        `[auth][register][bad-request] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res
        .status(400)
        .json({ ok: false, error: "name, email, password are required." });
    }
    if (password.length < 8) {
      console.warn(
        `[auth][register][weak-password] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(400).json({ ok: false, error: "Password is too short." });
    }

    const existing = await hasuraRequest(
      `
        query GetUserByEmail($email: String!) {
          users(where: {email: {_eq: $email}}, limit: 1) {
            id
          }
        }
      `,
      { email }
    );
    if (existing?.users?.length) {
      console.warn(
        `[auth][register][exists] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(409).json({ ok: false, error: "Email already in use." });
    }

    const passwordHash = hashPassword(password);
    const payUniqe = crypto.randomUUID();
    const created = await hasuraRequest(
      `
        mutation CreateUser($object: users_insert_input!) {
          insert_users_one(object: $object) {
            id
            name
            email
            phone
            payUniqe
            role_id
          }
        }
      `,
      {
        object: {
          name,
          email,
          phone,
          password: passwordHash,
          payUniqe,
        },
      }
    );

    const user = created?.insert_users_one;
    if (!user) {
      return res.status(500).json({ ok: false, error: "User creation failed." });
    }

    const { token, expiresAt } = buildJwt(user);
    console.log(
      `[auth][register][success] id=${requestId} ip=${req.ip} email=${email} userId=${user.id}`
    );
    return res.json({ ok: true, user, token, expiresAt });
  } catch (err) {
    console.error(
      `[auth][register][error] id=${requestId} ip=${req.ip} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({ ok: false, error: err.message || "Register failed." });
  }
});

app.post("/auth/login", async (req, res) => {
  const requestId = crypto.randomUUID();
  const emailForLog = normalizeEmail(req.body?.email);
  console.log(
    `[auth][login][start] id=${requestId} ip=${req.ip} email=${emailForLog}`
  );
  try {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");
    if (!email || !password) {
      console.warn(
        `[auth][login][bad-request] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(400).json({ ok: false, error: "email and password are required." });
    }

    const data = await hasuraRequest(
      `
        query GetUserByEmail($email: String!) {
          users(where: {email: {_eq: $email}}, limit: 1) {
            id
            name
            email
            phone
            payUniqe
            role_id
            password
          }
        }
      `,
      { email }
    );
    const user = data?.users?.[0];
    if (!user || !user.password) {
      console.warn(
        `[auth][login][invalid] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(401).json({ ok: false, error: "Invalid credentials." });
    }

    const ok = hashPassword(password) === user.password;
    if (!ok) {
      console.warn(
        `[auth][login][invalid] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(401).json({ ok: false, error: "Invalid credentials." });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      payUniqe: user.payUniqe,
      role_id: user.role_id,
    };
    const { token, expiresAt } = buildJwt(safeUser);
    console.log(
      `[auth][login][success] id=${requestId} ip=${req.ip} email=${email} userId=${safeUser.id}`
    );
    return res.json({ ok: true, user: safeUser, token, expiresAt });
  } catch (err) {
    console.error(
      `[auth][login][error] id=${requestId} ip=${req.ip} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({ ok: false, error: err.message || "Login failed." });
  }
});

app.post("/auth/guest-token", (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  if (!username || !password) {
    return res
      .status(400)
      .json({ ok: false, error: "username and password are required." });
  }
  if (username !== GUEST_AUTH_USERNAME || password !== GUEST_AUTH_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Invalid credentials." });
  }

  const guestUser = {
    id: "guest",
    name: "Guest",
    email: null,
  };
  const { token, expiresAt } = buildJwt(guestUser);
  return res.json({
    ok: true,
    user: { id: guestUser.id, name: guestUser.name },
    token,
    expiresAt,
  });
});

app.post("/graphql", optionalJwt, async (req, res) => {
  try {
    const { query, variables, operationName } = req.body || {};
    if (!query) {
      return res.status(400).json({ ok: false, error: "query is required." });
    }

    const response = await axios.post(
      HASURA_ENDPOINT,
      { query, variables, operationName },
      {
        headers: {
          "Content-Type": "application/json",
          ...buildHasuraAuthHeaders(req),
        },
        validateStatus: () => true,
      }
    );

    res.status(response.status);
    if (response.headers?.["content-type"]) {
      res.set("Content-Type", response.headers["content-type"]);
    }
    return res.send(response.data);
  } catch (err) {
    return res.status(500).json({ ok: false, error: "Hasura proxy failed." });
  }
});

app.post("/hasura", optionalJwt, async (req, res) => {
  try {
    const { query, variables, operationName } = req.body || {};
    if (!query) {
      return res.status(400).json({ ok: false, error: "query is required." });
    }

    const response = await axios.post(
      HASURA_ENDPOINT,
      { query, variables, operationName },
      {
        headers: {
          "Content-Type": "application/json",
          "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        },
        validateStatus: () => true,
      }
    );

    res.status(response.status);
    if (response.headers?.["content-type"]) {
      res.set("Content-Type", response.headers["content-type"]);
    }
    return res.send(response.data);
  } catch (err) {
    return res.status(500).json({ ok: false, error: "Hasura admin proxy failed." });
  }
});

const findUserById = async (userId) => {
  const data = await hasuraRequest(
    `
      query GetUserById($id: bigint!) {
        users_by_pk(id: $id) {
          id
          name
          email
          phone
          role_id
          payUniqe
        }
      }
    `,
    { id: userId }
  );
  return data?.users_by_pk || null;
};

const findUserByPayUniqe = async (payUniqe) => {
  const runLookup = async (value, gqlType) => {
    const data = await hasuraRequest(
      `
        query GetUserByPayUniqe($payUniqe: ${gqlType}) {
          users(where: {payUniqe: {_eq: $payUniqe}}, limit: 2) {
            id
            name
            email
            phone
            role_id
            payUniqe
          }
        }
      `,
      { payUniqe: value }
    );
    const users = data?.users || [];
    if (users.length > 1) {
      const err = new Error("payUniqe is not unique in users table.");
      err.statusCode = 409;
      throw err;
    }
    return users[0] || null;
  };

  try {
    return await runLookup(payUniqe, "String!");
  } catch (err) {
    if (!isHasuraVariableTypeMismatch(err, "payUniqe", "bigint")) {
      throw err;
    }
    const asBigint = toPositiveIntOrNull(payUniqe);
    if (!asBigint) return null;
    return runLookup(asBigint, "bigint!");
  }
};

const setUserPayUniqe = async (userId, payUniqe) => {
  const runUpdate = async (value, gqlType) => {
    const data = await hasuraRequest(
      `
        mutation UpdateUserPayUniqe($id: bigint!, $payUniqe: ${gqlType}) {
          update_users_by_pk(pk_columns: {id: $id}, _set: {payUniqe: $payUniqe}) {
            id
            payUniqe
          }
        }
      `,
      { id: userId, payUniqe: value }
    );
    return data?.update_users_by_pk || null;
  };

  try {
    return await runUpdate(payUniqe, "String!");
  } catch (err) {
    if (!isHasuraVariableTypeMismatch(err, "payUniqe", "bigint")) {
      throw err;
    }
    const asBigint = toPositiveIntOrNull(payUniqe);
    if (!asBigint) {
      const mismatchErr = new Error("payUniqe must be numeric for current schema.");
      mismatchErr.statusCode = 400;
      throw mismatchErr;
    }
    return runUpdate(asBigint, "bigint!");
  }
};

const resolveRevenueCatUser = async ({
  userId,
  appUserId,
  allowPayUniqeRelink = false,
}) => {
  const normalizedUserId = toPositiveIntOrNull(userId);
  const normalizedAppUserId = normalizeRevenueCatAppUserId(appUserId);

  let userById = null;
  let userByPayUniqe = null;
  if (normalizedUserId) {
    userById = await findUserById(normalizedUserId);
  }
  if (normalizedAppUserId) {
    if (userById) {
      // Ownership check: appUserId must not already belong to a different user.
      userByPayUniqe = await findUserByPayUniqe(normalizedAppUserId);
    } else {
      userByPayUniqe = await findUserByPayUniqe(normalizedAppUserId);
    }
  }

  if (userById && userByPayUniqe && Number(userById.id) !== Number(userByPayUniqe.id)) {
    const err = new Error("userId and appUserId belong to different users.");
    err.statusCode = 409;
    throw err;
  }

  const user = userById || userByPayUniqe;
  if (!user) {
    const err = new Error("User not found for provided userId/appUserId.");
    err.statusCode = 404;
    throw err;
  }

  const currentPayUniqe = normalizeRevenueCatAppUserId(user.payUniqe);
  if (normalizedAppUserId && currentPayUniqe && normalizedAppUserId !== currentPayUniqe) {
    if (!allowPayUniqeRelink) {
      const err = new Error("appUserId does not match user's payUniqe.");
      err.statusCode = 409;
      throw err;
    }
  }

  const resolvedAppUserId = normalizedAppUserId || currentPayUniqe || String(user.id);
  if (!currentPayUniqe || currentPayUniqe !== resolvedAppUserId) {
    try {
      const updated = await setUserPayUniqe(user.id, resolvedAppUserId);
      if (updated?.payUniqe) {
        user.payUniqe = updated.payUniqe;
      }
    } catch (err) {
      // Do not fail entitlement sync if identity persistence is incompatible with schema.
      console.warn(
        `[revenuecat][link-warning] userId=${user.id} appUserId=${resolvedAppUserId} msg=${err.message}`
      );
    }
  }

  return {
    userId: Number(user.id),
    appUserId: resolvedAppUserId,
    user,
  };
};

const getEntitlementFromSubscriber = (subscriberEntitlements, entitlementId) => {
  const targetKey = String(entitlementId || "").trim().toLowerCase();
  if (!targetKey || !subscriberEntitlements || typeof subscriberEntitlements !== "object") {
    return null;
  }

  const direct = subscriberEntitlements[entitlementId];
  if (direct) return direct;

  for (const [key, value] of Object.entries(subscriberEntitlements)) {
    if (String(key).trim().toLowerCase() === targetKey) {
      return value;
    }
  }

  return null;
};

const fetchRevenueCatEntitlementState = async ({ appUserId, entitlementId }) => {
  if (!appUserId) {
    return {
      checked: false,
      source: "payload",
      reason: "missing_app_user_id",
    };
  }
  if (!REVENUECAT_SECRET_API_KEY) {
    return {
      checked: false,
      source: "payload",
      reason: "missing_revenuecat_secret_key",
    };
  }

  const url = `${REVENUECAT_API_BASE_URL}/subscribers/${encodeURIComponent(appUserId)}`;
  const response = await axios.get(url, {
    headers: {
      Authorization: `Bearer ${REVENUECAT_SECRET_API_KEY}`,
    },
    timeout: REVENUECAT_HTTP_TIMEOUT_MS,
    validateStatus: () => true,
  });

  if (response.status === 404) {
    return {
      checked: true,
      source: "revenuecat",
      reason: "subscriber_not_found",
      isActive: false,
      expirationDate: null,
    };
  }

  if (response.status < 200 || response.status >= 300) {
    const err = new Error(`RevenueCat subscriber lookup failed (${response.status}).`);
    err.statusCode = 502;
    throw err;
  }

  const subscriberEntitlements = response.data?.subscriber?.entitlements || {};
  const entitlement = getEntitlementFromSubscriber(subscriberEntitlements, entitlementId);

  if (!entitlement) {
    return {
      checked: true,
      source: "revenuecat",
      reason: "entitlement_not_found",
      isActive: false,
      expirationDate: null,
    };
  }

  const expiresRaw = entitlement.expires_date ?? entitlement.expiresDate ?? null;
  const expirationDate = toIsoTimestampOrNull(expiresRaw);
  const hasExplicitExpiry = expiresRaw !== null && expiresRaw !== undefined && expiresRaw !== "";

  let isActive = true;
  if (hasExplicitExpiry && expirationDate) {
    isActive = new Date(expirationDate).getTime() > Date.now();
  } else if (hasExplicitExpiry && !expirationDate) {
    isActive = false;
  }

  return {
    checked: true,
    source: "revenuecat",
    reason: isActive ? "active" : "expired",
    isActive,
    expirationDate,
  };
};

const syncRevenueCatAccessByEntitlement = async ({
  userId,
  entitlementId,
  isActive,
  expirationDate,
}) => {
  const entitlementKey = String(entitlementId || "").trim().toLowerCase();
  const mapping = REVENUECAT_ENTITLEMENT_ACCESS[entitlementKey];
  if (!mapping) {
    return {
      mapped: false,
      reason: "unsupported_entitlement",
      entitlementId,
    };
  }

  const expiresAt = toIsoTimestampOrNull(expirationDate);
  const nowIso = new Date().toISOString();

  if (!isActive) {
    const data = await hasuraRequest(
      `
        mutation DeactivateRevenueCatAccess(
          $user_id: Int!
          $item_type: access_item_type!
          $ended_at: timestamptz!
        ) {
          update_user_content_access(
            where: {
              user_id: {_eq: $user_id}
              item_type: {_eq: $item_type}
              item_id: {_is_null: true}
              is_active: {_eq: true}
            }
            _set: {is_active: false, expires_at: $ended_at}
          ) {
            affected_rows
          }
        }
      `,
      {
        user_id: userId,
        item_type: mapping.itemType,
        ended_at: nowIso,
      }
    );

    return {
      mapped: true,
      action: "deactivated",
      affectedRows: data?.update_user_content_access?.affected_rows ?? 0,
      itemType: mapping.itemType,
    };
  }

  const activeData = await hasuraRequest(
    `
      query GetActiveRevenueCatAccess($user_id: Int!, $item_type: access_item_type!) {
        user_content_access(
          where: {
            user_id: {_eq: $user_id}
            item_type: {_eq: $item_type}
            item_id: {_is_null: true}
            is_active: {_eq: true}
          }
          order_by: {started_at: desc}
          limit: 1
        ) {
          id
        }
      }
    `,
    {
      user_id: userId,
      item_type: mapping.itemType,
    }
  );

  const activeRow = activeData?.user_content_access?.[0] || null;
  if (activeRow?.id) {
    await hasuraRequest(
      `
        mutation RefreshRevenueCatAccess($id: Int!, $expires_at: timestamptz) {
          update_user_content_access_by_pk(
            pk_columns: {id: $id}
            _set: {is_active: true, expires_at: $expires_at}
          ) {
            id
          }
        }
      `,
      {
        id: activeRow.id,
        expires_at: expiresAt,
      }
    );

    return {
      mapped: true,
      action: "updated",
      itemType: mapping.itemType,
      accessId: activeRow.id,
      expiresAt,
    };
  }

  const inserted = await hasuraRequest(
    `
      mutation InsertRevenueCatAccess($object: user_content_access_insert_input!) {
        insert_user_content_access_one(object: $object) {
          id
        }
      }
    `,
    {
      object: {
        user_id: userId,
        item_type: mapping.itemType,
        item_id: mapping.itemId,
        is_active: true,
        started_at: nowIso,
        expires_at: expiresAt,
      },
    }
  );

  return {
    mapped: true,
    action: "inserted",
    itemType: mapping.itemType,
    accessId: inserted?.insert_user_content_access_one?.id ?? null,
    expiresAt,
  };
};

app.post("/revenuecat/subscription/sync", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    const body = req.body || {};
    const entitlementId = normalizeRevenueCatAppUserId(body.entitlementId);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const resolvedUserIdInput = bodyUserId || jwtUserId;

    if (!entitlementId) {
      return res.status(400).json({ ok: false, error: "entitlementId is required." });
    }
    if (!resolvedUserIdInput && !appUserId) {
      return res.status(400).json({ ok: false, error: "userId or appUserId is required." });
    }
    if (
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId
    ) {
      return res.status(403).json({ ok: false, error: "Token userId mismatch." });
    }

    const resolved = await resolveRevenueCatUser({
      userId: resolvedUserIdInput,
      appUserId,
      allowPayUniqeRelink: req.revenueCatAuthMode === "jwt",
    });

    if (req.revenueCatAuthMode === "jwt" && jwtUserId && resolved.userId !== jwtUserId) {
      return res.status(403).json({ ok: false, error: "User mismatch." });
    }

    const verification = await fetchRevenueCatEntitlementState({
      appUserId: resolved.appUserId,
      entitlementId,
    });
    if (!verification.checked && body.isActive === undefined) {
      return res.status(400).json({
        ok: false,
        error: "isActive is required when RevenueCat verification is unavailable.",
      });
    }

    const isActive = verification.checked ? verification.isActive : toBool(body.isActive);
    const effectiveExpirationDate = verification.checked
      ? verification.expirationDate
      : body.expirationDate;
    const accessSync = await syncRevenueCatAccessByEntitlement({
      userId: resolved.userId,
      entitlementId,
      isActive,
      expirationDate: effectiveExpirationDate,
    });

    console.log(
      `[revenuecat][sync] id=${requestId} source=${verification.source} userId=${resolved.userId} appUserId=${resolved.appUserId} entitlement=${entitlementId} active=${isActive} action=${accessSync.action || "skipped"}`
    );

    return res.json({
      ok: true,
      requestId,
      userId: resolved.userId,
      appUserId: resolved.appUserId,
      entitlementId,
      isActive,
      expirationDate: effectiveExpirationDate || null,
      verification,
      accessSync,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    console.error(`[revenuecat][sync][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Sync failed." });
  }
});

app.post("/revenuecat/subscription/event", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    const body = req.body || {};
    const source = normalizeRevenueCatAppUserId(body.source) || "unknown";
    const result = normalizeRevenueCatAppUserId(body.result) || "unknown";
    const success = toBool(body.success);
    const entitlementId = normalizeRevenueCatAppUserId(body.entitlementId);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const resolvedUserIdInput = bodyUserId || jwtUserId;

    if (
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId
    ) {
      return res.status(403).json({ ok: false, error: "Token userId mismatch." });
    }

    let resolved = null;
    if (resolvedUserIdInput || appUserId) {
      resolved = await resolveRevenueCatUser({
        userId: resolvedUserIdInput,
        appUserId,
        allowPayUniqeRelink: req.revenueCatAuthMode === "jwt",
      });
    }

    if (req.revenueCatAuthMode === "jwt" && jwtUserId && resolved && resolved.userId !== jwtUserId) {
      return res.status(403).json({ ok: false, error: "User mismatch." });
    }

    let verification = null;
    let accessSync = null;
    if (resolved && entitlementId) {
      verification = await fetchRevenueCatEntitlementState({
        appUserId: resolved.appUserId,
        entitlementId,
      });

      const canSyncFromPayload = body.isActive !== undefined;
      if (verification.checked || canSyncFromPayload) {
        const isActive = verification.checked ? verification.isActive : toBool(body.isActive);
        const effectiveExpirationDate = verification.checked
          ? verification.expirationDate
          : body.expirationDate;
        accessSync = await syncRevenueCatAccessByEntitlement({
          userId: resolved.userId,
          entitlementId,
          isActive,
          expirationDate: effectiveExpirationDate,
        });
      } else {
        accessSync = {
          mapped: false,
          reason: "missing_is_active_and_no_verification",
          entitlementId,
        };
      }
    }

    console.log(
      `[revenuecat][event] id=${requestId} source=${source} result=${result} success=${success} userId=${resolved?.userId ?? "-"} appUserId=${resolved?.appUserId ?? appUserId ?? "-"} entitlement=${entitlementId || "-"} action=${accessSync?.action || "none"}`
    );

    return res.json({
      ok: true,
      requestId,
      source,
      result,
      success,
      userId: resolved?.userId ?? null,
      appUserId: resolved?.appUserId ?? appUserId ?? null,
      entitlementId: entitlementId || null,
      verification,
      accessSync,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    console.error(`[revenuecat][event][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Event failed." });
  }
});

const signViewToken = (payload) => {
  const serialized = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", VIEW_TOKEN_SECRET)
    .update(serialized)
    .digest("base64url");
  return `${serialized}.${signature}`;
};

const verifyViewToken = (token) => {
  if (!token || typeof token !== "string" || !token.includes(".")) {
    return { ok: false, error: "Invalid token." };
  }
  const [payloadB64, signature] = token.split(".");
  const expectedSig = crypto
    .createHmac("sha256", VIEW_TOKEN_SECRET)
    .update(payloadB64)
    .digest("base64url");
  if (signature !== expectedSig) {
    return { ok: false, error: "Signature mismatch." };
  }
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    if (!payload?.path || !payload?.exp) {
      return { ok: false, error: "Token payload missing fields." };
    }
    if (Date.now() > Number(payload.exp)) {
      return { ok: false, error: "Token expired." };
    }
    return { ok: true, payload };
  } catch (err) {
    return { ok: false, error: "Token parse failed." };
  }
};

const sanitizeFilename = (value) => {
  const raw = String(value || "").replace(/[\r\n]/g, "");
  const cleaned = raw.replace(/["\\]/g, "");
  return cleaned || "file.pdf";
};

const serveFile = (filePath, res, extraHeaders = {}, logContext = null) => {
  Object.entries(extraHeaders).forEach(([key, value]) => res.set(key, value));
  res.sendFile(filePath, (sendErr) => {
    if (sendErr) {
      console.error(`sendFile error for ${filePath}:`, sendErr);
      if (logContext) {
        logPdfRequest({
          ...logContext,
          status: sendErr.status || sendErr.statusCode || 500,
          outcome: "error",
          message: "File send failed.",
          error: sendErr,
        });
      }
      if (!res.headersSent) {
        res.status(500).json({ ok: false, error: "File send failed." });
      }
    } else if (logContext) {
      logPdfRequest({
        ...logContext,
        status: logContext.status || res.statusCode || 200,
        outcome: "success",
        message: logContext.message || "PDF delivered.",
      });
    }
  });
};

const generateUniqueFilename = (originalName) => {
  const ext = path.extname(originalName);
  const base = path.basename(originalName, ext).replace(/\s+/g, "_");
  const unique = crypto.randomUUID();
  const stamp = Date.now();
  return `${stamp}-${unique}-${base}${ext}`;
};

const uploadToBunny = async (fileBuffer, type, scope, filename) => {
  const url = `/${type}/${scope}/${filename}`;
  try {
    const response = await bunnyRequest(
      {
        method: "PUT",
        url,
        data: fileBuffer,
        headers: {
          "Content-Type": "application/octet-stream",
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
      },
      { retries: 0 }
    );
    return response.data;
  } catch (err) {
    const errorMsg = err.response?.data?.Message || err.response?.data || err.message;
    const statusCode = err.response?.status || 500;
    console.error(`[BunnyCDN Upload Error] ${statusCode}: ${JSON.stringify(errorMsg)}`);
    console.error(
      `[BunnyCDN Request Details] URL: ${bunnyHttp.defaults.baseURL}${url}, Zone: ${BUNNY_SETTINGS.storageZone}`
    );
    throw new Error(`BunnyCDN upload failed (${statusCode}): ${JSON.stringify(errorMsg)}`);
  }
};

const fetchFromBunny = async (type, scope, filename) => {
  const url = `/${type}/${scope}/${filename}`;
  try {
    const response = await bunnyRequest({
      method: "GET",
      url,
      responseType: "arraybuffer",
    });
    return response.data;
  } catch (err) {
    const errorMsg = err.response?.data?.Message || err.response?.data || err.message;
    const statusCode = err.response?.status || 500;
    console.error(`[BunnyCDN Fetch Error] ${statusCode}: ${JSON.stringify(errorMsg)}`);
    console.error(`[BunnyCDN Fetch Details] URL: ${bunnyHttp.defaults.baseURL}${url}`);
    throw new Error(`BunnyCDN fetch failed (${statusCode})`);
  }
};

const fetchStreamFromBunny = async (type, scope, filename) => {
  const url = `/${type}/${scope}/${filename}`;
  try {
    return await bunnyRequest({
      method: "GET",
      url,
      responseType: "stream",
    });
  } catch (err) {
    const errorMsg = err.response?.data?.Message || err.response?.data || err.message;
    const statusCode = err.response?.status || 500;
    console.error(`[BunnyCDN Stream Error] ${statusCode}: ${JSON.stringify(errorMsg)}`);
    console.error(`[BunnyCDN Stream Details] URL: ${bunnyHttp.defaults.baseURL}${url}`);
    throw new Error(`BunnyCDN fetch failed (${statusCode})`);
  }
};

const pipeBunnyStreamToResponse = async ({
  req,
  res,
  bunnyResponse,
  logBase,
  headers,
  successMessage,
}) => {
  const start = process.hrtime.bigint();
  const upstream = bunnyResponse.data;
  let finished = false;
  let idleTimer = null;
  const firstByteTimeoutMs =
    Number.isFinite(BUNNY_STREAM_FIRST_BYTE_TIMEOUT_MS) && BUNNY_STREAM_FIRST_BYTE_TIMEOUT_MS > 0
      ? BUNNY_STREAM_FIRST_BYTE_TIMEOUT_MS
      : null;
  let ttfbMs = null;

  const clearIdleTimer = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = null;
  };

  const touchIdleTimer = () => {
    clearIdleTimer();
    if (!Number.isFinite(BUNNY_STREAM_IDLE_TIMEOUT_MS) || BUNNY_STREAM_IDLE_TIMEOUT_MS <= 0) return;
    idleTimer = setTimeout(() => {
      upstream.destroy(new Error("Upstream idle timeout."));
    }, BUNNY_STREAM_IDLE_TIMEOUT_MS);
  };

  const finishOnce = () => {
    if (finished) return;
    finished = true;
    clearIdleTimer();
    upstream.removeListener("data", touchIdleTimer);
  };

  const fail = (status, message, err) => {
    finishOnce();
    logPdfRequest({
      ...logBase,
      status,
      outcome: "error",
      message,
      error: err,
    });
    if (!res.headersSent) {
      const corsHeaders = buildCorsHeaders(req);
      Object.entries(corsHeaders).forEach(([key, value]) => res.set(key, value));
      res.status(status).json({ ok: false, error: message });
    } else {
      res.destroy(err || new Error(message));
    }
  };

  res.on("close", () => {
    if (res.writableEnded) return;
    upstream.destroy();
    finishOnce();
    logPdfRequest({
      ...logBase,
      status: 499,
      outcome: "error",
      message: "Client aborted.",
    });
  });

  let cleanupFirstEventListeners = () => {};
  const firstEventPromise = new Promise((resolve) => {
    const onData = (chunk) => {
      cleanup();
      upstream.pause();
      ttfbMs = Number(process.hrtime.bigint() - start) / 1_000_000;
      resolve({ kind: "data", chunk });
    };
    const onEnd = () => {
      cleanup();
      resolve({ kind: "end" });
    };
    const onError = (err) => {
      cleanup();
      resolve({ kind: "error", err });
    };
    const cleanup = () => {
      upstream.removeListener("data", onData);
      upstream.removeListener("end", onEnd);
      upstream.removeListener("error", onError);
    };
    cleanupFirstEventListeners = cleanup;
    upstream.once("data", onData);
    upstream.once("end", onEnd);
    upstream.once("error", onError);
  });

  const firstEvent = await Promise.race([
    firstEventPromise,
    firstByteTimeoutMs === null
      ? new Promise(() => {})
      : sleep(firstByteTimeoutMs).then(() => ({ kind: "timeout" })),
  ]);

  if (firstEvent.kind === "timeout") {
    cleanupFirstEventListeners();
    upstream.destroy(new Error("Upstream first-byte timeout."));
    return fail(504, "Upstream timeout.");
  }

  if (firstEvent.kind === "error") {
    return fail(502, "Upstream fetch failed.", firstEvent.err);
  }

  if (firstEvent.kind === "end") {
    return fail(502, "Upstream returned an empty response.");
  }

  const corsHeaders = buildCorsHeaders(req);
  res.set({ ...corsHeaders, ...headers });
  if (bunnyResponse.headers?.["content-length"]) {
    res.set("Content-Length", bunnyResponse.headers["content-length"]);
  }

  upstream.on("error", (streamErr) => {
    if (finished) return;
    fail(502, "Upstream fetch failed.", streamErr);
  });

  upstream.on("data", touchIdleTimer);
  touchIdleTimer();

  upstream.on("end", () => {
    if (finished) return;
    finishOnce();
    logPdfRequest({
      ...logBase,
      status: 200,
      outcome: "success",
      message: Number.isFinite(ttfbMs) ? `${successMessage} (ttfb ${ttfbMs.toFixed(1)}ms)` : successMessage,
    });
  });

  res.write(firstEvent.chunk);
  upstream.pipe(res);
  upstream.resume();
};

const moveToFinal = (file, targetDir) =>
  new Promise((resolve, reject) => {
    const tmpPath = file.path || path.join(file.destination, file.filename);
    const finalPath = path.join(targetDir, file.filename);
    fs.mkdirSync(targetDir, { recursive: true });
    fs.rename(tmpPath, finalPath, (err) => {
      if (err) return reject(err);
      resolve({ finalPath, filename: path.basename(finalPath) });
    });
  });

app.post("/upload/public", requireJwt, upload.single("file"), async (req, res, next) => {
  try {
    const type = resolveType(req, PUBLIC_TYPES);
    if (!type) {
      return res
        .status(400)
        .json({ ok: false, error: `type is required: ${PUBLIC_TYPES.join(", ")}` });
    }
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "File is required." });
    }

    const filename = generateUniqueFilename(req.file.originalname);
    await uploadToBunny(req.file.buffer, type, "public", filename);

    return res.json({
      ok: true,
      scope: "public",
      type,
      file: filename,
      url: `https://${BUNNY_SETTINGS.cdnUrl}/${type}/public/${filename}`,
    });
  } catch (err) {
    next(err);
  }
});

app.post("/upload/private", requireJwt, upload.single("file"), async (req, res, next) => {
  try {
    const type = resolveType(req, PRIVATE_TYPES);
    if (!type) {
      return res
        .status(400)
        .json({ ok: false, error: `type is required: ${PRIVATE_TYPES.join(", ")}` });
    }
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "File is required." });
    }

    const filename = generateUniqueFilename(req.file.originalname);
    await uploadToBunny(req.file.buffer, type, "private", filename);

    return res.json({
      ok: true,
      scope: "private",
      type,
      file: filename,
      url: `https://${BUNNY_SETTINGS.cdnUrl}/${type}/private/${filename}`,
    });
  } catch (err) {
    next(err);
  }
});

app.get("/public/:type/:filename", (req, res) => {
  const type = (req.params.type || "").toLowerCase();
  if (!PUBLIC_TYPES.includes(type)) {
    return res.status(404).json({ ok: false, error: "Unknown type." });
  }
  const cdnUrl = `https://${BUNNY_SETTINGS.cdnUrl}/${type}/public/${req.params.filename}`;
  return res.redirect(cdnUrl);
});

app.get("/private/:type/:filename", requireAuth, async (req, res) => {
  const type = (req.params.type || "").toLowerCase();
  if (!PRIVATE_TYPES.includes(type)) {
    logPdfRequest({
      req,
      scope: "private",
      route: "/private/:type/:filename",
      action: "serve-private-file",
      type,
      filename: req.params.filename,
      status: 404,
      outcome: "error",
      message: "Unknown type.",
    });
    return res.status(404).json({ ok: false, error: "Unknown type." });
  }

  const logBase = {
    req,
    scope: "private",
    route: "/private/:type/:filename",
    action: "serve-private-file",
    type,
    filename: req.params.filename,
  };

  try {
    const bunnyResponse = await fetchStreamFromBunny(type, "private", req.params.filename);
    const ext = path.extname(req.params.filename).toLowerCase();
    const contentType = ext === ".pdf" ? "application/pdf" : "application/octet-stream";
    await pipeBunnyStreamToResponse({
      req,
      res,
      bunnyResponse,
      logBase,
      headers: { "Content-Type": contentType },
      successMessage: "File delivered from BunnyCDN.",
    });
  } catch (err) {
    logPdfRequest({
      ...logBase,
      status: err.message.includes("404") ? 404 : 500,
      outcome: "error",
      message: "Fetch from BunnyCDN failed.",
      error: err,
    });
    const status = err.message.includes("404") ? 404 : 500;
    res.status(status).json({ ok: false, error: "File not found or fetch failed." });
  }
});

app.post("/private/view", requireJwt, async (req, res) => {
  const rawPath = req.body?.path || req.body?.pdf || req.body?.file;
  const parsed = parsePrivatePath(rawPath);
  if (!parsed) {
    logPdfRequest({
      req,
      scope: "private",
      route: "/private/view",
      action: "view-inline",
      filename: rawPath,
      status: 400,
      outcome: "error",
      message: "Invalid path format.",
    });
    return res.status(400).json({
      ok: false,
      error: "path must be like /private/<type>/<file.pdf>",
    });
  }

  const logBase = {
    req,
    scope: "private",
    route: "/private/view",
    action: "view-inline",
    type: parsed.type,
    filename: parsed.filename,
  };

  try {
    const bunnyResponse = await fetchStreamFromBunny(parsed.type, "private", parsed.filename);
    await pipeBunnyStreamToResponse({
      req,
      res,
      bunnyResponse,
      logBase,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `inline; filename="${sanitizeFilename(parsed.filename)}"`,
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        Pragma: "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": `frame-ancestors ${FRAME_ANCESTORS_DIRECTIVE}`,
      },
      successMessage: "Inline PDF served from BunnyCDN.",
    });
  } catch (err) {
    logPdfRequest({
      ...logBase,
      status: err.message.includes("404") ? 404 : 500,
      outcome: "error",
      message: "Fetch from BunnyCDN failed.",
      error: err,
    });
    const status = err.message.includes("404") ? 404 : 500;
    res.status(status).json({ ok: false, error: "File not found or fetch failed." });
  }
});

app.get("/private/view-file", requireAuth, async (req, res) => {
  if (!ENABLE_BASE64_VIEWER) {
    return res.status(404).json({ ok: false, error: "Not found." });
  }
  const rawPath = req.query?.path || req.query?.pdf || req.query?.file;
  const parsed = parsePrivatePath(rawPath);
  if (!parsed) {
    logPdfRequest({
      req,
      scope: "private",
      route: "/private/view-file",
      action: "view-file-html",
      filename: rawPath,
      status: 400,
      outcome: "error",
      message: "Invalid path format.",
    });
    return res.status(400).json({
      ok: false,
      error: "path must be like /private/<type>/<file.pdf>",
    });
  }

  const logBase = {
    req,
    scope: "private",
    route: "/private/view-file",
    action: "view-file-html",
    type: parsed.type,
    filename: parsed.filename,
  };

  try {
    const buffer = await fetchFromBunny(parsed.type, "private", parsed.filename);
    if (buffer.length > MAX_BASE64_VIEW_BYTES) {
      logPdfRequest({
        ...logBase,
        status: 413,
        outcome: "error",
        message: "File too large for base64 viewer.",
      });
      return res
        .status(413)
        .json({ ok: false, error: "File too large for base64 viewer." });
    }
    const corsHeaders = buildCorsHeaders(req);
    const base64 = buffer.toString("base64");
    const dataUrl = `data:application/pdf;base64,${base64}`;
    const safeTitle = parsed.filename.replace(/"/g, "");

    res.set({
      ...corsHeaders,
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
    });

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${safeTitle}</title>
  <style>
    html, body { margin: 0; padding: 0; width: 100%; height: 100%; background: #111; }
    .viewer { position: fixed; inset: 0; background: #1b1b1b; }
    .viewer embed, .viewer object, .viewer iframe { width: 100%; height: 100%; border: none; }
    .fallback { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #eee; font-family: sans-serif; text-align: center; }
    .link { color: #7fd7ff; }
  </style>
</head>
<body>
  <div class="viewer">
    <embed src="${dataUrl}" type="application/pdf" />
    <div class="fallback">PDF görüntülenemedi. <a class="link" href="${dataUrl}" download="${safeTitle}">İndir</a></div>
  </div>
</body>
</html>`;

    res.send(html);
    logPdfRequest({
      ...logBase,
      status: 200,
      outcome: "success",
      message: "Inline base64 viewer served from BunnyCDN.",
    });
  } catch (err) {
    logPdfRequest({
      ...logBase,
      status: err.message.includes("404") ? 404 : 500,
      outcome: "error",
      message: "Fetch from BunnyCDN failed.",
      error: err,
    });
    const status = err.message.includes("404") ? 404 : 500;
    res.status(status).json({ ok: false, error: "File not found or fetch failed." });
  }
});

app.post("/private/view-token", requireJwt, (req, res) => {
  const rawPath = req.body?.path || req.body?.pdf || req.body?.file;
  const parsed = parsePrivatePath(rawPath);
  if (!parsed) {
    return res.status(400).json({
      ok: false,
      error: "path must be like /private/<type>/<file.pdf>",
    });
  }
  if (!VIEW_TOKEN_SECRET) {
    return res.status(500).json({ ok: false, error: "VIEW_TOKEN_SECRET missing." });
  }
  const ttlMinutes =
    Number.isFinite(VIEW_TOKEN_TTL_MIN) && VIEW_TOKEN_TTL_MIN > 0
      ? VIEW_TOKEN_TTL_MIN
      : 5;
  const exp = Date.now() + ttlMinutes * 60_000;
  const payload = { path: `/private/${parsed.type}/${parsed.filename}`, exp };
  const token = signViewToken(payload);
  const url = `/private/view-secure?token=${encodeURIComponent(token)}`;
  return res.json({
    ok: true,
    url,
    token,
    expiresAt: new Date(exp).toISOString(),
    ttlMinutes,
  });
});

app.get("/private/view-secure", requireJwt, async (req, res) => {
  const token = req.query?.token;
  const validation = verifyViewToken(token);
  if (!validation.ok) {
    logPdfRequest({
      req,
      scope: "private",
      route: "/private/view-secure",
      action: "view-secure",
      status: 401,
      outcome: "error",
      message: validation.error || "Unauthorized.",
    });
    return res.status(401).json({ ok: false, error: validation.error || "Unauthorized." });
  }
  const requestedPage = Number.parseInt(req.query?.page, 10);
  const pageParam = Number.isFinite(requestedPage) && requestedPage > 0 ? requestedPage : null;
  const renderMode = (req.query?.render || "").toLowerCase();
  const preferViewer = renderMode !== "raw";
  const requestedZoom = Number.parseFloat(req.query?.zoom);
  const initialZoom =
    Number.isFinite(requestedZoom) && requestedZoom > 0.3 && requestedZoom <= 3
      ? requestedZoom
      : 1.1;
  const parsed = parsePrivatePath(validation.payload.path);
  if (!parsed) {
    logPdfRequest({
      req,
      scope: "private",
      route: "/private/view-secure",
      action: "view-secure",
      status: 400,
      outcome: "error",
      message: "Invalid token path.",
    });
    return res.status(400).json({ ok: false, error: "Invalid token path." });
  }

  const logBase = {
    req,
    scope: "private",
    route: "/private/view-secure",
    action: "view-secure",
    type: parsed.type,
    filename: parsed.filename,
  };

  const corsHeaders = buildCorsHeaders(req);

  if (preferViewer) {
    const rawUrl = `${req.path}?token=${encodeURIComponent(token)}&render=raw`;
    const html = `<!doctype html>
<html lang="tr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <title>${parsed.filename}</title>
  <style>
    :root { color-scheme: dark; --chrome-bg: rgba(18,22,30,0.95); --border: #2a3345; --pill-bg: #1e2533; --accent: #4f8cff; }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    html, body { margin: 0; padding: 0; width: 100%; height: 100%; background: #0b0d11; color: #e2e8f0; font-family: "Inter", system-ui, -apple-system, sans-serif; overflow: hidden; }
    .chrome { position: fixed; top: 0; left: 0; right: 0; height: 60px; display: flex; align-items: center; justify-content: space-between; padding: 0 16px; background: var(--chrome-bg); border-bottom: 1px solid var(--border); backdrop-filter: blur(12px); z-index: 100; }
    .title { font-size: 14px; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px; opacity: 0.8; }
    .pill-group { display: flex; align-items: center; gap: 8px; background: var(--pill-bg); padding: 4px; border-radius: 12px; border: 1px solid var(--border); }
    button { cursor: pointer; background: transparent; border: none; color: #fff; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; border-radius: 8px; transition: all 0.2s; font-size: 18px; }
    button:hover { background: rgba(255,255,255,0.1); }
    button:active { transform: scale(0.92); }
    button:disabled { opacity: 0.3; cursor: not-allowed; }
    .zoom-val { font-size: 13px; font-weight: 600; min-width: 45px; text-align: center; color: var(--accent); }
    .canvas-wrap { position: absolute; inset: 60px 0 0 0; overflow: auto; display: flex; justify-content: center; align-items: flex-start; scroll-behavior: smooth; -webkit-overflow-scrolling: touch; }
    #pdf-canvas { margin: 20px auto 40px auto; box-shadow: 0 20px 50px rgba(0,0,0,0.5); border-radius: 4px; background: #fff; transition: transform 0.1s ease-out; }
    .page-info { display: flex; align-items: center; gap: 4px; font-size: 13px; font-weight: 500; }
    #page-input { background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: #fff; padding: 4px 0; border-radius: 6px; width: 40px; text-align: center; font-size: 13px; }
    #status { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: var(--accent); color: white; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; box-shadow: 0 10px 20px rgba(0,0,0,0.3); display: none; z-index: 1000; }
  </style>
  <script type="module">
    import * as pdfjsLib from "/pdfjs/pdf.min.mjs";
    pdfjsLib.GlobalWorkerOptions.workerSrc = "/pdfjs/pdf.worker.min.mjs";

    const rawUrl = ${JSON.stringify(rawUrl)};
    const docKey = "pdf-prog:" + ${JSON.stringify(parsed.filename)};
    const startPage = ${pageParam || "null"};
    
    let pdfDoc = null;
    let pageNum = startPage || Number(localStorage.getItem(docKey)) || 1;
    let isRendering = false;
    let renderTask = null;
    let scale = 1.25;
    let currentRotation = 0;

    const canvas = document.getElementById("pdf-canvas");
    const ctx = canvas.getContext("2d", { alpha: false });

    async function init() {
      try {
        showStatus("Yükleniyor...");
        const loadingTask = pdfjsLib.getDocument({ url: rawUrl, cMapUrl: "/pdfjs/cmaps/", cMapPacked: true });
        pdfDoc = await loadingTask.promise;
        document.getElementById("page-count").textContent = pdfDoc.numPages;
        hideStatus();
        
        // Initial auto-scale
        const page = await pdfDoc.getPage(pageNum);
        const viewport = page.getViewport({ scale: 1 });
        const containerWidth = window.innerWidth - 40;
        scale = containerWidth / viewport.width;
        if (scale > 2) scale = 1.5;
        
        renderPage(pageNum);
      } catch (err) {
        showStatus("Hata: PDF yüklenemedi", 5000);
        console.error(err);
      }
    }

    async function renderPage(num) {
      if (isRendering && renderTask) {
        renderTask.cancel();
      }
      isRendering = true;
      pageNum = num;
      
      try {
        const page = await pdfDoc.getPage(num);
        const pixelRatio = window.devicePixelRatio || 1;
        const viewport = page.getViewport({ scale: scale, rotation: currentRotation });

        canvas.height = viewport.height * pixelRatio;
        canvas.width = viewport.width * pixelRatio;
        canvas.style.height = viewport.height + "px";
        canvas.style.width = viewport.width + "px";

        const renderContext = {
          canvasContext: ctx,
          viewport: viewport,
          transform: [pixelRatio, 0, 0, pixelRatio, 0, 0]
        };

        renderTask = page.render(renderContext);
        await renderTask.promise;
        
        isRendering = false;
        document.getElementById("page-input").value = num;
        document.getElementById("zoom-val").textContent = Math.round(scale * 100) + "%";
        document.getElementById("prev").disabled = num <= 1;
        document.getElementById("next").disabled = num >= pdfDoc.numPages;
        localStorage.setItem(docKey, String(num));
      } catch (err) {
        if (err.name === "RenderingCancelledException") return;
        isRendering = false;
        console.error(err);
      }
    }

    function changeScale(delta) {
      scale = Math.min(Math.max(0.5, scale + delta), 4.0);
      renderPage(pageNum);
    }

    function showStatus(msg, duration) {
      const el = document.getElementById("status");
      el.textContent = msg;
      el.style.display = "block";
      if (duration) setTimeout(hideStatus, duration);
    }

    function hideStatus() {
      document.getElementById("status").style.display = "none";
    }

    // Events
    document.getElementById("prev").onclick = () => pageNum > 1 && renderPage(pageNum - 1);
    document.getElementById("next").onclick = () => pageNum < pdfDoc.numPages && renderPage(pageNum + 1);
    document.getElementById("zoom-in").onclick = () => changeScale(0.25);
    document.getElementById("zoom-out").onclick = () => changeScale(-0.25);
    document.getElementById("page-form").onsubmit = (e) => {
      e.preventDefault();
      const val = parseInt(document.getElementById("page-input").value);
      if (val > 0 && val <= pdfDoc.numPages) renderPage(val);
    };

    window.onresize = () => {
      // Re-render to adjust for pixel ratio or container changes if needed
      // But avoid heavy re-renders on simple mobile keyboard pops
    };

    init();
  </script>
</head>
<body>
  <div class="chrome">
    <div class="title">${parsed.filename}</div>
    <div class="pill-group">
      <button id="prev" title="Önceki">&#8592;</button>
      <form id="page-form" class="page-info">
        <input id="page-input" type="number" value="1" />
        <span>/ <span id="page-count">-</span></span>
      </form>
      <button id="next" title="Sonraki">&#8594;</button>
    </div>
    <div class="pill-group">
      <button id="zoom-out" title="Uzaklaştır">&#8722;</button>
      <div class="zoom-val" id="zoom-val">100%</div>
      <button id="zoom-in" title="Yakınlaştır">&#43;</button>
    </div>
  </div>
  <div class="canvas-wrap" id="canvas-wrap">
    <canvas id="pdf-canvas"></canvas>
  </div>
  <div id="status"></div>
</body>
</html>`;

    res.set({
      ...corsHeaders,
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": `frame-ancestors ${FRAME_ANCESTORS_DIRECTIVE}`,
    });
    res.send(html);
    logPdfRequest({
      ...logBase,
      status: 200,
      outcome: "success",
      message: "Secure viewer HTML served.",
    });
    return;
  }

  try {
    const data = await fetchFromBunny(parsed.type, "private", parsed.filename);
    res.set({
      ...corsHeaders,
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename="${sanitizeFilename(parsed.filename)}"`,
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": `frame-ancestors ${FRAME_ANCESTORS_DIRECTIVE}`,
    });
    res.send(data);
    logPdfRequest({
      ...logBase,
      status: 200,
      outcome: "success",
      message: "Secure PDF delivered from BunnyCDN.",
    });
  } catch (err) {
    logPdfRequest({
      ...logBase,
      status: err.message.includes("404") ? 404 : 500,
      outcome: "error",
      message: "Fetch from BunnyCDN failed.",
      error: err,
    });
    const status = err.message.includes("404") ? 404 : 500;
    res.status(status).json({ ok: false, error: "File not found or fetch failed." });
  }
});

app.post("/payment/session", requireAuth, async (req, res, next) => {
  try {
    const body = req.body || {};
    const pick = (...keys) => {
      for (const key of keys) {
        const value = body[key];
        if (value !== undefined && value !== null && value !== "") {
          return value;
        }
      }
      return undefined;
    };

    const merchantUser = PARATIKA_MERCHANTUSER || pick("MERCHANTUSER", "merchantUser");
    const merchantPassword =
      PARATIKA_MERCHANTPASSWORD || pick("MERCHANTPASSWORD", "merchantPassword");
    const merchant = PARATIKA_MERCHANT || pick("MERCHANT", "merchant");
    const returnUrl = PARATIKA_RETURNURL || pick("RETURNURL", "returnUrl");
    const sessionType = pick("SESSIONTYPE", "sessionType") || "PAYMENTSESSION";

    const missing = [];
    if (!PARATIKA_BASE_URL) missing.push("PARATIKA_BASE_URL");
    if (!merchantUser) missing.push("MERCHANTUSER");
    if (!merchantPassword) missing.push("MERCHANTPASSWORD");
    if (!merchant) missing.push("MERCHANT");
    if (!returnUrl) missing.push("RETURNURL");

    if (missing.length) {
      return res.status(400).json({
        ok: false,
        error: `Missing required fields: ${missing.join(", ")}`,
      });
    }

    const orderItemsRaw = pick("ORDERITEMS", "orderItems");
    const orderItems = normalizeJsonField(orderItemsRaw);
    if (orderItemsRaw && !orderItems) {
      return res.status(400).json({
        ok: false,
        error: "ORDERITEMS must be valid JSON or a JSON string.",
      });
    }

    const extraRaw = pick("EXTRA", "extra");
    const extra = normalizeJsonField(extraRaw);
    if (extraRaw && !extra) {
      return res.status(400).json({
        ok: false,
        error: "EXTRA must be valid JSON or a JSON string.",
      });
    }

    const discountAmountFromExtra =
      extra && typeof extra === "object"
        ? extra.discountAmount ?? extra.DISCOUNTAMOUNT
        : undefined;
    const discountAmount = pick("DISCOUNTAMOUNT", "discountAmount") ?? discountAmountFromExtra;

    const requestPayload = {
      ACTION: "SESSIONTOKEN",
      MERCHANTUSER: String(merchantUser),
      MERCHANTPASSWORD: String(merchantPassword),
      MERCHANT: String(merchant),
      RETURNURL: String(returnUrl),
      SESSIONTYPE: String(sessionType),
      AMOUNT: pick("AMOUNT", "amount"),
      CURRENCY: pick("CURRENCY", "currency"),
      MERCHANTPAYMENTID: pick("MERCHANTPAYMENTID", "merchantPaymentId"),
      CUSTOMER: pick("CUSTOMER", "customer"),
      CUSTOMERNAME: pick("CUSTOMERNAME", "customerName"),
      CUSTOMEREMAIL: pick("CUSTOMEREMAIL", "customerEmail"),
      CUSTOMERIP: pick("CUSTOMERIP", "customerIp"),
      CUSTOMERUSERAGENT: pick("CUSTOMERUSERAGENT", "customerUserAgent"),
      NAMEONCARD: pick("NAMEONCARD", "nameOnCard"),
      CUSTOMERPHONE: pick("CUSTOMERPHONE", "customerPhone"),
      DISCOUNTAMOUNT: discountAmount,
      BILLTOADDRESSLINE: pick("BILLTOADDRESSLINE", "billToAddressLine"),
      BILLTOCITY: pick("BILLTOCITY", "billToCity"),
      BILLTOCOUNTRY: pick("BILLTOCOUNTRY", "billToCountry"),
      BILLTOPOSTALCODE: pick("BILLTOPOSTALCODE", "billToPostalCode"),
      BILLTOPHONE: pick("BILLTOPHONE", "billToPhone"),
      SHIPTOADDRESSLINE: pick("SHIPTOADDRESSLINE", "shipToAddressLine"),
      SHIPTOCITY: pick("SHIPTOCITY", "shipToCity"),
      SHIPTOCOUNTRY: pick("SHIPTOCOUNTRY", "shipToCountry"),
      SHIPTOPOSTALCODE: pick("SHIPTOPOSTALCODE", "shipToPostalCode"),
      SHIPTOPHONE: pick("SHIPTOPHONE", "shipToPhone"),
      SELLERID: pick("SELLERID", "sellerId"),
      COMMISSIONAMOUNT: pick("COMMISSIONAMOUNT", "commissionAmount"),
      SESSIONEXPIRY: pick("SESSIONEXPIRY", "sessionExpiry"),
      LANGUAGE: pick("LANGUAGE", "language"),
      ORDERITEMS: orderItems || undefined,
      EXTRA: extra || undefined,
    };

    const data = formEncode(requestPayload);
    const response = await axios.request({
      method: "post",
      maxBodyLength: Infinity,
      url: PARATIKA_BASE_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(PARATIKA_COOKIE ? { Cookie: PARATIKA_COOKIE } : {}),
        Accept: "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        Connection: "keep-alive",
        "User-Agent": "PostmanRuntime/7.36.0",
      },
      data,
    });
    const payload = { data: response.data };
    return res.status(200).json({
      ok: true,
      status: 200,
      paratika: payload,
    });
  } catch (err) {
    next(err);
  }
});

app.post("/payment/query-card", requireAuth, async (req, res, next) => {
  try {
    const body = req.body || {};
    const pick = (...keys) => {
      for (const key of keys) {
        const value = body[key];
        if (value !== undefined && value !== null && value !== "") {
          return value;
        }
      }
      return undefined;
    };

    const merchantUser = PARATIKA_MERCHANTUSER || pick("MERCHANTUSER", "merchantUser");
    const merchantPassword =
      PARATIKA_MERCHANTPASSWORD || pick("MERCHANTPASSWORD", "merchantPassword");
    const merchant = PARATIKA_MERCHANT || pick("MERCHANT", "merchant");
    const customer = pick("CUSTOMER", "customer");

    const missing = [];
    if (!PARATIKA_BASE_URL) missing.push("PARATIKA_BASE_URL");
    if (!merchantUser) missing.push("MERCHANTUSER");
    if (!merchantPassword) missing.push("MERCHANTPASSWORD");
    if (!merchant) missing.push("MERCHANT");
    if (!customer) missing.push("CUSTOMER");

    if (missing.length) {
      return res.status(400).json({
        ok: false,
        error: `Missing required fields: ${missing.join(", ")}`,
      });
    }

    const requestPayload = {
      ACTION: "QUERYCARD",
      MERCHANTUSER: String(merchantUser),
      MERCHANTPASSWORD: String(merchantPassword),
      MERCHANT: String(merchant),
      CUSTOMER: String(customer),
    };

    const response = await axios.request({
      method: "post",
      maxBodyLength: Infinity,
      url: PARATIKA_BASE_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(PARATIKA_COOKIE ? { Cookie: PARATIKA_COOKIE } : {}),
        Accept: "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        Connection: "keep-alive",
        "User-Agent": "PostmanRuntime/7.36.0",
      },
      data: formEncode(requestPayload),
      validateStatus: () => true,
    });

    const status = Number.isInteger(response.status) ? response.status : 502;
    const contentType = response.headers?.["content-type"];

    if (response.data && typeof response.data === "object") {
      return res.status(status).json(response.data);
    }

    if (typeof response.data === "string") {
      const trimmed = response.data.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          return res.status(status).json(JSON.parse(trimmed));
        } catch (err) {
          // Fall through to raw response.
        }
      }
    }

    if (contentType) res.set("Content-Type", contentType);
    return res.status(status).send(response.data ?? "");
  } catch (err) {
    next(err);
  }
});

app.post("/payment/delete-card", requireAuth, async (req, res, next) => {
  try {
    const body = req.body || {};
    const pick = (...keys) => {
      for (const key of keys) {
        const value = body[key];
        if (value !== undefined && value !== null && value !== "") {
          return value;
        }
      }
      return undefined;
    };

    const merchantUser = PARATIKA_MERCHANTUSER || pick("MERCHANTUSER", "merchantUser");
    const merchantPassword =
      PARATIKA_MERCHANTPASSWORD || pick("MERCHANTPASSWORD", "merchantPassword");
    const merchant = PARATIKA_MERCHANT || pick("MERCHANT", "merchant");
    const cardToken = pick("CARDTOKEN", "cardToken");

    const missing = [];
    if (!PARATIKA_BASE_URL) missing.push("PARATIKA_BASE_URL");
    if (!merchantUser) missing.push("MERCHANTUSER");
    if (!merchantPassword) missing.push("MERCHANTPASSWORD");
    if (!merchant) missing.push("MERCHANT");
    if (!cardToken) missing.push("CARDTOKEN");

    if (missing.length) {
      return res.status(400).json({
        ok: false,
        error: `Missing required fields: ${missing.join(", ")}`,
      });
    }

    const requestPayload = {
      ACTION: "EWALLETDELETECARD",
      MERCHANTUSER: String(merchantUser),
      MERCHANTPASSWORD: String(merchantPassword),
      MERCHANT: String(merchant),
      CARDTOKEN: String(cardToken),
    };

    const response = await axios.request({
      method: "post",
      maxBodyLength: Infinity,
      url: PARATIKA_BASE_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(PARATIKA_COOKIE ? { Cookie: PARATIKA_COOKIE } : {}),
        Accept: "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        Connection: "keep-alive",
        "User-Agent": "PostmanRuntime/7.36.0",
      },
      data: formEncode(requestPayload),
      validateStatus: () => true,
    });

    const status = Number.isInteger(response.status) ? response.status : 502;
    const contentType = response.headers?.["content-type"];

    if (response.data && typeof response.data === "object") {
      return res.status(status).json(response.data);
    }

    if (typeof response.data === "string") {
      const trimmed = response.data.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          return res.status(status).json(JSON.parse(trimmed));
        } catch (err) {
          // Fall through to raw response.
        }
      }
    }

    if (contentType) res.set("Content-Type", contentType);
    return res.status(status).send(response.data ?? "");
  } catch (err) {
    next(err);
  }
});

app.post("/payment/pay", requireAuth, async (req, res, next) => {
  try {
    const payloadResult = buildPayPayload(req.body || {});
    if (!payloadResult.ok) {
      return res.status(400).json({ ok: false, error: payloadResult.error });
    }
    const response = await requestParatikaPay(
      payloadResult.sessionToken,
      payloadResult.requestPayload
    );

    return res.status(200).json({
      ok: true,
      response: response.data,
    });
  } catch (err) {
    next(err);
  }
});

app.post("/payment/pay/redirect", requireAuth, async (req, res, next) => {
  try {
    const payloadResult = buildPayPayload(req.body || {});
    if (!payloadResult.ok) {
      return res.status(400).json({ ok: false, error: payloadResult.error });
    }
    const response = await requestParatikaPay(
      payloadResult.sessionToken,
      payloadResult.requestPayload
    );
    res.set("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(response.data);
  } catch (err) {
    next(err);
  }
});

app.all("/payment/return", (req, res) => {
  const payload = { ...req.query, ...req.body };
  const safeLog = {
    responseCode: payload.responseCode ?? payload.responsecode,
    responseMsg: payload.responseMsg ?? payload.responsemsg,
    merchantPaymentId: payload.merchantPaymentId || payload.merchantpaymentid || null,
    pgOrderId: payload.pgOrderId || payload.pgorderid || null,
    errorCode: payload.errorCode || payload.errorcode || null,
  };
  console.log("Payment return:", safeLog);
  const decodeValue = (value) => {
    if (value === undefined || value === null) return null;
    const raw = String(value);
    try {
      return decodeURIComponent(raw.replace(/\+/g, " "));
    } catch (err) {
      return raw;
    }
  };

  const responseCode = payload.responseCode ?? payload.responsecode;
  const responseMsgRaw = payload.responseMsg ?? payload.responsemsg;
  const responseMsg = decodeValue(responseMsgRaw);
  const isApproved =
    String(responseCode || "") === "00" &&
    String(responseMsg || "").trim().toLowerCase() === "approved";

  const pgOrderId = payload.pgOrderId || payload.pgorderid || null;

  const normalized = {
    merchantPaymentId:
      payload.merchantPaymentId || payload.merchantpaymentid || null,
    customerId: payload.customerId || payload.customerid || null,
    sessionToken: payload.sessionToken || payload.sessiontoken || null,
    responseCode: responseCode || null,
    responseMsg: responseMsg || null,
    pgOrderId: pgOrderId || null,
    errorCode: payload.errorCode || payload.errorcode || null,
    errorMsg: decodeValue(payload.errorMsg || payload.errormsg),
    raw: payload,
  };

  const params = new URLSearchParams({
    responseCode: normalized.responseCode || "",
    responseMsg: normalized.responseMsg || "",
    merchantPaymentId: normalized.merchantPaymentId || "",
    pgOrderId: normalized.pgOrderId || "",
  });

  const redirectTarget = isApproved
    ? `/payment/pay/success?${params.toString()}`
    : `/payment/pay/error?${params.toString()}`;

  return res.redirect(redirectTarget);
});

app.post("/payment/test-session", requireAuth, async (req, res, next) => {
  try {
    if (process.env.NODE_ENV !== "development") {
      return res.status(404).json({ ok: false, error: "Not found." });
    }

    const testConfig = {
      merchant: process.env.TEST_MERCHANT || "",
      merchantUser: process.env.TEST_MERCHANTUSER || "",
      merchantPassword: process.env.TEST_MERCHANTPASSWORD || "",
      returnUrl: process.env.TEST_RETURNURL || "",
    };
    const missing = Object.entries(testConfig)
      .filter(([, value]) => !value)
      .map(([key]) => key);
    if (missing.length) {
      return res.status(400).json({
        ok: false,
        error: `Missing required test env vars: ${missing.join(", ")}`,
      });
    }

    const requestPayload = {
      MERCHANT: testConfig.merchant,
      MERCHANTUSER: testConfig.merchantUser,
      MERCHANTPASSWORD: testConfig.merchantPassword,
      SESSIONTYPE: "PAYMENTSESSION",
      ACTION: "SESSIONTOKEN",
      AMOUNT: "1049.93",
      CURRENCY: "TRY",
      MERCHANTPAYMENTID: `PaymentId-${Date.now()}`,
      RETURNURL: testConfig.returnUrl,
      CUSTOMER: "Customer-21321312",
      CUSTOMERNAME: "Test User",
      CUSTOMEREMAIL: "test.user@example.com",
      CUSTOMERIP: "127.0.0.1",
      CUSTOMERUSERAGENT: "Android",
      NAMEONCARD: "Test User",
      CUSTOMERPHONE: "5387401003",
      ORDERITEMS: JSON.stringify([
        {
          productCode: "T00D3AITCC",
          name: "Galaxy Note 3",
          description: "Description of Galaxy Note 3",
          quantity: 2,
          amount: 449.99,
        },
        {
          productCode: "B00D9AVYBM",
          name: "Samsung Galaxy S III",
          description: "Samsung Galaxy S III (S3) Triband White (Boost Mobile)",
          quantity: 1,
          amount: 149.95,
        },
      ]),
      BILLTOADDRESSLINE: "Road",
      BILLTOCITY: "Istanbul",
      BILLTOCOUNTRY: "TUR",
      BILLTOPOSTALCODE: "34200",
      BILLTOPHONE: "123456789",
      SHIPTOADDRESSLINE: "Road",
      SHIPTOCITY: "Ankara",
      SHIPTOCOUNTRY: "TUR",
      SHIPTOPOSTALCODE: "1105",
      SHIPTOPHONE: "987654321",
    };

    console.log("Payment session test request:", requestPayload);
    const data = formEncode(requestPayload);
    console.log("Payment session test encoded body:", data);

    const response = await axios.request({
      method: "post",
      maxBodyLength: Infinity,
      url: PARATIKA_BASE_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(PARATIKA_COOKIE ? { Cookie: PARATIKA_COOKIE } : {}),
        Accept: "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        Connection: "keep-alive",
        "User-Agent": "PostmanRuntime/7.36.0",
      },
      data,
    });
    console.log("Payment session test response:", response.data);

    return res.status(200).json({
      ok: true,
      request: requestPayload,
      encodedBody: data,
      response: response.data,
    });
  } catch (err) {
    next(err);
  }
});

app.post("/mail/send", requireMailAuth, async (req, res) => {
  const { to, cc, bcc, subject, text, html, replyTo, from } = req.body || {};

  if (!to || !subject || (!text && !html)) {
    return res.status(400).json({
      ok: false,
      error: "to, subject and at least one of text or html are required.",
    });
  }

  const message = {
    from: from || MAIL_SETTINGS.from,
    to,
    cc,
    bcc,
    subject: String(subject),
    text,
    html,
    replyTo,
  };

  try {
    const info = await mailTransporter.sendMail(message);
    return res.json({
      ok: true,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      envelope: info.envelope,
    });
  } catch (err) {
    console.error("Mail send failed:", err);
    return res.status(500).json({ ok: false, error: "Mail send failed." });
  }
});

app.options("/mail/send", requireMailAuth);

app.get("/health", (req, res) => {
  res.json({ ok: true, message: "alive" });
});

app.use((err, req, res, next) => {
  // Multer and manual errors land here
  console.error(err);
  res.status(400).json({ ok: false, error: err.message || "Upload failed." });
});

app.listen(PORT, () => {
  console.log(`File API listening on http://localhost:${PORT}`);
});
