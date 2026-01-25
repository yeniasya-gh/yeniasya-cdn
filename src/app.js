"use strict";

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const axios = require("axios");

const PORT = process.env.PORT || 3001;
// Hardcoded token per request (env not used intentionally).
const AUTH_TOKEN = "kPPm8b-12kA-9PxQ-YY822L";
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
const VIEW_TOKEN_SECRET = process.env.VIEW_TOKEN_SECRET || AUTH_TOKEN;
const VIEW_TOKEN_TTL_MIN = Number(process.env.VIEW_TOKEN_TTL_MIN || "5");
const FRAME_ANCESTORS = (process.env.ALLOWED_FRAME_ANCESTORS || "*")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const FRAME_ANCESTORS_DIRECTIVE =
  FRAME_ANCESTORS.length === 0 ? "'none'" : FRAME_ANCESTORS.join(" ");
const PUBLIC_ROOT = path.join(__dirname, "..", "public");
const MAIL_SETTINGS = {
  host: process.env.MAIL_HOST || "mail.yeniasya.com.tr",
  port: Number(process.env.MAIL_PORT || "587"),
  user: process.env.MAIL_USER || "app@yeniasya.com.tr",
  pass: process.env.MAIL_PASS || "Asya1970@1",
  from: process.env.MAIL_FROM || "app@yeniasya.com.tr",
  token: process.env.MAIL_API_TOKEN || AUTH_TOKEN,
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
      process.env.MAIL_TLS_REJECT_UNAUTHORIZED === "true"
        ? true
        : false,
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
  const url = `https://storage.bunnycdn.com/${BUNNY_SETTINGS.storageZone}/${type}/${scope}/${filename}`;
  try {
    const response = await axios.put(url, fileBuffer, {
      headers: {
        AccessKey: BUNNY_SETTINGS.accessKey,
        "Content-Type": "application/octet-stream",
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
    });
    return response.data;
  } catch (err) {
    const errorMsg = err.response?.data?.Message || err.response?.data || err.message;
    const statusCode = err.response?.status || 500;
    console.error(`[BunnyCDN Upload Error] ${statusCode}: ${JSON.stringify(errorMsg)}`);
    console.error(`[BunnyCDN Request Details] URL: ${url}, Zone: ${BUNNY_SETTINGS.storageZone}`);
    throw new Error(`BunnyCDN upload failed (${statusCode}): ${JSON.stringify(errorMsg)}`);
  }
};

const fetchFromBunny = async (type, scope, filename) => {
  const url = `https://storage.bunnycdn.com/${BUNNY_SETTINGS.storageZone}/${type}/${scope}/${filename}`;
  try {
    const response = await axios.get(url, {
      headers: {
        AccessKey: BUNNY_SETTINGS.accessKey,
      },
      responseType: "arraybuffer",
    });
    return response.data;
  } catch (err) {
    const errorMsg = err.response?.data?.Message || err.response?.data || err.message;
    const statusCode = err.response?.status || 500;
    console.error(`[BunnyCDN Fetch Error] ${statusCode}: ${JSON.stringify(errorMsg)}`);
    console.error(`[BunnyCDN Fetch Details] URL: ${url}`);
    throw new Error(`BunnyCDN fetch failed (${statusCode})`);
  }
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

app.post("/upload/public", upload.single("file"), async (req, res, next) => {
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

app.post("/upload/private", upload.single("file"), async (req, res, next) => {
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
    const data = await fetchFromBunny(type, "private", req.params.filename);
    const corsHeaders = buildCorsHeaders(req);
    Object.entries(corsHeaders).forEach(([key, value]) => res.set(key, value));

    // Determine content type based on extension
    const ext = path.extname(req.params.filename).toLowerCase();
    const contentType = ext === ".pdf" ? "application/pdf" : "application/octet-stream";
    res.set("Content-Type", contentType);

    res.send(data);

    logPdfRequest({
      ...logBase,
      status: 200,
      outcome: "success",
      message: "File delivered from BunnyCDN.",
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

app.post("/private/view", requireAuth, async (req, res) => {
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
    const data = await fetchFromBunny(parsed.type, "private", parsed.filename);
    const corsHeaders = buildCorsHeaders(req);

    res.set({
      ...corsHeaders,
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename="${parsed.filename}"`,
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
      message: "Inline PDF served from BunnyCDN.",
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

app.post("/private/view-token", requireAuth, (req, res) => {
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

app.get("/private/view-secure", async (req, res) => {
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
      "Content-Disposition": `inline; filename=\"${parsed.filename}\"`,
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
  console.log("Payment return payload:", payload);
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
    const requestPayload = {
      MERCHANT: "10001831",
      MERCHANTUSER: "yasinaydin@yeniasya.com.tr",
      MERCHANTPASSWORD: "YENIasya111..",
      SESSIONTYPE: "PAYMENTSESSION",
      ACTION: "SESSIONTOKEN",
      AMOUNT: "1049.93",
      CURRENCY: "TRY",
      MERCHANTPAYMENTID: "PaymentId-1232132132131",
      RETURNURL: "http://localhost:3000/payment/return",
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
