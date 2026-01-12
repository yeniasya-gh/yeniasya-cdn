"use strict";

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const axios = require("axios");

const PORT = process.env.PORT || 3000;
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

const PUBLIC_TYPES = ["kitap", "gazete", "dergi", "ek", "slider"];
const PRIVATE_TYPES = ["kitap", "gazete", "dergi", "ek"];

const parsePrivatePath = (input) => {
  if (!input) return null;
  const cleaned = String(input).trim();
  const match = cleaned.match(/^\/?private\/([a-z]+)\/([^/]+)$/i);
  if (!match) return null;
  const type = match[1].toLowerCase();
  if (!PRIVATE_TYPES.includes(type)) return null;
  const filename = path.basename(match[2]);
  if (!filename.toLowerCase().endsWith(".pdf")) return null;
  return { type, filename };
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

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, TMP_DIR);
  },
  filename: (req, file, cb) => {
    // Add a UUID to avoid collisions when multiple uploads land in the same ms.
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/\s+/g, "_");
    const unique = crypto.randomUUID();
    const stamp = Date.now();
    cb(null, `${stamp}-${unique}-${base}${ext}`);
  },
});

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 20 * 1024 * 1024 },
});

const requireAuth = (req, res, next) => {
  const raw = req.get("x-api-key") || req.get("authorization") || "";
  const token = raw.toLowerCase().startsWith("bearer ")
    ? raw.slice(7)
    : raw;

  if (!token || token !== AUTH_TOKEN) {
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

const serveFile = (filePath, res, extraHeaders = {}) => {
  Object.entries(extraHeaders).forEach(([key, value]) => res.set(key, value));
  res.sendFile(filePath, (sendErr) => {
    if (sendErr) {
      console.error(`sendFile error for ${filePath}:`, sendErr);
      if (!res.headersSent) {
        res.status(500).json({ ok: false, error: "File send failed." });
      }
    }
  });
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
    const targetDir = paths[type].public;
    const { filename } = await moveToFinal(req.file, targetDir);
    return res.json({
      ok: true,
      scope: "public",
      type,
      file: filename,
      url: `/public/${type}/${filename}`,
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
    const targetDir = paths[type]?.private;
    if (!targetDir) {
      return res
        .status(400)
        .json({ ok: false, error: "Private destination not configured for type." });
    }
    const { filename } = await moveToFinal(req.file, targetDir);
    return res.json({
      ok: true,
      scope: "private",
      type,
      file: filename,
      url: `/private/${type}/${filename}`,
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
  const filePath = path.join(paths[type].public, req.params.filename);
  fs.stat(filePath, (err, stats) => {
    if (err) {
      console.warn(`Public file missing: ${filePath}`);
      return res.status(404).json({ ok: false, error: "File not found." });
    }

    const etag = `W/"${stats.size}-${stats.mtimeMs}"`;
    const lastModified = stats.mtime.toUTCString();
    const ifNoneMatch = req.get("if-none-match");
    const ifModifiedSince = req.get("if-modified-since");
    const notModifiedByEtag = ifNoneMatch && ifNoneMatch === etag;
    const notModifiedByDate =
      ifModifiedSince &&
      !Number.isNaN(Date.parse(ifModifiedSince)) &&
      new Date(ifModifiedSince).getTime() >= stats.mtimeMs;

    const cacheHeaders = {
      "Cache-Control": "public, max-age=3600, must-revalidate",
      ETag: etag,
      "Last-Modified": lastModified,
    };

    if (notModifiedByEtag || notModifiedByDate) {
      res.set(cacheHeaders);
      return res.status(304).end();
    }

    serveFile(filePath, res, cacheHeaders);
  });
});

app.get("/private/:type/:filename", requireAuth, (req, res) => {
  const type = (req.params.type || "").toLowerCase();
  if (!PRIVATE_TYPES.includes(type)) {
    return res.status(404).json({ ok: false, error: "Unknown type." });
  }
  const targetDir = paths[type]?.private;
  if (!targetDir) {
    return res.status(404).json({ ok: false, error: "Private destination missing." });
  }
  const filePath = path.join(targetDir, req.params.filename);
  fs.access(filePath, fs.constants.R_OK, (err) => {
    if (err) {
      console.warn(`Private file missing: ${filePath}`);
      return res.status(404).json({ ok: false, error: "File not found." });
    }
    const corsHeaders = buildCorsHeaders(req);
    serveFile(filePath, res, corsHeaders);
  });
});

app.post("/private/view", requireAuth, (req, res) => {
  const rawPath = req.body?.path || req.body?.pdf || req.body?.file;
  const parsed = parsePrivatePath(rawPath);
  if (!parsed) {
    return res.status(400).json({
      ok: false,
      error: "path must be like /private/<type>/<file.pdf>",
    });
  }
  const targetDir = paths[parsed.type]?.private;
  if (!targetDir) {
    return res.status(404).json({ ok: false, error: "Unknown type." });
  }
  const filePath = path.join(targetDir, parsed.filename);
  fs.access(filePath, fs.constants.R_OK, (err) => {
    if (err) {
      return res.status(404).json({ ok: false, error: "File not found." });
    }
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
    res.sendFile(filePath, (sendErr) => {
      if (sendErr) {
        console.error(sendErr);
        if (!res.headersSent) {
          res.status(500).json({ ok: false, error: "File send failed." });
        }
      }
    });
  });
});

app.get("/private/view-file", requireAuth, (req, res) => {
  const rawPath = req.query?.path || req.query?.pdf || req.query?.file;
  const parsed = parsePrivatePath(rawPath);
  if (!parsed) {
    return res.status(400).json({
      ok: false,
      error: "path must be like /private/<type>/<file.pdf>",
    });
  }
  const targetDir = paths[parsed.type]?.private;
  if (!targetDir) {
    return res.status(404).json({ ok: false, error: "Unknown type." });
  }

  const filePath = path.join(targetDir, parsed.filename);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      console.warn(`Private file missing for view-file: ${filePath}`);
      return res.status(404).json({ ok: false, error: "File not found." });
    }

    const corsHeaders = buildCorsHeaders(req);
    const base64 = data.toString("base64");
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
  });
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

app.get("/private/view-secure", (req, res) => {
  const token = req.query?.token;
  const validation = verifyViewToken(token);
  if (!validation.ok) {
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
    return res.status(400).json({ ok: false, error: "Invalid token path." });
  }
  const targetDir = paths[parsed.type]?.private;
  if (!targetDir) {
    return res.status(404).json({ ok: false, error: "Unknown type." });
  }
  const filePath = path.join(targetDir, parsed.filename);
  fs.access(filePath, fs.constants.R_OK, (err) => {
    if (err) {
      return res.status(404).json({ ok: false, error: "File not found." });
    }
    const corsHeaders = buildCorsHeaders(req);
    if (preferViewer) {
      const rawUrl = `${req.path}?token=${encodeURIComponent(token)}&render=raw`;
      const html = `<!doctype html>
<html lang="tr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${parsed.filename}</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; width: 100%; height: 100%; background: #0f1115; color: #dfe7ff; font-family: "Inter", "Segoe UI", sans-serif; }
    .chrome { position: fixed; top: 0; left: 0; right: 0; height: 64px; display: flex; align-items: center; gap: 12px; padding: 0 16px; background: rgba(12,14,20,0.92); border-bottom: 1px solid #1f2533; backdrop-filter: blur(8px); z-index: 10; }
    .spacer { flex: 1; }
    .pill { display: inline-flex; align-items: center; gap: 8px; padding: 10px 14px; border-radius: 999px; background: #1a2232; border: 1px solid #202a3d; font-size: 13px; color: #c7d2ff; }
    button { cursor: pointer; background: #2b3650; border: 1px solid #3a4670; color: #dfe7ff; padding: 8px 12px; border-radius: 8px; font-size: 13px; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .canvas-wrap { position: absolute; inset: 64px 0 0 0; overflow: auto; display: flex; justify-content: center; background: #0f1115; }
    #pdf-canvas { margin: 16px auto 32px auto; box-shadow: 0 16px 48px rgba(0,0,0,0.35); border-radius: 6px; }
    .input { background: #101520; border: 1px solid #1f2738; color: #cfd9ff; padding: 8px 10px; border-radius: 8px; width: 72px; text-align: center; }
    .label { font-size: 12px; opacity: 0.7; }
    .controls { display: inline-flex; align-items: center; gap: 8px; }
  </style>
  <script type="module">
    import * as pdfjsLib from "/pdfjs/pdf.min.mjs";
    pdfjsLib.GlobalWorkerOptions.workerSrc = "/pdfjs/pdf.worker.min.mjs";

    const rawUrl = ${JSON.stringify(rawUrl)};
    const docKey = "pdf-progress:" + ${JSON.stringify(parsed.filename)};
    const startPage = ${pageParam || "null"};
    const startZoom = ${initialZoom};

    let pdfDoc = null;
    let pageNum = startPage || Number(localStorage.getItem(docKey)) || 1;
    let pageRendering = false;
    let pageNumPending = null;
    let scale = startZoom;
    let lastWheelTs = 0;

    async function fetchPdf() {
      const resp = await fetch(rawUrl);
      if (!resp.ok) throw new Error("PDF fetch failed");
      const data = await resp.arrayBuffer();
      return pdfjsLib.getDocument({ data }).promise;
    }

    function renderPage(num) {
      pageRendering = true;
      pdfDoc.getPage(num).then(function(page) {
        const viewport = page.getViewport({ scale });
        const canvas = document.getElementById("pdf-canvas");
        const ctx = canvas.getContext("2d");
        canvas.height = viewport.height;
        canvas.width = viewport.width;

        const renderContext = { canvasContext: ctx, viewport };
        const renderTask = page.render(renderContext);

        renderTask.promise.then(function() {
          pageRendering = false;
          document.getElementById("page-input").value = num;
          document.getElementById("page-count").textContent = pdfDoc.numPages;
          document.getElementById("prev").disabled = num <= 1;
          document.getElementById("next").disabled = num >= pdfDoc.numPages;
          localStorage.setItem(docKey, String(num));
          if (pageNumPending !== null) {
            renderPage(pageNumPending);
            pageNumPending = null;
          }
        });
      });
    }

    function setScale(next) {
      scale = Math.max(0.5, Math.min(3.0, next));
      queueRenderPage(pageNum);
      document.getElementById("zoom").textContent = Math.round(scale * 100) + "%";
    }

    function queueRenderPage(num) {
      if (pageRendering) {
        pageNumPending = num;
      } else {
        renderPage(num);
      }
    }

    function onPrevPage() {
      if (pageNum <= 1) return;
      pageNum--;
      queueRenderPage(pageNum);
    }

    function onNextPage() {
      if (pageNum >= pdfDoc.numPages) return;
      pageNum++;
      queueRenderPage(pageNum);
    }

    function onJump(event) {
      event.preventDefault();
      const input = document.getElementById("page-input");
      const val = Number.parseInt(input.value, 10);
      if (!Number.isFinite(val)) return;
      const next = Math.min(Math.max(1, val), pdfDoc.numPages);
      pageNum = next;
      queueRenderPage(pageNum);
    }

    function onWheelScroll(event) {
      const now = Date.now();
      if (now - lastWheelTs < 350) return;
      if (Math.abs(event.deltaY) < 80) return;
      if (event.deltaY > 0 && pageNum < pdfDoc.numPages) {
        pageNum++;
        queueRenderPage(pageNum);
        lastWheelTs = now;
      } else if (event.deltaY < 0 && pageNum > 1) {
        pageNum--;
        queueRenderPage(pageNum);
        lastWheelTs = now;
      }
    }

    window.addEventListener("DOMContentLoaded", async () => {
      document.getElementById("prev").addEventListener("click", onPrevPage);
      document.getElementById("next").addEventListener("click", onNextPage);
      document.getElementById("zoom-in").addEventListener("click", () => setScale(scale + 0.15));
      document.getElementById("zoom-out").addEventListener("click", () => setScale(scale - 0.15));
      document.getElementById("zoom-reset").addEventListener("click", () => setScale(startZoom));
      document.getElementById("page-form").addEventListener("submit", onJump);
      document.getElementById("canvas-wrap").addEventListener("wheel", onWheelScroll, { passive: true });
      try {
        pdfDoc = await fetchPdf();
        if (pageNum > pdfDoc.numPages) pageNum = pdfDoc.numPages;
        document.getElementById("page-count").textContent = pdfDoc.numPages;
        document.getElementById("zoom").textContent = Math.round(scale * 100) + "%";
        renderPage(pageNum);
      } catch (err) {
        document.getElementById("status").textContent = "PDF yüklenemedi";
        console.error(err);
      }
    });
  </script>
</head>
<body>
  <div class="chrome">
    <div class="spacer"></div>
    <div class="pill controls">
      <button id="prev">&#8592;</button>
      <form id="page-form" style="display:inline-flex;align-items:center;gap:6px;">
        <input class="input" id="page-input" type="number" min="1" value="${pageParam || 1}" />
        <span class="label">/ <span id="page-count">-</span></span>
      </form>
      <button id="next">&#8594;</button>
    </div>
    <div class="pill controls">
      <button id="zoom-out">-</button>
      <span id="zoom">100%</span>
      <button id="zoom-in">+</button>
      <button id="zoom-reset">=</button>
    </div>
    <div id="status" style="font-size:12px; color:#7da5ff; padding-left:12px;"></div>
  </div>
  <div class="canvas-wrap" id="canvas-wrap">
    <canvas id="pdf-canvas"></canvas>
  </div>
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
      return res.send(html);
    }
    res.set({
      ...corsHeaders,
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename=\"${parsed.filename}\"`,
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": `frame-ancestors ${FRAME_ANCESTORS_DIRECTIVE}`,
    });
    res.sendFile(filePath, (sendErr) => {
      if (sendErr) {
        console.error(sendErr);
        if (!res.headersSent) {
          res.status(500).json({ ok: false, error: "File send failed." });
        }
      }
    });
  });
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
      DISCOUNTAMOUNT: pick("DISCOUNTAMOUNT", "discountAmount"),
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

  const normalized = {
    merchantPaymentId:
      payload.merchantPaymentId || payload.merchantpaymentid || null,
    customerId: payload.customerId || payload.customerid || null,
    sessionToken: payload.sessionToken || payload.sessiontoken || null,
    responseCode: responseCode || null,
    responseMsg: responseMsg || null,
    errorCode: payload.errorCode || payload.errorcode || null,
    errorMsg: decodeValue(payload.errorMsg || payload.errormsg),
    raw: payload,
  };

  if (isApproved) {
    return res.status(200).json({ ok: true, approved: true, ...normalized });
  }
  return res.status(200).json({ ok: false, approved: false, ...normalized });
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
