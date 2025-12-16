"use strict";

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

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
const MAIL_SETTINGS = {
  host: process.env.MAIL_HOST || "mail.yeniasya.com.tr",
  port: Number(process.env.MAIL_PORT || "587"),
  user: process.env.MAIL_USER || "app@yeniasya.com.tr",
  pass: process.env.MAIL_PASS || "Asya1970@1",
  from: process.env.MAIL_FROM || "app@yeniasya.com.tr",
  token: process.env.MAIL_API_TOKEN || AUTH_TOKEN,
};

const allowedTypes = ["kitap", "gazete", "dergi"];

const parsePrivatePath = (input) => {
  if (!input) return null;
  const cleaned = String(input).trim();
  const match = cleaned.match(/^\/?private\/([a-z]+)\/([^/]+)$/i);
  if (!match) return null;
  const type = match[1].toLowerCase();
  if (!allowedTypes.includes(type)) return null;
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

const resolveType = (req) => {
  const type = (req.body?.type || req.query?.type || "").toLowerCase();
  if (!allowedTypes.includes(type)) {
    return null;
  }
  return type;
};

const mailTransporter = nodemailer.createTransport({
  host: MAIL_SETTINGS.host,
  port: MAIL_SETTINGS.port,
  secure: MAIL_SETTINGS.port === 465,
  auth: {
    user: MAIL_SETTINGS.user,
    pass: MAIL_SETTINGS.pass,
  },
});

app.use(express.json());

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

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
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
    const type = resolveType(req);
    if (!type) {
      return res
        .status(400)
        .json({ ok: false, error: `type is required: ${allowedTypes.join(", ")}` });
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
    const type = resolveType(req);
    if (!type) {
      return res
        .status(400)
        .json({ ok: false, error: `type is required: ${allowedTypes.join(", ")}` });
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
  if (!allowedTypes.includes(type)) {
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
  if (!allowedTypes.includes(type)) {
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
      "X-Frame-Options": "SAMEORIGIN",
      "Content-Security-Policy": "frame-ancestors 'self'",
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
    res.set({
      ...corsHeaders,
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename=\"${parsed.filename}\"`,
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "SAMEORIGIN",
      "Content-Security-Policy": "frame-ancestors 'self'",
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
