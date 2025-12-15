"use strict";

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

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

const resolveType = (req) => {
  const type = (req.body?.type || req.query?.type || "").toLowerCase();
  if (!allowedTypes.includes(type)) {
    return null;
  }
  return type;
};

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
    const requestOrigin = req.get("origin");
    const originAllowed =
      ALLOWED_ORIGINS.includes("*") ||
      (requestOrigin && ALLOWED_ORIGINS.includes(requestOrigin));

    const corsHeaders = originAllowed
      ? {
          "Access-Control-Allow-Origin": requestOrigin || "*",
          "Access-Control-Allow-Methods": ALLOWED_METHODS,
          "Access-Control-Allow-Headers": ALLOWED_HEADERS,
        }
      : {};

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
    const requestOrigin = req.get("origin");
    const originAllowed =
      ALLOWED_ORIGINS.includes("*") ||
      (requestOrigin && ALLOWED_ORIGINS.includes(requestOrigin));

    const corsHeaders = originAllowed
      ? {
          "Access-Control-Allow-Origin": requestOrigin || "*",
          "Access-Control-Allow-Methods": ALLOWED_METHODS,
          "Access-Control-Allow-Headers": ALLOWED_HEADERS,
        }
      : {};

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
