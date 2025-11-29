"use strict";

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const AUTH_TOKEN = process.env.AUTH_TOKEN || "change-me";
const STORAGE_ROOT =
  process.env.STORAGE_ROOT || path.join(__dirname, "..", "storage");
const TMP_DIR = path.join(STORAGE_ROOT, "_tmp");

const allowedTypes = ["kitap", "gazete", "dergi"];

const paths = {
  kitap: {
    public: path.join(STORAGE_ROOT, "kitap", "public"),
    private: path.join(STORAGE_ROOT, "kitap", "private"),
  },
  gazete: {
    public: path.join(STORAGE_ROOT, "gazete", "public"),
  },
  dergi: {
    public: path.join(STORAGE_ROOT, "dergi", "public"),
  },
};

const app = express();

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
    const safeName = file.originalname.replace(/\s+/g, "_");
    const stamp = Date.now();
    cb(null, `${stamp}-${safeName}`);
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
    if (type !== "kitap") {
      return res
        .status(400)
        .json({ ok: false, error: "Private uploads allowed only for type kitap." });
    }
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "File is required." });
    }
    const targetDir = paths.kitap.private;
    const { filename } = await moveToFinal(req.file, targetDir);
    return res.json({
      ok: true,
      scope: "private",
      type,
      file: filename,
      url: `/private/${filename}`,
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
  fs.access(filePath, fs.constants.R_OK, (err) => {
    if (err) {
      return res.status(404).json({ ok: false, error: "File not found." });
    }
    res.sendFile(filePath);
  });
});

app.get("/private/:filename", requireAuth, (req, res) => {
  const filePath = path.join(paths.kitap.private, req.params.filename);
  fs.access(filePath, fs.constants.R_OK, (err) => {
    if (err) {
      return res.status(404).json({ ok: false, error: "File not found." });
    }
    res.sendFile(filePath);
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
