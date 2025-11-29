"use strict";

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const AUTH_TOKEN = process.env.AUTH_TOKEN || "change-me";
const STORAGE_ROOT =
  process.env.STORAGE_ROOT || path.join(__dirname, "..", "storage");

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
  destination: (req, file, cb) => {
    if (!req.uploadDest) {
      return cb(new Error("Upload destination not set."));
    }
    cb(null, req.uploadDest);
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
  const type = (req.body.type || req.query.type || "").toLowerCase();
  if (!allowedTypes.includes(type)) {
    return null;
  }
  return type;
};

const prepareUpload = (destResolver) => (req, res, next) => {
  const type = resolveType(req);
  if (!type) {
    return res
      .status(400)
      .json({ ok: false, error: `type is required: ${allowedTypes.join(", ")}` });
  }
  const dest = destResolver(type);
  if (!dest) {
    return res.status(400).json({ ok: false, error: "Invalid destination." });
  }
  fs.mkdirSync(dest, { recursive: true });
  req.uploadDest = dest;
  req.uploadType = type;
  next();
};

app.use(express.json());

app.post(
  "/upload/public",
  prepareUpload((type) => paths[type].public),
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "File is required." });
    }

    return res.json({
      ok: true,
      scope: "public",
      type: req.uploadType,
      file: req.file.filename,
      url: `/public/${req.uploadType}/${req.file.filename}`,
    });
  }
);

app.post(
  "/upload/private",
  prepareUpload((type) => {
    if (type !== "kitap") {
      return null;
    }
    return paths.kitap.private;
  }),
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "File is required." });
    }

    return res.json({
      ok: true,
      scope: "private",
      type: req.uploadType,
      file: req.file.filename,
      url: `/private/${req.file.filename}`,
    });
  }
);

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
