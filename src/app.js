"use strict";

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn, spawnSync } = require("child_process");
const https = require("https");
const { setTimeout: sleep } = require("timers/promises");
const nodemailer = require("nodemailer");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 3001;
const AUTH_TOKEN = process.env.AUTH_TOKEN || "";
// Resolve to absolute path so sendFile receives an absolute path.
const STORAGE_ROOT = path.resolve(
  process.env.STORAGE_ROOT || path.join(__dirname, "..", "storage")
);
const TMP_DIR = path.join(STORAGE_ROOT, "_tmp");
const ALLOWED_ORIGINS = (() => {
  const origins = (process.env.ALLOWED_ORIGINS || "*")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  const normalized = new Set(origins);
  const domainAliases = [
    ["https://yeniasyadijital.com", "https://www.yeniasyadijital.com"],
    ["https://yeniasya.com.tr", "https://www.yeniasya.com.tr"],
  ];

  for (const [bare, www] of domainAliases) {
    if (normalized.has(bare)) normalized.add(www);
    if (normalized.has(www)) normalized.add(bare);
  }

  return Array.from(normalized);
})();
const ALLOWED_HEADERS =
  process.env.ALLOWED_HEADERS || "content-type, x-api-key, authorization, x-mail-token";
const ALLOWED_METHODS = "GET, POST, OPTIONS";
const REQUEST_BODY_LIMIT = process.env.REQUEST_BODY_LIMIT || "2mb";
const TRUST_PROXY = process.env.TRUST_PROXY || "loopback";
const RATE_LIMIT_WINDOW_MS_RAW = Number(process.env.RATE_LIMIT_WINDOW_MS || "900000");
const RATE_LIMIT_WINDOW_MS =
  Number.isFinite(RATE_LIMIT_WINDOW_MS_RAW) && RATE_LIMIT_WINDOW_MS_RAW > 0
    ? RATE_LIMIT_WINDOW_MS_RAW
    : 900000;
const RATE_LIMIT_MAX_RAW = Number(process.env.RATE_LIMIT_MAX || "6000");
const RATE_LIMIT_MAX =
  Number.isFinite(RATE_LIMIT_MAX_RAW) && RATE_LIMIT_MAX_RAW > 0
    ? RATE_LIMIT_MAX_RAW
    : 1200;
const AUTH_RATE_LIMIT_MAX_RAW = Number(process.env.AUTH_RATE_LIMIT_MAX || "120");
const AUTH_RATE_LIMIT_MAX =
  Number.isFinite(AUTH_RATE_LIMIT_MAX_RAW) && AUTH_RATE_LIMIT_MAX_RAW > 0
    ? AUTH_RATE_LIMIT_MAX_RAW
    : 20;
const LOGIN_RATE_LIMIT_MAX_RAW = Number(process.env.LOGIN_RATE_LIMIT_MAX || "240");
const LOGIN_RATE_LIMIT_MAX =
  Number.isFinite(LOGIN_RATE_LIMIT_MAX_RAW) && LOGIN_RATE_LIMIT_MAX_RAW > 0
    ? LOGIN_RATE_LIMIT_MAX_RAW
    : 60;
const GUEST_TOKEN_RATE_LIMIT_MAX_RAW = Number(
  process.env.GUEST_TOKEN_RATE_LIMIT_MAX || "300"
);
const GUEST_TOKEN_RATE_LIMIT_MAX =
  Number.isFinite(GUEST_TOKEN_RATE_LIMIT_MAX_RAW) && GUEST_TOKEN_RATE_LIMIT_MAX_RAW > 0
    ? GUEST_TOKEN_RATE_LIMIT_MAX_RAW
    : 120;
const PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX_RAW = Number(
  process.env.PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX || "30"
);
const PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX =
  Number.isFinite(PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX_RAW) &&
  PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX_RAW > 0
    ? PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX_RAW
    : 8;
const PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX_RAW = Number(
  process.env.PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX || "30"
);
const PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX =
  Number.isFinite(PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX_RAW) &&
  PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX_RAW > 0
    ? PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX_RAW
    : 10;
const PASSWORD_RESET_TOKEN_TTL_MINUTES_RAW = Number(
  process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES || "30"
);
const PASSWORD_RESET_TOKEN_TTL_MINUTES =
  Number.isFinite(PASSWORD_RESET_TOKEN_TTL_MINUTES_RAW) &&
  PASSWORD_RESET_TOKEN_TTL_MINUTES_RAW > 0
    ? PASSWORD_RESET_TOKEN_TTL_MINUTES_RAW
    : 30;
const EMAIL_VERIFICATION_TOKEN_TTL_MINUTES_RAW = Number(
  process.env.EMAIL_VERIFICATION_TOKEN_TTL_MINUTES || "60"
);
const EMAIL_VERIFICATION_TOKEN_TTL_MINUTES =
  Number.isFinite(EMAIL_VERIFICATION_TOKEN_TTL_MINUTES_RAW) &&
  EMAIL_VERIFICATION_TOKEN_TTL_MINUTES_RAW > 0
    ? EMAIL_VERIFICATION_TOKEN_TTL_MINUTES_RAW
    : 60;
const UPLOAD_RATE_LIMIT_MAX_RAW = Number(process.env.UPLOAD_RATE_LIMIT_MAX || "120");
const UPLOAD_RATE_LIMIT_MAX =
  Number.isFinite(UPLOAD_RATE_LIMIT_MAX_RAW) && UPLOAD_RATE_LIMIT_MAX_RAW > 0
    ? UPLOAD_RATE_LIMIT_MAX_RAW
    : 60;
const PDF_UPLOAD_OPTIMIZE_MIN_BYTES_RAW = Number(
  process.env.PDF_UPLOAD_OPTIMIZE_MIN_BYTES || String(2 * 1024 * 1024)
);
const PDF_UPLOAD_OPTIMIZE_MIN_BYTES =
  Number.isFinite(PDF_UPLOAD_OPTIMIZE_MIN_BYTES_RAW) && PDF_UPLOAD_OPTIMIZE_MIN_BYTES_RAW > 0
    ? PDF_UPLOAD_OPTIMIZE_MIN_BYTES_RAW
    : 2 * 1024 * 1024;
const PDF_UPLOAD_OPTIMIZE_PDFSETTINGS = (
  process.env.PDF_UPLOAD_OPTIMIZE_PDFSETTINGS || "/ebook"
)
  .trim()
  .replace(/\s+/g, "");
const PDF_UPLOAD_OPTIMIZE_KEEP_RATIO_RAW = Number(
  process.env.PDF_UPLOAD_OPTIMIZE_KEEP_RATIO || "0.98"
);
const PDF_UPLOAD_OPTIMIZE_KEEP_RATIO =
  Number.isFinite(PDF_UPLOAD_OPTIMIZE_KEEP_RATIO_RAW) &&
  PDF_UPLOAD_OPTIMIZE_KEEP_RATIO_RAW > 0 &&
  PDF_UPLOAD_OPTIMIZE_KEEP_RATIO_RAW < 1
    ? PDF_UPLOAD_OPTIMIZE_KEEP_RATIO_RAW
    : 0.98;
const BCRYPT_COST_RAW = Number(process.env.BCRYPT_COST || "12");
const BCRYPT_COST =
  Number.isInteger(BCRYPT_COST_RAW) && BCRYPT_COST_RAW >= 10 && BCRYPT_COST_RAW <= 14
    ? BCRYPT_COST_RAW
    : 12;
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
const PASSWORD_RESET_WEB_URL =
  process.env.PASSWORD_RESET_WEB_URL ||
  "https://cdn.yeniasyadijital.com/sifre-sifirla";
const EMAIL_VERIFICATION_WEB_URL =
  process.env.EMAIL_VERIFICATION_WEB_URL ||
  "https://yeniasyadijital.com/hesap-aktivasyon/";
const MAIL_TLS_SERVERNAME = (process.env.MAIL_TLS_SERVERNAME || "")
  .trim()
  .replace(/\.$/, "");
const MAIL_TLS_REJECT_UNAUTHORIZED =
  process.env.MAIL_TLS_REJECT_UNAUTHORIZED === "false" ? false : true;
const FIREBASE_SERVICE_ACCOUNT_JSON =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON || "";
const FIREBASE_SERVICE_ACCOUNT_JSON_PATH =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON_PATH || "";
const FIREBASE_PROJECT_ID = (process.env.FIREBASE_PROJECT_ID || "").trim();
const FCM_HTTP_TIMEOUT_MS = Number(process.env.FCM_HTTP_TIMEOUT_MS || "15000");
const ADMIN_ROLE_IDS_RAW = (process.env.ADMIN_ROLE_IDS || "2")
  .split(",")
  .map((v) => Number.parseInt(v.trim(), 10))
  .filter((v) => Number.isInteger(v) && v > 0);
const ADMIN_ROLE_IDS = ADMIN_ROLE_IDS_RAW.length ? ADMIN_ROLE_IDS_RAW : [2];
const PAYMENT_RETURN_REDIRECT_URL = process.env.PAYMENT_RETURN_REDIRECT_URL || "";
const PARATIKA_BASE_URL =
  process.env.PARATIKA_BASE_URL || "https://vpos.paratika.com.tr/paratika/api/v2";
const PARATIKA_MERCHANTUSER = process.env.PARATIKA_MERCHANTUSER || "";
const PARATIKA_MERCHANTPASSWORD = process.env.PARATIKA_MERCHANTPASSWORD || "";
const PARATIKA_MERCHANT = process.env.PARATIKA_MERCHANT || "";
const PARATIKA_RETURNURL = process.env.PARATIKA_RETURNURL || "";
const PARATIKA_COOKIE = process.env.PARATIKA_COOKIE || "";
const LEGACY_NEWSPAPER_TOKEN_SECRET = String(
  process.env.LEGACY_NEWSPAPER_TOKEN_SECRET || ""
);
const LEGACY_NEWSPAPER_BASE_URL = String(
  process.env.LEGACY_NEWSPAPER_BASE_URL || "https://www.yeniasya.com.tr/e-gazete/content/0"
).replace(/\/+$/, "");
const LEGACY_NEWSPAPER_PDF_BASE_URL = String(
  process.env.LEGACY_NEWSPAPER_PDF_BASE_URL ||
    "https://www.yeniasya.com.tr/Sites/YeniAsya/Upload/files/EPub"
).replace(/\/+$/, "");
const BUNNY_SETTINGS = {
  cdnUrl: process.env.BUNNY_CDN_URL || "yeniasya.b-cdn.net",
  storageZone: process.env.BUNNY_STORAGE_ZONE || "yeniasya",
  accessKey: process.env.BUNNY_ACCESS_KEY || "",
};
const CDN_PUBLIC_HOST = String(process.env.CDN_PUBLIC_HOST || "cdn.yeniasyadijital.com")
  .trim()
  .replace(/^https?:\/\//i, "")
  .replace(/\/.*$/, "")
  .toLowerCase();
const BUNNY_HTTP_TIMEOUT_MS = Number(process.env.BUNNY_HTTP_TIMEOUT_MS || "20000");
const BUNNY_HTTP_RETRIES = Number(process.env.BUNNY_HTTP_RETRIES || "1");
const BUNNY_HTTP_RETRY_BASE_DELAY_MS = Number(
  process.env.BUNNY_HTTP_RETRY_BASE_DELAY_MS || "400"
);
const BUNNY_UPLOAD_TIMEOUT_MS_RAW = Number(
  process.env.BUNNY_UPLOAD_TIMEOUT_MS || "120000"
);
const BUNNY_UPLOAD_TIMEOUT_MS =
  Number.isFinite(BUNNY_UPLOAD_TIMEOUT_MS_RAW) && BUNNY_UPLOAD_TIMEOUT_MS_RAW > 0
    ? BUNNY_UPLOAD_TIMEOUT_MS_RAW
    : 120000;
const BUNNY_UPLOAD_RETRIES_RAW = Number(process.env.BUNNY_UPLOAD_RETRIES || "1");
const BUNNY_UPLOAD_RETRIES =
  Number.isInteger(BUNNY_UPLOAD_RETRIES_RAW) && BUNNY_UPLOAD_RETRIES_RAW >= 0
    ? BUNNY_UPLOAD_RETRIES_RAW
    : 1;
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
const HASURA_HTTP_TIMEOUT_MS = Number(process.env.HASURA_HTTP_TIMEOUT_MS || "15000");
const HASURA_ALLOW_JWTLESS =
  (process.env.HASURA_ALLOW_JWTLESS || "").toLowerCase() === "true";
const HOME_BOOTSTRAP_HASURA_TIMEOUT_MS = Number(
  process.env.HOME_BOOTSTRAP_HASURA_TIMEOUT_MS || "30000"
);
const HOME_BOOTSTRAP_CACHE_TTL_MS = Number(
  process.env.HOME_BOOTSTRAP_CACHE_TTL_MS || "60000"
);
const HOME_POSTGRES_URL =
  process.env.HOME_POSTGRES_URL ||
  process.env.POSTGRES_URL ||
  process.env.DATABASE_URL ||
  "";
const HOME_POSTGRES_HOST =
  process.env.HOME_POSTGRES_HOST || process.env.POSTGRES_HOST || process.env.PGHOST || "";
const HOME_POSTGRES_PORT_RAW = Number(
  process.env.HOME_POSTGRES_PORT || process.env.POSTGRES_PORT || process.env.PGPORT || "5432"
);
const HOME_POSTGRES_PORT =
  Number.isInteger(HOME_POSTGRES_PORT_RAW) && HOME_POSTGRES_PORT_RAW > 0
    ? HOME_POSTGRES_PORT_RAW
    : 5432;
const HOME_POSTGRES_DATABASE =
  process.env.HOME_POSTGRES_DATABASE ||
  process.env.POSTGRES_DATABASE ||
  process.env.PGDATABASE ||
  "";
const HOME_POSTGRES_USER =
  process.env.HOME_POSTGRES_USER || process.env.POSTGRES_USER || process.env.PGUSER || "";
const HOME_POSTGRES_PASSWORD =
  process.env.HOME_POSTGRES_PASSWORD ||
  process.env.POSTGRES_PASSWORD ||
  process.env.PGPASSWORD ||
  "";
const HOME_POSTGRES_SSL =
  (process.env.HOME_POSTGRES_SSL || process.env.POSTGRES_SSL || "").toLowerCase() === "true";
const HOME_POSTGRES_SSLMODE = String(
  process.env.HOME_POSTGRES_SSLMODE || process.env.POSTGRES_SSLMODE || process.env.PGSSLMODE || ""
)
  .trim()
  .toLowerCase();
const HOME_POSTGRES_SSL_REJECT_UNAUTHORIZED =
  process.env.HOME_POSTGRES_SSL_REJECT_UNAUTHORIZED === "false" ||
  process.env.POSTGRES_SSL_REJECT_UNAUTHORIZED === "false"
    ? false
    : true;
const HOME_POSTGRES_POOL_MAX_RAW = Number(process.env.HOME_POSTGRES_POOL_MAX || "10");
const HOME_POSTGRES_POOL_MAX =
  Number.isInteger(HOME_POSTGRES_POOL_MAX_RAW) && HOME_POSTGRES_POOL_MAX_RAW > 0
    ? HOME_POSTGRES_POOL_MAX_RAW
    : 10;
const HOME_POSTGRES_IDLE_TIMEOUT_MS_RAW = Number(
  process.env.HOME_POSTGRES_IDLE_TIMEOUT_MS || "30000"
);
const HOME_POSTGRES_IDLE_TIMEOUT_MS =
  Number.isFinite(HOME_POSTGRES_IDLE_TIMEOUT_MS_RAW) && HOME_POSTGRES_IDLE_TIMEOUT_MS_RAW >= 0
    ? HOME_POSTGRES_IDLE_TIMEOUT_MS_RAW
    : 30000;
const HOME_POSTGRES_CONNECTION_TIMEOUT_MS_RAW = Number(
  process.env.HOME_POSTGRES_CONNECTION_TIMEOUT_MS || "5000"
);
const HOME_POSTGRES_CONNECTION_TIMEOUT_MS =
  Number.isFinite(HOME_POSTGRES_CONNECTION_TIMEOUT_MS_RAW) &&
  HOME_POSTGRES_CONNECTION_TIMEOUT_MS_RAW >= 0
    ? HOME_POSTGRES_CONNECTION_TIMEOUT_MS_RAW
    : 5000;
const HOME_POSTGRES_QUERY_TIMEOUT_MS_RAW = Number(
  process.env.HOME_POSTGRES_QUERY_TIMEOUT_MS || "10000"
);
const HOME_POSTGRES_QUERY_TIMEOUT_MS =
  Number.isFinite(HOME_POSTGRES_QUERY_TIMEOUT_MS_RAW) && HOME_POSTGRES_QUERY_TIMEOUT_MS_RAW > 0
    ? HOME_POSTGRES_QUERY_TIMEOUT_MS_RAW
    : 10000;
const JWT_SECRET = process.env.JWT_SECRET || "";
const JWT_EXPIRES_IN = (() => {
  const configured = String(process.env.JWT_EXPIRES_IN || "").trim();
  if (!configured || configured === "1d") {
    return "90d";
  }
  return configured;
})();
const JWT_ISSUER = process.env.JWT_ISSUER || "yeniasya";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "yeniasya-app";
const JWT_DEFAULT_ROLE = process.env.JWT_DEFAULT_ROLE || "user";
const JWT_ALLOWED_ROLES = (process.env.JWT_ALLOWED_ROLES || JWT_DEFAULT_ROLE)
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const GUEST_JWT_ROLE = (process.env.GUEST_JWT_ROLE || "guest").trim() || "guest";
const GUEST_JWT_ALLOWED_ROLES = (
  process.env.GUEST_JWT_ALLOWED_ROLES || GUEST_JWT_ROLE
)
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const GUEST_JWT_EXPIRES_IN = process.env.GUEST_JWT_EXPIRES_IN || "6h";
const REVENUECAT_ENTITLEMENT_ACCESS = {
  "yeniasya pro": { itemType: "newspaper_subscription", itemId: null },
};
const REVENUECAT_API_BASE_URL = (
  process.env.REVENUECAT_API_BASE_URL || "https://api.revenuecat.com/v1"
).replace(/\/+$/, "");
const REVENUECAT_SECRET_API_KEY =
  process.env.REVENUECAT_SECRET_API_KEY || process.env.REVENUECAT_REST_API_KEY || "";
const REVENUECAT_HTTP_TIMEOUT_MS = Number(process.env.REVENUECAT_HTTP_TIMEOUT_MS || "10000");
const REVENUECAT_WEBHOOK_AUTH_TOKEN = (
  process.env.REVENUECAT_WEBHOOK_AUTH_TOKEN ||
  AUTH_TOKEN ||
  ""
).trim();
const REVENUECAT_DEFAULT_ENTITLEMENT_ID =
  process.env.REVENUECAT_DEFAULT_ENTITLEMENT_ID || "Yeniasya Pro";
const REVENUECAT_WEB_CHECKOUT_PLATFORM =
  process.env.REVENUECAT_WEB_CHECKOUT_PLATFORM || "paratika";
const REVENUECAT_ACCESS_SOURCE = "revenuecat";
const REVENUECAT_RECONCILE_ENABLED =
  (process.env.REVENUECAT_RECONCILE_ENABLED || "true").toLowerCase() === "true";
const REVENUECAT_RECONCILE_INTERVAL_MINUTES_RAW = Number(
  process.env.REVENUECAT_RECONCILE_INTERVAL_MINUTES || "30"
);
const REVENUECAT_RECONCILE_INTERVAL_MINUTES =
  Number.isFinite(REVENUECAT_RECONCILE_INTERVAL_MINUTES_RAW) &&
  REVENUECAT_RECONCILE_INTERVAL_MINUTES_RAW > 0
    ? REVENUECAT_RECONCILE_INTERVAL_MINUTES_RAW
    : 30;
const REVENUECAT_RECONCILE_BATCH_SIZE_RAW = Number(
  process.env.REVENUECAT_RECONCILE_BATCH_SIZE || "50"
);
const REVENUECAT_RECONCILE_BATCH_SIZE =
  Number.isInteger(REVENUECAT_RECONCILE_BATCH_SIZE_RAW) &&
  REVENUECAT_RECONCILE_BATCH_SIZE_RAW > 0
    ? REVENUECAT_RECONCILE_BATCH_SIZE_RAW
    : 50;
const REVENUECAT_RECONCILE_STARTUP_DELAY_MS_RAW = Number(
  process.env.REVENUECAT_RECONCILE_STARTUP_DELAY_MS || "15000"
);
const REVENUECAT_RECONCILE_STARTUP_DELAY_MS =
  Number.isFinite(REVENUECAT_RECONCILE_STARTUP_DELAY_MS_RAW) &&
  REVENUECAT_RECONCILE_STARTUP_DELAY_MS_RAW >= 0
    ? REVENUECAT_RECONCILE_STARTUP_DELAY_MS_RAW
    : 15000;
const REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS_RAW = Number(
  process.env.REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS || "300000"
);
const REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS =
  Number.isFinite(REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS_RAW) &&
  REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS_RAW >= 0
    ? REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS_RAW
    : 300000;
const REVENUECAT_ACTIVE_EVENT_TYPES = new Set([
  "INITIAL_PURCHASE",
  "RENEWAL",
  "NON_RENEWING_PURCHASE",
  "PRODUCT_CHANGE",
  "SUBSCRIPTION_EXTENDED",
  "TEMPORARY_ENTITLEMENT_GRANT",
  "UNCANCELLATION",
]);
const REVENUECAT_INACTIVE_EVENT_TYPES = new Set([
  "EXPIRATION",
  "REFUND",
  "SUBSCRIPTION_PAUSED",
]);
const AUTH_SESSION_CLAIM_KEY = "x-hasura-session-id";

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

const hasuraHttp = axios.create({
  timeout: HASURA_HTTP_TIMEOUT_MS,
  httpsAgent: new https.Agent({
    keepAlive: true,
    keepAliveMsecs: 30_000,
    maxSockets: 64,
    maxFreeSockets: 16,
  }),
});

let homePostgresPool = null;
let userContentAccessGrantSourceSupported = true;
let userContentAccessPurchasePlatformSupported = true;
let revenueCatOwnershipLockSupported = true;
let revenueCatReconcileTimer = null;
let revenueCatReconcileRunning = false;

const decodeUriComponentSafe = (value) => {
  try {
    return decodeURIComponent(value);
  } catch (_) {
    return value;
  }
};

const normalizePostgresCredential = (value) =>
  encodeURIComponent(decodeUriComponentSafe(String(value || "")));

// node-postgres expects reserved URL characters in credentials to be encoded.
const normalizePostgresConnectionString = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return raw;

  const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*:\/\/)(.*)$/i);
  if (!schemeMatch) return raw;

  const [, scheme, remainder] = schemeMatch;
  const slashIndex = remainder.indexOf("/");
  if (slashIndex < 0) return raw;

  const authority = remainder.slice(0, slashIndex);
  const pathAndMore = remainder.slice(slashIndex);
  const atIndex = authority.lastIndexOf("@");
  if (atIndex < 0) return raw;

  const userInfo = authority.slice(0, atIndex);
  const hostInfo = authority.slice(atIndex + 1);
  const colonIndex = userInfo.indexOf(":");
  const rawUser = colonIndex >= 0 ? userInfo.slice(0, colonIndex) : userInfo;
  const rawPassword = colonIndex >= 0 ? userInfo.slice(colonIndex + 1) : "";
  const normalizedUser = normalizePostgresCredential(rawUser);
  const normalizedPassword =
    colonIndex >= 0 ? `:${normalizePostgresCredential(rawPassword)}` : "";

  return `${scheme}${normalizedUser}${normalizedPassword}@${hostInfo}${pathAndMore}`;
};

const HOME_POSTGRES_CONNECTION_STRING = normalizePostgresConnectionString(HOME_POSTGRES_URL);

const isHomePostgresSslEnabled = () => {
  if (HOME_POSTGRES_SSL) return true;
  return ["require", "verify-ca", "verify-full"].includes(HOME_POSTGRES_SSLMODE);
};

const buildHomePostgresSslConfig = () => {
  if (!isHomePostgresSslEnabled()) return undefined;
  return {
    rejectUnauthorized: HOME_POSTGRES_SSL_REJECT_UNAUTHORIZED,
  };
};

const getHomePostgresPool = () => {
  if (homePostgresPool) return homePostgresPool;

  const ssl = buildHomePostgresSslConfig();
  const hasConnectionString = !!String(HOME_POSTGRES_CONNECTION_STRING || "").trim();
  const poolConfig = hasConnectionString
    ? {
        connectionString: HOME_POSTGRES_CONNECTION_STRING,
      }
    : {
        host: HOME_POSTGRES_HOST,
        port: HOME_POSTGRES_PORT,
        database: HOME_POSTGRES_DATABASE,
        user: HOME_POSTGRES_USER,
        password: HOME_POSTGRES_PASSWORD,
      };

  if (
    !hasConnectionString &&
    (!HOME_POSTGRES_HOST || !HOME_POSTGRES_DATABASE || !HOME_POSTGRES_USER)
  ) {
    throw new Error(
      "Home Postgres configuration missing. Set HOME_POSTGRES_URL or HOME_POSTGRES_HOST/PORT/DATABASE/USER/PASSWORD."
    );
  }

  homePostgresPool = new Pool({
    ...poolConfig,
    max: HOME_POSTGRES_POOL_MAX,
    idleTimeoutMillis: HOME_POSTGRES_IDLE_TIMEOUT_MS,
    connectionTimeoutMillis: HOME_POSTGRES_CONNECTION_TIMEOUT_MS,
    allowExitOnIdle: false,
    ...(ssl ? { ssl } : {}),
  });

  homePostgresPool.on("error", (err) => {
    console.error(`[home][db][pool-error] ${err?.message || err}`);
  });

  return homePostgresPool;
};

const homePostgresQuery = async (text, values = []) => {
  const pool = getHomePostgresPool();
  const result = await pool.query({
    text,
    values,
    query_timeout: HOME_POSTGRES_QUERY_TIMEOUT_MS,
    statement_timeout: HOME_POSTGRES_QUERY_TIMEOUT_MS,
  });
  return result.rows || [];
};

const homePostgresQueryWithClient = async (client, text, values = []) => {
  const result = await client.query({
    text,
    values,
    query_timeout: HOME_POSTGRES_QUERY_TIMEOUT_MS,
    statement_timeout: HOME_POSTGRES_QUERY_TIMEOUT_MS,
  });
  return result.rows || [];
};

const withHomePostgresClient = async (callback) => {
  const client = await getHomePostgresPool().connect();
  try {
    return await callback(client);
  } finally {
    client.release();
  }
};

const quoteSqlIdentifier = (value) =>
  `"${String(value || "").replace(/"/g, '""')}"`;

const qualifySqlTable = (tableName) => {
  const normalized = String(tableName || "").trim();
  if (!normalized) {
    throw new Error("Table name is required.");
  }
  if (normalized.includes(".")) {
    const [schema, table] = normalized.split(".", 2);
    return `${quoteSqlIdentifier(schema)}.${quoteSqlIdentifier(table)}`;
  }
  return `public.${quoteSqlIdentifier(normalized)}`;
};

const compactObject = (value) => {
  const entries = Object.entries(value || {}).filter(([, v]) => v !== undefined);
  return Object.fromEntries(entries);
};

const buildInsertSql = (tableName, object, returning = "*") => {
  const payload = compactObject(object);
  const keys = Object.keys(payload);
  if (!keys.length) {
    throw new Error("Insert payload is empty.");
  }
  const columns = keys.map((key) => quoteSqlIdentifier(key)).join(", ");
  const values = keys.map((key) => payload[key]);
  const placeholders = keys.map((_, index) => `$${index + 1}`).join(", ");
  return {
    text: `INSERT INTO ${qualifySqlTable(tableName)} (${columns}) VALUES (${placeholders}) RETURNING ${returning}`,
    values,
  };
};

const buildUpdateByPkSql = (tableName, pkColumn, id, object, returning = "*") => {
  const payload = compactObject(object);
  const keys = Object.keys(payload);
  if (!keys.length) {
    throw new Error("Update payload is empty.");
  }
  const setSql = keys
    .map((key, index) => `${quoteSqlIdentifier(key)} = $${index + 2}`)
    .join(", ");
  const values = [id, ...keys.map((key) => payload[key])];
  return {
    text: `UPDATE ${qualifySqlTable(tableName)} SET ${setSql} WHERE ${quoteSqlIdentifier(pkColumn)} = $1 RETURNING ${returning}`,
    values,
  };
};

const buildDeleteByPkSql = (tableName, pkColumn, id, returning = "*") => ({
  text: `DELETE FROM ${qualifySqlTable(tableName)} WHERE ${quoteSqlIdentifier(pkColumn)} = $1 RETURNING ${returning}`,
  values: [id],
});

const buildSelectSql = ({
  tableName,
  columns = "*",
  where = "",
  values = [],
  orderBy = "",
  limit = null,
  offset = null,
}) => {
  const clauses = [
    `SELECT ${columns}`,
    `FROM ${qualifySqlTable(tableName)}`,
  ];
  if (where) clauses.push(`WHERE ${where}`);
  if (orderBy) clauses.push(`ORDER BY ${orderBy}`);
  if (limit !== null && limit !== undefined) clauses.push(`LIMIT ${Number(limit)}`);
  if (offset !== null && offset !== undefined) clauses.push(`OFFSET ${Number(offset)}`);
  return { text: clauses.join(" "), values };
};

const isMissingUserContentAccessGrantSourceError = (err) =>
  String(err?.code || "") === "42703" &&
  String(err?.message || "").toLowerCase().includes("grant_source");
const isMissingUserContentAccessPurchasePlatformError = (err) =>
  String(err?.code || "") === "42703" &&
  String(err?.message || "").toLowerCase().includes("purchase_platform");
const isMissingOrderPaymentProviderError = (err) =>
  String(err?.code || "") === "42703" &&
  String(err?.message || "").toLowerCase().includes("payment_provider");
const isMissingOrderPaymentMetadataError = (err) => {
  if (String(err?.code || "") !== "42703") return false;
  const message = String(err?.message || "").toLowerCase();
  return (
    message.includes("payment_provider") ||
    message.includes("merchant_payment_id") ||
    message.includes("payment_session_token")
  );
};

const parseTimestampOrNull = (value) => {
  const normalized = normalizeRevenueCatAppUserId(value);
  if (!normalized) return null;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const pickLaterExpiryEntry = (first, second) => {
  if (!first) return second;
  if (!second) return first;

  const firstExpiry = parseTimestampOrNull(first.expires_at);
  const secondExpiry = parseTimestampOrNull(second.expires_at);
  if (!firstExpiry) return second;
  if (!secondExpiry) return first;
  return secondExpiry.getTime() > firstExpiry.getTime() ? second : first;
};

const isRevenueCatManagedAccessRow = (row, expirationDate) => {
  if (!row) return false;
  const grantSource = String(row.grant_source || "")
    .trim()
    .toLowerCase();
  if (grantSource === REVENUECAT_ACCESS_SOURCE) {
    return true;
  }

  const rowExpiry = parseTimestampOrNull(row.expires_at);
  const rcExpiry = parseTimestampOrNull(expirationDate);
  if (!rowExpiry || !rcExpiry) {
    return false;
  }

  return (
    Math.abs(rowExpiry.getTime() - rcExpiry.getTime()) <=
    REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS
  );
};

const hasManualOverrideExpiry = (row, expirationDate) => {
  if (!row) return false;
  const rowExpiry = parseTimestampOrNull(row.expires_at);
  const rcExpiry = parseTimestampOrNull(expirationDate);
  if (!rowExpiry) {
    return true;
  }
  if (!rcExpiry) {
    return false;
  }
  return rowExpiry.getTime() > rcExpiry.getTime() + REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS;
};

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

const PUBLIC_TYPES = ["kitap", "gazete", "dergi", "ek", "slider", "profil"];
const PRIVATE_TYPES = ["kitap", "gazete", "dergi", "ek"];
const MANAGED_CDN_HOSTS = Array.from(
  new Set(
    [BUNNY_SETTINGS.cdnUrl, CDN_PUBLIC_HOST]
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean)
  )
);

const normalizeManagedFilePath = (value) => String(value || "").replace(/\/{2,}/g, "/");

const decodePathSegment = (value) => {
  try {
    return decodeURIComponent(value);
  } catch (_) {
    return value;
  }
};

const parseManagedFileReference = (input) => {
  const raw = String(input || "").trim();
  if (!raw) return null;

  let pathCandidate = raw;
  if (/^https?:\/\//i.test(raw)) {
    let parsed;
    try {
      parsed = new URL(raw);
    } catch (_) {
      return null;
    }
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    if (!MANAGED_CDN_HOSTS.includes((parsed.host || "").toLowerCase())) return null;
    pathCandidate = parsed.pathname || "";
  } else if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(:\d+)?\//i.test(raw)) {
    return parseManagedFileReference(`https://${raw}`);
  }

  const normalizedPath = normalizeManagedFilePath(
    pathCandidate.startsWith("/") ? pathCandidate : `/${pathCandidate}`
  );

  let type;
  let scope;
  let filename;

  const directMatch = normalizedPath.match(/^\/([a-z0-9_-]+)\/(public|private)\/([^/]+)$/i);
  const routedMatch = normalizedPath.match(/^\/(public|private)\/([a-z0-9_-]+)\/([^/]+)$/i);
  const privateAliasMatch = normalizedPath.match(/^\/private\/([a-z0-9_-]+)\/([^/]+)$/i);

  if (directMatch) {
    type = directMatch[1].toLowerCase();
    scope = directMatch[2].toLowerCase();
    filename = directMatch[3];
  } else if (routedMatch) {
    scope = routedMatch[1].toLowerCase();
    type = routedMatch[2].toLowerCase();
    filename = routedMatch[3];
  } else if (privateAliasMatch) {
    scope = "private";
    type = privateAliasMatch[1].toLowerCase();
    filename = privateAliasMatch[2];
  } else {
    return null;
  }

  if (scope === "public" && !PUBLIC_TYPES.includes(type)) return null;
  if (scope === "private" && !PRIVATE_TYPES.includes(type)) return null;

  const decodedFilename = decodePathSegment(filename);
  if (!decodedFilename || /[/?#]/.test(decodedFilename)) return null;

  const storagePath = `/${type}/${scope}/${decodedFilename}`;
  return {
    type,
    scope,
    filename: decodedFilename,
    storagePath,
    normalizedUrl: `https://${BUNNY_SETTINGS.cdnUrl}${storagePath}`,
  };
};

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

  if (!PRIVATE_TYPES.includes(type)) return null;

  return { type, filename };
};

const sanitizeUrlForLog = (urlLike) => {
  const raw = String(urlLike || "");
  if (!raw) return raw;
  try {
    const parsed = new URL(raw, "http://localhost");
    ["token", "password", "authorization", "x-api-key", "x-mail-token"].forEach((key) => {
      if (parsed.searchParams.has(key)) {
        parsed.searchParams.set(key, "[redacted]");
      }
    });
    return `${parsed.pathname}${parsed.search}`;
  } catch (err) {
    return raw;
  }
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
    path: sanitizeUrlForLog(req?.originalUrl || req?.url),
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
  profil: {
    public: path.join(STORAGE_ROOT, "profil", "public"),
  },
};

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", TRUST_PROXY);

const safeTokenCompare = (provided, expected) => {
  const expectedValue = String(expected || "");
  const providedValue = String(provided || "");
  if (!expectedValue || providedValue.length !== expectedValue.length) {
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(providedValue, "utf8"),
    Buffer.from(expectedValue, "utf8")
  );
};

const buildRateLimiter = ({ windowMs, max, message, skip }) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, error: message },
    skip,
  });

const isStaticAssetRequest = (req) => {
  const method = String(req.method || "").trim().toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    return false;
  }

  const pathname = String(req.path || "").trim();
  if (!pathname) return false;
  if (pathname === "/health") return true;
  if (pathname === "/" || pathname === "/favicon.ico" || pathname === "/manifest.json") {
    return true;
  }

  if (
    pathname.startsWith("/assets/") ||
    pathname.startsWith("/icons/") ||
    pathname.startsWith("/images/") ||
    pathname.startsWith("/fonts/") ||
    pathname.startsWith("/packages/")
  ) {
    return true;
  }

  return (
    pathname.endsWith(".js") ||
    pathname.endsWith(".css") ||
    pathname.endsWith(".map") ||
    pathname.endsWith(".png") ||
    pathname.endsWith(".jpg") ||
    pathname.endsWith(".jpeg") ||
    pathname.endsWith(".gif") ||
    pathname.endsWith(".webp") ||
    pathname.endsWith(".svg") ||
    pathname.endsWith(".ico") ||
    pathname.endsWith(".woff") ||
    pathname.endsWith(".woff2") ||
    pathname.endsWith(".ttf") ||
    pathname.endsWith(".eot") ||
    pathname.endsWith(".wasm")
  );
};

const shouldSkipGlobalRateLimit = (req) => {
  if (req.path === "/health") {
    return true;
  }
  return isStaticAssetRequest(req);
};

const hasAdminRoleInBearerToken = (token) => {
  if (!token) return false;
  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    const claims = payload?.["https://hasura.io/jwt/claims"] || {};
    const defaultRole = String(claims["x-hasura-default-role"] || "")
      .trim()
      .toLowerCase();
    const allowedRoles = Array.isArray(claims["x-hasura-allowed-roles"])
      ? claims["x-hasura-allowed-roles"].map((value) =>
          String(value || "").trim().toLowerCase()
        )
      : [];
    return defaultRole === "admin" || allowedRoles.includes("admin");
  } catch (_) {
    return false;
  }
};

const shouldSkipUploadRateLimit = (req) => {
  const authHeader = String(req.get("authorization") || "").trim();
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";

  if (!bearerToken) return false;
  if (AUTH_TOKEN && safeTokenCompare(bearerToken, AUTH_TOKEN)) return true;
  return hasAdminRoleInBearerToken(bearerToken);
};

const globalRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  message: "Too many requests.",
  skip: shouldSkipGlobalRateLimit,
});
const authRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX,
  message: "Too many authentication attempts.",
});
const loginRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: LOGIN_RATE_LIMIT_MAX,
  message: "Too many login attempts.",
});
const guestTokenRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: GUEST_TOKEN_RATE_LIMIT_MAX,
  message: "Too many guest token requests.",
});
const passwordResetRequestRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX,
  message: "Too many password reset requests.",
});
const passwordResetConfirmRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX,
  message: "Too many password reset attempts.",
});
const uploadRateLimiter = buildRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: UPLOAD_RATE_LIMIT_MAX,
  message: "Too many upload attempts.",
  skip: shouldSkipUploadRateLimit,
});

app.use(globalRateLimiter);
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false,
  })
);

// Basic request/response logger to surface hung/slow requests.
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${sanitizeUrlForLog(req.originalUrl)} -> ${res.statusCode} (${durationMs.toFixed(
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
  const allowedByMime = {
    "application/pdf": [".pdf"],
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/webp": [".webp"],
  };
  const ext = path.extname(file.originalname || "").toLowerCase();
  const allowedExts = allowedByMime[file.mimetype] || null;
  const ok = Array.isArray(allowedExts) && allowedExts.includes(ext);

  if (!ok) {
    return cb(
      new Error("Only pdf, jpg/jpeg, png, or webp files are allowed for uploads.")
    );
  }

  cb(null, true);
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, TMP_DIR),
  filename: (req, file, cb) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}-${crypto.randomUUID()}${extension}`);
  },
});

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
  mustHaveEnv("JWT_SECRET", JWT_SECRET);
};

assertRequiredEnv();

const requireAuth = (req, res, next) => {
  const raw = req.get("x-api-key") || req.get("authorization") || "";
  const token = raw.toLowerCase().startsWith("bearer ")
    ? raw.slice(7)
    : raw;

  if (!token || !safeTokenCompare(token, AUTH_TOKEN)) {
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
    return res.status(401).json({ ok: false, error: "Yetkisiz erişim." });
  }

  next();
};

const requireMailAuth = (req, res, next) => {
  const raw = req.get("x-mail-token") || req.get("authorization") || req.get("x-api-key") || "";
  const token = raw.toLowerCase().startsWith("bearer ")
    ? raw.slice(7)
    : raw;
  if (!MAIL_SETTINGS.token || !token || !safeTokenCompare(token, MAIL_SETTINGS.token)) {
    return res.status(401).json({ ok: false, error: "Yetkisiz erişim." });
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
const smtpTlsServername = (MAIL_TLS_SERVERNAME || smtpHost || "").trim().replace(/\.$/, "");
const mailTransporter = nodemailer.createTransport({
  host: smtpHost,
  port: MAIL_SETTINGS.port,
  secure: MAIL_SETTINGS.port === 465,
  auth: {
    user: MAIL_SETTINGS.user,
    pass: MAIL_SETTINGS.pass,
  },
  tls: {
    // Keep TLS verification on by default. Override servername when SMTP host and cert CN/SAN differ.
    rejectUnauthorized: MAIL_TLS_REJECT_UNAUTHORIZED,
    ...(smtpTlsServername ? { servername: smtpTlsServername } : {}),
  },
});

app.use(express.json({ limit: REQUEST_BODY_LIMIT }));
app.use(express.urlencoded({ extended: false, limit: REQUEST_BODY_LIMIT }));

app.use((req, res, next) => {
  const requestOrigin = req.get("origin");
  const originAllowed =
    ALLOWED_ORIGINS.includes("*") ||
    (requestOrigin && ALLOWED_ORIGINS.includes(requestOrigin));

  if (originAllowed) {
    res.vary("Origin");
    res.set("Access-Control-Allow-Origin", requestOrigin || "*");
  }
  res.set("Access-Control-Allow-Methods", ALLOWED_METHODS);
  res.set("Access-Control-Allow-Headers", ALLOWED_HEADERS);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});

app.use(express.static(PUBLIC_ROOT));

app.get("/privacy", (req, res) => {
  return res.sendFile(path.join(PUBLIC_ROOT, "privacy.html"));
});

app.get(["/sifre-sifirla", "/reset-password"], (req, res) => {
  return res.sendFile(path.join(PUBLIC_ROOT, "password-reset.html"));
});

app.get("/home/bootstrap", async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    const { data, cache } = await getCachedHomeBootstrap();
    const maxAgeSeconds = Math.max(
      1,
      Math.floor(HOME_BOOTSTRAP_CACHE_TTL_MS / 1000)
    );
    res.set(
      "Cache-Control",
      `public, max-age=${maxAgeSeconds}, stale-while-revalidate=300`
    );
    return res.json({ ok: true, cache, data });
  } catch (err) {
    const payload = await logHomeServerError({
      req,
      requestId,
      section: "bootstrap",
      err,
    });
    return res.status(503).json({
      ok: false,
      error: "Home bootstrap unavailable.",
      code: payload.code,
      requestId,
      details: {
        message: payload.message,
        hint: payload.hint,
        driverCode: payload.driverCode,
      },
    });
  }
});

const sendHomeSectionResponse = async (req, res, key) => {
  const requestId = crypto.randomUUID();
  try {
    const { data, cache } = await getCachedHomeSection(key);
    const maxAgeSeconds = Math.max(
      1,
      Math.floor(HOME_BOOTSTRAP_CACHE_TTL_MS / 1000)
    );
    res.set(
      "Cache-Control",
      `public, max-age=${maxAgeSeconds}, stale-while-revalidate=300`
    );
    return res.json({ ok: true, cache, data });
  } catch (err) {
    const payload = await logHomeServerError({
      req,
      requestId,
      section: key,
      err,
    });
    return res.status(503).json({
      ok: false,
      error: `${key} unavailable.`,
      code: payload.code,
      requestId,
      details: {
        message: payload.message,
        hint: payload.hint,
        driverCode: payload.driverCode,
      },
    });
  }
};

app.get("/home/sliders", async (req, res) =>
  sendHomeSectionResponse(req, res, "sliders")
);
app.get("/home/magazines", async (req, res) =>
  sendHomeSectionResponse(req, res, "magazines")
);
app.get("/home/books", async (req, res) =>
  sendHomeSectionResponse(req, res, "books")
);
app.get("/home/newspapers", async (req, res) =>
  sendHomeSectionResponse(req, res, "newspapers")
);
app.get("/home/attachments", async (req, res) =>
  sendHomeSectionResponse(req, res, "attachments")
);
app.get("/home/showcase/books", async (req, res) =>
  sendHomeSectionResponse(req, res, "homeBookEntries")
);
app.get("/home/showcase/magazines", async (req, res) =>
  sendHomeSectionResponse(req, res, "homeMagazineEntries")
);
app.get("/home/showcase/attachments", async (req, res) =>
  sendHomeSectionResponse(req, res, "homeEkEntries")
);

app.get("/app/feature-flags", async (req, res) => {
  const requestId = crypto.randomUUID();
  const flagId = Number(req.query.id || "");
  if (!Number.isInteger(flagId) || flagId <= 0) {
    return res.status(400).json({
      ok: false,
      error: "Invalid feature flag id.",
      code: "APP_FEATURE_FLAGS_INVALID_ID",
    });
  }

  try {
    const { data, cache } = await getCachedAppFeatureFlags(flagId);
    const maxAgeSeconds = Math.max(
      1,
      Math.floor(APP_FEATURE_FLAGS_CACHE_TTL_MS / 1000)
    );
    res.set(
      "Cache-Control",
      `public, max-age=${maxAgeSeconds}, stale-while-revalidate=300`
    );
    return res.json({ ok: true, cache, data });
  } catch (err) {
    const payload = await logHomeServerError({
      req,
      requestId,
      section: "appFeatureFlags",
      err,
      serviceLabel: "CDN/AppFeatureFlags",
    });
    return res.status(503).json({
      ok: false,
      error: "App feature flags unavailable.",
      code: payload.code,
      requestId,
      details: {
        message: payload.message,
        hint: payload.hint,
        driverCode: payload.driverCode,
      },
    });
  }
});

app.get("/app/version", async (req, res) => {
  const requestId = crypto.randomUUID();
  const platform = String(req.query.platform || "").trim().toLowerCase();
  if (!["android", "ios"].includes(platform)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid platform key.",
      code: "APP_VERSION_INVALID_PLATFORM",
    });
  }

  try {
    const { data, cache } = await getCachedAppVersion(platform);
    const maxAgeSeconds = Math.max(
      1,
      Math.floor(APP_VERSION_CACHE_TTL_MS / 1000)
    );
    res.set(
      "Cache-Control",
      `public, max-age=${maxAgeSeconds}, stale-while-revalidate=300`
    );
    return res.json({ ok: true, cache, data });
  } catch (err) {
    const payload = await logHomeServerError({
      req,
      requestId,
      section: "appVersion",
      err,
      serviceLabel: "CDN/AppVersion",
    });
    return res.status(503).json({
      ok: false,
      error: "App version unavailable.",
      code: payload.code,
      requestId,
      details: {
        message: payload.message,
        hint: payload.hint,
        driverCode: payload.driverCode,
      },
    });
  }
});

app.get("/magazines/:id/issues/public", async (req, res) => {
  const requestId = crypto.randomUUID();
  const magazineId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(magazineId) || magazineId <= 0) {
    return res.status(400).json({
      ok: false,
      error: "Invalid magazine id.",
      code: "MAGAZINE_PUBLIC_ISSUES_INVALID_ID",
    });
  }

  try {
    const { data, cache } = await getCachedPublicMagazineIssues(magazineId);
    const maxAgeSeconds = Math.max(
      1,
      Math.floor(MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS / 1000)
    );
    res.set(
      "Cache-Control",
      `public, max-age=${maxAgeSeconds}, stale-while-revalidate=300`
    );
    return res.json({ ok: true, cache, data });
  } catch (err) {
    const payload = await logHomeServerError({
      req,
      requestId,
      section: "magazinePublicIssues",
      err,
      serviceLabel: "CDN/MagazineIssues",
    });
    return res.status(503).json({
      ok: false,
      error: "Magazine issues unavailable.",
      code: payload.code,
      requestId,
      details: {
        message: payload.message,
        hint: payload.hint,
        driverCode: payload.driverCode,
      },
    });
  }
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

const hasuraRequest = async (query, variables = {}, options = {}) => {
  return executeDirectGraphqlRequest({
    query,
    variables,
    operationName: options.operationName,
  });
};

const proxyHasuraRequest = async (req, res) => {
  try {
    const { query, variables, operationName } = req.body || {};
    if (!query) {
      return res.status(400).json({
        errors: [{ message: "query is required." }],
      });
    }

    const data = await executeDirectGraphqlRequest({
      query,
      variables,
      operationName,
      req,
    });

    return res.status(200).json({ data });
  } catch (err) {
    return res.status(200).json({
      errors: [
        {
          message: err?.message || "GraphQL request failed.",
          extensions: err?.code ? { code: err.code } : undefined,
        },
      ],
    });
  }
};

const HOME_ERROR_HINTS = {
  HOME_DB_CONFIG_MISSING:
    "HOME_POSTGRES_URL veya HOME_POSTGRES_HOST/PORT/DATABASE/USER/PASSWORD env değerlerini kontrol edin.",
  HOME_DB_AUTH_FAILED:
    "Postgres kullanıcı adı/şifre bilgisini kontrol edin.",
  HOME_DB_UNREACHABLE:
    "Postgres host/port, firewall ve ağ erişimini kontrol edin.",
  HOME_DB_SSL_REQUIRED:
    "Postgres SSL ayarlarını HOME_POSTGRES_SSL ve HOME_POSTGRES_SSL_REJECT_UNAUTHORIZED ile doğrulayın.",
  HOME_DB_TIMEOUT:
    "DB erişimi veya sorgu süresi aşılıyor; ağ ve query timeout ayarlarını kontrol edin.",
  HOME_DB_QUERY_FAILED:
    "SQL tarafında tablo/kolon adı veya izin problemi olabilir.",
};

const classifyHomeError = (err) => {
  const message = String(err?.message || err || "").trim();
  const code = String(err?.code || "").trim();
  const lower = message.toLowerCase();

  if (message.includes("Home Postgres configuration missing")) {
    return {
      code: "HOME_DB_CONFIG_MISSING",
      message: "Home database configuration missing.",
      hint: HOME_ERROR_HINTS.HOME_DB_CONFIG_MISSING,
    };
  }

  if (["28P01", "28000"].includes(code) || lower.includes("password authentication failed")) {
    return {
      code: "HOME_DB_AUTH_FAILED",
      message: "Home database authentication failed.",
      hint: HOME_ERROR_HINTS.HOME_DB_AUTH_FAILED,
    };
  }

  if (
    ["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "57P03"].includes(code) ||
    lower.includes("connect econnrefused") ||
    lower.includes("getaddrinfo") ||
    lower.includes("could not connect") ||
    lower.includes("connection terminated unexpectedly")
  ) {
    return {
      code: "HOME_DB_UNREACHABLE",
      message: "Home database is unreachable.",
      hint: HOME_ERROR_HINTS.HOME_DB_UNREACHABLE,
    };
  }

  if (
    code === "ETIMEDOUT" ||
    lower.includes("timeout") ||
    lower.includes("statement timeout") ||
    lower.includes("query read timeout")
  ) {
    return {
      code: "HOME_DB_TIMEOUT",
      message: "Home database request timed out.",
      hint: HOME_ERROR_HINTS.HOME_DB_TIMEOUT,
    };
  }

  if (
    lower.includes("ssl") ||
    lower.includes("self signed certificate") ||
    lower.includes("no pg_hba.conf entry")
  ) {
    return {
      code: "HOME_DB_SSL_REQUIRED",
      message: "Home database SSL configuration failed.",
      hint: HOME_ERROR_HINTS.HOME_DB_SSL_REQUIRED,
    };
  }

  return {
    code: "HOME_DB_QUERY_FAILED",
    message: "Home database query failed.",
    hint: HOME_ERROR_HINTS.HOME_DB_QUERY_FAILED,
  };
};

const buildHomeErrorPayload = ({ req, requestId, section, err }) => {
  const classification = classifyHomeError(err);
  return {
    requestId,
    section,
    code: classification.code,
    message: classification.message,
    hint: classification.hint,
    driverCode: err?.code || null,
    detail:
      err?.detail || err?.severity || err?.routine || err?.where || err?.schema || null,
    path: sanitizeUrlForLog(req?.originalUrl || req?.url),
    ip: req?.ip || null,
    method: req?.method || null,
    postgresConfig: {
      hasConnectionString: !!String(HOME_POSTGRES_CONNECTION_STRING || "").trim(),
      hasHost: !!String(HOME_POSTGRES_HOST || "").trim(),
      hasDatabase: !!String(HOME_POSTGRES_DATABASE || "").trim(),
      hasUser: !!String(HOME_POSTGRES_USER || "").trim(),
      sslEnabled: isHomePostgresSslEnabled(),
      sslRejectUnauthorized: HOME_POSTGRES_SSL_REJECT_UNAUTHORIZED,
      poolMax: HOME_POSTGRES_POOL_MAX,
      queryTimeoutMs: HOME_POSTGRES_QUERY_TIMEOUT_MS,
    },
  };
};

const logHomeServerError = async ({
  req,
  requestId,
  section,
  err,
  serviceLabel = "CDN/HomeService",
}) => {
  const payload = buildHomeErrorPayload({ req, requestId, section, err });
  const line = `[home][${section}][error] ${JSON.stringify(payload)}`;
  if (err?.stack) {
    console.error(line, err.stack);
  } else {
    console.error(line);
  }

  try {
    const object = {
      service: serviceLabel,
      operation: section,
      message: payload.message,
      stack_trace: err?.stack || null,
      payload,
    };
    await homePostgresQuery(
      `
        INSERT INTO public.app_error_logs (
          service,
          operation,
          message,
          stack_trace,
          payload
        ) VALUES ($1::text, $2::text, $3::text, $4::text, $5::jsonb)
      `,
      [
        object.service,
        object.operation,
        object.message,
        object.stack_trace,
        object.payload ? JSON.stringify(object.payload) : null,
      ]
    );
  } catch (logErr) {
    console.error(
      `[home][${section}][app_error_logs_failed] requestId=${requestId} msg=${logErr?.message || logErr}`
    );
  }

  return payload;
};

const APP_FEATURE_FLAGS_CACHE_TTL_MS_RAW = Number(
  process.env.APP_FEATURE_FLAGS_CACHE_TTL_MS || "60000"
);
const APP_FEATURE_FLAGS_CACHE_TTL_MS =
  Number.isFinite(APP_FEATURE_FLAGS_CACHE_TTL_MS_RAW) &&
  APP_FEATURE_FLAGS_CACHE_TTL_MS_RAW > 0
    ? APP_FEATURE_FLAGS_CACHE_TTL_MS_RAW
    : 60000;
const APP_VERSION_CACHE_TTL_MS_RAW = Number(
  process.env.APP_VERSION_CACHE_TTL_MS || "60000"
);
const APP_VERSION_CACHE_TTL_MS =
  Number.isFinite(APP_VERSION_CACHE_TTL_MS_RAW) &&
  APP_VERSION_CACHE_TTL_MS_RAW > 0
    ? APP_VERSION_CACHE_TTL_MS_RAW
    : 60000;
const MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS_RAW = Number(
  process.env.MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS ||
    process.env.HOME_BOOTSTRAP_CACHE_TTL_MS ||
    "60000"
);
const MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS =
  Number.isFinite(MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS_RAW) &&
  MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS_RAW > 0
    ? MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS_RAW
    : 60000;

const appFeatureFlagsCache = new Map();
const appVersionCache = new Map();
const magazinePublicIssuesCache = new Map();

const appFeatureFlagsSql = `
  SELECT
    id::int AS id,
    version,
    hide_magazines,
    hide_newspapers
  FROM public.app_feature_flags
  WHERE id = $1
  LIMIT 1
`;

const appVersionSql = `
  SELECT
    "key"::text AS key,
    value
  FROM public.app_version
  WHERE "key" = $1
  LIMIT 1
`;

const clonePlainObject = (value) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? { ...value }
    : null;

const cloneMagazinePublicIssues = (value) =>
  Array.isArray(value)
    ? value.map((item) => {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          return item;
        }
        const cloned = { ...item };
        if (cloned.publish_date == null && cloned.added_at != null) {
          cloned.publish_date = cloned.added_at;
        }
        return cloned;
      })
    : [];

const getCachedAppFeatureFlags = async (id) => {
  const key = Number(id);
  if (!Number.isInteger(key) || key <= 0) {
    throw new Error("Invalid app feature flags id.");
  }

  const existing =
    appFeatureFlagsCache.get(key) || {
      value: null,
      expiresAt: 0,
      inflight: null,
    };
  appFeatureFlagsCache.set(key, existing);

  const now = Date.now();
  if (existing.value && existing.expiresAt > now) {
    return { data: clonePlainObject(existing.value), cache: "hit" };
  }

  if (!existing.inflight) {
    existing.inflight = homePostgresQuery(appFeatureFlagsSql, [key])
      .then((rows) => {
        const row = rows[0] ? clonePlainObject(rows[0]) : null;
        existing.value = row;
        existing.expiresAt = Date.now() + APP_FEATURE_FLAGS_CACHE_TTL_MS;
        return row;
      })
      .finally(() => {
        existing.inflight = null;
      });
  }

  try {
    const data = await existing.inflight;
    return { data: clonePlainObject(data), cache: "miss" };
  } catch (err) {
    if (existing.value) {
      return { data: clonePlainObject(existing.value), cache: "stale" };
    }
    throw err;
  }
};

const getCachedAppVersion = async (platformKey) => {
  const key = String(platformKey || "").trim().toLowerCase();
  if (!key) {
    throw new Error("Invalid app version key.");
  }

  const existing =
    appVersionCache.get(key) || {
      value: null,
      expiresAt: 0,
      inflight: null,
    };
  appVersionCache.set(key, existing);

  const now = Date.now();
  if (existing.value && existing.expiresAt > now) {
    return { data: clonePlainObject(existing.value), cache: "hit" };
  }

  if (!existing.inflight) {
    existing.inflight = homePostgresQuery(appVersionSql, [key])
      .then((rows) => {
        const row = rows[0] ? clonePlainObject(rows[0]) : null;
        existing.value = row;
        existing.expiresAt = Date.now() + APP_VERSION_CACHE_TTL_MS;
        return row;
      })
      .finally(() => {
        existing.inflight = null;
      });
  }

  try {
    const data = await existing.inflight;
    return { data: clonePlainObject(data), cache: "miss" };
  } catch (err) {
    if (existing.value) {
      return { data: clonePlainObject(existing.value), cache: "stale" };
    }
    throw err;
  }
};

const magazinePublicIssuesSql = `
  SELECT
    id::int AS id,
    magazine_id::int AS magazine_id,
    issue_number::int AS issue_number,
    photo_url,
    price,
    description,
    added_at,
    added_at::date::text AS publish_date,
    EXTRACT(YEAR FROM added_at)::int AS publish_year
  FROM public.magazine_issue
  WHERE magazine_id = $1
    AND COALESCE(is_published, TRUE) = TRUE
  ORDER BY issue_number DESC NULLS LAST, added_at DESC NULLS LAST, id DESC
`;

const loadPublicMagazineIssuesFromHasura = async (magazineId) => {
  const rows = await homePostgresQuery(
    `
      SELECT
        id::int AS id,
        magazine_id::int AS magazine_id,
        issue_number::int AS issue_number,
        photo_url,
        price,
        description,
        added_at,
        added_at::date::text AS publish_date
      FROM public.magazine_issue
      WHERE magazine_id = $1::bigint
        AND COALESCE(is_published, TRUE) = TRUE
      ORDER BY issue_number DESC NULLS LAST, added_at DESC NULLS LAST, id DESC
    `,
    [magazineId]
  );
  return cloneMagazinePublicIssues(rows);
};

const loadPublicMagazineIssues = async (magazineId) => {
  try {
    const rows = await homePostgresQuery(magazinePublicIssuesSql, [magazineId]);
    return cloneMagazinePublicIssues(rows);
  } catch (primaryError) {
    try {
      return await loadPublicMagazineIssuesFromHasura(magazineId);
    } catch (fallbackError) {
      if (!fallbackError.code && primaryError?.code) {
        fallbackError.code = primaryError.code;
      }
      if (!fallbackError.detail && primaryError?.detail) {
        fallbackError.detail = primaryError.detail;
      }
      throw fallbackError;
    }
  }
};

const getCachedPublicMagazineIssues = async (magazineId) => {
  const key = Number.parseInt(String(magazineId), 10);
  if (!Number.isInteger(key) || key <= 0) {
    throw new Error("Invalid magazine id.");
  }

  const existing =
    magazinePublicIssuesCache.get(key) || {
      value: null,
      expiresAt: 0,
      inflight: null,
    };
  magazinePublicIssuesCache.set(key, existing);

  const now = Date.now();
  if (existing.value && existing.expiresAt > now) {
    return { data: cloneMagazinePublicIssues(existing.value), cache: "hit" };
  }

  if (!existing.inflight) {
    existing.inflight = loadPublicMagazineIssues(key)
      .then((data) => {
        existing.value = data;
        existing.expiresAt = Date.now() + MAGAZINE_PUBLIC_ISSUES_CACHE_TTL_MS;
        return data;
      })
      .finally(() => {
        existing.inflight = null;
      });
  }

  try {
    const data = await existing.inflight;
    return { data: cloneMagazinePublicIssues(data), cache: "miss" };
  } catch (err) {
    if (existing.value) {
      return { data: cloneMagazinePublicIssues(existing.value), cache: "stale" };
    }
    throw err;
  }
};

const HOME_SECTION_KEYS = [
  "sliders",
  "magazines",
  "books",
  "newspapers",
  "attachments",
  "homeBookEntries",
  "homeMagazineEntries",
  "homeEkEntries",
];

const createHomeSectionCacheEntry = () => ({
  value: null,
  expiresAt: 0,
  inflight: null,
});

const homeSectionCaches = Object.fromEntries(
  HOME_SECTION_KEYS.map((key) => [key, createHomeSectionCacheEntry()])
);

const HOME_MAGAZINE_DESCRIPTION_PREVIEW_LENGTH = 220;
const HOME_ATTACHMENT_DESCRIPTION_PREVIEW_LENGTH = 180;

const buildHomePreviewSql = (columnRef, maxLength) => `
  CASE
    WHEN ${columnRef} IS NULL THEN NULL
    WHEN length(trim(${columnRef})) <= ${maxLength} THEN trim(${columnRef})
    ELSE rtrim(substr(trim(${columnRef}), 1, ${maxLength - 3})) || '...'
  END
`;

const homeMagazineDescriptionPreviewSql = buildHomePreviewSql(
  "m.description",
  HOME_MAGAZINE_DESCRIPTION_PREVIEW_LENGTH
);

const homeBookDescriptionPreviewSql = "trim(b.description)";

const homeAttachmentDescriptionPreviewSql = buildHomePreviewSql(
  "e.aciklama",
  HOME_ATTACHMENT_DESCRIPTION_PREVIEW_LENGTH
);

const homeBooksSql = `
  SELECT
    b.id,
    b.title,
    b.cover_url,
    b.price,
    b.discount_price,
    ${homeBookDescriptionPreviewSql} AS description,
    b.min_description,
    CASE
      WHEN c.id IS NULL THEN NULL
      ELSE jsonb_build_object('id', c.id, 'name', c.name)
    END AS category_rel,
    CASE
      WHEN a.id IS NULL THEN NULL
      ELSE jsonb_build_object('id', a.id, 'name', a.name)
    END AS author_rel
  FROM public.books AS b
  LEFT JOIN public.categories AS c ON c.id = b.category_id
  LEFT JOIN public.authors AS a ON a.id = b.author_id
  WHERE COALESCE(b.is_published, TRUE) = TRUE
  ORDER BY b.id DESC
`;

const homeMagazinesSql = `
  SELECT
    m.id,
    m.name,
    m.category,
    m.cover_image_url,
    m.period,
    ${homeMagazineDescriptionPreviewSql} AS description
  FROM public.magazine AS m
  ORDER BY m.id DESC
`;

const homeNewspapersSql = `
  SELECT
    id,
    image_url,
    publish_date::text AS publish_date,
    file_url
  FROM public.newspaper
  ORDER BY publish_date DESC
`;

const homeAttachmentsSql = `
  SELECT
    e.id,
    e.ad,
    ${homeAttachmentDescriptionPreviewSql} AS aciklama,
    e.fiyat,
    e.pdf_url,
    e.photo_url,
    e.is_public
  FROM public.ekler AS e
  ORDER BY e.created_at DESC
`;

const homeSlidersSql = `
  SELECT
    id,
    title,
    subtitle,
    description,
    image_url,
    link_url
  FROM public.slider
  WHERE is_active = TRUE
  ORDER BY sort_order ASC NULLS LAST, created_at DESC
`;

const homeShowcaseSql = `
  SELECT
    id,
    product_type,
    product_id,
    sort_order,
    is_active,
    created_at
  FROM public.home_showcase
  WHERE product_type = $1
    AND is_active = TRUE
  ORDER BY sort_order ASC NULLS LAST, created_at DESC
`;

const homeSectionLoaders = {
  sliders: async () => homePostgresQuery(homeSlidersSql),
  magazines: async () => homePostgresQuery(homeMagazinesSql),
  books: async () => homePostgresQuery(homeBooksSql),
  newspapers: async () => homePostgresQuery(homeNewspapersSql),
  attachments: async () => homePostgresQuery(homeAttachmentsSql),
  homeBookEntries: async () => homePostgresQuery(homeShowcaseSql, ["book"]),
  homeMagazineEntries: async () => homePostgresQuery(homeShowcaseSql, ["magazine"]),
  homeEkEntries: async () => homePostgresQuery(homeShowcaseSql, ["ek"]),
};

const cloneHomeSectionValue = (value) =>
  Array.isArray(value)
    ? value.map((item) =>
        item && typeof item === "object" && !Array.isArray(item) ? { ...item } : item
      )
    : [];

const fetchHomeSection = async (key) => {
  const loader = homeSectionLoaders[key];
  if (typeof loader !== "function") {
    throw new Error(`Unknown home section: ${key}`);
  }
  const rows = await loader();
  return cloneHomeSectionValue(rows);
};

const getCachedHomeSection = async (key) => {
  const cacheEntry = homeSectionCaches[key];
  if (!cacheEntry) {
    throw new Error(`Unknown home section cache: ${key}`);
  }

  const now = Date.now();
  if (cacheEntry.value && cacheEntry.expiresAt > now) {
    return { data: cloneHomeSectionValue(cacheEntry.value), cache: "hit" };
  }

  if (!cacheEntry.inflight) {
    cacheEntry.inflight = fetchHomeSection(key)
      .then((data) => {
        cacheEntry.value = data;
        cacheEntry.expiresAt = Date.now() + HOME_BOOTSTRAP_CACHE_TTL_MS;
        return data;
      })
      .finally(() => {
        cacheEntry.inflight = null;
      });
  }

  try {
    const data = await cacheEntry.inflight;
    return { data: cloneHomeSectionValue(data), cache: "miss" };
  } catch (err) {
    if (cacheEntry.value) {
      return { data: cloneHomeSectionValue(cacheEntry.value), cache: "stale" };
    }
    throw err;
  }
};

const summarizeHomeCacheState = (states) => {
  if (!Array.isArray(states) || states.length === 0) return "miss";
  if (states.every((state) => state === "hit")) return "hit";
  if (states.some((state) => state === "stale")) return "stale";
  if (states.some((state) => state === "miss")) return "miss";
  return states[0];
};

const getCachedHomeBootstrap = async () => {
  const sections = await Promise.all(HOME_SECTION_KEYS.map((key) => getCachedHomeSection(key)));
  const data = {
    sliders: sections[0].data,
    magazines: sections[1].data,
    books: sections[2].data,
    newspapers: sections[3].data,
    attachments: sections[4].data,
    homeBookEntries: sections[5].data,
    homeMagazineEntries: sections[6].data,
    homeEkEntries: sections[7].data,
    fetchedAt: new Date().toISOString(),
  };
  return {
    data,
    cache: summarizeHomeCacheState(sections.map((section) => section.cache)),
  };
};

const USER_ACCESS_ITEM_TYPES = new Set([
  "book",
  "magazine",
  "magazine_issue",
  "newspaper_subscription",
  "ek",
]);

const normalizeUserAccessItemType = (value) => {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  return USER_ACCESS_ITEM_TYPES.has(normalized) ? normalized : null;
};

const sortUserAccessEntries = (entries) => {
  const parseDate = (value) => {
    if (!value) return 0;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? 0 : parsed.getTime();
  };

  entries.sort((a, b) => {
    const startedCmp = parseDate(b.started_at) - parseDate(a.started_at);
    if (startedCmp !== 0) return startedCmp;
    const expiresCmp = parseDate(b.expires_at) - parseDate(a.expires_at);
    if (expiresCmp !== 0) return expiresCmp;
    return Number(b.id || 0) - Number(a.id || 0);
  });

  return entries;
};

const getManualNewspaperAccessRows = async ({ userId }) => {
  try {
    const rows = await homePostgresQuery(
      `
        SELECT
          id::int AS id,
          starts_at,
          ends_at,
          is_active,
          COALESCE(status, 'new') AS status,
          note
        FROM public.manual_newspaper_users
        WHERE user_id = $1
          AND is_active = TRUE
        ORDER BY ends_at DESC NULLS LAST, starts_at DESC NULLS LAST, id DESC
      `,
      [userId]
    );

    return rows.map((row) => ({
      id: `manual_${row.id}`,
      item_id: null,
      item_type: "newspaper_subscription",
      started_at: row.starts_at,
      expires_at: row.ends_at,
      is_active: row.is_active === true,
      source: "manual_newspaper",
      status: row.status,
      note: row.note || null,
    }));
  } catch (err) {
    const message = String(err?.message || "").toLowerCase();
    if (String(err?.code || "") === "42P01" || message.includes("manual_newspaper_users")) {
      return [];
    }
    throw err;
  }
};

const getUserAccessEntriesFromPostgres = async ({ userId, itemType = null }) => {
  const values = [userId];
  let itemTypeWhere = "";
  if (itemType) {
    values.push(itemType);
    itemTypeWhere = ` AND item_type = $${values.length}::public.access_item_type`;
  }

  const rows = await (async () => {
    try {
      return await homePostgresQuery(
        `
          SELECT
            id::int AS id,
            CASE WHEN item_id IS NULL THEN NULL ELSE item_id::int END AS item_id,
            item_type,
            started_at,
            expires_at,
            is_active,
            grant_source,
            purchase_platform
          FROM public.user_content_access
          WHERE user_id = $1
            AND is_active = TRUE
            ${itemTypeWhere}
          ORDER BY started_at DESC NULLS LAST, expires_at DESC NULLS LAST, id DESC
        `,
        values
      );
    } catch (err) {
      if (
        !isMissingUserContentAccessGrantSourceError(err) &&
        !isMissingUserContentAccessPurchasePlatformError(err)
      ) {
        throw err;
      }
      return homePostgresQuery(
        `
          SELECT
            id::int AS id,
            CASE WHEN item_id IS NULL THEN NULL ELSE item_id::int END AS item_id,
            item_type,
            started_at,
            expires_at,
            is_active
          FROM public.user_content_access
          WHERE user_id = $1
            AND is_active = TRUE
            ${itemTypeWhere}
          ORDER BY started_at DESC NULLS LAST, expires_at DESC NULLS LAST, id DESC
        `,
        values
      );
    }
  })();

  const entries = rows.map((row) => ({
    ...row,
    source: "user_content_access",
  }));

  if (!itemType || itemType === "newspaper_subscription") {
    entries.push(...(await getManualNewspaperAccessRows({ userId })));
  }

  return sortUserAccessEntries(entries);
};

const getUserOrdersFromPostgres = async ({ userId, includeItems = false }) => {
  const orders = await (async () => {
    try {
      return await homePostgresQuery(
        `
          SELECT
            id::int AS id,
            total_paid,
            status::text AS status,
            payment_provider,
            merchant_payment_id,
            payment_session_token,
            CASE WHEN promo_code_id IS NULL THEN NULL ELSE promo_code_id::int END AS promo_code_id,
            promo_code,
            promo_discount_percent,
            promo_discount_amount,
            created_at
          FROM public.orders
          WHERE user_id = $1
          ORDER BY created_at DESC, id DESC
        `,
        [userId]
      );
    } catch (err) {
      if (!isMissingOrderPaymentMetadataError(err)) {
        throw err;
      }
      return homePostgresQuery(
        `
          SELECT
            id::int AS id,
            total_paid,
            status::text AS status,
            merchant_payment_id,
            payment_session_token,
            CASE WHEN promo_code_id IS NULL THEN NULL ELSE promo_code_id::int END AS promo_code_id,
            promo_code,
            promo_discount_percent,
            promo_discount_amount,
            created_at
          FROM public.orders
          WHERE user_id = $1
          ORDER BY created_at DESC, id DESC
        `,
        [userId]
      );
    }
  })();

  if (!includeItems || orders.length === 0) {
    return orders.map((order) => ({ ...order }));
  }

  const orderIds = orders.map((order) => Number(order.id)).filter(Number.isFinite);
  if (orderIds.length === 0) {
    return orders.map((order) => ({ ...order, order_items: [] }));
  }

  const items = await homePostgresQuery(
    `
      SELECT
        id::int AS id,
        order_id::int AS order_id,
        product_id::int AS product_id,
        ek_id::int AS ek_id,
        title,
        quantity::int AS quantity,
        unit_price,
        line_total,
        product_type,
        metadata
      FROM public.order_items
      WHERE order_id = ANY($1::bigint[])
      ORDER BY id ASC
    `,
    [orderIds]
  );

  const itemsByOrderId = new Map();
  for (const item of items) {
    const orderId = Number(item.order_id);
    if (!itemsByOrderId.has(orderId)) {
      itemsByOrderId.set(orderId, []);
    }
    itemsByOrderId.get(orderId).push({ ...item });
  }

  return orders.map((order) => ({
    ...order,
    order_items: itemsByOrderId.get(Number(order.id)) || [],
  }));
};

const getOrderDetailFromPostgres = async ({ userId = null, orderId }) => {
  const normalizedOrderId = toPositiveIntOrNull(orderId);
  if (!normalizedOrderId) return null;

  const normalizedUserId = toPositiveIntOrNull(userId);
  const whereClauseParts = ["id = $1::bigint"];
  const whereValues = [normalizedOrderId];
  if (normalizedUserId) {
    whereClauseParts.push(`user_id = $${whereValues.length + 1}::bigint`);
    whereValues.push(normalizedUserId);
  }

  const rows = await (async () => {
    try {
      return await homePostgresQuery(
        `
          SELECT
            id::int AS id,
            total_paid,
            status::text AS status,
            created_at,
            payment_provider,
            merchant_payment_id,
            payment_session_token,
            CASE
              WHEN delivery_address_id IS NULL THEN NULL
              ELSE delivery_address_id::int
            END AS delivery_address_id,
            CASE
              WHEN billing_address_id IS NULL THEN NULL
              ELSE billing_address_id::int
            END AS billing_address_id,
            CASE
              WHEN promo_code_id IS NULL THEN NULL
              ELSE promo_code_id::int
            END AS promo_code_id,
            promo_code,
            promo_discount_percent,
            promo_discount_amount
          FROM public.orders
          WHERE ${whereClauseParts.join(" AND ")}
          LIMIT 1
        `,
        whereValues
      );
    } catch (err) {
      if (!isMissingOrderPaymentMetadataError(err)) {
        throw err;
      }
      return homePostgresQuery(
        `
          SELECT
            id::int AS id,
            total_paid,
            status::text AS status,
            created_at,
            merchant_payment_id,
            payment_session_token,
            CASE
              WHEN delivery_address_id IS NULL THEN NULL
              ELSE delivery_address_id::int
            END AS delivery_address_id,
            CASE
              WHEN billing_address_id IS NULL THEN NULL
              ELSE billing_address_id::int
            END AS billing_address_id,
            CASE
              WHEN promo_code_id IS NULL THEN NULL
              ELSE promo_code_id::int
            END AS promo_code_id,
            promo_code,
            promo_discount_percent,
            promo_discount_amount
          FROM public.orders
          WHERE ${whereClauseParts.join(" AND ")}
          LIMIT 1
        `,
        whereValues
      );
    }
  })();

  const order = rows[0];
  if (!order) return null;

  const items = await homePostgresQuery(
    `
      SELECT
        id::int AS id,
        title,
        quantity::int AS quantity,
        unit_price,
        line_total,
        product_type,
        product_id::int AS product_id,
        ek_id::int AS ek_id,
        metadata
      FROM public.order_items
      WHERE order_id = $1
      ORDER BY id ASC
    `,
    [orderId]
  );

  return {
    ...order,
    order_items: items.map((item) => ({ ...item })),
  };
};

const getUserOrderDetailFromPostgres = async ({ userId, orderId }) =>
  getOrderDetailFromPostgres({ userId, orderId });

const parseOrderItemMetadata = (metadata) => {
  if (!metadata) return {};
  if (typeof metadata === "object") {
    return metadata;
  }
  const raw = String(metadata).trim();
  if (!raw) return {};
  try {
    const decoded = JSON.parse(raw);
    if (decoded && typeof decoded === "object") {
      return decoded;
    }
  } catch (err) {
    return {};
  }
  return {};
};

const computeOrderItemExpiryFromMetadata = (metadata) => {
  const parsed = parseOrderItemMetadata(metadata);
  const durationMonths = toPositiveIntOrNull(
    parsed.durationMonths ||
      parsed.periodMonths ||
      parsed.period_months ||
      parsed.period
  );
  if (!durationMonths) {
    return null;
  }
  const expiration = new Date();
  expiration.setMonth(expiration.getMonth() + durationMonths);
  return expiration.toISOString();
};

const buildOrderAccessItemsFromRows = (orderItems) => {
  const nowIso = new Date().toISOString();
  const accessItems = [];
  for (const item of Array.isArray(orderItems) ? orderItems : []) {
    const productType = String(item.product_type || "").trim().toLowerCase();
    if (!productType) continue;

    let itemType = null;
    let itemId = null;
    let expiresAt = null;

    switch (productType) {
      case "book":
      case "magazine":
      case "magazine_issue":
        itemType = productType;
        itemId = toPositiveIntOrNull(item.product_id);
        if (itemType === "magazine") {
          expiresAt = computeOrderItemExpiryFromMetadata(item.metadata);
        }
        break;
      case "ek":
        itemType = "ek";
        itemId = toPositiveIntOrNull(item.ek_id ?? item.product_id);
        break;
      case "newspaper_subscription":
        itemType = "newspaper_subscription";
        itemId = toPositiveIntOrNull(item.product_id);
        expiresAt = computeOrderItemExpiryFromMetadata(item.metadata);
        break;
      default:
        continue;
    }

    const quantity = Math.max(1, toPositiveIntOrNull(item.quantity) || 1);
    for (let index = 0; index < quantity; index += 1) {
      accessItems.push({
        item_type: itemType,
        item_id: itemId,
        started_at: nowIso,
        expires_at: expiresAt,
        purchase_price: item.unit_price ?? item.line_total ?? null,
      });
    }
  }
  return accessItems;
};

const insertOrderAccessRowIfMissing = async ({
  userId,
  item,
}) => {
  const itemType = String(item?.item_type || "").trim();
  if (!itemType) return { inserted: false, reason: "missing_item_type" };

  const itemId = item?.item_id === null || item?.item_id === undefined
    ? null
    : toPositiveIntOrNull(item.item_id);
  const rows = await homePostgresQuery(
    itemId === null
      ? `
        SELECT id::bigint AS id
        FROM public.user_content_access
        WHERE user_id = $1::bigint
          AND item_type = $2::access_item_type
          AND item_id IS NULL
          AND is_active = TRUE
        LIMIT 1
      `
      : `
        SELECT id::bigint AS id
        FROM public.user_content_access
        WHERE user_id = $1::bigint
          AND item_type = $2::access_item_type
          AND item_id = $3::bigint
          AND is_active = TRUE
        LIMIT 1
      `,
    itemId === null ? [userId, itemType] : [userId, itemType, itemId]
  );

  if (rows.length) {
    return { inserted: false, reason: "exists", accessId: rows[0].id || null };
  }

  const columns = [
    "user_id",
    "item_type",
    "item_id",
    "started_at",
    "expires_at",
    "purchase_price",
    "is_active",
    "grant_source",
    "purchase_platform",
  ];
  const values = [
    userId,
    itemType,
    itemId,
    item.started_at || new Date().toISOString(),
    item.expires_at || null,
    item.purchase_price ?? null,
    true,
    "order_payment",
    "paratika",
  ];

  const insertRows = await homePostgresQuery(
    `
      INSERT INTO public.user_content_access (
        ${columns.join(", ")}
      ) VALUES (
        $1::bigint,
        $2::access_item_type,
        $3::bigint,
        $4::timestamptz,
        $5::timestamptz,
        $6::numeric,
        $7::boolean,
        $8::text,
        $9::text
      )
      RETURNING id::int AS id
    `,
    values
  );

  return { inserted: true, accessId: insertRows[0]?.id || null };
};

const settleApprovedPaymentOrder = async ({
  merchantPaymentId,
  paymentSessionToken = null,
  responseCode = "00",
  responseMsg = "Approved",
  errorCode = null,
  errorMsg = null,
}) => {
  const normalizedMerchantPaymentId = String(merchantPaymentId || "").trim();
  const normalizedSessionToken = String(paymentSessionToken || "").trim();
  if (!normalizedMerchantPaymentId && !normalizedSessionToken) {
    return { ok: false, reason: "missing_payment_identity" };
  }

  const whereClauses = [];
  const whereValues = [];
  if (normalizedMerchantPaymentId) {
    whereValues.push(normalizedMerchantPaymentId);
    whereClauses.push(`o.merchant_payment_id = $${whereValues.length}::text`);
  }
  if (normalizedSessionToken) {
    whereValues.push(normalizedSessionToken);
    whereClauses.push(`o.payment_session_token = $${whereValues.length}::text`);
  }

  const rows = await homePostgresQuery(
    `
      SELECT
        o.id::bigint AS id,
        o.user_id::bigint AS user_id,
        o.status::text AS status,
        o.payment_approved,
        o.merchant_payment_id,
        o.payment_session_token,
        o.payment_provider,
        o.payment_response_code,
        o.payment_response_msg,
        o.payment_error_code,
        o.payment_error_msg,
        jsonb_build_object(
          'id', u.id::bigint,
          'name', u.name,
          'email', u.email,
          'payUniqe', u."payUniqe"
        ) AS user
      FROM public.orders o
      LEFT JOIN public.users u ON u.id = o.user_id
      WHERE ${whereClauses.map((clause) => `(${clause})`).join(" OR ")}
      ORDER BY o.created_at DESC, o.id DESC
      LIMIT 1
    `,
    whereValues
  );

  const order = rows[0] || null;
  if (!order) {
    return { ok: false, reason: "order_not_found" };
  }

  const orderId = toPositiveIntOrNull(order.id);
  const userId = toPositiveIntOrNull(order.user_id);
  if (!orderId || !userId) {
    return { ok: false, reason: "invalid_order_identity" };
  }

  await directUpdateByPk({
    tableName: "orders",
    id: orderId,
    object: {
      status: "paid",
      payment_approved: true,
      payment_response_code: responseCode || "00",
      payment_response_msg: responseMsg || "Approved",
      payment_error_code: errorCode ?? null,
      payment_error_msg: errorMsg ?? null,
    },
    returning: "id::bigint AS id",
  });

  const itemRows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        order_id::bigint AS order_id,
        product_id::bigint AS product_id,
        ek_id::bigint AS ek_id,
        title,
        quantity::int AS quantity,
        unit_price,
        line_total,
        product_type,
        metadata,
        created_at
      FROM public.order_items
      WHERE order_id = $1::bigint
      ORDER BY id ASC
    `,
    [orderId]
  );

  const accessItems = buildOrderAccessItemsFromRows(itemRows);
  const directItems = accessItems.filter(
    (item) => item.item_type !== "newspaper_subscription"
  );
  const newspaperItems = accessItems.filter(
    (item) => item.item_type === "newspaper_subscription"
  );

  let directInserted = 0;
  for (const item of directItems) {
    try {
      const result = await insertOrderAccessRowIfMissing({
        userId,
        item,
      });
      if (result.inserted) {
        directInserted += 1;
      }
    } catch (err) {
      console.error(
        `[payment][settle][access][direct][error] orderId=${orderId} userId=${userId} itemType=${item.item_type} itemId=${item.item_id ?? "-"} msg=${err.message}`
      );
    }
  }

  let newspaperSettled = 0;
  if (newspaperItems.length) {
    const user = order.user?.id
      ? {
          id: order.user.id,
          payUniqe: order.user.payUniqe || null,
        }
      : await getUserByIdForAuth(userId);
    const revenueCatAppUserId =
      normalizeRevenueCatAppUserId(user?.payUniqe) || String(userId);

    for (const item of newspaperItems) {
      try {
        const accessResult = await syncRevenueCatAccessByEntitlement({
          userId,
          entitlementId: REVENUECAT_DEFAULT_ENTITLEMENT_ID,
          isActive: true,
          expirationDate: item.expires_at || null,
          appUserId: revenueCatAppUserId,
          originalAppUserId: revenueCatAppUserId,
          purchasePlatform: "paratika",
        });
        if (accessResult?.mapped) {
          newspaperSettled += 1;
        }
      } catch (err) {
        console.error(
          `[payment][settle][access][newspaper][error] orderId=${orderId} userId=${userId} msg=${err.message}`
        );
      }
    }

    if (newspaperSettled === 0) {
      for (const item of newspaperItems) {
        try {
          const result = await insertOrderAccessRowIfMissing({
            userId,
            item: {
              item_type: item.item_type,
              item_id: item.item_id,
              started_at: item.started_at || nowIso,
              expires_at: item.expires_at || null,
              purchase_price: item.purchase_price ?? null,
            },
          });
          if (result.inserted) {
            newspaperSettled += 1;
            console.log(
              `[payment][settle][access][newspaper][fallback] orderId=${orderId} userId=${userId} itemType=${item.item_type} itemId=${item.item_id ?? "-"} accessId=${result.accessId || "-"}`
            );
          }
        } catch (err) {
          console.error(
            `[payment][settle][access][newspaper][fallback][error] orderId=${orderId} userId=${userId} itemType=${item.item_type} itemId=${item.item_id ?? "-"} msg=${err.message}`
          );
        }
      }
    }
  }

  console.log(
    `[payment][settle][success] orderId=${orderId} userId=${userId} merchantPaymentId=${normalizedMerchantPaymentId || "-"} directInserted=${directInserted} newspaperSettled=${newspaperSettled}`
  );

  return {
    ok: true,
    orderId,
    userId,
    directInserted,
    newspaperSettled,
  };
};

const buildJwt = (user, options = {}) => {
  const userId = String(user.id);
  const defaultRole = String(options.defaultRole || JWT_DEFAULT_ROLE).trim() || JWT_DEFAULT_ROLE;
  const configuredRoles = Array.isArray(options.allowedRoles)
    ? options.allowedRoles
    : JWT_ALLOWED_ROLES;
  const sessionId = normalizeAuthSessionId(options.sessionId);
  const roles = [...new Set([defaultRole, ...configuredRoles.map((v) => String(v).trim())].filter(Boolean))];
  const payload = {
    sub: userId,
    name: user.name || undefined,
    email: user.email || undefined,
    "https://hasura.io/jwt/claims": {
      "x-hasura-default-role": defaultRole,
      "x-hasura-allowed-roles": roles,
      "x-hasura-user-id": userId,
      ...(sessionId ? { [AUTH_SESSION_CLAIM_KEY]: sessionId } : {}),
    },
    ...(sessionId ? { session_id: sessionId } : {}),
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: options.expiresIn || JWT_EXPIRES_IN,
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

const buildJwtForAppUser = (user) => {
  return buildJwt(user, {
    defaultRole: "admin",
    allowedRoles: ["admin", "user", ...JWT_ALLOWED_ROLES],
    sessionId: user.auth_session_id || user.session_id || null,
  });
};

const BCRYPT_HASH_REGEX = /^\$2[abxy]\$\d{2}\$/;
const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/i;
const normalizeEmail = (value) => String(value || "").trim().toLowerCase();
const normalizeAuthSessionId = (value) => {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  return normalized || null;
};
const hashLegacyPassword = (value) =>
  crypto.createHash("sha256").update(String(value || "")).digest("hex");
const hashPassword = (value) => bcrypt.hash(String(value || ""), BCRYPT_COST);
const verifyPasswordHash = async (plainTextPassword, persistedHash) => {
  const hash = String(persistedHash || "");
  if (!hash) return { ok: false, needsUpgrade: false };

  if (BCRYPT_HASH_REGEX.test(hash)) {
    const ok = await bcrypt.compare(String(plainTextPassword || ""), hash);
    return { ok, needsUpgrade: false };
  }

  if (!SHA256_HEX_REGEX.test(hash)) {
    return { ok: false, needsUpgrade: false };
  }

  const legacy = hashLegacyPassword(plainTextPassword);
  const ok = safeTokenCompare(legacy.toLowerCase(), hash.toLowerCase());
  return { ok, needsUpgrade: ok };
};
const normalizeRevenueCatAppUserId = (value) => {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  return normalized || null;
};
const normalizePurchasePlatform = (value) => {
  if (value === undefined || value === null) return null;
  const normalized = String(value)
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");
  if (!normalized) return null;
  switch (normalized) {
    case "appstore":
    case "app_store":
    case "apple":
    case "mac_app_store":
      return "apple";
    case "playstore":
    case "play_store":
    case "googleplay":
    case "google_play":
      return "google_play";
    case "paratika":
    case "sanal_pos":
    case "virtual_pos":
      return "paratika";
    default:
      return normalized;
  }
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
const toNullableBool = (value) => {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
    return null;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["true", "1", "yes"].includes(normalized)) return true;
    if (["false", "0", "no"].includes(normalized)) return false;
  }
  return null;
};
const toIsoFromMillisOrNull = (value) => {
  if (value === undefined || value === null || value === "") return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  const date = new Date(parsed);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
};
const boolForLog = (value) => {
  if (value === true) return "true";
  if (value === false) return "false";
  return "-";
};
const verifyJwtToken = (token) =>
  jwt.verify(token, JWT_SECRET, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
const extractJwtSessionId = (payload) => {
  const claims = payload?.["https://hasura.io/jwt/claims"] || {};
  return normalizeAuthSessionId(
    claims[AUTH_SESSION_CLAIM_KEY] ?? payload?.session_id ?? payload?.sid
  );
};
const extractJwtUserId = (payload) => {
  const claims = payload?.["https://hasura.io/jwt/claims"] || {};
  const rawId = claims["x-hasura-user-id"] ?? payload?.sub;
  return toPositiveIntOrNull(rawId);
};
const validateJwtSession = async (payload) => {
  const userId = extractJwtUserId(payload);
  if (!userId) {
    return {
      ok: false,
      statusCode: 401,
      code: "INVALID_TOKEN",
      error: "Invalid user token.",
    };
  }

  const user = await getUserByIdForAuth(userId);
  if (!user || user.is_active === false) {
    return {
      ok: false,
      statusCode: 401,
      code: "INVALID_TOKEN",
      error: "Invalid token.",
    };
  }

  return {
    ok: true,
    userId,
    user,
    tokenSessionId: extractJwtSessionId(payload),
    activeSessionId: normalizeAuthSessionId(user.auth_session_id),
  };
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

const FCM_OAUTH_AUDIENCE = "https://oauth2.googleapis.com/token";
const FCM_OAUTH_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_INVALID_TOKEN_CODES = new Set(["UNREGISTERED", "INVALID_ARGUMENT"]);

let firebaseServiceAccountCache = null;
let firebaseAccessTokenCache = {
  token: "",
  expiresAtMs: 0,
};

const encodeBase64Url = (value) =>
  Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const safeJsonParse = (value) => {
  try {
    return JSON.parse(value);
  } catch (err) {
    return null;
  }
};

const readFirebaseServiceAccount = () => {
  if (firebaseServiceAccountCache) return firebaseServiceAccountCache;

  let serviceAccount = null;
  if (FIREBASE_SERVICE_ACCOUNT_JSON.trim()) {
    serviceAccount = safeJsonParse(FIREBASE_SERVICE_ACCOUNT_JSON.trim());
  } else if (FIREBASE_SERVICE_ACCOUNT_JSON_PATH.trim()) {
    const absPath = path.resolve(FIREBASE_SERVICE_ACCOUNT_JSON_PATH.trim());
    const raw = fs.readFileSync(absPath, "utf8");
    serviceAccount = safeJsonParse(raw);
  }

  if (!serviceAccount || typeof serviceAccount !== "object") {
    const err = new Error("Firebase service account JSON is not configured.");
    err.statusCode = 503;
    throw err;
  }

  const clientEmail = String(serviceAccount.client_email || "").trim();
  const privateKey = String(serviceAccount.private_key || "").trim();
  const projectId = String(serviceAccount.project_id || "").trim();
  if (!clientEmail || !privateKey || !projectId) {
    const err = new Error(
      "Firebase service account must include client_email, private_key and project_id."
    );
    err.statusCode = 503;
    throw err;
  }

  firebaseServiceAccountCache = serviceAccount;
  return firebaseServiceAccountCache;
};

const resolveFirebaseProjectId = () => {
  if (FIREBASE_PROJECT_ID) return FIREBASE_PROJECT_ID;
  const serviceAccount = readFirebaseServiceAccount();
  const projectId = String(serviceAccount.project_id || "").trim();
  if (!projectId) {
    const err = new Error("Firebase project id is missing.");
    err.statusCode = 503;
    throw err;
  }
  return projectId;
};

const buildGoogleServiceAccountJwt = (serviceAccount) => {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: serviceAccount.client_email,
    scope: FCM_OAUTH_SCOPE,
    aud: FCM_OAUTH_AUDIENCE,
    iat: nowSec,
    exp: nowSec + 3600,
  };

  const unsigned = `${encodeBase64Url(JSON.stringify(header))}.${encodeBase64Url(
    JSON.stringify(payload)
  )}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const signature = signer
    .sign(serviceAccount.private_key, "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `${unsigned}.${signature}`;
};

const getFirebaseAccessToken = async () => {
  const nowMs = Date.now();
  if (
    firebaseAccessTokenCache.token &&
    firebaseAccessTokenCache.expiresAtMs - 60_000 > nowMs
  ) {
    return firebaseAccessTokenCache.token;
  }

  const serviceAccount = readFirebaseServiceAccount();
  const assertion = buildGoogleServiceAccountJwt(serviceAccount);
  const payload = formEncode({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
  });

  const response = await axios.post(FCM_OAUTH_AUDIENCE, payload, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: FCM_HTTP_TIMEOUT_MS,
    validateStatus: () => true,
  });

  if (response.status < 200 || response.status >= 300) {
    const msg = response?.data?.error_description || response?.data?.error || "OAuth failed";
    const err = new Error(`Firebase OAuth token request failed: ${msg}`);
    err.statusCode = 502;
    throw err;
  }

  const accessToken = String(response?.data?.access_token || "").trim();
  const expiresIn = Number(response?.data?.expires_in || 3600);
  if (!accessToken) {
    const err = new Error("Firebase OAuth response did not include access_token.");
    err.statusCode = 502;
    throw err;
  }

  firebaseAccessTokenCache = {
    token: accessToken,
    expiresAtMs: Date.now() + Math.max(60, expiresIn) * 1000,
  };
  return accessToken;
};

const normalizeFcmDataPayload = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const out = {};
  for (const [key, raw] of Object.entries(value)) {
    const normalizedKey = String(key || "").trim();
    if (!normalizedKey) continue;
    if (raw === undefined || raw === null) continue;
    out[normalizedKey] = typeof raw === "string" ? raw : JSON.stringify(raw);
  }
  return Object.keys(out).length ? out : undefined;
};

const maskDeviceToken = (token) => {
  const value = String(token || "");
  if (value.length <= 16) return value ? "***" : "";
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
};

const extractFcmErrorCode = (errorPayload) => {
  const direct = String(errorPayload?.error?.status || "").trim();
  if (direct) return direct;
  const details = errorPayload?.error?.details;
  if (!Array.isArray(details)) return "";
  for (const detail of details) {
    const code = String(detail?.errorCode || detail?.error_code || "").trim();
    if (code) return code;
  }
  return "";
};

const sendFirebaseMessageToToken = async ({
  token,
  title,
  body,
  data,
  dryRun = false,
}) => {
  const accessToken = await getFirebaseAccessToken();
  const projectId = resolveFirebaseProjectId();

  const payload = {
    message: {
      token,
      notification: { title, body },
      ...(data ? { data } : {}),
      android: { priority: "HIGH" },
      apns: { headers: { "apns-priority": "10" } },
    },
    validate_only: !!dryRun,
  };

  const response = await axios.post(
    `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(
      projectId
    )}/messages:send`,
    payload,
    {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      timeout: FCM_HTTP_TIMEOUT_MS,
      validateStatus: () => true,
    }
  );

  if (response.status >= 200 && response.status < 300) {
    return {
      ok: true,
      messageId: response?.data?.name || null,
      statusCode: response.status,
    };
  }

  const errorCode = extractFcmErrorCode(response?.data);
  return {
    ok: false,
    statusCode: response.status,
    errorCode,
    errorMessage:
      response?.data?.error?.message ||
      response?.data?.error_description ||
      "FCM send failed.",
  };
};

const fetchUsersWithFirebaseTokens = async ({ userId, userIds } = {}) => {
  if (userId) {
    const rows = await homePostgresQuery(
      `
        SELECT
          id::bigint AS id,
          firebase_token
        FROM public.users
        WHERE id = $1::bigint
        LIMIT 1
      `,
      [userId]
    );
    const user = rows[0];
    if (!user || !String(user.firebase_token || "").trim()) return [];
    return [{ id: user.id, firebase_token: String(user.firebase_token).trim() }];
  }

  if (Array.isArray(userIds) && userIds.length) {
    const rows = await homePostgresQuery(
      `
        SELECT
          id::bigint AS id,
          firebase_token
        FROM public.users
        WHERE id = ANY($1::bigint[])
          AND firebase_token IS NOT NULL
          AND firebase_token <> ''
      `,
      [userIds]
    );
    return rows
      .map((u) => ({
        id: u.id,
        firebase_token: String(u.firebase_token || "").trim(),
      }))
      .filter((u) => !!u.firebase_token);
  }

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        firebase_token
      FROM public.users
      WHERE firebase_token IS NOT NULL
        AND firebase_token <> ''
      ORDER BY firebase_token_updated_at DESC NULLS LAST, id DESC
    `
  );
  return rows
    .map((u) => ({
      id: u.id,
      firebase_token: String(u.firebase_token || "").trim(),
    }))
    .filter((u) => !!u.firebase_token);
};

const persistNotifications = async ({ title, body, userIds }) => {
  if (!Array.isArray(userIds) || userIds.length === 0) {
    return 0;
  }
  const uniqueIds = [...new Set(userIds.map((id) => toPositiveIntOrNull(id)).filter(Boolean))];
  if (!uniqueIds.length) return 0;
  const rows = await withHomePostgresClient(async (client) => {
    const inserted = [];
    for (const userId of uniqueIds) {
      const object = {
        title,
        body,
        user_id: userId,
      };
      const result = await homePostgresQueryWithClient(
        client,
        `
          INSERT INTO public.notifications (title, body, user_id)
          VALUES ($1::text, $2::text, $3::bigint)
          RETURNING id
        `,
        [object.title, object.body, object.user_id]
      );
      inserted.push(...result);
    }
    return inserted;
  });
  return Number(rows.length || 0);
};

const clearUsersFirebaseTokens = async (userIds) => {
  const uniqueIds = [...new Set((userIds || []).map((id) => toPositiveIntOrNull(id)).filter(Boolean))];
  if (!uniqueIds.length) return 0;
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET firebase_token = NULL,
          firebase_token_updated_at = NULL
      WHERE id = ANY($1::bigint[])
      RETURNING id
    `,
    [uniqueIds]
  );
  return Number(rows.length || 0);
};

const escapeHtml = (value) =>
  String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const buildWelcomeMailHtml = (name) => {
  const safeName = escapeHtml(name || "Değerli Okur");
  return `
    <div style="font-family:Arial,sans-serif;background:#fafafa;padding:16px;">
      <div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.05);padding:20px;">
        <div style="text-align:center;margin-bottom:16px;">
          <h1 style="color:#d32f2f;margin:0;">Yeni Asya Dijital</h1>
        </div>
        <h2>Merhaba ${safeName},</h2>
        <p>Aramıza katıldığınız için teşekkürler. Yeni Asya uygulamasında dijital içeriklerinize hemen ulaşabilirsiniz.</p>
        <p>Keyifli okumalar!</p>
        <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
        <p style="font-size:12px;color:#777;text-align:center;">Bu e-posta otomatik gönderilmiştir.</p>
      </div>
    </div>
  `;
};

const formatCurrencyTry = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return "0.00";
  return parsed.toFixed(2);
};

const buildOrderSummaryMailHtml = ({ name, orderId, total, rowsHtml }) => {
  const safeName = escapeHtml(name || "Değerli Okur");
  const safeOrderId = escapeHtml(orderId || "-");
  const safeRows = rowsHtml || "";
  const safeTotal = formatCurrencyTry(total);
  return `
    <div style="font-family:Arial,sans-serif;background:#fafafa;padding:16px;">
      <div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.05);padding:20px;">
        <div style="text-align:center;margin-bottom:16px;">
          <h1 style="color:#d32f2f;margin:0;">Yeni Asya Dijital</h1>
        </div>
        <h2>Teşekkürler ${safeName},</h2>
        <p>Siparişiniz alındı. Detaylar aşağıda:</p>
        <p><strong>Sipariş No:</strong> ${safeOrderId}</p>
        <table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
          <thead>
            <tr style="background:#f5f5f5;">
              <th align="left">Ürün</th>
              <th align="center">Adet</th>
              <th align="right">Tutar</th>
            </tr>
          </thead>
          <tbody>
            ${safeRows}
          </tbody>
        </table>
        <p style="text-align:right;font-weight:bold;margin-top:12px;">Toplam: ₺${safeTotal}</p>
        <p>İyi okumalar dileriz.</p>
        <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
        <p style="font-size:12px;color:#777;text-align:center;">Bu e-posta otomatik gönderilmiştir.</p>
      </div>
    </div>
  `;
};

const buildPasswordResetMailHtml = ({ name, resetLink, expiresInMinutes }) => {
  const safeName = escapeHtml(name || "Değerli Okur");
  const safeResetLink = escapeHtml(resetLink || "");
  const safeExpires = escapeHtml(String(expiresInMinutes || PASSWORD_RESET_TOKEN_TTL_MINUTES));

  return `
    <div style="font-family:Arial, sans-serif; background:#fafafa; padding:16px;">
      <div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.05);padding:20px;">
        <div style="text-align:center;margin-bottom:16px;">
          <h1 style="color:#d32f2f;margin:0;">Yeni Asya Dijital</h1>
        </div>
        <p>Merhaba ${safeName},</p>
        <p>Şifrenizi sıfırlamak için aşağıdaki bağlantıyı kullanın:</p>
        <p style="margin:16px 0;">
          <a href="${safeResetLink}" style="background:#d32f2f;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;">Şifreyi Sıfırla</a>
        </p>
        <p>Bu bağlantı tek kullanımlıktır ve ${safeExpires} dakika geçerlidir.</p>
        <p>Bağlantı çalışmazsa şu adresi kopyalayın:<br><small>${safeResetLink}</small></p>
        <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
        <p style="font-size:12px;color:#777;text-align:center;">Bu e-posta otomatik gönderilmiştir.</p>
      </div>
    </div>
  `;
};

const buildEmailVerificationMailHtml = ({
  name,
  verificationLink,
  expiresInMinutes,
}) => {
  const safeName = escapeHtml(name || "Değerli Okur");
  const safeVerificationLink = escapeHtml(verificationLink || "");
  const safeExpires = escapeHtml(
    String(expiresInMinutes || EMAIL_VERIFICATION_TOKEN_TTL_MINUTES)
  );

  return `
    <div style="font-family:Arial, sans-serif; background:#fafafa; padding:16px;">
      <div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.05);padding:20px;">
        <div style="text-align:center;margin-bottom:16px;">
          <h1 style="color:#d32f2f;margin:0;">Yeni Asya Dijital</h1>
        </div>
        <p>Merhaba ${safeName},</p>
        <p>Hesabınızı aktifleştirmek için aşağıdaki bağlantıyı kullanın:</p>
        <p style="margin:16px 0;">
          <a href="${safeVerificationLink}" style="background:#d32f2f;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;">Hesabı Aktifleştir</a>
        </p>
        <p>Bağlantı tek kullanımlıktır ve ${safeExpires} dakika geçerlidir.</p>
        <p>Bağlantı çalışmazsa şu adresi kopyalayın:<br><small>${safeVerificationLink}</small></p>
        <hr style="margin:20px 0;border:none;border-top:1px solid #eee;">
        <p style="font-size:12px;color:#777;text-align:center;">Bu e-posta otomatik gönderilmiştir.</p>
      </div>
    </div>
  `;
};

const getUserMailProfile = async (userId) => {
  const normalizedUserId = toPositiveIntOrNull(userId);
  if (!normalizedUserId) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email
      FROM public.users
      WHERE id = $1::bigint
      LIMIT 1
    `,
    [normalizedUserId]
  );
  return rows[0] || null;
};

const getOldManualNewspaperAccessByEmail = async (email) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return null;

  try {
    const rows = await homePostgresQuery(
      `
        SELECT
          m.id::int AS id,
          m.user_id::int AS user_id,
          u.email
        FROM public.manual_newspaper_users m
        INNER JOIN public.users u ON u.id = m.user_id
        WHERE lower(u.email) = lower($1)
          AND m.is_active = TRUE
          AND COALESCE(m.status, 'new') = 'old'
        ORDER BY m.ends_at DESC NULLS LAST, m.starts_at DESC NULLS LAST, m.id DESC
        LIMIT 1
      `,
      [normalizedEmail]
    );
    return rows[0] || null;
  } catch (err) {
    const message = String(err?.message || "").toLowerCase();
    if (
      String(err?.code || "") === "42P01" ||
      String(err?.code || "") === "42703" ||
      message.includes("manual_newspaper_users")
    ) {
      return null;
    }
    throw err;
  }
};

const getUserByEmailForAuth = async (email) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        u.id::bigint AS id,
        u.name,
        u.email,
        u.phone,
        u.avatar_url,
        u."payUniqe",
        u.auth_session_id,
        u.role_id::bigint AS role_id,
        u.password,
        u.is_active,
        u.email_verified_at,
        jsonb_build_object('id', r.id, 'name', r.name) AS role
      FROM public.users u
      LEFT JOIN public.roles r ON r.id = u.role_id
      WHERE u.is_active = TRUE
        AND (LOWER(u.email) = $1 OR LOWER(u.email) LIKE $2)
      ORDER BY u.email_verified_at DESC NULLS LAST, u.id ASC
      LIMIT 1
    `,
    [normalizedEmail, normalizedEmail]
  );
  return rows[0] || null;
};

const getInactiveUserByEmailForAuth = async (email) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        u.id::bigint AS id,
        u.name,
        u.email,
        u.phone,
        u.avatar_url,
        u."payUniqe",
        u.auth_session_id,
        u.role_id::bigint AS role_id,
        u.password,
        u.is_active,
        u.email_verified_at,
        u.deactivated_at,
        jsonb_build_object('id', r.id, 'name', r.name) AS role
      FROM public.users u
      LEFT JOIN public.roles r ON r.id = u.role_id
      WHERE u.is_active = FALSE
        AND (LOWER(u.email) = $1 OR LOWER(u.email) LIKE $2)
      ORDER BY u.email_verified_at DESC NULLS LAST, u.id ASC
      LIMIT 1
    `,
    [normalizedEmail, normalizedEmail]
  );
  return rows[0] || null;
};

const getUserByPhoneForAuth = async (phone) => {
  const normalizedPhone = String(phone || "").trim();
  if (!normalizedPhone) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        u.id::bigint AS id,
        u.name,
        u.email,
        u.phone,
        u.avatar_url,
        u."payUniqe",
        u.auth_session_id,
        u.role_id::bigint AS role_id,
        u.password,
        u.is_active,
        u.email_verified_at,
        jsonb_build_object('id', r.id, 'name', r.name) AS role
      FROM public.users u
      LEFT JOIN public.roles r ON r.id = u.role_id
      WHERE u.is_active = TRUE
        AND u.phone = $1
      ORDER BY u.email_verified_at DESC NULLS LAST, u.id ASC
      LIMIT 1
    `,
    [normalizedPhone]
  );
  return rows[0] || null;
};

const getInactiveUserByPhoneForAuth = async (phone) => {
  const normalizedPhone = String(phone || "").trim();
  if (!normalizedPhone) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        u.id::bigint AS id,
        u.name,
        u.email,
        u.phone,
        u.avatar_url,
        u."payUniqe",
        u.auth_session_id,
        u.role_id::bigint AS role_id,
        u.password,
        u.is_active,
        u.email_verified_at,
        u.deactivated_at,
        jsonb_build_object('id', r.id, 'name', r.name) AS role
      FROM public.users u
      LEFT JOIN public.roles r ON r.id = u.role_id
      WHERE u.is_active = FALSE
        AND u.phone = $1
      ORDER BY u.email_verified_at DESC NULLS LAST, u.id ASC
      LIMIT 1
    `,
    [normalizedPhone]
  );
  return rows[0] || null;
};

const getInactiveUsersByIdentityForAuth = async ({ email, phone }) => {
  const normalizedEmail = normalizeEmail(email);
  const normalizedPhone = String(phone || "").trim();
  if (normalizedEmail) {
    const emailRows = await homePostgresQuery(
      `
        SELECT
          id::bigint AS id,
          name,
          email,
          phone,
          email_verified_at,
          deactivated_at
        FROM public.users
        WHERE is_active = FALSE
          AND LOWER(email) = LOWER($1)
        ORDER BY email_verified_at DESC NULLS LAST, id ASC
      `,
      [normalizedEmail]
    );
    if (emailRows.length) {
      return emailRows;
    }
  }

  if (!normalizedPhone) {
    return [];
  }

  return homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        phone,
        email_verified_at,
        deactivated_at
      FROM public.users
      WHERE is_active = FALSE
        AND phone = $1
      ORDER BY email_verified_at DESC NULLS LAST, id ASC
    `,
    [normalizedPhone]
  );
};

const purgeInactiveUsersForAuthIdentity = async ({ email, phone }) => {
  const inactiveUsers = await getInactiveUsersByIdentityForAuth({ email, phone });
  if (!inactiveUsers.length) {
    return {
      deletedUserIds: [],
      deletedCount: 0,
      deletedCounts: {},
    };
  }

  return purgeUsersByIdsFromPostgres(inactiveUsers.map((user) => user.id));
};

const homePostgresTableExists = async (client, tableName) => {
  const rows = await homePostgresQueryWithClient(
    client,
    `
      SELECT to_regclass($1::text) IS NOT NULL AS exists
    `,
    [tableName]
  );
  return rows[0]?.exists === true;
};

const homePostgresColumnExists = async (client, tableName, columnName) => {
  const rows = await homePostgresQueryWithClient(
    client,
    `
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = $1::text
          AND column_name = $2::text
      ) AS exists
    `,
    [tableName, columnName]
  );
  return rows[0]?.exists === true;
};

const deleteHomePostgresRowsIfTableExists = async (
  client,
  tableName,
  query,
  values = []
) => {
  const exists = await homePostgresTableExists(client, tableName);
  if (!exists) return 0;
  const rows = await homePostgresQueryWithClient(client, query, values);
  return rows.length;
};

const purgeUsersByIdsFromPostgres = async (userIds) => {
  const ids = Array.from(
    new Set(
      (Array.isArray(userIds) ? userIds : [userIds])
        .map((value) => Number.parseInt(value, 10))
        .filter((value) => Number.isInteger(value) && value > 0)
    )
  );

  if (!ids.length) {
    return { deletedUserIds: [], deletedCount: 0 };
  }

  return withHomePostgresClient(async (client) => {
    await client.query("BEGIN");
    try {
      const deletedCounts = {};
      const deleteMany = async (key, tableName, query, values) => {
        deletedCounts[key] = await deleteHomePostgresRowsIfTableExists(
          client,
          tableName,
          query,
          values
        );
      };

      await deleteMany(
        "order_items",
        "order_items",
        `
          DELETE FROM public.order_items
          WHERE order_id IN (
            SELECT id FROM public.orders WHERE user_id = ANY($1::bigint[])
          )
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "orders",
        "orders",
        `
          DELETE FROM public.orders
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "manual_newspaper_users",
        "manual_newspaper_users",
        `
          DELETE FROM public.manual_newspaper_users
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "user_content_access",
        "user_content_access",
        `
          DELETE FROM public.user_content_access
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "notifications",
        "notifications",
        `
          DELETE FROM public.notifications
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "contact_messages",
        "contact_messages",
        `
          DELETE FROM public.contact_messages
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "product_reviews",
        "product_reviews",
        `
          DELETE FROM public.product_reviews
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "user_addresses",
        "user_addresses",
        `
          DELETE FROM public.user_addresses
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "password_reset_tokens",
        "password_reset_tokens",
        `
          DELETE FROM public.password_reset_tokens
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      await deleteMany(
        "email_verification_tokens",
        "email_verification_tokens",
        `
          DELETE FROM public.email_verification_tokens
          WHERE user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      if (
        (await homePostgresTableExists(client, "user_access_audit_log")) &&
        (await homePostgresColumnExists(client, "user_access_audit_log", "user_id")) &&
        (await homePostgresColumnExists(
          client,
          "user_access_audit_log",
          "actor_user_id"
        ))
      ) {
        deletedCounts.user_access_audit_log = (
          await homePostgresQueryWithClient(
            client,
            `
              DELETE FROM public.user_access_audit_log
              WHERE user_id = ANY($1::bigint[])
                 OR actor_user_id = ANY($1::bigint[])
              RETURNING id
            `,
            [ids]
          )
        ).length;
      }

      await deleteMany(
        "revenuecat_subscription_locks",
        "revenuecat_subscription_locks",
        `
          DELETE FROM public.revenuecat_subscription_locks
          WHERE owner_user_id = ANY($1::bigint[])
          RETURNING id
        `,
        [ids]
      );

      if (
        (await homePostgresTableExists(client, "revenuecat_sync_logs")) &&
        (await homePostgresColumnExists(client, "revenuecat_sync_logs", "user_id"))
      ) {
        deletedCounts.revenuecat_sync_logs = (
          await homePostgresQueryWithClient(
            client,
            `
              DELETE FROM public.revenuecat_sync_logs
              WHERE user_id = ANY($1::bigint[])
              RETURNING id
            `,
            [ids]
          )
        ).length;
      }

      deletedCounts.users = (
        await homePostgresQueryWithClient(
          client,
          `
            DELETE FROM public.users
            WHERE id = ANY($1::bigint[])
            RETURNING id
          `,
          [ids]
        )
      ).length;

      await client.query("COMMIT");
      return {
        deletedUserIds: ids,
        deletedCount: Object.values(deletedCounts).reduce(
          (total, count) => total + Number(count || 0),
          0
        ),
        deletedCounts,
      };
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  });
};

const getInactiveUserIdentityById = async (userId) => {
  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        phone,
        is_active
      FROM public.users
      WHERE id = $1
      LIMIT 1
    `,
    [userId]
  );
  return rows[0] || null;
};

const getUserByIdForAuth = async (id) => {
  const normalizedUserId = toPositiveIntOrNull(id);
  if (!normalizedUserId) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        phone,
        avatar_url,
        "payUniqe",
        auth_session_id,
        role_id::bigint AS role_id,
        email_verified_at,
        is_active
      FROM public.users
      WHERE id = $1::bigint
      LIMIT 1
    `,
    [normalizedUserId]
  );
  return rows[0] || null;
};

const getUserByIdForPasswordChange = async (id) => {
  const normalizedUserId = toPositiveIntOrNull(id);
  if (!normalizedUserId) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        phone,
        avatar_url,
        "payUniqe",
        role_id::bigint AS role_id,
        password,
        auth_session_id,
        is_active,
        email_verified_at
      FROM public.users
      WHERE id = $1::bigint
      LIMIT 1
    `,
    [normalizedUserId]
  );
  return rows[0] || null;
};

const toSafeUser = (user) => {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    avatar_url: user.avatar_url || null,
    payUniqe: user.payUniqe,
    role_id: user.role_id,
  };
};

const issueUserAuthSession = async (userId) => {
  const sessionId = crypto.randomUUID();
  try {
    const rows = await homePostgresQuery(
      `
        UPDATE public.users
        SET auth_session_id = $2::text
        WHERE id = $1::bigint
        RETURNING
          id::bigint AS id,
          auth_session_id
      `,
      [userId, sessionId]
    );
    return rows[0] || null;
  } catch (err) {
    console.warn(
      `[auth][session-issue-warning] userId=${userId} msg=${err.message}`
    );
    return null;
  }
};

const normalizeAvatarUrl = (value) => {
  const parsed = parseManagedFileReference(value);
  if (!parsed || parsed.type !== "profil" || parsed.scope !== "public") {
    return null;
  }
  return parsed.normalizedUrl;
};

const updateUserProfileFields = async ({ userId, name, phone }) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET name = $2::text,
          phone = $3::text
      WHERE id = $1::bigint
      RETURNING
        id::bigint AS id,
        name,
        email,
        phone,
        avatar_url,
        "payUniqe",
        role_id::bigint AS role_id,
        email_verified_at,
        is_active
    `,
    [userId, name, phone || null]
  );
  return rows[0] || null;
};

const updateUserAvatarUrl = async ({ userId, avatarUrl }) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET avatar_url = $2::text
      WHERE id = $1::bigint
      RETURNING
        id::bigint AS id,
        name,
        email,
        phone,
        avatar_url,
        "payUniqe",
        role_id::bigint AS role_id,
        email_verified_at,
        is_active
    `,
    [userId, avatarUrl || null]
  );
  return rows[0] || null;
};

const getActiveUserByEmail = async (email) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        email_verified_at
      FROM public.users
      WHERE is_active = TRUE
        AND LOWER(email) = $1
      LIMIT 1
    `,
    [normalizedEmail]
  );
  return rows[0] || null;
};

const hashPasswordResetToken = (token) =>
  crypto.createHash("sha256").update(String(token || ""), "utf8").digest("hex");

const createPasswordResetToken = () => crypto.randomBytes(32).toString("base64url");
const createEmailVerificationToken = () => crypto.randomBytes(32).toString("base64url");

const buildPasswordResetLink = ({ token, email }) => {
  const url = new URL(PASSWORD_RESET_WEB_URL);
  url.searchParams.set("token", token);
  if (email) {
    url.searchParams.set("email", email);
  }
  return url.toString();
};

const buildEmailVerificationLink = ({ token, email }) => {
  const url = new URL(EMAIL_VERIFICATION_WEB_URL);
  url.searchParams.set("token", token);
  if (email) {
    url.searchParams.set("email", email);
  }
  return url.toString();
};

const invalidatePasswordResetTokensForUser = async (userId, usedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.password_reset_tokens
      SET used_at = $2::timestamptz
      WHERE user_id = $1::bigint
        AND used_at IS NULL
      RETURNING id
    `,
    [userId, usedAt]
  );
  return Number(rows.length || 0);
};

const createPasswordResetTokenRecord = async ({
  userId,
  tokenHash,
  expiresAt,
  requestedIp,
  userAgent,
}) => {
  const rows = await homePostgresQuery(
    `
      INSERT INTO public.password_reset_tokens (
        user_id,
        token_hash,
        expires_at,
        requested_ip,
        user_agent
      ) VALUES ($1::bigint, $2::text, $3::timestamptz, $4::text, $5::text)
      RETURNING
        id,
        user_id,
        token_hash,
        expires_at,
        used_at
    `,
    [userId, tokenHash, expiresAt, requestedIp || null, userAgent || null]
  );
  return rows[0] || null;
};

const getPasswordResetTokenStateByHash = async (tokenHash) => {
  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        user_id::bigint AS user_id,
        expires_at,
        used_at
      FROM public.password_reset_tokens
      WHERE token_hash = $1::text
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `,
    [tokenHash]
  );
  return rows[0] || null;
};

const markPasswordResetTokenUsed = async (tokenId, usedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.password_reset_tokens
      SET used_at = $2::timestamptz
      WHERE id = $1::bigint
      RETURNING id::bigint AS id, used_at
    `,
    [tokenId, usedAt]
  );
  return rows[0] || null;
};

const invalidateEmailVerificationTokensForUser = async (userId, usedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.email_verification_tokens
      SET used_at = $2::timestamptz
      WHERE user_id = $1::bigint
        AND used_at IS NULL
      RETURNING id
    `,
    [userId, usedAt]
  );
  return Number(rows.length || 0);
};

const createEmailVerificationTokenRecord = async ({
  userId,
  tokenHash,
  expiresAt,
  requestedIp,
  userAgent,
}) => {
  const rows = await homePostgresQuery(
    `
      INSERT INTO public.email_verification_tokens (
        user_id,
        token_hash,
        expires_at,
        requested_ip,
        user_agent
      ) VALUES ($1::bigint, $2::text, $3::timestamptz, $4::text, $5::text)
      RETURNING
        id,
        user_id,
        token_hash,
        expires_at,
        used_at
    `,
    [userId, tokenHash, expiresAt, requestedIp || null, userAgent || null]
  );
  return rows[0] || null;
};

const getEmailVerificationTokenStateByHash = async (tokenHash) => {
  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        user_id::bigint AS user_id,
        expires_at,
        used_at
      FROM public.email_verification_tokens
      WHERE token_hash = $1::text
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `,
    [tokenHash]
  );
  return rows[0] || null;
};

const markEmailVerificationTokenUsed = async (tokenId, usedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.email_verification_tokens
      SET used_at = $2::timestamptz
      WHERE id = $1::bigint
      RETURNING id::bigint AS id, used_at
    `,
    [tokenId, usedAt]
  );
  return rows[0] || null;
};

const markUserEmailVerified = async (userId, verifiedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET email_verified_at = $2::timestamptz
      WHERE id = $1::bigint
      RETURNING
        id::bigint AS id,
        name,
        email,
        phone,
        avatar_url,
        "payUniqe",
        role_id::bigint AS role_id,
        email_verified_at
    `,
    [userId, verifiedAt]
  );
  return rows[0] || null;
};

const sendEmailVerificationMail = async ({ user, req }) => {
  const rawToken = createEmailVerificationToken();
  const tokenHash = hashPasswordResetToken(rawToken);
  const nowIso = new Date().toISOString();
  const expiresAt = new Date(
    Date.now() + EMAIL_VERIFICATION_TOKEN_TTL_MINUTES * 60 * 1000
  ).toISOString();

  await invalidateEmailVerificationTokensForUser(user.id, nowIso);
  await createEmailVerificationTokenRecord({
    userId: user.id,
    tokenHash,
    expiresAt,
    requestedIp: req.ip,
    userAgent: String(req.get("user-agent") || "").slice(0, 512),
  });

  const verificationLink = buildEmailVerificationLink({
    token: rawToken,
    email: user.email,
  });
  const safeName = String(user.name || "").trim() || user.email.split("@")[0];
  const text = `Merhaba ${safeName}, hesabınızı aktifleştirmek için bu bağlantıyı kullanın: ${verificationLink}`;
  const html = buildEmailVerificationMailHtml({
    name: safeName,
    verificationLink,
    expiresInMinutes: EMAIL_VERIFICATION_TOKEN_TTL_MINUTES,
  });

  return mailTransporter.sendMail({
    from: MAIL_SETTINGS.from,
    to: user.email,
    subject: "Hesabınızı aktifleştirin",
    text,
    html,
  });
};

const PASSWORD_RESET_GENERIC_RESPONSE = {
  ok: true,
  message:
    "Bu e-posta adresi kayıtlıysa şifre sıfırlama bağlantısı gönderildi.",
};

const EMAIL_VERIFICATION_GENERIC_RESPONSE = {
  ok: true,
  message:
    "Bu e-posta adresi kayıtlıysa aktivasyon bağlantısı gönderildi.",
};

const formatIsoDateOnly = (value) => {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const parseIsoDateOnly = (value) => {
  const raw = String(value || "").trim();
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw);
  if (!match) return null;
  const year = Number.parseInt(match[1], 10);
  const month = Number.parseInt(match[2], 10);
  const day = Number.parseInt(match[3], 10);
  if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) {
    return null;
  }
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() + 1 !== month ||
    date.getUTCDate() !== day
  ) {
    return null;
  }
  return date;
};

const buildLegacyNewspaperToken = (fileName, nowMs = Date.now()) => {
  if (!LEGACY_NEWSPAPER_TOKEN_SECRET) {
    const err = new Error("LEGACY_NEWSPAPER_TOKEN_SECRET missing.");
    err.statusCode = 503;
    throw err;
  }
  const slice = Math.floor(Math.floor(nowMs / 1000) / 600);
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(BigInt(slice), 0);
  return crypto
    .createHmac("sha256", `${LEGACY_NEWSPAPER_TOKEN_SECRET}${fileName}`)
    .update(bytes)
    .digest("hex")
    .toUpperCase()
    .slice(0, 16);
};

const buildLegacyNewspaperUrl = (date) => {
  const isoDate = formatIsoDateOnly(date);
  if (!isoDate) {
    const err = new Error("Invalid newspaper date.");
    err.statusCode = 400;
    throw err;
  }
  const fileName = `${isoDate}.pdf`;
  return `${LEGACY_NEWSPAPER_PDF_BASE_URL}/${fileName}`;
};

const buildLegacyNewspaperProxyUrl = (isoDate) =>
  `/newspaper/legacy-file?date=${encodeURIComponent(isoDate)}`;

const isPrivateStorageUrl = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return false;
  const parsed = URL.canParse(raw) ? new URL(raw) : null;
  const path = (parsed?.pathname || raw).toLowerCase();
  return (
    path.startsWith("/private/") ||
      /^\/(kitap|dergi|gazete|ek|slider)\/private\/.+/.test(path)
  );
};

const getActiveNewspaperAccessRowFromPostgres = async ({
  userId,
  nowIso,
  client = null,
  requireCurrent = true,
}) => {
  const currentWhere = requireCurrent
    ? "AND (expires_at IS NULL OR expires_at > $2::timestamptz)"
    : "";
  const queryWithGrantSource = `
    SELECT
      id::int AS id,
      expires_at,
      started_at,
      grant_source
    FROM public.user_content_access
    WHERE user_id = $1
      AND item_type = 'newspaper_subscription'::public.access_item_type
      AND item_id IS NULL
      AND is_active = TRUE
      ${currentWhere}
    ORDER BY expires_at DESC NULLS LAST, started_at DESC NULLS LAST, id DESC
    LIMIT 1
  `;
  const queryWithoutGrantSource = `
    SELECT
      id::int AS id,
      expires_at,
      started_at,
      NULL::text AS grant_source
    FROM public.user_content_access
    WHERE user_id = $1
      AND item_type = 'newspaper_subscription'::public.access_item_type
      AND item_id IS NULL
      AND is_active = TRUE
      ${currentWhere}
    ORDER BY expires_at DESC NULLS LAST, started_at DESC NULLS LAST, id DESC
    LIMIT 1
  `;
  const queryRunner = client
    ? (text, values) => homePostgresQueryWithClient(client, text, values)
    : homePostgresQuery;
  const values = requireCurrent ? [userId, nowIso] : [userId];

  if (!userContentAccessGrantSourceSupported) {
    const rows = await queryRunner(queryWithoutGrantSource, values);
    return rows[0] || null;
  }

  try {
    const rows = await queryRunner(queryWithGrantSource, values);
    return rows[0] || null;
  } catch (err) {
    if (!isMissingUserContentAccessGrantSourceError(err)) {
      throw err;
    }
    userContentAccessGrantSourceSupported = false;
    const rows = await queryRunner(queryWithoutGrantSource, values);
    return rows[0] || null;
  }
};

const getActiveManualNewspaperAccessRowFromPostgres = async ({ userId, nowIso }) => {
  try {
    const rows = await homePostgresQuery(
      `
        SELECT
          id::int AS id,
          ends_at AS expires_at,
          starts_at AS started_at,
          COALESCE(status, 'new') AS status,
          'manual_newspaper'::text AS grant_source
        FROM public.manual_newspaper_users
        WHERE user_id = $1
          AND is_active = TRUE
          AND (ends_at IS NULL OR ends_at > $2::timestamptz)
        ORDER BY ends_at DESC NULLS LAST, starts_at DESC NULLS LAST, id DESC
        LIMIT 1
      `,
      [userId, nowIso]
    );
    return rows[0] || null;
  } catch (err) {
    const message = String(err?.message || "").toLowerCase();
    if (String(err?.code || "") === "42P01" || message.includes("manual_newspaper_users")) {
      return null;
    }
    throw err;
  }
};

const getActiveNewspaperSubscriptionAccess = async (userId) => {
  const nowIso = new Date().toISOString();
  try {
    const accessEntry = await getActiveNewspaperAccessRowFromPostgres({
      userId,
      nowIso,
    });
    const manualEntry = await getActiveManualNewspaperAccessRowFromPostgres({
      userId,
      nowIso,
    });
    const preferred = pickLaterExpiryEntry(accessEntry, manualEntry);
    if (preferred) return preferred;
  } catch (_) {
    // Fallback to Hasura if direct Postgres is unavailable.
  }
  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        expires_at
      FROM public.user_content_access
      WHERE user_id = $1::bigint
        AND item_type = 'newspaper_subscription'
        AND is_active = TRUE
        AND (expires_at IS NULL OR expires_at > $2::timestamptz)
      ORDER BY expires_at DESC NULLS LAST, id DESC
      LIMIT 1
    `,
    [userId, nowIso]
  );
  return rows[0] || null;
};

const getNewspaperByPublishDate = async (publishDate) => {
  try {
    const rows = await homePostgresQuery(
      `
        SELECT
          id::int AS id,
          publish_date,
          file_url
        FROM public.newspaper
        WHERE publish_date = $1::date
        ORDER BY id DESC
        LIMIT 1
      `,
      [publishDate]
    );
    return rows[0] || null;
  } catch (_) {
    return null;
  }
};

const getUserWelcomeMailState = async (userId) => {
  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        welcome_mail_sent_at
      FROM public.users
      WHERE id = $1::bigint
      LIMIT 1
    `,
    [userId]
  );
  return rows[0] || null;
};

const claimWelcomeMailSend = async (userId, claimedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET welcome_mail_sent_at = $2::timestamptz
      WHERE id = $1::bigint
        AND welcome_mail_sent_at IS NULL
      RETURNING
        id::bigint AS id,
        name,
        email,
        welcome_mail_sent_at
    `,
    [userId, claimedAt]
  );
  return {
    affected_rows: rows.length,
    returning: rows,
  };
};

const rollbackWelcomeMailClaim = async (userId, claimedAt) => {
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET welcome_mail_sent_at = NULL
      WHERE id = $1::bigint
        AND welcome_mail_sent_at = $2::timestamptz
      RETURNING id
    `,
    [userId, claimedAt]
  );
  return Number(rows.length || 0);
};

const sendWelcomeMailOnce = async (userId) => {
  const claimedAt = new Date().toISOString();
  const claim = await claimWelcomeMailSend(userId, claimedAt);
  if (Number(claim?.affected_rows || 0) === 0) {
    const userState = await getUserWelcomeMailState(userId);
    return {
      ok: true,
      skipped: true,
      reason: "already_sent",
      welcomeMailSentAt: userState?.welcome_mail_sent_at || null,
    };
  }

  const user = claim?.returning?.[0];
  const email = normalizeEmail(user?.email);
  if (!email) {
    await rollbackWelcomeMailClaim(userId, claimedAt);
    throw new Error("User email is missing.");
  }
  const name = String(user?.name || "").trim() || email.split("@")[0];

  try {
    const subject = `Yeni Asya’ya hoş geldiniz, ${name}`;
    const html = buildWelcomeMailHtml(name);
    const text = `Merhaba ${name}, aramıza katıldığınız için teşekkürler. Keyifli okumalar!`;

    const info = await mailTransporter.sendMail({
      from: MAIL_SETTINGS.from,
      to: email,
      subject,
      text,
      html,
    });

    return {
      ok: true,
      sent: true,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      welcomeMailSentAt: claimedAt,
    };
  } catch (err) {
    await rollbackWelcomeMailClaim(userId, claimedAt);
    throw err;
  }
};

const requireJwt = async (req, res, next) => {
  const raw = req.get("authorization") || "";
  const token = raw.toLowerCase().startsWith("bearer ") ? raw.slice(7) : raw;
  if (!token) {
    return res.status(401).json({ ok: false, error: "Token eksik." });
  }
  try {
    const payload = verifyJwtToken(token);
    const validation = await validateJwtSession(payload);
    if (!validation.ok) {
      return res.status(validation.statusCode || 401).json({
        ok: false,
        code: validation.code || "SESSION_REVOKED",
        error: validation.error || "Oturumunuz sonlandırıldı. Lütfen tekrar giriş yapın.",
      });
    }
    req.jwt = payload;
    req.jwtToken = token;
    req.hasuraAuthMode = "jwt";
    return next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Geçersiz token." });
  }
};

const optionalJwt = async (req, res, next) => {
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
    const validation = await validateJwtSession(payload);
    if (!validation.ok) {
      return res.status(validation.statusCode || 401).json({
        ok: false,
        code: validation.code || "SESSION_REVOKED",
        error: validation.error || "Oturumunuz sonlandırıldı. Lütfen tekrar giriş yapın.",
      });
    }
    req.jwt = payload;
    req.jwtToken = token;
    req.hasuraAuthMode = "jwt";
    return next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Geçersiz token." });
  }
};

const requireJwtOrServiceAuth = async (req, res, next) => {
  const authHeader = req.get("authorization") || "";
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";
  if (bearerToken) {
    try {
      const payload = verifyJwtToken(bearerToken);
      const validation = await validateJwtSession(payload);
      if (!validation.ok) {
        return res.status(validation.statusCode || 401).json({
          ok: false,
          code: validation.code || "SESSION_REVOKED",
          error: validation.error || "Oturumunuz sonlandırıldı. Lütfen tekrar giriş yapın.",
        });
      }
      req.jwt = payload;
      req.jwtToken = bearerToken;
      req.hasuraAuthMode = "jwt";
      return next();
    } catch (err) {
      // Fall back to service token mode.
    }
  }

  const serviceRaw = req.get("x-api-key") || authHeader || "";
  const serviceToken = serviceRaw.toLowerCase().startsWith("bearer ")
    ? serviceRaw.slice(7).trim()
    : serviceRaw.trim();
  if (serviceToken && safeTokenCompare(serviceToken, AUTH_TOKEN)) {
    req.hasuraAuthMode = "service";
    return next();
  }

  return res.status(401).json({ ok: false, error: "Yetkisiz erişim." });
};

const requireRevenueCatAuth = async (req, res, next) => {
  const authHeader = req.get("authorization") || "";
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";

  if (bearerToken) {
    try {
      const payload = verifyJwtToken(bearerToken);
      const validation = await validateJwtSession(payload);
      if (!validation.ok) {
        return res.status(validation.statusCode || 401).json({
          ok: false,
          code: validation.code || "SESSION_REVOKED",
          error: validation.error || "Oturumunuz sonlandırıldı. Lütfen tekrar giriş yapın.",
        });
      }
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

  if (serviceToken && safeTokenCompare(serviceToken, AUTH_TOKEN)) {
    req.revenueCatAuthMode = "service";
    return next();
  }

  if (
    typeof req.path === "string" &&
    req.path.startsWith("/revenuecat/subscription/")
  ) {
    req.revenueCatAuthMode = "guest";
    req.revenueCatGuest = true;
    return next();
  }

  return res.status(401).json({ ok: false, error: "Yetkisiz erişim." });
};

const requireRevenueCatWebhookAuth = (req, res, next) => {
  if (!REVENUECAT_WEBHOOK_AUTH_TOKEN) {
    return res.status(503).json({
      ok: false,
      error: "RevenueCat webhook auth token is not configured.",
    });
  }

  const authHeader = req.get("authorization") || "";
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";
  const headerToken =
    (req.get("x-revenuecat-webhook-token") || req.get("x-api-key") || "").trim();
  const token = bearerToken || headerToken;

  if (!token || !safeTokenCompare(token, REVENUECAT_WEBHOOK_AUTH_TOKEN)) {
    return res
      .status(401)
      .json({ ok: false, error: "Yetkisiz webhook isteği." });
  }

  req.revenueCatAuthMode = "webhook";
  return next();
};

const buildHasuraAuthHeaders = (req) => {
  if (req?.hasuraAuthMode === "service") {
    return { "x-direct-db-mode": "service" };
  }
  if (req?.hasuraAuthMode === "jwt" && req?.jwtToken) {
    return { Authorization: `Bearer ${req.jwtToken}` };
  }
  return {};
};

const extractGraphqlOperationName = (query, fallbackOperationName = null) => {
  const fallback = String(fallbackOperationName || "").trim();
  if (fallback) return fallback;
  const text = String(query || "");
  const match = text.match(/\b(query|mutation)\s+([A-Za-z0-9_]+)/);
  return match?.[2] || null;
};

const directSelect = async ({
  tableName,
  columns = "*",
  whereSql = "",
  values = [],
  orderBy = "",
  limit = null,
}) => {
  const query = [
    `SELECT ${columns}`,
    `FROM ${qualifySqlTable(tableName)}`,
    whereSql ? `WHERE ${whereSql}` : "",
    orderBy ? `ORDER BY ${orderBy}` : "",
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const directInsert = async ({
  tableName,
  object,
  returning = "*",
}) => {
  const payload = compactObject(object);
  const keys = Object.keys(payload);
  if (!keys.length) {
    throw new Error(`Insert payload for ${tableName} is empty.`);
  }
  const columns = keys.map((key) => quoteSqlIdentifier(key)).join(", ");
  const placeholders = keys.map((_, index) => `$${index + 1}`).join(", ");
  const values = keys.map((key) => payload[key]);
  return homePostgresQuery(
    `INSERT INTO ${qualifySqlTable(tableName)} (${columns}) VALUES (${placeholders}) RETURNING ${returning}`,
    values
  );
};

const directUpdateByPk = async ({
  tableName,
  pkColumn = "id",
  id,
  object,
  returning = "*",
}) => {
  const payload = compactObject(object);
  const keys = Object.keys(payload);
  if (!keys.length) {
    throw new Error(`Update payload for ${tableName} is empty.`);
  }
  const setSql = keys
    .map((key, index) => `${quoteSqlIdentifier(key)} = $${index + 2}`)
    .join(", ");
  const values = [id, ...keys.map((key) => payload[key])];
  return homePostgresQuery(
    `UPDATE ${qualifySqlTable(tableName)} SET ${setSql} WHERE ${quoteSqlIdentifier(pkColumn)} = $1 RETURNING ${returning}`,
    values
  );
};

const directDeleteByPk = async ({
  tableName,
  pkColumn = "id",
  id,
  returning = "*",
}) => {
  return homePostgresQuery(
    `DELETE FROM ${qualifySqlTable(tableName)} WHERE ${quoteSqlIdentifier(pkColumn)} = $1 RETURNING ${returning}`,
    [id]
  );
};

const directCount = async ({ tableName, whereSql = "", values = [] }) => {
  const rows = await homePostgresQuery(
    `SELECT COUNT(*)::int AS count FROM ${qualifySqlTable(tableName)} ${whereSql ? `WHERE ${whereSql}` : ""}`,
    values
  );
  return Number(rows[0]?.count || 0);
};

const selectUsersDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "u.id ASC",
  limit = null,
  offset = null,
  includeRole = false,
  includePassword = false,
  includeDeactivatedAt = false,
}) => {
  const selectParts = [
    "u.id::bigint AS id",
    "u.name",
    "u.email",
    "u.phone",
    "u.avatar_url",
    'u."payUniqe"',
    "u.auth_session_id",
    "u.role_id::bigint AS role_id",
    "u.email_verified_at",
    "u.is_active",
  ];
  if (includePassword) selectParts.push("u.password");
  if (includeDeactivatedAt) selectParts.push("u.deactivated_at");
  if (includeRole) {
    selectParts.push("jsonb_build_object('id', r.id, 'name', r.name) AS role");
  }
  const sql = [
    `SELECT ${selectParts.join(", ")}`,
    "FROM public.users u",
    includeRole ? "LEFT JOIN public.roles r ON r.id = u.role_id" : "",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    offset !== null && offset !== undefined ? `OFFSET ${Number(offset)}` : "",
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(sql, values);
};

const selectRolesDirect = async () =>
  homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        description
      FROM public.roles
      ORDER BY id ASC
    `
  );

const selectNotificationsDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "created_at DESC, id DESC",
  limit = null,
  includeUser = false,
}) => {
  const selectParts = [
    "n.id::int AS id",
    "n.user_id::int AS user_id",
    "n.title",
    "n.body",
    "n.created_at",
    "n.is_read",
  ];
  if (includeUser) {
    selectParts.push(
      "CASE WHEN u.id IS NULL THEN NULL ELSE jsonb_build_object('id', u.id::int, 'name', u.name, 'email', u.email) END AS user"
    );
  }
  const sql = [
    `SELECT ${selectParts.join(", ")}`,
    "FROM public.notifications n",
    includeUser ? "LEFT JOIN public.users u ON u.id = n.user_id" : "",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(sql, values);
};

const selectOrdersDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "created_at DESC, id DESC",
  limit = null,
  includeItems = false,
  includeUser = false,
}) => {
  const selectParts = [
    "o.id::bigint AS id",
    "o.user_id::bigint AS user_id",
    "o.total_paid",
    "o.status::text AS status",
    "o.payment_provider",
    "o.merchant_payment_id",
    "o.payment_session_token",
    "CASE WHEN o.promo_code_id IS NULL THEN NULL ELSE o.promo_code_id::bigint END AS promo_code_id",
    "o.promo_code",
    "o.promo_discount_percent",
    "o.promo_discount_amount",
    "o.created_at",
  ];
  if (includeUser) {
    selectParts.push(
      "CASE WHEN u.id IS NULL THEN NULL ELSE jsonb_build_object('id', u.id, 'name', u.name, 'email', u.email) END AS user"
    );
  }
  const orders = await homePostgresQuery(
    [
      `SELECT ${selectParts.join(", ")}`,
      "FROM public.orders o",
      includeUser ? "LEFT JOIN public.users u ON u.id = o.user_id" : "",
      `WHERE ${whereSql}`,
      `ORDER BY ${orderBy}`,
      limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
    ]
      .filter(Boolean)
      .join(" "),
    values
  );

  if (!includeItems || !orders.length) {
    return orders.map((order) => ({ ...order }));
  }

  const orderIds = orders.map((order) => Number(order.id)).filter(Number.isFinite);
  const items = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        order_id::bigint AS order_id,
        product_id::bigint AS product_id,
        ek_id::bigint AS ek_id,
        title,
        quantity::int AS quantity,
        unit_price,
        line_total,
        product_type,
        metadata,
        created_at
      FROM public.order_items
      WHERE order_id = ANY($1::bigint[])
      ORDER BY id ASC
    `,
    [orderIds]
  );
  const itemsByOrderId = new Map();
  for (const item of items) {
    const key = Number(item.order_id);
    if (!itemsByOrderId.has(key)) itemsByOrderId.set(key, []);
    itemsByOrderId.get(key).push({ ...item });
  }
  return orders.map((order) => ({
    ...order,
    order_items: itemsByOrderId.get(Number(order.id)) || [],
  }));
};

const selectUserContentAccessDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "started_at DESC NULLS LAST, expires_at DESC NULLS LAST, id DESC",
  limit = null,
  includeManual = false,
}) => {
  const rows = await homePostgresQuery(
    [
      "SELECT",
      "id::bigint AS id",
      ", user_id::bigint AS user_id",
      ", CASE WHEN item_id IS NULL THEN NULL ELSE item_id::bigint END AS item_id",
      ", item_type",
      ", started_at",
      ", expires_at",
      ", purchase_price",
      ", is_active",
      ", grant_source",
      ", purchase_platform",
      "FROM public.user_content_access",
      `WHERE ${whereSql}`,
      `ORDER BY ${orderBy}`,
      limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
    ]
      .filter(Boolean)
      .join(" "),
    values
  );

  const entries = rows.map((row) => ({ ...row }));
  if (includeManual) {
    const manualRows = await homePostgresQuery(
      `
        SELECT
          id::bigint AS id,
          user_id::bigint AS user_id,
          NULL::bigint AS item_id,
          'newspaper_subscription'::text AS item_type,
          starts_at AS started_at,
          ends_at AS expires_at,
          NULL::numeric AS purchase_price,
          is_active,
          COALESCE(status, 'new') AS status,
          'manual_newspaper'::text AS grant_source,
          NULL::text AS purchase_platform,
          note
        FROM public.manual_newspaper_users
        WHERE ${whereSql.replaceAll("user_id", "user_id")}
      `,
      values
    ).catch(() => []);
    entries.push(...manualRows);
  }
  return entries;
};

const selectBooksDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "b.id DESC",
  limit = null,
  onlyPublished = false,
}) => {
  const conditions = [whereSql];
  if (onlyPublished) {
    conditions.push("COALESCE(b.is_published, TRUE) = TRUE");
  }
  const query = [
    "SELECT",
    "b.id::int AS id",
    ", b.title",
    ", b.isbn",
    ", b.cover_url",
    ", b.book_url",
    ", COALESCE(b.is_published, TRUE) AS is_published",
    ", b.price",
    ", b.discount_price",
    ", b.description",
    ", b.min_description",
    ", b.category_id",
    ", b.author_id",
    ", b.created_at",
    ", NULL::timestamptz AS updated_at",
    ", CASE WHEN c.id IS NULL THEN NULL ELSE jsonb_build_object('id', c.id, 'name', c.name) END AS category_rel",
    ", CASE WHEN a.id IS NULL THEN NULL ELSE jsonb_build_object('id', a.id, 'name', a.name) END AS author_rel",
    "FROM public.books b",
    "LEFT JOIN public.categories c ON c.id = b.category_id",
    "LEFT JOIN public.authors a ON a.id = b.author_id",
    `WHERE ${conditions.join(" AND ")}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectMagazinesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "m.id DESC",
  limit = null,
}) => {
  const query = [
    "SELECT",
    "m.id::int AS id",
    ", m.name",
    ", m.category",
    ", m.cover_image_url",
    ", m.period",
    ", m.description",
    ", m.created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.magazine m",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectMagazineIssuesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "mi.issue_number DESC NULLS LAST, mi.added_at DESC NULLS LAST, mi.id DESC",
  limit = null,
  includeMagazine = false,
}) => {
  const query = [
    "SELECT",
    "mi.id::int AS id",
    ", mi.magazine_id::int AS magazine_id",
    ", mi.issue_number::int AS issue_number",
    ", mi.file_url",
    ", mi.photo_url",
    ", mi.price",
    ", mi.description",
    ", mi.added_at",
    ", mi.added_at::date::text AS publish_date",
    ", NULL::timestamptz AS created_at",
    ", NULL::timestamptz AS updated_at",
    ", COALESCE(mi.is_published, TRUE) AS is_published",
    includeMagazine
      ? ", CASE WHEN m.id IS NULL THEN NULL ELSE jsonb_build_object('id', m.id, 'name', m.name) END AS magazine"
      : "",
    "FROM public.magazine_issue mi",
    includeMagazine ? "LEFT JOIN public.magazine m ON m.id = mi.magazine_id" : "",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectNewspapersDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "publish_date DESC, id DESC",
  limit = null,
}) => {
  const query = [
    "SELECT",
    "id::int AS id",
    ", image_url",
    ", publish_date::text AS publish_date",
    ", file_url",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.newspaper",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectEklerDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "e.created_at DESC, e.id DESC",
  limit = null,
}) => {
  const query = [
    "SELECT",
    "e.id::bigint AS id",
    ", e.ad",
    ", e.aciklama",
    ", e.fiyat",
    ", e.pdf_url",
    ", e.photo_url",
    ", COALESCE(e.is_public, TRUE) AS is_public",
    ", e.created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.ekler e",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectSlidersDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "sort_order ASC NULLS LAST, created_at DESC",
  limit = null,
}) => {
  const query = [
    "SELECT",
    "id::int AS id",
    ", title",
    ", subtitle",
    ", description",
    ", image_url",
    ", link_url",
    ", sort_order",
    ", COALESCE(is_active, TRUE) AS is_active",
    ", created_at",
    ", updated_at",
    "FROM public.slider",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectFaqDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "sort_order ASC, id ASC",
  limit = null,
}) => {
  const query = [
    "SELECT",
    "id::int AS id",
    ", title",
    ", description",
    ", sort_order",
    ", COALESCE(is_active, TRUE) AS is_active",
    ", created_at",
    ", updated_at",
    "FROM public.faq",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(query, values);
};

const selectAuthorsDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "id ASC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::int AS id",
    ", name",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.authors",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectCategoriesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "id ASC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::int AS id",
    ", name",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.categories",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectMagazineTypesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "sort_order ASC, id ASC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::int AS id",
    ", title",
    ", duration_months",
    ", COALESCE(is_active, TRUE) AS is_active",
    ", sort_order",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.magazine_type",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectNewspaperSubscriptionTypesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "sort_order ASC, id DESC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::bigint AS id",
    ", title",
    ", duration_months",
    ", price",
    ", COALESCE(is_active, TRUE) AS is_active",
    ", sort_order",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.newspaper_subscription_type",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectMagazineTypePricesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "sort_order ASC, id ASC",
  limit = null,
  includeTypes = false,
}) => {
  const sql = [
    "SELECT",
    "mtp.id::int AS id",
    ", mtp.magazine_id::int AS magazine_id",
    ", mtp.magazine_type_id::int AS magazine_type_id",
    ", mtp.price",
    ", COALESCE(mtp.is_active, TRUE) AS is_active",
    ", mtp.sort_order",
    includeTypes
      ? ", CASE WHEN mt.id IS NULL THEN NULL ELSE jsonb_build_object('id', mt.id, 'title', mt.title, 'duration_months', mt.duration_months) END AS magazine_type"
      : "",
    "FROM public.magazine_type_price mtp",
    includeTypes ? "LEFT JOIN public.magazine_type mt ON mt.id = mtp.magazine_type_id" : "",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(sql, values);
};

const PROMO_SCOPE_CATEGORIES = ["book", "magazine", "subscription", "supplement"];

function normalizePromoScopeCategories(rawCategories) {
  if (!Array.isArray(rawCategories)) return [];
  return [...new Set(
    rawCategories
      .map((value) => String(value || "").trim().toLowerCase())
      .filter((value) => PROMO_SCOPE_CATEGORIES.includes(value)),
  )];
}

function promoCategoryFromProductType(productType) {
  const normalized = String(productType || "").trim().toLowerCase();
  switch (normalized) {
    case "book":
      return "book";
    case "magazine":
    case "magazine_issue":
    case "magazine_one":
      return "magazine";
    case "newspaper":
    case "newspaper_subscription":
      return "subscription";
    case "supplement":
    case "ek":
      return "supplement";
    default:
      return null;
  }
}

function promoScopeAppliesToItems(scopeCategories, items) {
  const allowed = new Set(normalizePromoScopeCategories(scopeCategories));
  if (!allowed.size) return true;
  const itemCategories = (Array.isArray(items) ? items : [])
    .map((item) => promoCategoryFromProductType(item?.product_type))
    .filter(Boolean);
  if (!itemCategories.length) return false;
  return itemCategories.every((category) => allowed.has(category));
}

function createPromoCodeError(message, code) {
  const err = new Error(message);
  if (code) err.code = code;
  return err;
}

const selectPromoCodesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "created_at DESC, id DESC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::bigint AS id",
    ", code",
    ", discount_percent",
    ", starts_at",
    ", ends_at",
    ", COALESCE(is_active, TRUE) AS is_active",
    ", usage_limit",
    ", usage_count",
    ", COALESCE(applicable_categories, ARRAY[]::text[]) AS applicable_categories",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.promo_codes",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectReviewsDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "created_at DESC, id DESC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::bigint AS id",
    ", product_type",
    ", product_id::bigint AS product_id",
    ", product_title",
    ", user_id::bigint AS user_id",
    ", user_name",
    ", user_email",
    ", rating",
    ", comment",
    ", status",
    ", created_at",
    ", NULL::timestamptz AS updated_at",
    "FROM public.product_reviews",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectContactMessagesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "cm.created_at DESC, cm.id DESC",
  limit = null,
  includeUser = false,
}) => {
  const sql = [
    "SELECT",
    "cm.id::bigint AS id",
    ", cm.subject",
    ", cm.message",
    ", cm.email",
    ", cm.user_id::bigint AS user_id",
    ", cm.created_at",
    ", cm.reply_message",
    ", cm.reply_at",
    ", cm.reply_admin_user_id::bigint AS reply_admin_user_id",
    includeUser
      ? ", CASE WHEN u.id IS NULL THEN NULL ELSE jsonb_build_object('id', u.id, 'name', u.name, 'email', u.email, 'phone', u.phone, 'role', jsonb_build_object('id', r.id, 'name', r.name)) END AS user"
      : "",
    ", CASE WHEN ru.id IS NULL THEN NULL ELSE jsonb_build_object('id', ru.id, 'name', ru.name, 'email', ru.email, 'phone', ru.phone, 'role', jsonb_build_object('id', rr.id, 'name', rr.name)) END AS reply_user",
    "FROM public.contact_messages cm",
    includeUser ? "LEFT JOIN public.users u ON u.id = cm.user_id LEFT JOIN public.roles r ON r.id = u.role_id" : "",
    "LEFT JOIN public.users ru ON ru.id = cm.reply_admin_user_id",
    "LEFT JOIN public.roles rr ON rr.id = ru.role_id",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return homePostgresQuery(sql, values);
};

const selectUserAccessAuditLogsDirect = async ({
  userId = null,
  limit = 20,
  includeActors = false,
}) => {
  const values = [];
  let whereSql = "TRUE";
  if (userId !== null && userId !== undefined) {
    values.push(userId);
    whereSql = `user_id = $${values.length}::bigint`;
  }
  values.push(limit);
  const rows = await homePostgresQuery(
    [
      "SELECT",
      "id::bigint AS id",
      ", user_id::bigint AS user_id",
      ", actor_user_id::bigint AS actor_user_id",
      ", action",
      ", item_type",
      ", item_id::bigint AS item_id",
      ", item_title",
      ", access_source",
      ", previous_expires_at",
      ", new_expires_at",
      ", note",
      ", created_at",
      "FROM public.user_access_audit_log",
      `WHERE ${whereSql}`,
      "ORDER BY created_at DESC, id DESC",
      `LIMIT $${values.length}::int`,
    ]
      .filter(Boolean)
      .join(" "),
    values
  );

  if (!includeActors || rows.length === 0) {
    return rows.map((row) => ({ ...row }));
  }

  const actorIds = rows
    .map((row) => row.actor_user_id)
    .filter((value) => value !== null && value !== undefined)
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value));
  if (!actorIds.length) return rows.map((row) => ({ ...row }));

  const actors = await selectUsersDirect({
    whereSql: "u.id = ANY($1::bigint[])",
    values: [actorIds],
    includeRole: false,
  });
  const byId = new Map(actors.map((user) => [String(user.id), user]));
  return rows.map((row) => ({
    ...row,
    actor: byId.get(String(row.actor_user_id)) || null,
  }));
};

const selectHomeShowcaseDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "sort_order ASC NULLS LAST, created_at DESC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::bigint AS id",
    ", product_type",
    ", product_id::bigint AS product_id",
    ", sort_order",
    ", COALESCE(is_active, TRUE) AS is_active",
    ", created_at",
    "FROM public.home_showcase",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const selectUserAddressesDirect = async ({
  whereSql = "TRUE",
  values = [],
  orderBy = "created_at DESC, id DESC",
  limit = null,
}) => homePostgresQuery(
  [
    "SELECT",
    "id::int AS id",
    ", user_id::int AS user_id",
    ", address_name",
    ", address_type",
    ", country",
    ", city",
    ", district",
    ", full_address",
    ", postal_code",
    ", tax_or_tc_no",
    ", tax_address",
    ", company_name",
    ", created_at",
    "FROM public.user_addresses",
    `WHERE ${whereSql}`,
    `ORDER BY ${orderBy}`,
    limit !== null && limit !== undefined ? `LIMIT ${Number(limit)}` : "",
  ]
    .filter(Boolean)
    .join(" "),
  values
);

const executeDirectGraphqlRequest = async ({ query, variables = {}, operationName, req }) => {
  const op = extractGraphqlOperationName(query, operationName);
  if (!op) {
    throw new Error("GraphQL operation name could not be determined.");
  }

  switch (op) {
    case "GetRoles": {
      return { roles: await selectRolesDirect() };
    }
    case "GetAllUsers": {
      return {
        users: await selectUsersDirect({
          whereSql: "u.is_active = TRUE",
          orderBy: "u.id ASC",
          includeRole: true,
        }),
      };
    }
    case "GetUsersPage": {
      const limit = toPositiveIntOrNull(variables.limit) || 25;
      const offset = toPositiveIntOrNull(variables.offset) || 0;
      const keyword = String(variables.keyword || "").trim();
      const searchValues = [];
      let whereSql = "u.is_active = TRUE";
      if (keyword) {
        searchValues.push(`%${keyword}%`);
        whereSql +=
          " AND (u.name ILIKE $1::text OR u.email ILIKE $1::text OR COALESCE(u.phone, '') ILIKE $1::text OR CAST(u.id AS text) ILIKE $1::text)";
      }

      const users = await selectUsersDirect({
        whereSql,
        values: searchValues,
        orderBy: "u.id DESC",
        limit,
        offset,
        includeRole: true,
      });
      const countRows = await homePostgresQuery(
        `SELECT COUNT(*)::int AS count FROM public.users u WHERE ${whereSql}`,
        searchValues
      );
      return {
        users,
        users_aggregate: {
          aggregate: {
            count: Number(countRows[0]?.count || 0),
          },
        },
      };
    }
    case "GetAdminUserDetail": {
      const userId = toPositiveIntOrNull(variables.id);
      return { users_by_pk: userId ? (await selectUsersDirect({ whereSql: "u.id = $1::bigint", values: [userId], includeRole: true, includeDeactivatedAt: true, includePassword: true, limit: 1 }))[0] || null : null };
    }
    case "GetPassiveUsers": {
      return {
        users: await selectUsersDirect({
          whereSql: "u.is_active = FALSE",
          orderBy: "u.deactivated_at DESC NULLS LAST, u.id DESC",
          includeRole: true,
          includeDeactivatedAt: true,
        }),
      };
    }
    case "GetPassiveUsersFallback": {
      return {
        users: await selectUsersDirect({
          whereSql: "TRUE",
          orderBy: "u.id DESC",
          includeRole: true,
          includeDeactivatedAt: true,
        }),
      };
    }
    case "GetUserByEmail":
    case "GetUserByEmailForAuth": {
      const email = normalizeEmail(variables.email);
      return {
        users: await selectUsersDirect({
          whereSql: "u.is_active = TRUE AND (LOWER(u.email) = $1 OR LOWER(u.email) = $2)",
          values: [email, email],
          orderBy: "u.email_verified_at DESC NULLS LAST, u.id ASC",
          includeRole: true,
        }),
      };
    }
    case "GetUser":
    case "GetUserById":
    case "GetUserByIdForAuth":
    case "GetUserByIdForPasswordChange": {
      const userId = toPositiveIntOrNull(variables.id);
      return {
        users_by_pk: userId
          ? (await selectUsersDirect({
              whereSql: "u.id = $1::bigint",
              values: [userId],
              includeRole: true,
              includePassword: op === "GetUserByIdForPasswordChange",
              includeDeactivatedAt: true,
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "Register":
    case "AddUser":
    case "CreateSocialLoginUser":
    case "CreateSocialUser": {
      const payload =
        variables.object ||
        {
          name: variables.name,
          phone: variables.phone,
          email: variables.email,
          password: variables.password,
          payUniqe: variables.payUniqe || crypto.randomUUID(),
          role_id: variables.role_id || 1,
          is_active: variables.is_active ?? true,
          email_verified_at: variables.email_verified_at || new Date().toISOString(),
        };
      const rows = await directInsert({
        tableName: "users",
        object: {
          name: payload.name,
          phone: payload.phone || null,
          email: normalizeEmail(payload.email),
          password: payload.password || null,
          payUniqe: payload.payUniqe || crypto.randomUUID(),
          role_id: payload.role_id || 1,
          is_active: payload.is_active ?? true,
          email_verified_at: payload.email_verified_at || new Date().toISOString(),
          avatar_url: payload.avatar_url || null,
          auth_session_id: payload.auth_session_id || null,
        },
        returning: "id",
      });
      const insertedId = rows[0]?.id;
      return {
        insert_users_one: insertedId
          ? (await selectUsersDirect({
              whereSql: "u.id = $1::bigint",
              values: [insertedId],
              includeRole: true,
              includePassword: true,
              includeDeactivatedAt: true,
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "Login": {
      const email = normalizeEmail(variables.email);
      const password = String(variables.password || "");
      return {
        users: await selectUsersDirect({
          whereSql:
            "(LOWER(u.email) = $1 OR LOWER(u.email) = $2) AND u.password = $3 AND u.is_active = TRUE",
          values: [email, email, password],
          orderBy: "u.email_verified_at DESC NULLS LAST, u.id ASC",
          includeRole: true,
          includePassword: false,
        }),
      };
    }
    case "UpdateProfile":
    case "UpdateUser":
    case "UpdateProfileFields":
    case "UpdateUserProfileFields": {
      const userId = toPositiveIntOrNull(variables.id);
      if (!userId) return { update_users_by_pk: null };
      const updates = {
        name: variables.name,
        phone: variables.phone ?? null,
        email: variables.email,
        role_id: variables.role_id,
      };
      const rows = await directUpdateByPk({
        tableName: "users",
        id: userId,
        object: updates,
        returning: "id",
      }).catch(async () => {
        const safeUpdates = compactObject(updates);
        const safeRows = await homePostgresQuery(
          `UPDATE public.users SET ${Object.keys(safeUpdates)
            .map((key, index) => `${quoteSqlIdentifier(key)} = $${index + 2}`)
            .join(", ")} WHERE id = $1::bigint RETURNING id`,
          [userId, ...Object.values(safeUpdates)]
        );
        return safeRows;
      });
      const id = rows[0]?.id || userId;
      return {
        update_users_by_pk: id
          ? (await selectUsersDirect({
              whereSql: "u.id = $1::bigint",
              values: [id],
              includeRole: true,
              includePassword: true,
              includeDeactivatedAt: true,
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "ChangePassword": {
      const userId = toPositiveIntOrNull(variables.id);
      if (!userId) {
        return { update_users: { affected_rows: 0 } };
      }
      const rows = await homePostgresQuery(
        `
          UPDATE public.users
          SET password = $3::text
          WHERE id = $1::bigint AND password = $2::text
          RETURNING id
        `,
        [userId, String(variables.current || variables.password || ""), String(variables.next || variables.password || "")]
      );
      return { update_users: { affected_rows: rows.length } };
    }
    case "DeleteAccount": {
      const userId = toPositiveIntOrNull(variables.id);
      if (!userId) return { delete_users_by_pk: null };
      const deleted = await homePostgresQuery(
        `DELETE FROM public.users WHERE id = $1::bigint RETURNING id`,
        [userId]
      ).catch(() => []);
      if (deleted.length) {
        return { delete_users_by_pk: { id: deleted[0].id } };
      }
      const anonEmail = `deleted_${userId}_${Date.now()}@yeniasya.local`;
      const rows = await homePostgresQuery(
        `
          UPDATE public.users
          SET name = 'Silinmiş Hesap',
              email = $2::text,
              phone = NULL,
              password = $3::text,
              is_active = FALSE,
              firebase_token = NULL,
              deactivated_at = NOW()
          WHERE id = $1::bigint
          RETURNING id
        `,
        [userId, anonEmail, HashHelper.hashPassword(`deleted_${userId}_${Date.now()}`)]
      ).catch(() => []);
      return { delete_users_by_pk: rows[0] ? { id: rows[0].id } : null };
    }
    case "DeactivateAccount":
    case "DeactivateUser": {
      const userId = toPositiveIntOrNull(variables.id);
      if (!userId) return { update_users_by_pk: null };
      const rows = await homePostgresQuery(
        `
          UPDATE public.users
          SET is_active = FALSE,
              deactivated_at = COALESCE($2::timestamptz, NOW())
          WHERE id = $1::bigint
          RETURNING id
        `,
        [userId, variables.deactivated_at || variables.deactivatedAt || null]
      );
      return { update_users_by_pk: rows[0] ? { id: rows[0].id, is_active: false } : null };
    }
    case "UpdateUserToken": {
      const userId = toPositiveIntOrNull(variables.user_id || variables.id);
      if (!userId) return { update_users_by_pk: null };
      const rows = await homePostgresQuery(
        `
          UPDATE public.users
          SET firebase_token = $2::text,
              firebase_token_updated_at = $3::timestamptz
          WHERE id = $1::bigint
          RETURNING id
        `,
        [userId, variables.token || null, variables.firebase_token_updated_at || new Date().toISOString()]
      );
      return { update_users_by_pk: rows[0] ? { id: rows[0].id } : null };
    }
    case "GetTokens":
    case "GetUserTokensByIds":
    case "GetAllUserTokens": {
      const whereSql =
        op === "GetUserTokensByIds"
          ? "id = ANY($1::bigint[]) AND firebase_token IS NOT NULL AND firebase_token <> ''"
          : "firebase_token IS NOT NULL AND firebase_token <> ''";
      const values = op === "GetUserTokensByIds" ? [variables.ids || []] : [];
      return {
        users: await selectUsersDirect({
          whereSql: `u.${whereSql.replaceAll("id", "id").replaceAll("firebase_token", "firebase_token")}`,
          values,
          orderBy: "u.firebase_token_updated_at DESC NULLS LAST, u.id DESC",
          includeRole: false,
        }),
      };
    }
    case "GetPublicBooks": {
      return { books: await selectBooksDirect({ onlyPublished: true }) };
    }
    case "GetAllBooks": {
      return { books: await selectBooksDirect({ orderBy: "b.id DESC" }) };
    }
    case "GetBook": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        books_by_pk: id
          ? (await selectBooksDirect({
              whereSql: "b.id = $1::bigint",
              values: [id],
              orderBy: "b.id DESC",
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "AddBook": {
      const rows = await directInsert({
        tableName: "books",
        object: {
          title: variables.title,
          isbn: variables.isbn,
          cover_url: variables.cover_url ?? null,
          book_url: variables.book_url ?? null,
          price: variables.price,
          discount_price: variables.discount_price ?? null,
          category_id: variables.category_id ?? null,
          author_id: variables.author_id ?? null,
          description: variables.description ?? null,
          min_description: variables.min_description ?? null,
        },
        returning: "id::int AS id",
      });
      return { insert_books_one: rows[0] || null };
    }
    case "UpdateBook": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_books_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "books",
        id,
        object: {
          title: variables.title,
          isbn: variables.isbn,
          cover_url: variables.cover_url ?? null,
          book_url: variables.book_url ?? null,
          price: variables.price,
          discount_price: variables.discount_price ?? null,
          category_id: variables.category_id ?? null,
          author_id: variables.author_id ?? null,
          description: variables.description ?? null,
          min_description: variables.min_description ?? null,
        },
        returning: "id::int AS id",
      });
      return { update_books_by_pk: rows[0] || null };
    }
    case "DeleteBook": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "books",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_books_by_pk: rows[0] || null };
    }
    case "SetBookPublicationStatus": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_books_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "books",
        id,
        object: { is_published: toBool(variables.is_published) },
        returning: "id::int AS id, COALESCE(is_published, TRUE) AS is_published",
      });
      return { update_books_by_pk: rows[0] || null };
    }
    case "GetBooksByIds": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        books: ids.length
          ? await selectBooksDirect({
              whereSql: "b.id = ANY($1::bigint[])",
              values: [ids],
              orderBy: "b.id ASC",
            })
          : [],
      };
    }
    case "GetMagazines":
      return { magazine: await selectMagazinesDirect({ orderBy: "m.id DESC" }) };
    case "GetMagazine": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        magazine_by_pk: id
          ? (await selectMagazinesDirect({
              whereSql: "m.id = $1::bigint",
              values: [id],
              orderBy: "m.id DESC",
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "AddMagazine": {
      const rows = await directInsert({
        tableName: "magazine",
        object: {
          name: variables.name,
          category: variables.category,
          period: variables.period,
          description: variables.description ?? null,
          cover_image_url: variables.cover_image_url ?? null,
        },
        returning: "id::int AS id",
      });
      return { insert_magazine_one: rows[0] || null };
    }
    case "UpdateMagazine": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_magazine_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "magazine",
        id,
        object: {
          name: variables.name,
          category: variables.category,
          period: variables.period,
          description: variables.description ?? null,
          cover_image_url: variables.cover_image_url ?? null,
        },
        returning: "id::int AS id",
      });
      return { update_magazine_by_pk: rows[0] || null };
    }
    case "DeleteMagazine": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "magazine",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_magazine_by_pk: rows[0] || null };
    }
    case "GetIssues": {
      const magazineId = toPositiveIntOrNull(variables.magazine_id);
      return {
        magazine_issue: magazineId
          ? await selectMagazineIssuesDirect({
              whereSql: "mi.magazine_id = $1::bigint",
              values: [magazineId],
              orderBy: "mi.issue_number DESC NULLS LAST, mi.id DESC",
            })
          : [],
      };
    }
    case "GetAdminIssues": {
      const magazineId = toPositiveIntOrNull(variables.magazine_id);
      return {
        magazine_issue: magazineId
          ? await selectMagazineIssuesDirect({
              whereSql: "mi.magazine_id = $1::bigint",
              values: [magazineId],
              orderBy: "mi.issue_number DESC NULLS LAST, mi.id DESC",
            })
          : [],
      };
    }
    case "GetIssue": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        magazine_issue_by_pk: id
          ? (await selectMagazineIssuesDirect({
              whereSql: "mi.id = $1::bigint",
              values: [id],
              orderBy: "mi.id DESC",
              limit: 1,
              includeMagazine: true,
            }))[0] || null
          : null,
      };
    }
    case "AddIssue": {
      const rows = await directInsert({
        tableName: "magazine_issue",
        object: {
          magazine_id: variables.magazine_id,
          issue_number: variables.issue_number,
          file_url: variables.file_url,
          photo_url: variables.photo_url ?? null,
          price: variables.price,
          description: variables.description ?? null,
          added_at: variables.added_at ?? null,
        },
        returning: "id::int AS id",
      });
      return { insert_magazine_issue_one: rows[0] || null };
    }
    case "UpdateIssue": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_magazine_issue_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "magazine_issue",
        id,
        object: {
          issue_number: variables.issue_number,
          file_url: variables.file_url,
          photo_url: variables.photo_url ?? null,
          price: variables.price,
          description: variables.description ?? null,
          added_at: variables.added_at ?? null,
        },
        returning: "id::int AS id",
      });
      return { update_magazine_issue_by_pk: rows[0] || null };
    }
    case "DeleteIssue": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "magazine_issue",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_magazine_issue_by_pk: rows[0] || null };
    }
    case "SetIssuePublicationStatus": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_magazine_issue_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "magazine_issue",
        id,
        object: { is_published: toBool(variables.is_published) },
        returning: "id::int AS id, COALESCE(is_published, TRUE) AS is_published",
      });
      return { update_magazine_issue_by_pk: rows[0] || null };
    }
    case "GetMagazinesByIds": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        magazine: ids.length
          ? await selectMagazinesDirect({
              whereSql: "m.id = ANY($1::bigint[])",
              values: [ids],
              orderBy: "m.id ASC",
            })
          : [],
      };
    }
    case "GetMagazineIssuesByIds": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        magazine_issue: ids.length
          ? await selectMagazineIssuesDirect({
              whereSql: "mi.id = ANY($1::bigint[])",
              values: [ids],
              orderBy: "mi.id ASC",
              includeMagazine: true,
            })
          : [],
      };
    }
    case "GetPublicNewspapers": {
      return {
        newspaper: await selectNewspapersDirect({
          orderBy: "publish_date DESC, id DESC",
        }),
      };
    }
    case "GetNewspapers": {
      return {
        newspaper: await selectNewspapersDirect({
          orderBy: "publish_date DESC, id DESC",
        }),
      };
    }
    case "GetNewspaper": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        newspaper_by_pk: id
          ? (await selectNewspapersDirect({
              whereSql: "id = $1::bigint",
              values: [id],
              orderBy: "publish_date DESC, id DESC",
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "AddNewspaper": {
      const rows = await directInsert({
        tableName: "newspaper",
        object: {
          image_url: variables.image_url,
          file_url: variables.file_url,
          publish_date: variables.publish_date,
        },
        returning: "id::int AS id",
      });
      return { insert_newspaper_one: rows[0] || null };
    }
    case "UpdateNewspaper": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_newspaper_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "newspaper",
        id,
        object: {
          image_url: variables.image_url,
          file_url: variables.file_url,
          publish_date: variables.publish_date,
        },
        returning: "id::int AS id",
      });
      return { update_newspaper_by_pk: rows[0] || null };
    }
    case "DeleteNewspaper": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "newspaper",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_newspaper_by_pk: rows[0] || null };
    }
    case "GetEkler": {
      return { ekler: await selectEklerDirect({ orderBy: "e.created_at DESC, e.id DESC" }) };
    }
    case "GetEk": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        ekler_by_pk: id
          ? (await selectEklerDirect({
              whereSql: "e.id = $1::bigint",
              values: [id],
              orderBy: "e.created_at DESC, e.id DESC",
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "GetEklerByIds": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        ekler: ids.length
          ? await selectEklerDirect({
              whereSql: "e.id = ANY($1::bigint[])",
              values: [ids],
              orderBy: "e.id ASC",
            })
          : [],
      };
    }
    case "InsertEk": {
      const rows = await directInsert({
        tableName: "ekler",
        object: {
          ad: variables.ad,
          aciklama: variables.aciklama ?? null,
          fiyat: variables.fiyat,
          pdf_url: variables.pdf_url,
          photo_url: variables.photo_url ?? null,
          is_public: variables.is_public ?? true,
        },
        returning: "id::bigint AS id",
      });
      return { insert_ekler_one: rows[0] || null };
    }
    case "UpdateEk": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_ekler_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "ekler",
        id,
        object: {
          ad: variables.ad,
          aciklama: variables.aciklama ?? null,
          fiyat: variables.fiyat,
          pdf_url: variables.pdf_url,
          photo_url: variables.photo_url ?? null,
          is_public: variables.is_public,
        },
        returning: "id::bigint AS id",
      });
      return { update_ekler_by_pk: rows[0] || null };
    }
    case "DeleteEk": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "ekler",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_ekler_by_pk: rows[0] || null };
    }
    case "GetAuthors": {
      return { authors: await selectAuthorsDirect({ orderBy: "id ASC" }) };
    }
    case "AddAuthor": {
      const rows = await directInsert({
        tableName: "authors",
        object: { name: variables.name },
        returning: "id::int AS id",
      });
      return { insert_authors_one: rows[0] || null };
    }
    case "UpdateAuthor": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_authors_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "authors",
        id,
        object: { name: variables.name },
        returning: "id::int AS id",
      });
      return { update_authors_by_pk: rows[0] || null };
    }
    case "DeleteAuthor": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({ tableName: "authors", id, returning: "id::int AS id" })
        : [];
      return { delete_authors_by_pk: rows[0] || null };
    }
    case "GetCategories": {
      return { categories: await selectCategoriesDirect({ orderBy: "id ASC" }) };
    }
    case "AddCategory": {
      const rows = await directInsert({
        tableName: "categories",
        object: { name: variables.name },
        returning: "id::int AS id",
      });
      return { insert_categories_one: rows[0] || null };
    }
    case "UpdateCategory": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_categories_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "categories",
        id,
        object: { name: variables.name },
        returning: "id::int AS id",
      });
      return { update_categories_by_pk: rows[0] || null };
    }
    case "DeleteCategory": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "categories",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_categories_by_pk: rows[0] || null };
    }
    case "GetFaqAdminList":
    case "GetActiveFaqs": {
      const whereSql = op === "GetActiveFaqs" ? "COALESCE(is_active, TRUE) = TRUE" : "TRUE";
      return { faq: await selectFaqDirect({ whereSql, orderBy: "sort_order ASC, id ASC" }) };
    }
    case "AddFaq": {
      const rows = await directInsert({
        tableName: "faq",
        object: {
          title: variables.title,
          description: variables.description,
          sort_order: variables.sort_order,
          is_active: variables.is_active,
        },
        returning: "id::int AS id",
      });
      return { insert_faq_one: rows[0] || null };
    }
    case "UpdateFaq": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_faq_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "faq",
        id,
        object: {
          title: variables.title,
          description: variables.description,
          sort_order: variables.sort_order,
          is_active: variables.is_active,
        },
        returning: "id::int AS id",
      });
      return { update_faq_by_pk: rows[0] || null };
    }
    case "DeleteFaq": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({ tableName: "faq", id, returning: "id::int AS id" })
        : [];
      return { delete_faq_by_pk: rows[0] || null };
    }
    case "GetSliders": {
      const whereSql = op === "GetSliders" && req?.query?.onlyActive === "true"
        ? "COALESCE(is_active, TRUE) = TRUE"
        : "TRUE";
      return { slider: await selectSlidersDirect({ whereSql, orderBy: "sort_order ASC, created_at DESC" }) };
    }
    case "AddSlider": {
      const rows = await directInsert({
        tableName: "slider",
        object: {
          title: variables.title,
          subtitle: variables.subtitle ?? null,
          description: variables.description ?? null,
          image_url: variables.image_url,
          link_url: variables.link_url ?? null,
          sort_order: variables.sort_order,
          is_active: variables.is_active,
        },
        returning: "id::int AS id",
      });
      return { insert_slider_one: rows[0] || null };
    }
    case "UpdateSlider": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_slider_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "slider",
        id,
        object: {
          title: variables.title,
          subtitle: variables.subtitle ?? null,
          description: variables.description ?? null,
          image_url: variables.image_url,
          link_url: variables.link_url ?? null,
          sort_order: variables.sort_order,
          is_active: variables.is_active,
        },
        returning: "id::int AS id",
      });
      return { update_slider_by_pk: rows[0] || null };
    }
    case "DeleteSlider": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({ tableName: "slider", id, returning: "id::int AS id" })
        : [];
      return { delete_slider_by_pk: rows[0] || null };
    }
    case "GetMagazineTypes": {
      return { magazine_type: await selectMagazineTypesDirect({ orderBy: "sort_order ASC, id ASC" }) };
    }
    case "CreateMagazineType": {
      const rows = await directInsert({
        tableName: "magazine_type",
        object: {
          title: variables.title,
          duration_months: variables.duration_months,
          is_active: variables.is_active,
          sort_order: variables.sort_order,
        },
        returning: "id::int AS id",
      });
      return { insert_magazine_type_one: rows[0] || null };
    }
    case "UpdateMagazineType": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_magazine_type_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "magazine_type",
        id,
        object: {
          title: variables.title,
          duration_months: variables.duration_months,
          is_active: variables.is_active,
          sort_order: variables.sort_order,
        },
        returning: "id::int AS id",
      });
      return { update_magazine_type_by_pk: rows[0] || null };
    }
    case "DeleteMagazineType": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "magazine_type",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_magazine_type_by_pk: rows[0] || null };
    }
    case "GetNewspaperSubscriptionTypes": {
      return {
        newspaper_subscription_type: await selectNewspaperSubscriptionTypesDirect({
          orderBy: "sort_order ASC, id DESC",
        }),
      };
    }
    case "GetActiveNewspaperSubscriptionTypes": {
      return {
        newspaper_subscription_type: await selectNewspaperSubscriptionTypesDirect({
          whereSql: "COALESCE(is_active, TRUE) = TRUE",
          orderBy: "sort_order ASC, id ASC",
        }),
      };
    }
    case "CreateNewspaperSubscriptionType": {
      const rows = await directInsert({
        tableName: "newspaper_subscription_type",
        object: {
          title: variables.title,
          duration_months: variables.duration_months,
          price: variables.price,
          is_active: variables.is_active,
          sort_order: variables.sort_order,
        },
        returning: "id::bigint AS id",
      });
      return { insert_newspaper_subscription_type_one: rows[0] || null };
    }
    case "UpdateNewspaperSubscriptionType": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_newspaper_subscription_type_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "newspaper_subscription_type",
        id,
        object: {
          title: variables.title,
          duration_months: variables.duration_months,
          price: variables.price,
          is_active: variables.is_active,
          sort_order: variables.sort_order,
        },
        returning: "id::bigint AS id",
      });
      return { update_newspaper_subscription_type_by_pk: rows[0] || null };
    }
    case "DeleteNewspaperSubscriptionType": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "newspaper_subscription_type",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_newspaper_subscription_type_by_pk: rows[0] || null };
    }
    case "GetMagazineTypePrices": {
      const magazineId = toPositiveIntOrNull(variables.magazine_id);
      return {
        magazine_type_price: magazineId
          ? await selectMagazineTypePricesDirect({
              whereSql: "mtp.magazine_id = $1::bigint",
              values: [magazineId],
              orderBy: "mtp.sort_order ASC, mtp.id ASC",
              includeTypes: true,
            })
          : [],
      };
    }
    case "GetActiveMagazineTypePrices": {
      const magazineId = toPositiveIntOrNull(variables.magazine_id);
      return {
        magazine_type_price: magazineId
          ? await selectMagazineTypePricesDirect({
              whereSql: "mtp.magazine_id = $1::bigint AND COALESCE(mtp.is_active, TRUE) = TRUE",
              values: [magazineId],
              orderBy: "mtp.sort_order ASC, mtp.id ASC",
              includeTypes: true,
            })
          : [],
      };
    }
    case "GetMagazineTypesByIds": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        magazine_type: ids.length
          ? await selectMagazineTypesDirect({
              whereSql: "id = ANY($1::bigint[])",
              values: [ids],
              orderBy: "id ASC",
            })
          : [],
      };
    }
    case "GetNewspaperTypesByIds": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        newspaper_subscription_type: ids.length
          ? await selectNewspaperSubscriptionTypesDirect({
              whereSql: "id = ANY($1::bigint[])",
              values: [ids],
              orderBy: "id ASC",
            })
          : [],
      };
    }
    case "InsertMagazineTypePrices": {
      const items = Array.isArray(variables.items) ? variables.items : [];
      if (!items.length) return { insert_magazine_type_price: { affected_rows: 0 } };
      const rows = [];
      for (const item of items) {
        const inserted = await directInsert({
          tableName: "magazine_type_price",
          object: {
            magazine_id: item.magazine_id,
            magazine_type_id: item.magazine_type_id,
            price: item.price,
            is_active: item.is_active ?? true,
            sort_order: item.sort_order ?? 0,
          },
          returning: "id::int AS id",
        });
        rows.push(...inserted);
      }
      return { insert_magazine_type_price: { affected_rows: rows.length } };
    }
    case "DeleteMagazineTypePrices": {
      const magazineId = toPositiveIntOrNull(variables.magazine_id);
      if (!magazineId) return { delete_magazine_type_price: { affected_rows: 0 } };
      const rows = await homePostgresQuery(
        `DELETE FROM public.magazine_type_price WHERE magazine_id = $1::bigint RETURNING id`,
        [magazineId]
      );
      return { delete_magazine_type_price: { affected_rows: rows.length } };
    }
    case "AdminPromoCodes":
      return { promo_codes: await selectPromoCodesDirect({ orderBy: "created_at DESC, id DESC" }) };
    case "InsertPromoCode": {
      const rows = await directInsert({
        tableName: "promo_codes",
        object: {
          code: variables.code,
          discount_percent: variables.discount_percent,
          starts_at: variables.starts_at,
          ends_at: variables.ends_at,
          is_active: variables.is_active,
          usage_limit: variables.usage_limit ?? null,
          applicable_categories: Array.isArray(variables.applicable_categories)
            ? variables.applicable_categories
            : [],
          usage_count: 0,
        },
        returning: "id::bigint AS id",
      });
      return { insert_promo_codes_one: rows[0] || null };
    }
    case "TogglePromo": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_promo_codes_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "promo_codes",
        id,
        object: { is_active: toBool(variables.is_active) },
        returning: "id::bigint AS id",
      });
      return { update_promo_codes_by_pk: rows[0] || null };
    }
    case "DeletePromo": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "promo_codes",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_promo_codes_by_pk: rows[0] || null };
    }
    case "PromoCode": {
      const code = String(variables.code || "").trim();
      const rows = code
        ? await selectPromoCodesDirect({
            whereSql: "LOWER(code) = LOWER($1::text) AND COALESCE(is_active, TRUE) = TRUE",
            values: [code],
            limit: 1,
            orderBy: "created_at DESC, id DESC",
          })
        : [];
      return { promo_codes: rows };
    }
    case "IncreaseUsage": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_promo_codes_by_pk: null };
      const rows = await homePostgresQuery(
        `UPDATE public.promo_codes SET usage_count = COALESCE(usage_count, 0) + 1 WHERE id = $1::bigint RETURNING id::bigint AS id`,
        [id]
      );
      return { update_promo_codes_by_pk: rows[0] || null };
    }
    case "AdminAllReviews":
      return { product_reviews: await selectReviewsDirect({ orderBy: "created_at DESC, id DESC" }) };
    case "AdminProductReviews": {
      const productType = String(variables.product_type || "").trim();
      const productId = toPositiveIntOrNull(variables.product_id);
      const rows = productId
        ? await selectReviewsDirect({
            whereSql: "product_type = $1::text AND product_id = $2::bigint",
            values: [productType, productId],
            orderBy: "created_at DESC, id DESC",
          })
        : [];
      const stats = await homePostgresQuery(
        `
          SELECT
            COUNT(*)::int AS count,
            AVG(rating)::numeric AS avg_rating
          FROM public.product_reviews
          WHERE product_type = $1::text AND product_id = $2::bigint
        `,
        [productType, productId || 0]
      ).catch(() => [{ count: 0, avg_rating: null }]);
      return {
        product_reviews: rows,
        product_reviews_aggregate: {
          aggregate: {
            count: stats[0]?.count ?? 0,
            avg: { rating: stats[0]?.avg_rating ? Number(stats[0].avg_rating) : null },
          },
        },
      };
    }
    case "UpdateReviewStatus": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_product_reviews_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "product_reviews",
        id,
        object: { status: variables.status },
        returning: "id::bigint AS id",
      });
      return { update_product_reviews_by_pk: rows[0] || null };
    }
    case "DeleteReview": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "product_reviews",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_product_reviews_by_pk: rows[0] || null };
    }
    case "InsertReview": {
      const rows = await directInsert({
        tableName: "product_reviews",
        object: {
          product_type: variables.product_type,
          product_id: variables.product_id,
          user_id: variables.user_id,
          rating: variables.rating,
          comment: variables.comment,
          user_name: variables.user_name ?? null,
          user_email: variables.user_email ?? null,
          product_title: variables.product_title ?? null,
          status: variables.status ?? "pending",
        },
        returning: "id::bigint AS id",
      });
      return { insert_product_reviews_one: rows[0] || null };
    }
    case "ProductReviews": {
      const productType = String(variables.product_type || "").trim();
      const productId = toPositiveIntOrNull(variables.product_id);
      const rows = productId
        ? await selectReviewsDirect({
            whereSql: "product_type = $1::text AND product_id = $2::bigint AND status = 'published'",
            values: [productType, productId],
            orderBy: "created_at DESC, id DESC",
          })
        : [];
      const stats = await homePostgresQuery(
        `
          SELECT
            COUNT(*)::int AS count,
            AVG(rating)::numeric AS avg_rating
          FROM public.product_reviews
          WHERE product_type = $1::text AND product_id = $2::bigint AND status = 'published'
        `,
        [productType, productId || 0]
      ).catch(() => [{ count: 0, avg_rating: null }]);
      return {
        product_reviews: rows,
        product_reviews_aggregate: {
          aggregate: {
            count: stats[0]?.count ?? 0,
            avg: { rating: stats[0]?.avg_rating ? Number(stats[0].avg_rating) : null },
          },
        },
      };
    }
    case "AdminContactMessages":
    case "AdminContactMessagesFallback": {
      return {
        contact_messages: await selectContactMessagesDirect({
          orderBy: op === "AdminContactMessagesFallback" ? "cm.id DESC" : "cm.created_at DESC, cm.id DESC",
          includeUser: true,
        }),
      };
    }
    case "MyContactMessages": {
      const userId = extractJwtUserId(req?.jwt);
      if (!userId) {
        return { contact_messages: [] };
      }
      const currentUser = await getUserByIdForAuth(userId);
      const email = String(currentUser?.email || "").trim();
      return {
        contact_messages: await selectContactMessagesDirect({
          whereSql:
            "(cm.user_id = $1::bigint OR (cm.email IS NOT NULL AND LOWER(cm.email) = LOWER($2::text)))",
          values: [userId, email],
          orderBy: "cm.created_at DESC, cm.id DESC",
        }),
      };
    }
    case "AdminContactMessageUsers": {
      const ids = (variables.ids || []).map((value) => Number.parseInt(value, 10)).filter((v) => Number.isInteger(v) && v > 0);
      return {
        users: ids.length
          ? await selectUsersDirect({
              whereSql: "u.id = ANY($1::bigint[])",
              values: [ids],
              includeRole: true,
              orderBy: "u.id ASC",
            })
          : [],
      };
    }
    case "DeleteContactMessage": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "contact_messages",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_contact_messages_by_pk: rows[0] || null };
    }
    case "UpdateContactMessageReply": {
      const id = toPositiveIntOrNull(variables.id);
      const replyMessage = String(variables.reply_message || "").trim();
      if (!id) {
        return { update_contact_messages_by_pk: null };
      }
      if (!replyMessage) {
        throw new Error("Yanıt boş olamaz.");
      }
      const actor = req.hasuraAuthMode === "jwt" ? await ensureAdminJwtActor(req) : null;
      if (!actor) {
        throw new Error("Yetkisiz erişim.");
      }
      const rows = await directUpdateByPk({
        tableName: "contact_messages",
        id,
        object: {
          reply_message: replyMessage,
          reply_at: new Date().toISOString(),
          reply_admin_user_id: actor.id,
        },
        returning:
          "id::bigint AS id, reply_message, reply_at, reply_admin_user_id::bigint AS reply_admin_user_id",
      });
      return { update_contact_messages_by_pk: rows[0] || null };
    }
    case "AdminStats": {
      const today = new Date();
      const startOfDay = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
      const lastMonth = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const [booksCount, magazinesCount, newspapersCount, ordersCount, usersCount, ordersToday, ordersLastMonth] = await Promise.all([
        directCount({ tableName: "books" }),
        directCount({ tableName: "magazine" }),
        directCount({ tableName: "newspaper" }),
        directCount({ tableName: "orders" }),
        directCount({ tableName: "users" }),
        homePostgresQuery(`SELECT COUNT(*)::int AS count FROM public.orders WHERE created_at >= $1::timestamptz`, [startOfDay.toISOString()]).then((rows) => Number(rows[0]?.count || 0)).catch(() => 0),
        homePostgresQuery(`SELECT COUNT(*)::int AS count FROM public.orders WHERE created_at >= $1::timestamptz`, [lastMonth.toISOString()]).then((rows) => Number(rows[0]?.count || 0)).catch(() => 0),
      ]);
      return {
        books_aggregate: { aggregate: { count: booksCount } },
        magazine_aggregate: { aggregate: { count: magazinesCount } },
        newspaper_aggregate: { aggregate: { count: newspapersCount } },
        orders_aggregate: { aggregate: { count: ordersCount } },
        users_aggregate: { aggregate: { count: usersCount } },
        orders_today: { aggregate: { count: ordersToday } },
        orders_last_month: { aggregate: { count: ordersLastMonth } },
      };
    }
    case "AdminReport": {
      const type = String(variables.type || "").trim();
      const start = variables.start ? new Date(variables.start) : null;
      const end = variables.end ? new Date(variables.end) : null;
      const whereParts = ["product_type = $1::text"];
      const params = [type];
      if (start) {
        params.push(start.toISOString());
        whereParts.push(`created_at >= $${params.length}::timestamptz`);
      }
      if (end) {
        params.push(end.toISOString());
        whereParts.push(`created_at <= $${params.length}::timestamptz`);
      }
      const whereSql = whereParts.join(" AND ");
      const rows = await homePostgresQuery(
        `
          SELECT
            id::bigint AS id,
            title,
            quantity::int AS quantity,
            unit_price,
            line_total,
            created_at
          FROM public.order_items
          WHERE ${whereSql}
          ORDER BY line_total DESC NULLS LAST, id DESC
          LIMIT 100
        `,
        params
      );
      const agg = await homePostgresQuery(
        `
          SELECT
            COUNT(*)::int AS count,
            COALESCE(SUM(line_total), 0)::numeric AS revenue,
            COALESCE(AVG(unit_price), 0)::numeric AS avg_price
          FROM public.order_items
          WHERE ${whereSql}
        `,
        params
      );
      return {
        agg: {
          aggregate: {
            count: Number(agg[0]?.count || 0),
            sum: { line_total: Number(agg[0]?.revenue || 0) },
            avg: { unit_price: Number(agg[0]?.avg_price || 0) },
          },
        },
        items: rows,
      };
    }
    case "GetHomeShowcase": {
      const type = String(variables.type || "").trim();
      const isActive = query.includes("is_active: {_eq: true}");
      const rows = await selectHomeShowcaseDirect({
        whereSql: isActive
          ? "product_type = $1::text AND COALESCE(is_active, TRUE) = TRUE"
          : "product_type = $1::text",
        values: [type],
        orderBy: "sort_order ASC NULLS LAST, created_at DESC",
      });
      return { home_showcase: rows };
    }
    case "AddHomeShowcase": {
      const rows = await directInsert({
        tableName: "home_showcase",
        object: {
          product_type: variables.product_type,
          product_id: variables.product_id,
          sort_order: variables.sort_order,
          is_active: variables.is_active,
        },
        returning: "id::bigint AS id",
      });
      return { insert_home_showcase_one: rows[0] || null };
    }
    case "UpdateHomeShowcaseOrder": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_home_showcase_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "home_showcase",
        id,
        object: { sort_order: variables.sort_order },
        returning: "id::bigint AS id",
      });
      return { update_home_showcase_by_pk: rows[0] || null };
    }
    case "DeleteHomeShowcase": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "home_showcase",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_home_showcase_by_pk: rows[0] || null };
    }
    case "GetAddresses": {
      const userId = toPositiveIntOrNull(variables.user_id);
      return {
        user_addresses: userId
          ? await selectUserAddressesDirect({
              whereSql: "user_id = $1::bigint",
              values: [userId],
              orderBy: "created_at DESC, id DESC",
            })
          : [],
      };
    }
    case "GetAddressById": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        user_addresses_by_pk: id
          ? (await selectUserAddressesDirect({
              whereSql: "id = $1::bigint",
              values: [id],
              orderBy: "created_at DESC, id DESC",
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "InsertUserAddress": {
      const rows = await directInsert({
        tableName: "user_addresses",
        object: {
          user_id: variables.user_id,
          address_type: variables.address_type,
          address_name: variables.address_name,
          country: variables.country,
          city: variables.city,
          district: variables.district,
          full_address: variables.full_address,
          postal_code: variables.postal_code ?? null,
          tax_or_tc_no: variables.tax_or_tc_no ?? null,
          tax_address: variables.tax_address ?? null,
          company_name: variables.company_name ?? null,
        },
        returning: "id::int AS id",
      });
      return { insert_user_addresses_one: rows[0] || null };
    }
    case "UpdateUserAddress": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_user_addresses_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "user_addresses",
        id,
        object: {
          address_type: variables.address_type,
          address_name: variables.address_name,
          country: variables.country,
          city: variables.city,
          district: variables.district,
          full_address: variables.full_address,
          postal_code: variables.postal_code ?? null,
          tax_or_tc_no: variables.tax_or_tc_no ?? null,
          tax_address: variables.tax_address ?? null,
          company_name: variables.company_name ?? null,
        },
        returning: "id::int AS id",
      });
      return { update_user_addresses_by_pk: rows[0] || null };
    }
    case "DeleteAddress": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "user_addresses",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_user_addresses_by_pk: rows[0] || null };
    }
    case "GetOrders": {
      const userId = toPositiveIntOrNull(variables.user_id);
      return {
        orders: userId
          ? await getUserOrdersFromPostgres({ userId, includeItems: false })
          : [],
      };
    }
    case "GetOrderItems": {
      const orderIds = (variables.order_ids || [])
        .map((value) => Number.parseInt(value, 10))
        .filter((value) => Number.isInteger(value) && value > 0);
      if (!orderIds.length) return { order_items: [] };
      const rows = await homePostgresQuery(
        `
          SELECT
            id::bigint AS id,
            order_id::bigint AS order_id,
            product_id::bigint AS product_id,
            ek_id::bigint AS ek_id,
            title,
            quantity::int AS quantity,
            unit_price,
            line_total,
            product_type,
            metadata,
            created_at
          FROM public.order_items
          WHERE order_id = ANY($1::bigint[])
          ORDER BY id ASC
        `,
        [orderIds]
      );
      return { order_items: rows };
    }
    case "GetOrderDetail": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) {
        return { orders_by_pk: null, order_items: [] };
      }
      const userId = extractJwtUserId(req?.jwt);
      const isAdminRequest =
        req?.hasuraAuthMode === "service" ||
        hasAdminRoleInBearerToken(req?.jwtToken || "");
      const order = await getOrderDetailFromPostgres({
        userId: isAdminRequest ? null : userId,
        orderId: id,
      });
      if (!order) {
        return { orders_by_pk: null, order_items: [] };
      }
      const { order_items = [], ...orderRow } = order;
      return { orders_by_pk: orderRow, order_items };
    }
    case "GetAccess": {
      const userId = toPositiveIntOrNull(variables.user_id);
      const itemType = String(variables.item_type || "").trim();
      if (!userId || !itemType) return { user_content_access: [] };
      const entries = await selectUserContentAccessDirect({
        whereSql:
          "user_id = $1::bigint AND item_type = $2::public.access_item_type AND is_active = TRUE",
        values: [userId, itemType],
        orderBy: "started_at DESC NULLS LAST, expires_at DESC NULLS LAST, id DESC",
      });
      if (itemType === "newspaper_subscription") {
        entries.push(...await getManualNewspaperAccessRows({ userId }));
      }
      return { user_content_access: sortUserAccessEntries(entries) };
    }
    case "GetAccessAll": {
      const userId = toPositiveIntOrNull(variables.user_id);
      if (!userId) return { user_content_access: [] };
      return {
        user_content_access: await selectUserContentAccessDirect({
          whereSql: "user_id = $1::bigint AND is_active = TRUE",
          values: [userId],
          orderBy: "started_at DESC NULLS LAST, expires_at DESC NULLS LAST, id DESC",
          includeManual: true,
        }),
      };
    }
    case "GetLatestAccess": {
      const userId = toPositiveIntOrNull(variables.user_id);
      const itemType = String(variables.item_type || "").trim();
      const itemId = toPositiveIntOrNull(variables.item_id);
      if (!userId || !itemType) return { user_content_access: [] };
      const conditions = [
        "user_id = $1::bigint",
        "item_type = $2::public.access_item_type",
        "is_active = TRUE",
      ];
      const values = [userId, itemType];
      if (itemId == null) {
        conditions.push("item_id IS NULL");
      } else {
        values.push(itemId);
        conditions.push(`item_id = $${values.length}::bigint`);
      }
      const accessRows = await selectUserContentAccessDirect({
        whereSql: conditions.join(" AND "),
        values,
        orderBy: "expires_at DESC NULLS LAST, started_at DESC NULLS LAST, id DESC",
        limit: 1,
      });
      if (itemType !== "newspaper_subscription" || itemId != null) {
        return { user_content_access: accessRows };
      }
      const manualRows = await getManualNewspaperAccessRows({ userId });
      return { user_content_access: sortUserAccessEntries([...accessRows, ...manualRows]).slice(0, 1) };
    }
    case "GetLatestManualNewspaperAccess": {
      const userId = toPositiveIntOrNull(variables.user_id);
      if (!userId) return { manual_newspaper_users: [] };
      return {
        manual_newspaper_users: await homePostgresQuery(
          `
            SELECT
              id::bigint AS id,
              user_id::bigint AS user_id,
              starts_at,
              ends_at,
              is_active,
              COALESCE(status, 'new') AS status,
              note,
              created_at,
              updated_at
            FROM public.manual_newspaper_users
            WHERE user_id = $1::bigint AND is_active = TRUE
            ORDER BY ends_at DESC NULLS LAST, starts_at DESC NULLS LAST, id DESC
            LIMIT 1
          `,
          [userId]
        ),
      };
    }
    case "CreateOrder": {
      const merchantPaymentId = String(variables.merchant_payment_id || "").trim();
      const paymentSessionToken = String(variables.payment_session_token || "").trim();
      if (merchantPaymentId || paymentSessionToken) {
        const existingWhere = [];
        const existingValues = [];
        if (merchantPaymentId) {
          existingValues.push(merchantPaymentId);
          existingWhere.push(`merchant_payment_id = $${existingValues.length}::text`);
        }
        if (paymentSessionToken) {
          existingValues.push(paymentSessionToken);
          existingWhere.push(`payment_session_token = $${existingValues.length}::text`);
        }
        const existingRows = await homePostgresQuery(
          `
            SELECT
              id::int AS id,
              total_paid,
              created_at,
              promo_code,
              promo_discount_percent,
              promo_discount_amount,
              payment_provider
            FROM public.orders
            WHERE ${existingWhere.map((clause) => `(${clause})`).join(" OR ")}
            ORDER BY created_at DESC, id DESC
            LIMIT 1
          `,
          existingValues
        );
        if (existingRows.length) {
          console.log(
            `[orders][create][idempotent] reused orderId=${existingRows[0].id || "-"} merchantPaymentId=${merchantPaymentId || "-"} sessionToken=${paymentSessionToken || "-"}`
          );
          return { insert_orders_one: existingRows[0] };
        }
      }

      const rows = await homePostgresQuery(
        `
          INSERT INTO public.orders (
            user_id,
            delivery_address_id,
            billing_address_id,
            total_paid,
            status,
            promo_code_id,
            promo_code,
            promo_discount_percent,
            promo_discount_amount,
            payment_provider,
            merchant_payment_id,
            payment_session_token,
            payment_approved,
            payment_response_code,
            payment_response_msg,
            payment_error_code,
            payment_error_msg
          ) VALUES (
            $1::bigint,
            $2::bigint,
            $3::bigint,
            $4::numeric,
            $5::order_status,
            $6::bigint,
            $7::text,
            $8::numeric,
            $9::numeric,
            $10::text,
            $11::text,
            $12::text,
            $13::boolean,
            $14::text,
            $15::text,
            $16::text,
            $17::text
          )
          RETURNING
            id::int AS id,
            total_paid,
            created_at,
            promo_code,
            promo_discount_percent,
            promo_discount_amount,
            payment_provider
        `,
        [
          variables.user_id,
          variables.delivery_address_id,
          variables.billing_address_id,
          variables.total_paid,
          variables.status,
          variables.promo_code_id ?? null,
          variables.promo_code ?? null,
          variables.promo_discount_percent ?? null,
          variables.promo_discount_amount ?? null,
          variables.payment_provider ?? null,
          variables.merchant_payment_id ?? null,
          variables.payment_session_token ?? null,
          variables.payment_approved ?? null,
          variables.payment_response_code ?? null,
          variables.payment_response_msg ?? null,
          variables.payment_error_code ?? null,
          variables.payment_error_msg ?? null,
        ]
      );
      return { insert_orders_one: rows[0] || null };
    }
    case "InsertItems": {
      const items = Array.isArray(variables.items) ? variables.items : [];
      if (!items.length) return { insert_order_items: { affected_rows: 0 } };
      const normalizedItems = items.map((item) => ({
        order_id: item.order_id,
        product_id: item.product_id ?? null,
        ek_id: item.ek_id ?? null,
        title: item.title,
        quantity: item.quantity,
        unit_price: item.unit_price,
        line_total: item.line_total,
        product_type: item.product_type,
        metadata: item.metadata ?? null,
      }));
      const firstOrderId = toPositiveIntOrNull(normalizedItems[0]?.order_id);
      if (firstOrderId) {
        const existing = await homePostgresQuery(
          `
            SELECT id::bigint AS id
            FROM public.order_items
            WHERE order_id = $1::bigint
            LIMIT 1
          `,
          [firstOrderId]
        );
        if (existing.length) {
          console.log(
            `[order_items][insert][idempotent] skipped orderId=${firstOrderId} existingItems=true count=${normalizedItems.length}`
          );
          return { insert_order_items: { affected_rows: 0 } };
        }

        const orderRows = await homePostgresQuery(
          `
            SELECT
              id::bigint AS id,
              promo_code_id,
              promo_code
            FROM public.orders
            WHERE id = $1::bigint
            LIMIT 1
          `,
          [firstOrderId]
        );
        const orderRow = orderRows[0] || null;
        const promoCodeId = toPositiveIntOrNull(orderRow?.promo_code_id);
        const promoCodeText = String(orderRow?.promo_code || "").trim();
        if (promoCodeId || promoCodeText) {
          const promoRows = promoCodeId
            ? await homePostgresQuery(
                `
                  SELECT
                    id::bigint AS id,
                    code,
                    COALESCE(applicable_categories, ARRAY[]::text[]) AS applicable_categories
                  FROM public.promo_codes
                  WHERE id = $1::bigint
                  LIMIT 1
                `,
                [promoCodeId]
              )
            : await homePostgresQuery(
                `
                  SELECT
                    id::bigint AS id,
                    code,
                    COALESCE(applicable_categories, ARRAY[]::text[]) AS applicable_categories
                  FROM public.promo_codes
                  WHERE LOWER(code) = LOWER($1::text)
                  LIMIT 1
                `,
                [promoCodeText]
              );
          const promoRow = promoRows[0] || null;
          if (!promoRow) {
            await homePostgresQuery(
              `DELETE FROM public.orders WHERE id = $1::bigint`,
              [firstOrderId]
            ).catch(() => {});
            throw createPromoCodeError(
              "Promosyon kodu bulunamadı. Bu kod zaten kayıtlı değil.",
              "PROMO_CODE_NOT_FOUND",
            );
          }
          if (!promoScopeAppliesToItems(promoRow.applicable_categories, normalizedItems)) {
            await homePostgresQuery(
              `DELETE FROM public.orders WHERE id = $1::bigint`,
              [firstOrderId]
            ).catch(() => {});
            throw createPromoCodeError(
              "Promosyon kodu seçili ürünler için geçerli değil. Bu kod zaten kayıtlı ürün kategorisi için tanımlı.",
              "PROMO_CODE_NOT_APPLICABLE",
            );
          }
        }
      }
      for (const item of normalizedItems) {
        await directInsert({
          tableName: "order_items",
          object: item,
          returning: "id::bigint AS id",
        });
      }
      return { insert_order_items: { affected_rows: normalizedItems.length } };
    }
    case "InsertContact": {
      const rows = await homePostgresQuery(
        `
          INSERT INTO public.contact_messages (
            subject,
            message,
            user_id,
            email
          ) VALUES ($1::text, $2::text, $3::bigint, $4::text)
          RETURNING id::bigint AS id
        `,
        [
          variables.subject,
          variables.message,
          variables.user_id ?? null,
          variables.email ?? null,
        ]
      );
      return { insert_contact_messages_one: rows[0] || null };
    }
    case "UpdateOrderPayment": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_orders_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "orders",
        id,
        object: {
          status: variables.status,
          payment_approved: variables.payment_approved ?? null,
          payment_response_code: variables.payment_response_code ?? null,
          payment_response_msg: variables.payment_response_msg ?? null,
          payment_error_code: variables.payment_error_code ?? null,
          payment_error_msg: variables.payment_error_msg ?? null,
        },
        returning: "id::bigint AS id",
      });
      return { update_orders_by_pk: rows[0] || null };
    }
    case "GetAllOrders": {
      return {
        orders: await selectOrdersDirect({
          orderBy: "o.created_at DESC, o.id DESC",
          includeUser: true,
        }),
      };
    }
    case "InsertAccess": {
      const items = Array.isArray(variables.items) ? variables.items : [];
      if (!items.length) return { insert_user_content_access: { affected_rows: 0 } };
      let affectedRows = 0;
      for (const item of items) {
        await homePostgresQuery(
          `
            INSERT INTO public.user_content_access (
              user_id,
              item_id,
              item_type,
              started_at,
              expires_at,
              purchase_price,
              is_active,
              grant_source,
              purchase_platform
            ) VALUES (
              $1::bigint,
              $2::bigint,
              $3::access_item_type,
              $4::timestamptz,
              $5::timestamptz,
              $6::numeric,
              COALESCE($7::boolean, TRUE),
              $8::text,
              $9::text
            )
          `,
          [
            item.user_id,
            item.item_id ?? null,
            item.item_type,
            item.started_at ?? null,
            item.expires_at ?? null,
            item.purchase_price ?? null,
            item.is_active ?? true,
            item.grant_source ?? null,
            item.purchase_platform ?? null,
          ]
        );
        affectedRows += 1;
      }
      return { insert_user_content_access: { affected_rows: affectedRows } };
    }
    case "DeactivateExpiredAccess": {
      const userId = toPositiveIntOrNull(variables.user_id);
      const itemType = String(variables.item_type || "").trim();
      const itemId = toPositiveIntOrNull(variables.item_id);
      const now = variables.now || new Date().toISOString();
      if (!userId || !itemType) return { update_user_content_access: { affected_rows: 0 } };
      const clauses = [
        "user_id = $1::bigint",
        "item_type = $2::access_item_type",
        "is_active = TRUE",
        "expires_at <= $3::timestamptz",
      ];
      const values = [userId, itemType, now];
      if (itemId == null) {
        clauses.push("item_id IS NULL");
      } else {
        values.push(itemId);
        clauses.push(`item_id = $${values.length}::bigint`);
      }
      const rows = await homePostgresQuery(
        `UPDATE public.user_content_access SET is_active = FALSE WHERE ${clauses.join(" AND ")} RETURNING id`,
        values
      );
      return { update_user_content_access: { affected_rows: rows.length } };
    }
    case "DeactivateUserContentAccess": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_user_content_access: { affected_rows: 0 } };
      const rows = await homePostgresQuery(
        `
          UPDATE public.user_content_access
          SET is_active = FALSE
          WHERE id = $1::bigint
          RETURNING id
        `,
        [id]
      );
      return { update_user_content_access: { affected_rows: rows.length } };
    }
    case "DeleteUserContentAccess": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { delete_user_content_access: { affected_rows: 0 } };
      const rows = await homePostgresQuery(
        `DELETE FROM public.user_content_access WHERE id = $1::bigint RETURNING id`,
        [id]
      );
      return { delete_user_content_access: { affected_rows: rows.length } };
    }
    case "UpdateAccessExpiry": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_user_content_access_by_pk: null };
      const set = compactObject({
        expires_at: variables.expires_at,
        grant_source: variables.grant_source,
        purchase_platform: variables.purchase_platform,
      });
      if (!Object.keys(set).length) {
        const row = await homePostgresQuery(
          `
            SELECT
              id::bigint AS id,
              expires_at
            FROM public.user_content_access
            WHERE id = $1::bigint
            LIMIT 1
          `,
          [id]
        );
        return { update_user_content_access_by_pk: row[0] || null };
      }
      const rows = await homePostgresQuery(
        `
          UPDATE public.user_content_access
          SET ${Object.keys(set)
            .map((key, index) => `${quoteSqlIdentifier(key)} = $${index + 2}`)
            .join(", ")}
          WHERE id = $1::bigint
          RETURNING id::bigint AS id, expires_at
        `,
        [id, ...Object.values(set)]
      );
      return { update_user_content_access_by_pk: rows[0] || null };
    }
    case "UpdateManualNewspaperExpiry": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_manual_newspaper_users_by_pk: null };
      const rows = await homePostgresQuery(
        `
          UPDATE public.manual_newspaper_users
          SET ends_at = $2::timestamptz,
              updated_at = $3::timestamptz
          WHERE id = $1::bigint
          RETURNING id::bigint AS id, ends_at
        `,
        [id, variables.ends_at ?? null, variables.updated_at || new Date().toISOString()]
      );
      return { update_manual_newspaper_users_by_pk: rows[0] || null };
    }
    case "DeactivateManualNewspaperAccess": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_manual_newspaper_users: { affected_rows: 0 } };
      const rows = await homePostgresQuery(
        `
          UPDATE public.manual_newspaper_users
          SET is_active = FALSE
          WHERE id = $1::bigint
          RETURNING id
        `,
        [id]
      );
      return { update_manual_newspaper_users: { affected_rows: rows.length } };
    }
    case "DeleteManualNewspaperAccess": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { delete_manual_newspaper_users: { affected_rows: 0 } };
      const rows = await homePostgresQuery(
        `DELETE FROM public.manual_newspaper_users WHERE id = $1::bigint RETURNING id`,
        [id]
      );
      return { delete_manual_newspaper_users: { affected_rows: rows.length } };
    }
    case "GetUserNotifications": {
      const where = variables.where || {};
      const userId = toPositiveIntOrNull(where?.user_id?._eq);
      const isRead = where?.is_read?._eq;
      const clauses = [];
      const values = [];
      if (userId) {
        values.push(userId);
        clauses.push(`n.user_id = $${values.length}::bigint`);
      }
      if (isRead !== undefined) {
        values.push(isRead);
        clauses.push(`n.is_read = $${values.length}::boolean`);
      }
      return {
        notifications: await selectNotificationsDirect({
          whereSql: clauses.length ? clauses.join(" AND ") : "TRUE",
          values,
          orderBy: "n.created_at DESC, n.id DESC",
        }),
      };
    }
    case "GetNotificationDetail": {
      const id = toPositiveIntOrNull(variables.id);
      return {
        notifications_by_pk: id
          ? (await selectNotificationsDirect({
              whereSql: "n.id = $1::bigint",
              values: [id],
              orderBy: "n.created_at DESC, n.id DESC",
              limit: 1,
            }))[0] || null
          : null,
      };
    }
    case "GetAdminNotifications": {
      const where = variables.where || {};
      const limit = toPositiveIntOrNull(variables.limit) || 200;
      const clauses = [];
      const values = [];
      const andNodes = Array.isArray(where?._and) ? where._and : [];
      for (const node of andNodes) {
        if (node?.is_read?._eq !== undefined) {
          values.push(node.is_read._eq);
          clauses.push(`n.is_read = $${values.length}::boolean`);
        }
        const orNodes = Array.isArray(node?._or) ? node._or : [];
        const searchTerm = orNodes
          .map((entry) => entry?.title?._ilike || entry?.body?._ilike || "")
          .find((text) => text);
        if (searchTerm) {
          values.push(searchTerm);
          clauses.push(`(n.title ILIKE $${values.length} OR n.body ILIKE $${values.length})`);
        }
      }
      return {
        notifications: await selectNotificationsDirect({
          whereSql: clauses.length ? clauses.join(" AND ") : "TRUE",
          values,
          orderBy: "n.created_at DESC, n.id DESC",
          limit,
          includeUser: true,
        }),
      };
    }
    case "UpdateNotificationRead": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_notifications_by_pk: null };
      const rows = await directUpdateByPk({
        tableName: "notifications",
        id,
        object: { is_read: toBool(variables.is_read) },
        returning: "id::int AS id",
      });
      return { update_notifications_by_pk: rows[0] || null };
    }
    case "DeleteNotification": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "notifications",
            id,
            returning: "id::int AS id",
          })
        : [];
      return { delete_notifications_by_pk: rows[0] || null };
    }
    case "LogError": {
      const input = variables.input || {};
      const rows = await homePostgresQuery(
        `
          INSERT INTO public.app_error_logs (
            service,
            operation,
            message,
            stack_trace,
            payload
          ) VALUES ($1::text, $2::text, $3::text, $4::text, $5::jsonb)
          RETURNING id
        `,
        [
          input.service || "Client",
          input.operation || "logError",
          input.message || "Unknown error",
          input.stack_trace || null,
          input.payload ? JSON.stringify(input.payload) : null,
        ]
      );
      return { insert_app_error_logs_one: rows[0] || null };
    }
    case "GetUserAccess":
    case "GetUserAccessAll":
    case "GetExportAccess": {
      const userIds = op === "GetExportAccess" ? (variables.user_ids || []) : [variables.user_id];
      if (!Array.isArray(userIds) || !userIds.length) {
        return { user_content_access: [] };
      }
      const normalizedIds = userIds
        .map((value) => Number.parseInt(value, 10))
        .filter((value) => Number.isInteger(value) && value > 0);
      if (!normalizedIds.length) return { user_content_access: [] };
      const includeManual = true;
      const access = await selectUserContentAccessDirect({
        whereSql: op === "GetUserAccess"
          ? "user_id = $1::bigint AND is_active = TRUE"
          : op === "GetUserAccessAll"
            ? "user_id = $1::bigint"
            : "user_id = ANY($1::bigint[]) AND is_active = TRUE",
        values: op === "GetExportAccess" ? [normalizedIds] : [normalizedIds[0]],
        orderBy: "started_at DESC NULLS LAST, expires_at DESC NULLS LAST, id DESC",
        includeManual,
      });
      return { user_content_access: access };
    }
    case "GetManualNewspaperAccess": {
      const userId = toPositiveIntOrNull(variables.user_id);
      if (!userId) return { manual_newspaper_users: [] };
      const rows = await homePostgresQuery(
        `
          SELECT
            id::bigint AS id,
            user_id::bigint AS user_id,
            starts_at,
            ends_at,
            is_active,
            COALESCE(status, 'new') AS status,
            note,
            created_at,
            updated_at
          FROM public.manual_newspaper_users
          WHERE user_id = $1::bigint
          ORDER BY is_active DESC, ends_at ASC NULLS LAST, id DESC
        `,
        [userId]
      );
      return { manual_newspaper_users: rows };
    }
    case "GetManualNewspaperAccessForUsers": {
      const userIds = (variables.user_ids || [])
        .map((value) => Number.parseInt(value, 10))
        .filter((value) => Number.isInteger(value) && value > 0);
      if (!userIds.length) return { manual_newspaper_users: [] };
      const rows = await homePostgresQuery(
        `
          SELECT
            id::bigint AS id,
            user_id::bigint AS user_id,
            starts_at,
            ends_at,
            is_active,
            COALESCE(status, 'new') AS status,
            note,
            created_at,
            updated_at
          FROM public.manual_newspaper_users
          WHERE user_id = ANY($1::bigint[])
          ORDER BY user_id ASC, ends_at DESC NULLS LAST, id DESC
        `,
        [userIds]
      );
      return { manual_newspaper_users: rows };
    }
    case "ListManualNewspaperUsers": {
      const rows = await homePostgresQuery(
        `
          SELECT
            id::bigint AS id,
            user_id::bigint AS user_id,
            starts_at,
            ends_at,
            is_active,
            COALESCE(status, 'new') AS status,
            note,
            created_at,
            updated_at
          FROM public.manual_newspaper_users
          ORDER BY is_active DESC, ends_at ASC NULLS LAST, id DESC
        `
      );
      return { manual_newspaper_users: rows };
    }
    case "SearchManualUsers":
    case "SearchManualUsersFallback": {
      const limit = toPositiveIntOrNull(variables.limit) || 20;
      const keyword = String(variables.keyword || "").trim();
      const sql = keyword
        ? `
          SELECT
            id::bigint AS id,
            name,
            email
          FROM public.users
          WHERE name ILIKE $1::text OR email ILIKE $1::text
          ORDER BY id DESC
          LIMIT $2::int
        `
        : `
          SELECT
            id::bigint AS id,
            name,
            email
          FROM public.users
          ORDER BY id DESC
          LIMIT $1::int
        `;
      const rows = await homePostgresQuery(
        sql,
        keyword ? [keyword, limit] : [limit]
      );
      return { users: rows };
    }
    case "GetManualNewspaperUsersByIds": {
      const ids = (variables.ids || [])
        .map((value) => Number.parseInt(value, 10))
        .filter((value) => Number.isInteger(value) && value > 0);
      if (!ids.length) return { users: [] };
      return {
        users: await selectUsersDirect({
          whereSql: "u.id = ANY($1::bigint[])",
          values: [ids],
          includeRole: false,
          orderBy: "u.id ASC",
        }),
      };
    }
    case "UpsertManualNewspaperUser": {
      const object = variables.object || {};
      const rows = await homePostgresQuery(
        `
          INSERT INTO public.manual_newspaper_users (
            user_id,
            starts_at,
            ends_at,
            is_active,
            status,
            note,
            updated_at
          ) VALUES ($1::bigint, $2::timestamptz, $3::timestamptz, $4::boolean, $5::text, $6::text, $7::timestamptz)
          ON CONFLICT (user_id) DO UPDATE SET
            starts_at = EXCLUDED.starts_at,
            ends_at = EXCLUDED.ends_at,
            is_active = EXCLUDED.is_active,
            status = EXCLUDED.status,
            note = EXCLUDED.note,
            updated_at = EXCLUDED.updated_at
          RETURNING id::bigint AS id
        `,
        [
          object.user_id,
          object.starts_at,
          object.ends_at,
          object.is_active,
          object.status || "new",
          object.note ?? null,
          object.updated_at || new Date().toISOString(),
        ]
      );
      return { insert_manual_newspaper_users_one: rows[0] || null };
    }
    case "UpdateManualNewspaperUser": {
      const id = toPositiveIntOrNull(variables.id);
      if (!id) return { update_manual_newspaper_users_by_pk: null };
      const set = variables._set || {};
      const rows = await homePostgresQuery(
        `
          UPDATE public.manual_newspaper_users
          SET starts_at = COALESCE($2::timestamptz, starts_at),
              ends_at = COALESCE($3::timestamptz, ends_at),
              is_active = COALESCE($4::boolean, is_active),
              status = COALESCE($5::text, status),
              note = COALESCE($6::text, note),
              updated_at = COALESCE($7::timestamptz, NOW())
          WHERE id = $1::bigint
          RETURNING id::bigint AS id
        `,
        [
          id,
          set.starts_at || null,
          set.ends_at || null,
          set.is_active ?? null,
          set.status || null,
          set.note ?? null,
          set.updated_at || new Date().toISOString(),
        ]
      );
      return { update_manual_newspaper_users_by_pk: rows[0] || null };
    }
    case "DeleteManualNewspaperUser": {
      const id = toPositiveIntOrNull(variables.id);
      const rows = id
        ? await directDeleteByPk({
            tableName: "manual_newspaper_users",
            id,
            returning: "id::bigint AS id",
          })
        : [];
      return { delete_manual_newspaper_users_by_pk: rows[0] || null };
    }
    case "InsertUserAccessAuditLog": {
      const object = variables.object || {};
      const rows = await homePostgresQuery(
        `
          INSERT INTO public.user_access_audit_log (
            user_id,
            actor_user_id,
            action,
            item_type,
            item_id,
            item_title,
            access_source,
            previous_expires_at,
            new_expires_at,
            note
          ) VALUES ($1::bigint, $2::bigint, $3::text, $4::text, $5::bigint, $6::text, $7::text, $8::timestamptz, $9::timestamptz, $10::text)
          RETURNING id::bigint AS id
        `,
        [
          object.user_id,
          object.actor_user_id ?? null,
          object.action,
          object.item_type,
          object.item_id ?? null,
          object.item_title ?? null,
          object.access_source ?? null,
          object.previous_expires_at ?? null,
          object.new_expires_at ?? null,
          object.note ?? null,
        ]
      );
      return { insert_user_access_audit_log_one: rows[0] || null };
    }
    case "GetUserAccessAuditLog": {
      const userId = toPositiveIntOrNull(variables.user_id);
      const limit = toPositiveIntOrNull(variables.limit) || 20;
      return {
        user_access_audit_log: userId
          ? await selectUserAccessAuditLogsDirect({
              userId,
              limit,
              includeActors: true,
            })
          : [],
      };
    }
    case "GetAuditActors": {
      const ids = (variables.ids || [])
        .map((value) => Number.parseInt(value, 10))
        .filter((value) => Number.isInteger(value) && value > 0);
      return {
        users: ids.length
          ? await selectUsersDirect({
              whereSql: "u.id = ANY($1::bigint[])",
              values: [ids],
              includeRole: false,
              orderBy: "u.id ASC",
            })
          : [],
      };
    }
    default:
      break;
  }

  throw new Error(`Direct GraphQL operation not implemented: ${op}`);
};

const setUserPasswordHash = async (userId, passwordHash) => {
  await homePostgresQuery(
    `
      UPDATE public.users
      SET password = $2::text
      WHERE id = $1::bigint
    `,
    [userId, passwordHash]
  );
};

const isRegisterDuplicateConstraintError = (error) => {
  const message = String(error?.message || "").toLowerCase();
  if (!message.includes("duplicate key value violates unique constraint")) {
    return false;
  }
  return (
    message.includes("users_email_key") ||
    message.includes("users_phone_key") ||
    message.includes("users_email_active_unique_idx") ||
    message.includes("users_phone_active_unique_idx") ||
    message.includes("users_email_lower_unique_idx")
  );
};

app.use(
  ["/auth/register", "/auth/social-login"],
  authRateLimiter
);
app.use("/auth/login", loginRateLimiter);
app.use("/auth/social-register", authRateLimiter);
app.use("/auth/guest-token", guestTokenRateLimiter);
app.use("/auth/email-verification/request", passwordResetRequestRateLimiter);
app.use("/auth/email-verification/confirm", passwordResetConfirmRateLimiter);
app.use("/auth/password-reset/request", passwordResetRequestRateLimiter);
app.use("/auth/password-reset/confirm", passwordResetConfirmRateLimiter);
app.use(["/upload/public", "/upload/private", "/upload/delete"], uploadRateLimiter);

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
        .json({
          ok: false,
          error: "Ad, e-posta ve şifre zorunludur.",
        });
    }
    if (password.length < 8) {
      console.warn(
        `[auth][register][weak-password] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(400).json({
        ok: false,
        error: "Şifre en az 8 karakter olmalıdır.",
      });
    }

    const oldManualAccess = await getOldManualNewspaperAccessByEmail(email);
    if (oldManualAccess) {
      console.warn(
        `[auth][register][old-manual-newspaper] id=${requestId} ip=${req.ip} email=${email} userId=${oldManualAccess.user_id}`
      );
      return res.status(409).json({
        ok: false,
        code: "OLD_MANUAL_NEWSPAPER_ACCOUNT",
        redirectToPasswordReset: true,
          error:
          "Bu e-posta eski e-gazete aboneliğine ait. Lütfen şifrenizi sıfırlayın.",
      });
    }

    if (phone) {
      const existingPhone = await getUserByPhoneForAuth(phone);
      if (existingPhone?.id) {
        console.warn(
          `[auth][register][phone-exists] id=${requestId} ip=${req.ip} email=${email} phone=${phone} userId=${existingPhone.id}`
        );
        return res.status(409).json({
          ok: false,
          code: "USER_PHONE_ALREADY_EXISTS",
          error: "Bu telefon numarası zaten kayıtlı.",
        });
      }
    }

    const existing = await getUserByEmailForAuth(email);
    if (existing?.id && existing.email_verified_at) {
      console.warn(
        `[auth][register][exists] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res.status(409).json({
        ok: false,
        error: "Bu e-posta adresi zaten kayıtlı.",
      });
    }
    if (existing?.id && !existing.email_verified_at) {
      await sendEmailVerificationMail({ user: existing, req });
      console.log(
        `[auth][register][resent] id=${requestId} ip=${req.ip} email=${email} userId=${existing.id}`
      );
      return res.json({
        ok: true,
        requiresEmailVerification: true,
        email,
        message:
          "Üye kaydı başarılı. E-posta adresinize gönderilen bağlantı ile hesabınızı aktifleştirin.",
      });
    }

    const passwordHash = await hashPassword(password);
    const payUniqe = crypto.randomUUID();
    const createPayload = {
      name,
      email,
      phone,
      password: passwordHash,
      payUniqe,
    };

    const initialPurge = await purgeInactiveUsersForAuthIdentity({
      email,
      phone,
    });
    if (initialPurge.deletedUserIds.length > 0) {
      console.log(
        `[auth][register][purged-inactive] id=${requestId} ip=${req.ip} email=${email} deletedUserIds=${initialPurge.deletedUserIds.join(",")}`
      );
    }

    const createUser = async () => {
      const rows = await homePostgresQuery(
        `
          INSERT INTO public.users (
            name,
            email,
            phone,
            password,
            "payUniqe",
            is_active,
            email_verified_at
          ) VALUES (
            $1::text,
            $2::text,
            $3::text,
            $4::text,
            $5::text,
            TRUE,
            NOW()
          )
          RETURNING
            id::bigint AS id,
            name,
            email,
            phone,
            avatar_url,
            "payUniqe",
            role_id::bigint AS role_id
        `,
        [
          createPayload.name,
          createPayload.email,
          createPayload.phone,
          createPayload.password,
          createPayload.payUniqe,
        ]
      );
      return { insert_users_one: rows[0] || null };
    };

    try {
      const created = await createUser();
      const user = created?.insert_users_one;
      if (!user) {
        return res.status(500).json({ ok: false, error: "User creation failed." });
      }

      await sendEmailVerificationMail({ user, req });
      console.log(
        `[auth][register][success] id=${requestId} ip=${req.ip} email=${email} userId=${user.id}`
      );
      return res.json({
        ok: true,
        requiresEmailVerification: true,
        email,
        message:
          "Üye kaydı başarılı. E-posta adresinize gönderilen bağlantı ile hesabınızı aktifleştirin.",
      });
    } catch (createErr) {
      if (!isRegisterDuplicateConstraintError(createErr)) {
        throw createErr;
      }

      const purgedFallback = await purgeInactiveUsersForAuthIdentity({
        email,
        phone,
      });
      if (!purgedFallback.deletedUserIds.length) {
        throw createErr;
      }

      console.log(
        `[auth][register][purged-fallback] id=${requestId} ip=${req.ip} email=${email} deletedUserIds=${purgedFallback.deletedUserIds.join(",")}`
      );

      const created = await createUser();
      const user = created?.insert_users_one;
      if (!user) {
        return res.status(500).json({ ok: false, error: "User creation failed." });
      }

      await sendEmailVerificationMail({ user, req });
      console.log(
        `[auth][register][success-after-purge] id=${requestId} ip=${req.ip} email=${email} userId=${user.id}`
      );
      return res.json({
        ok: true,
        requiresEmailVerification: true,
        email,
        message:
          "Üye kaydı başarılı. E-posta adresinize gönderilen bağlantı ile hesabınızı aktifleştirin.",
      });
    }
  } catch (err) {
    console.error(
      `[auth][register][error] id=${requestId} ip=${req.ip} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: err.message || "Kayıt işlemi tamamlanamadı.",
    });
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
      return res
        .status(400)
        .json({ ok: false, error: "E-posta ve şifre zorunludur." });
    }

    const user = await getUserByEmailForAuth(email);
    if (!user || !user.password) {
      console.warn(
        `[auth][login][invalid] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res
        .status(401)
        .json({ ok: false, error: "E-posta veya şifre hatalı." });
    }

    const passwordCheck = await verifyPasswordHash(password, user.password);
    if (!passwordCheck.ok) {
      console.warn(
        `[auth][login][invalid] id=${requestId} ip=${req.ip} email=${email}`
      );
      return res
        .status(401)
        .json({ ok: false, error: "E-posta veya şifre hatalı." });
    }

    if (passwordCheck.needsUpgrade) {
      try {
        await setUserPasswordHash(user.id, await hashPassword(password));
        console.log(
          `[auth][login][password-upgrade] id=${requestId} ip=${req.ip} email=${email} userId=${user.id}`
        );
      } catch (upgradeErr) {
        console.warn(
          `[auth][login][password-upgrade-failed] id=${requestId} ip=${req.ip} email=${email} userId=${user.id} msg=${upgradeErr.message}`
        );
      }
    }

    if (!user.email_verified_at) {
      console.warn(
        `[auth][login][unverified] id=${requestId} ip=${req.ip} email=${email} userId=${user.id}`
      );
      return res.status(403).json({
        ok: false,
        code: "EMAIL_NOT_VERIFIED",
        error: "Önce e-posta adresinizi doğrulayın.",
      });
    }

    const sessionUser = (await issueUserAuthSession(user.id)) || user;
    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      avatar_url: user.avatar_url || null,
      payUniqe: user.payUniqe,
      role_id: user.role_id,
    };
    const { token, expiresAt } = buildJwtForAppUser(sessionUser);
    console.log(
      `[auth][login][success] id=${requestId} ip=${req.ip} email=${email} userId=${safeUser.id}`
    );
    return res.json({ ok: true, user: safeUser, token, expiresAt });
  } catch (err) {
    console.error(
      `[auth][login][error] id=${requestId} ip=${req.ip} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: err.message || "Giriş işlemi tamamlanamadı.",
    });
  }
});

app.post("/auth/social-login", async (req, res) => {
  const requestId = crypto.randomUUID();
  const emailForLog = normalizeEmail(req.body?.email);
  const provider = String(req.body?.provider || "").trim().toLowerCase();
  const phone = req.body?.phone ? String(req.body.phone).trim() : null;
  const requestedName = String(req.body?.name || "").trim();
  console.log(
    `[auth][social-login][start] id=${requestId} ip=${req.ip} provider=${provider || "-"} email=${emailForLog}`
  );

  try {
    const email = normalizeEmail(req.body?.email);
    const allowedProviders = new Set(["google", "apple"]);
    if (!email || !provider || !allowedProviders.has(provider)) {
      return res.status(400).json({
        ok: false,
        error: "E-posta ve sağlayıcı (google|apple) zorunludur.",
      });
    }

    let user = await getUserByEmailForAuth(email);
    if (!user) {
      const socialName = requestedName || email.split("@")[0] || "Kullanıcı";
      const inactiveExisting = await getInactiveUsersByIdentityForAuth({
        email,
        phone,
      });
      if (inactiveExisting.length > 0) {
        const purged = await purgeUsersByIdsFromPostgres(
          inactiveExisting.map((inactiveUser) => inactiveUser.id)
        );
        console.log(
          `[auth][social-login][purged-inactive] id=${requestId} provider=${provider} email=${email} deletedUserIds=${purged.deletedUserIds.join(",")}`
        );
      }

      const passwordHash = await hashPassword(
        crypto.randomBytes(24).toString("base64url")
      );
      const payUniqe = crypto.randomUUID();
      const verifiedAt = new Date().toISOString();
      const created = await homePostgresQuery(
        `
          INSERT INTO public.users (
            name,
            email,
            phone,
            password,
            "payUniqe",
            is_active,
            email_verified_at
          ) VALUES (
            $1::text,
            $2::text,
            $3::text,
            $4::text,
            $5::text,
            TRUE,
            $6::timestamptz
          )
          RETURNING
            id::bigint AS id,
            name,
            email,
            phone,
            avatar_url,
            "payUniqe",
            role_id::bigint AS role_id,
            email_verified_at
        `,
        [socialName, email, phone, passwordHash, payUniqe, verifiedAt]
      );
      user = created?.[0] || null;
      if (!user) {
        throw new Error("Social login user creation failed.");
      }
      console.log(
        `[auth][social-login][created-new] id=${requestId} provider=${provider} email=${email} userId=${user.id}`
      );
    }

    if (!user.email_verified_at) {
      user = await markUserEmailVerified(user.id, new Date().toISOString());
    }

    const sessionUser = (await issueUserAuthSession(user.id)) || user;
    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      avatar_url: user.avatar_url || null,
      payUniqe: user.payUniqe,
      role_id: user.role_id,
    };

    const { token, expiresAt } = buildJwtForAppUser(sessionUser);
    console.log(
      `[auth][social-login][success] id=${requestId} provider=${provider} email=${email} userId=${safeUser.id}`
    );
    return res.json({ ok: true, user: safeUser, token, expiresAt });
  } catch (err) {
    console.error(
      `[auth][social-login][error] id=${requestId} provider=${provider || "-"} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: err.message || "Sosyal giriş işlemi tamamlanamadı.",
    });
  }
});

app.post("/auth/social-register", async (req, res) => {
  const requestId = crypto.randomUUID();
  const emailForLog = normalizeEmail(req.body?.email);
  const provider = String(req.body?.provider || "").trim().toLowerCase();
  console.log(
    `[auth][social-register][start] id=${requestId} ip=${req.ip} provider=${provider || "-"} email=${emailForLog}`
  );

  try {
    const name = String(req.body?.name || "").trim();
    const email = normalizeEmail(req.body?.email);
    const phone = req.body?.phone ? String(req.body.phone).trim() : null;
    const allowedProviders = new Set(["google", "apple"]);

    if (!name || !email || !allowedProviders.has(provider)) {
      return res.status(400).json({
        ok: false,
        error: "Ad, e-posta ve sağlayıcı (google|apple) zorunludur.",
      });
    }

    const existing = await getUserByEmailForAuth(email);
    if (existing?.id) {
      return res.status(409).json({
        ok: false,
        error: "Bu e-posta adresi zaten kayıtlı.",
      });
    }

    const inactiveExisting = await getInactiveUsersByIdentityForAuth({
      email,
      phone,
    });
    if (inactiveExisting.length > 0) {
      const purged = await purgeUsersByIdsFromPostgres(
        inactiveExisting.map((user) => user.id)
      );
      console.log(
        `[auth][social-register][purged-inactive] id=${requestId} ip=${req.ip} provider=${provider} email=${email} deletedUserIds=${purged.deletedUserIds.join(",")}`
      );
    }

    const passwordHash = await hashPassword(
      crypto.randomBytes(24).toString("base64url")
    );
    const payUniqe = crypto.randomUUID();
    const verifiedAt = new Date().toISOString();
    const createSocialUser = async () => {
      const rows = await homePostgresQuery(
        `
          INSERT INTO public.users (
            name,
            email,
            phone,
            password,
            "payUniqe",
            is_active,
            email_verified_at
          ) VALUES (
            $1::text,
            $2::text,
            $3::text,
            $4::text,
            $5::text,
            TRUE,
            $6::timestamptz
          )
          RETURNING
            id::bigint AS id,
            name,
            email,
            phone,
            avatar_url,
            "payUniqe",
            role_id::bigint AS role_id,
            email_verified_at
        `,
        [name, email, phone, passwordHash, payUniqe, verifiedAt]
      );
      return { insert_users_one: rows[0] || null };
    };

    try {
      const created = await createSocialUser();
      const user = created?.insert_users_one;
      if (!user) {
        return res.status(500).json({ ok: false, error: "User creation failed." });
      }

      const sessionUser = (await issueUserAuthSession(user.id)) || user;
      const { token, expiresAt } = buildJwtForAppUser(sessionUser);
      console.log(
        `[auth][social-register][success] id=${requestId} ip=${req.ip} provider=${provider} email=${email} userId=${user.id}`
      );
      return res.json({ ok: true, user, token, expiresAt });
    } catch (createErr) {
      if (!isRegisterDuplicateConstraintError(createErr)) {
        throw createErr;
      }

      const purgedFallback = await purgeInactiveUsersForAuthIdentity({
        email,
        phone,
      });
      if (!purgedFallback.deletedUserIds.length) {
        throw createErr;
      }

      console.log(
        `[auth][social-register][purged-fallback] id=${requestId} ip=${req.ip} provider=${provider} email=${email} deletedUserIds=${purgedFallback.deletedUserIds.join(",")}`
      );

      const created = await createSocialUser();
      const user = created?.insert_users_one;
      if (!user) {
        return res.status(500).json({ ok: false, error: "User creation failed." });
      }

      const sessionUser = (await issueUserAuthSession(user.id)) || user;
      const { token, expiresAt } = buildJwtForAppUser(sessionUser);
      console.log(
        `[auth][social-register][success-after-purge] id=${requestId} ip=${req.ip} provider=${provider} email=${email} userId=${user.id}`
      );
      return res.json({ ok: true, user, token, expiresAt });
    }
  } catch (err) {
    console.error(
      `[auth][social-register][error] id=${requestId} ip=${req.ip} provider=${provider || "-"} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: err.message || "Sosyal kayıt işlemi tamamlanamadı.",
    });
  }
});

app.get("/auth/me", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const user = await getUserByIdForAuth(userId);
    if (!user || user.is_active === false) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }
    return res.json({ ok: true, user: toSafeUser(user), requestId });
  } catch (err) {
    console.error(`[auth][me][error] id=${requestId} userId=${userId} msg=${err.message}`);
    return res.status(500).json({ ok: false, error: "User fetch failed.", requestId });
  }
});

app.patch("/auth/me", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const name = String(req.body?.name || "").trim();
    const phoneRaw = req.body?.phone;
    const phone =
      phoneRaw === undefined || phoneRaw === null || String(phoneRaw).trim() === ""
        ? null
        : String(phoneRaw).trim();

    if (!name) {
      return res.status(400).json({ ok: false, error: "name is required." });
    }

    const updated = await updateUserProfileFields({ userId, name, phone });
    if (!updated) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    return res.json({ ok: true, user: toSafeUser(updated), requestId });
  } catch (err) {
    console.error(
      `[auth][me][update][error] id=${requestId} userId=${userId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Profile update failed.",
      requestId,
    });
  }
});

app.put("/auth/me/avatar", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const avatarUrl = normalizeAvatarUrl(req.body?.avatarUrl || req.body?.avatar_url);
    if (!avatarUrl) {
      return res.status(400).json({
        ok: false,
        error: "avatarUrl must be a valid /profil/public URL.",
      });
    }

    const currentUser = await findUserById(userId);
    if (!currentUser) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }
    const previousAvatarUrl = normalizeAvatarUrl(currentUser.avatar_url);
    const updated = await updateUserAvatarUrl({ userId, avatarUrl });
    if (!updated) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    if (previousAvatarUrl && previousAvatarUrl !== avatarUrl) {
      await cleanupManagedBunnyFile(previousAvatarUrl, {
        logPrefix: `[auth][me][avatar][cleanup] id=${requestId} userId=${userId}`,
      });
    }

    return res.json({ ok: true, user: toSafeUser(updated), requestId });
  } catch (err) {
    console.error(
      `[auth][me][avatar][error] id=${requestId} userId=${userId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Avatar update failed.",
      requestId,
    });
  }
});

app.delete("/auth/me/avatar", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const currentUser = await findUserById(userId);
    if (!currentUser) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }
    const previousAvatarUrl = normalizeAvatarUrl(currentUser.avatar_url);
    const updated = await updateUserAvatarUrl({ userId, avatarUrl: null });
    if (!updated) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    if (previousAvatarUrl) {
      await cleanupManagedBunnyFile(previousAvatarUrl, {
        logPrefix: `[auth][me][avatar-delete][cleanup] id=${requestId} userId=${userId}`,
      });
    }

    return res.json({ ok: true, user: toSafeUser(updated), requestId });
  } catch (err) {
    console.error(
      `[auth][me][avatar-delete][error] id=${requestId} userId=${userId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Avatar remove failed.",
      requestId,
    });
  }
});

app.post("/auth/me/password", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const currentPassword = String(req.body?.currentPassword || "");
    const newPassword = String(req.body?.newPassword || "");

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        ok: false,
        error: "currentPassword and newPassword are required.",
        code: "INVALID_PASSWORD_INPUT",
      });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({
        ok: false,
        error: "Yeni şifre en az 6 karakter olmalı.",
        code: "WEAK_PASSWORD",
      });
    }

    const currentUser = await getUserByIdForPasswordChange(userId);
    if (!currentUser || currentUser.is_active === false) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    const passwordCheck = await verifyPasswordHash(
      currentPassword,
      currentUser.password
    );
    if (!passwordCheck.ok) {
      return res.status(401).json({
        ok: false,
        code: "INVALID_CURRENT_PASSWORD",
        error: "Mevcut şifre hatalı.",
      });
    }

    const newPasswordHash = await hashPassword(newPassword);
    await setUserPasswordHash(currentUser.id, newPasswordHash);
    const sessionUser = (await issueUserAuthSession(currentUser.id)) || currentUser;
    const { token, expiresAt } = buildJwtForAppUser(sessionUser);

    return res.json({
      ok: true,
      user: toSafeUser(sessionUser),
      token,
      expiresAt,
      requestId,
    });
  } catch (err) {
    console.error(
      `[auth][me][password][error] id=${requestId} userId=${userId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Password change failed.",
      requestId,
    });
  }
});

app.get("/auth/me/access", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  const rawItemType = req.query?.itemType;
  const itemType =
    rawItemType === undefined ? null : normalizeUserAccessItemType(rawItemType);

  if (rawItemType !== undefined && !itemType) {
    return res.status(400).json({
      ok: false,
      error: "Invalid itemType.",
      requestId,
    });
  }

  try {
    const data = await getUserAccessEntriesFromPostgres({ userId, itemType });
    return res.json({ ok: true, data, requestId });
  } catch (err) {
    console.error(
      `[auth][me][access][error] id=${requestId} userId=${userId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Access records fetch failed.",
      requestId,
    });
  }
});

app.get("/auth/me/orders", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const includeItems = toBool(req.query?.includeItems);
    const data = await getUserOrdersFromPostgres({ userId, includeItems });
    return res.json({ ok: true, data, requestId });
  } catch (err) {
    console.error(
      `[auth][me][orders][error] id=${requestId} userId=${userId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Orders fetch failed.",
      requestId,
    });
  }
});

app.get("/auth/me/orders/:id", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  const orderId = toPositiveIntOrNull(req.params?.id);
  if (!orderId) {
    return res.status(400).json({
      ok: false,
      error: "Invalid order id.",
      requestId,
    });
  }

  try {
    const order = await getUserOrderDetailFromPostgres({ userId, orderId });
    if (!order) {
      return res.status(404).json({
        ok: false,
        error: "Order not found.",
        requestId,
      });
    }
    return res.json({ ok: true, order, requestId });
  } catch (err) {
    console.error(
      `[auth][me][order-detail][error] id=${requestId} userId=${userId} orderId=${orderId} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Order detail fetch failed.",
      requestId,
    });
  }
});

app.post("/auth/email-verification/request", async (req, res) => {
  const requestId = crypto.randomUUID();
  const emailForLog = normalizeEmail(req.body?.email);
  console.log(
    `[auth][email-verification][request][start] id=${requestId} ip=${req.ip} email=${emailForLog}`
  );

  try {
    const email = normalizeEmail(req.body?.email);
    const isValidEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
    if (!email || !isValidEmail) {
      return res.json(EMAIL_VERIFICATION_GENERIC_RESPONSE);
    }

    const user = await getActiveUserByEmail(email);
    if (!user || user.email_verified_at) {
      return res.json(EMAIL_VERIFICATION_GENERIC_RESPONSE);
    }

    const info = await sendEmailVerificationMail({ user, req });
    console.log(
      `[auth][email-verification][request][success] id=${requestId} ip=${req.ip} email=${email} userId=${user.id} messageId=${info?.messageId || "-"}`
    );
    return res.json(EMAIL_VERIFICATION_GENERIC_RESPONSE);
  } catch (err) {
    console.error(
      `[auth][email-verification][request][error] id=${requestId} ip=${req.ip} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Email verification request failed.",
    });
  }
});

app.post("/auth/email-verification/confirm", async (req, res) => {
  const requestId = crypto.randomUUID();
  console.log(
    `[auth][email-verification][confirm][start] id=${requestId} ip=${req.ip}`
  );

  try {
    const token = String(req.body?.token || "").trim();
    if (!token) {
      return res.status(400).json({
        ok: false,
        error: "token is required.",
      });
    }

    const tokenHash = hashPasswordResetToken(token);
    const tokenState = await getEmailVerificationTokenStateByHash(tokenHash);
    if (!tokenState) {
      return res.status(400).json({
        ok: false,
        error: "Verification token is invalid or already used.",
      });
    }
    if (tokenState.used_at) {
      return res.status(400).json({
        ok: false,
        error: "Verification token is invalid or already used.",
      });
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const expiresAtMs = Date.parse(tokenState.expires_at);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now.getTime()) {
      await markEmailVerificationTokenUsed(tokenState.id, nowIso);
      return res.status(410).json({
        ok: false,
        error: "Verification token has expired.",
      });
    }

    const user = await markUserEmailVerified(tokenState.user_id, nowIso);
    await invalidateEmailVerificationTokensForUser(tokenState.user_id, nowIso);

    try {
      await sendWelcomeMailOnce(tokenState.user_id);
    } catch (mailErr) {
      console.warn(
        `[auth][email-verification][confirm][welcome-mail-failed] id=${requestId} userId=${tokenState.user_id} msg=${mailErr.message}`
      );
    }

    console.log(
      `[auth][email-verification][confirm][success] id=${requestId} ip=${req.ip} userId=${tokenState.user_id}`
    );
    return res.json({
      ok: true,
      user,
      message: "E-posta adresiniz doğrulandı.",
    });
  } catch (err) {
    console.error(
      `[auth][email-verification][confirm][error] id=${requestId} ip=${req.ip} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Email verification failed.",
    });
  }
});

app.post("/auth/password-reset/request", async (req, res) => {
  const requestId = crypto.randomUUID();
  const emailForLog = normalizeEmail(req.body?.email);
  console.log(
    `[auth][password-reset][request][start] id=${requestId} ip=${req.ip} email=${emailForLog}`
  );

  try {
    const email = normalizeEmail(req.body?.email);
    const isValidEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);

    if (!email || !isValidEmail) {
      console.log(
        `[auth][password-reset][request][ignored] id=${requestId} ip=${req.ip} email=${emailForLog || "-"} reason=invalid-email`
      );
      return res.json(PASSWORD_RESET_GENERIC_RESPONSE);
    }

    const user = await getActiveUserByEmail(email);
    if (!user) {
      console.log(
        `[auth][password-reset][request][ignored] id=${requestId} ip=${req.ip} email=${email} reason=user-not-found`
      );
      return res.json(PASSWORD_RESET_GENERIC_RESPONSE);
    }

    const rawToken = createPasswordResetToken();
    const tokenHash = hashPasswordResetToken(rawToken);
    const nowIso = new Date().toISOString();
    const expiresAt = new Date(
      Date.now() + PASSWORD_RESET_TOKEN_TTL_MINUTES * 60 * 1000
    ).toISOString();

    await invalidatePasswordResetTokensForUser(user.id, nowIso);
    await createPasswordResetTokenRecord({
      userId: user.id,
      tokenHash,
      expiresAt,
      requestedIp: req.ip,
      userAgent: String(req.get("user-agent") || "").slice(0, 512),
    });

    const resetLink = buildPasswordResetLink({ token: rawToken, email: user.email });
    const safeName = String(user.name || "").trim() || user.email.split("@")[0];
    const text = `Merhaba ${safeName}, sifrenizi sifirlamak icin bu baglantiyi kullanin: ${resetLink}`;
    const html = buildPasswordResetMailHtml({
      name: safeName,
      resetLink,
      expiresInMinutes: PASSWORD_RESET_TOKEN_TTL_MINUTES,
    });

    const info = await mailTransporter.sendMail({
      from: MAIL_SETTINGS.from,
      to: user.email,
      subject: "Sifre sifirlama talebiniz",
      text,
      html,
    });

    console.log(
      `[auth][password-reset][request][success] id=${requestId} ip=${req.ip} email=${email} userId=${user.id} messageId=${info?.messageId || "-"}`
    );
    return res.json(PASSWORD_RESET_GENERIC_RESPONSE);
  } catch (err) {
    console.error(
      `[auth][password-reset][request][error] id=${requestId} ip=${req.ip} email=${emailForLog} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Password reset request failed.",
    });
  }
});

app.post("/auth/password-reset/confirm", async (req, res) => {
  const requestId = crypto.randomUUID();
  console.log(`[auth][password-reset][confirm][start] id=${requestId} ip=${req.ip}`);

  try {
    const token = String(req.body?.token || "").trim();
    const password = String(req.body?.password || "");
    if (!token || !password) {
      return res.status(400).json({
        ok: false,
        error: "Token ve şifre zorunludur.",
      });
    }
    if (password.length < 8) {
      return res.status(400).json({
        ok: false,
        error: "Şifre en az 8 karakter olmalıdır.",
      });
    }

    const tokenHash = hashPasswordResetToken(token);
    const tokenState = await getPasswordResetTokenStateByHash(tokenHash);
    if (!tokenState) {
      console.warn(
        `[auth][password-reset][confirm][invalid] id=${requestId} ip=${req.ip} reason=token-not-found`
      );
      return res.status(400).json({
        ok: false,
        error: "Reset token is invalid or already used.",
      });
    }
    if (tokenState.used_at) {
      console.warn(
        `[auth][password-reset][confirm][invalid] id=${requestId} ip=${req.ip} reason=token-used tokenId=${tokenState.id}`
      );
      return res.status(400).json({
        ok: false,
        error: "Reset token is invalid or already used.",
      });
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const expiresAtMs = Date.parse(tokenState.expires_at);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now.getTime()) {
      await markPasswordResetTokenUsed(tokenState.id, nowIso);
      console.warn(
        `[auth][password-reset][confirm][expired] id=${requestId} ip=${req.ip} tokenId=${tokenState.id}`
      );
      return res.status(410).json({
        ok: false,
        error: "Reset token has expired.",
      });
    }

    const passwordHash = await hashPassword(password);
    await setUserPasswordHash(tokenState.user_id, passwordHash);
    await invalidatePasswordResetTokensForUser(tokenState.user_id, nowIso);

    console.log(
      `[auth][password-reset][confirm][success] id=${requestId} ip=${req.ip} userId=${tokenState.user_id}`
    );
    return res.json({
      ok: true,
      message: "Password updated successfully.",
    });
  } catch (err) {
    console.error(
      `[auth][password-reset][confirm][error] id=${requestId} ip=${req.ip} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Password reset failed.",
    });
  }
});

app.post("/auth/guest-token", (req, res) => {
  const guestUser = {
    id: "guest",
    name: "Guest",
    email: null,
  };
  const { token, expiresAt } = buildJwt(guestUser, {
    defaultRole: GUEST_JWT_ROLE,
    allowedRoles: GUEST_JWT_ALLOWED_ROLES,
    expiresIn: GUEST_JWT_EXPIRES_IN,
  });
  return res.json({
    ok: true,
    user: { id: guestUser.id, name: guestUser.name },
    token,
    expiresAt,
  });
});

app.post("/newspaper/view-url", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  const rawDate = String(req.body?.date || req.body?.publishDate || "").trim();
  const preferLocal = req.body?.preferLocal === true || req.body?.localOnly === true;
  console.log(
    `[newspaper][view-url][start] id=${requestId} ip=${req.ip} userId=${userId || "-"} date=${rawDate || "-"} preferLocal=${preferLocal}`
  );

  try {
    if (!userId) {
      return res.status(401).json({ ok: false, error: "Invalid token user." });
    }

    const targetDate = parseIsoDateOnly(rawDate);
    if (!targetDate) {
      return res.status(400).json({
        ok: false,
        error: "date must be in YYYY-MM-DD format.",
      });
    }

    const access = await getActiveNewspaperSubscriptionAccess(userId);
    if (!access) {
      console.warn(
        `[newspaper][view-url][forbidden] id=${requestId} ip=${req.ip} userId=${userId} date=${rawDate}`
      );
      return res.status(403).json({
        ok: false,
        error: "Active newspaper subscription required.",
      });
    }

    const isoDate = formatIsoDateOnly(targetDate);
    const newspaper = await getNewspaperByPublishDate(isoDate);
    const storedUrl = String(newspaper?.file_url || "").trim();
    if (!storedUrl && preferLocal) {
      console.warn(
        `[newspaper][view-url][local-miss] id=${requestId} ip=${req.ip} userId=${userId} date=${isoDate}`
      );
      return res.status(404).json({
        ok: false,
        code: "LOCAL_NEWSPAPER_NOT_FOUND",
        error: "Selected date is not available in local newspaper storage.",
      });
    }
    const source = storedUrl ? "system" : "legacy";
    const url = storedUrl || buildLegacyNewspaperProxyUrl(isoDate);
    const isPrivate = storedUrl ? isPrivateStorageUrl(storedUrl) : false;
    console.log(
      `[newspaper][view-url][success] id=${requestId} ip=${req.ip} userId=${userId} date=${isoDate} source=${source}`
    );
    return res.json({
      ok: true,
      date: isoDate,
      url,
      isPrivate,
      source,
    });
  } catch (err) {
    const statusCode =
      Number.isFinite(err?.statusCode) && err.statusCode >= 400
        ? err.statusCode
        : 500;
    console.error(
      `[newspaper][view-url][error] id=${requestId} ip=${req.ip} userId=${userId || "-"} date=${rawDate || "-"} msg=${err.message}`
    );
    return res.status(statusCode).json({
      ok: false,
      error: err.message || "Newspaper view failed.",
    });
  }
});

app.get("/newspaper/legacy-file", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  const rawDate = String(req.query?.date || "").trim();
  console.log(
    `[newspaper][legacy-file][start] id=${requestId} ip=${req.ip} userId=${userId || "-"} date=${rawDate || "-"}`
  );

  try {
    if (!userId) {
      return res.status(401).json({ ok: false, error: "Invalid token user." });
    }

    const targetDate = parseIsoDateOnly(rawDate);
    if (!targetDate) {
      return res.status(400).json({
        ok: false,
        error: "date must be in YYYY-MM-DD format.",
      });
    }

    const access = await getActiveNewspaperSubscriptionAccess(userId);
    if (!access) {
      return res.status(403).json({
        ok: false,
        error: "Active newspaper subscription required.",
      });
    }

    const legacyUrl = buildLegacyNewspaperUrl(targetDate);
    const upstream = await axios.get(legacyUrl, {
      responseType: "arraybuffer",
      timeout: 20000,
      validateStatus: () => true,
      headers: {
        Accept: "application/pdf,*/*",
        "User-Agent": "Mozilla/5.0",
        Referer: "https://www.yeniasya.com.tr/",
      },
    });

    const contentType = String(upstream.headers?.["content-type"] || "").toLowerCase();
    const body = Buffer.from(upstream.data || []);
    if (upstream.status !== 200 || !contentType.includes("application/pdf") || body.length === 0) {
      const statusCode = upstream.status === 404 ? 404 : 502;
      console.warn(
        `[newspaper][legacy-file][upstream] id=${requestId} status=${upstream.status} type=${contentType || "-"} bytes=${body.length}`
      );
      return res.status(statusCode).json({
        ok: false,
        error: "Legacy newspaper PDF unavailable.",
      });
    }

    const isoDate = formatIsoDateOnly(targetDate);
    res.set({
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename="${isoDate}.pdf"`,
      "Cache-Control": "private, max-age=300",
    });
    console.log(
      `[newspaper][legacy-file][success] id=${requestId} ip=${req.ip} userId=${userId} date=${isoDate} bytes=${body.length}`
    );
    return res.status(200).send(body);
  } catch (err) {
    console.error(
      `[newspaper][legacy-file][error] id=${requestId} ip=${req.ip} userId=${userId || "-"} date=${rawDate || "-"} msg=${err.message}`
    );
    return res.status(500).json({
      ok: false,
      error: "Legacy newspaper PDF unavailable.",
    });
  }
});

app.post("/graphql", optionalJwt, proxyHasuraRequest);
app.post("/hasura", requireJwt, proxyHasuraRequest);
app.post("/internal/hasura", requireJwtOrServiceAuth, proxyHasuraRequest);

const findUserById = async (userId) => {
  const normalizedUserId = toPositiveIntOrNull(userId);
  if (!normalizedUserId) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        phone,
        avatar_url,
        role_id::bigint AS role_id,
        "payUniqe"
      FROM public.users
      WHERE id = $1::bigint
      LIMIT 1
    `,
    [normalizedUserId]
  );
  return rows[0] || null;
};

const ensureAdminJwtActor = async (req) => {
  const jwtPayload = req?.jwt;
  const jwtUserId = extractJwtUserId(jwtPayload);
  if (!jwtUserId) {
    const err = new Error("Missing user id in JWT.");
    err.statusCode = 401;
    throw err;
  }

  const actor = await findUserById(jwtUserId);
  if (!actor) {
    const err = new Error("Authenticated user not found.");
    err.statusCode = 401;
    throw err;
  }

  const roleId = toPositiveIntOrNull(actor.role_id);
  if (!roleId || !ADMIN_ROLE_IDS.includes(roleId)) {
    const err = new Error("Admin privileges required.");
    err.statusCode = 403;
    throw err;
  }

  return actor;
};

const ensureNotificationAdminActor = async (req) => {
  if (req?.hasuraAuthMode === "service") {
    return { mode: "service", actor: null };
  }

  const actor = await ensureAdminJwtActor(req);
  return { mode: "jwt", actor };
};

const findUserByPayUniqe = async (payUniqe) => {
  const normalizedValue = normalizeRevenueCatAppUserId(payUniqe);
  if (!normalizedValue) return null;

  const rows = await homePostgresQuery(
    `
      SELECT
        id::bigint AS id,
        name,
        email,
        phone,
        role_id,
        "payUniqe"
      FROM public.users
      WHERE "payUniqe"::text = $1::text
      LIMIT 2
    `,
    [normalizedValue]
  );

  if (rows.length > 1) {
    const err = new Error("payUniqe is not unique in users table.");
    err.statusCode = 409;
    throw err;
  }

  return rows[0] || null;
};

const setUserPayUniqe = async (userId, payUniqe) => {
  const normalizedValue = normalizeRevenueCatAppUserId(payUniqe);
  if (!normalizedValue) {
    return null;
  }
  const rows = await homePostgresQuery(
    `
      UPDATE public.users
      SET "payUniqe" = $2::text
      WHERE id = $1::bigint
      RETURNING
        id::bigint AS id,
        "payUniqe"
    `,
    [userId, normalizedValue]
  );
  return rows[0] || null;
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
  const resolvedAppUserId = normalizedAppUserId || currentPayUniqe || String(user.id);
  if (normalizedAppUserId && currentPayUniqe && normalizedAppUserId !== currentPayUniqe) {
    if (!allowPayUniqeRelink) {
      const err = new Error("appUserId does not match user's payUniqe.");
      err.statusCode = 409;
      throw err;
    }
  }

  return {
    userId: Number(user.id),
    appUserId: resolvedAppUserId,
    user,
  };
};

const getRevenueCatLockFallbackAppUserId = async (
  userId,
  entitlementId = REVENUECAT_DEFAULT_ENTITLEMENT_ID
) => {
  const normalizedUserId = toPositiveIntOrNull(userId);
  const normalizedEntitlementId = normalizeRevenueCatAppUserId(entitlementId);
  if (!normalizedUserId || !normalizedEntitlementId) {
    return null;
  }

  const rows = await homePostgresQuery(
    `
      SELECT
        owner_app_user_id,
        owner_original_app_user_id,
        is_active,
        expires_at
      FROM public.revenuecat_subscription_locks
      WHERE owner_user_id = $1::bigint
        AND entitlement_id = $2::text
      ORDER BY
        last_seen_at DESC NULLS LAST,
        updated_at DESC NULLS LAST,
        locked_at DESC NULLS LAST,
        is_active DESC,
        id DESC
      LIMIT 10
    `,
    [normalizedUserId, normalizedEntitlementId]
  );

  const currentUserId = normalizedUserId.toString();
  for (const lock of rows || []) {
    const candidates = [
      normalizeRevenueCatAppUserId(lock.owner_original_app_user_id),
      normalizeRevenueCatAppUserId(lock.owner_app_user_id),
    ];
    for (const candidate of candidates) {
      if (candidate && candidate !== currentUserId) {
        return candidate;
      }
    }
  }

  return null;
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

const purchasePlatformFromRevenueCatStore = (store) => {
  const normalized = String(store || "").trim().toLowerCase();
  switch (normalized) {
    case "appstore":
    case "macappstore":
      return "apple";
    case "playstore":
      return "google_play";
    default:
      return null;
  }
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
    const transientStatus = [429, 500, 502, 503, 504].includes(response.status);
    return {
      checked: false,
      source: "revenuecat",
      reason: transientStatus
        ? `subscriber_lookup_failed_${response.status}`
        : "subscriber_lookup_failed",
      statusCode: response.status,
      isActive: false,
      expirationDate: null,
    };
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
  const purchasePlatform = purchasePlatformFromRevenueCatStore(
    entitlement.store || entitlement.store_name || entitlement.storeName
  );
  const productIdentifier =
    entitlement.product_identifier ||
    entitlement.productIdentifier ||
    entitlement.product_id ||
    null;

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
    purchasePlatform,
    productIdentifier,
    store: entitlement.store || entitlement.store_name || entitlement.storeName || null,
  };
};

const ensureRevenueCatSubscriber = async ({
  appUserId,
  platform = REVENUECAT_WEB_CHECKOUT_PLATFORM,
}) => {
  const normalizedAppUserId = normalizeRevenueCatAppUserId(appUserId);
  if (!normalizedAppUserId) {
    const err = new Error("appUserId is required.");
    err.statusCode = 400;
    throw err;
  }
  if (!REVENUECAT_SECRET_API_KEY) {
    const err = new Error("RevenueCat secret key is not configured.");
    err.statusCode = 503;
    throw err;
  }

  const response = await axios.get(
    `${REVENUECAT_API_BASE_URL}/subscribers/${encodeURIComponent(normalizedAppUserId)}`,
    {
      headers: {
        Authorization: `Bearer ${REVENUECAT_SECRET_API_KEY}`,
        ...(platform ? { "X-Platform": String(platform).trim() } : {}),
      },
      timeout: REVENUECAT_HTTP_TIMEOUT_MS,
      validateStatus: () => true,
    }
  );

  if (response.status === 404) return false;
  if (response.status < 200 || response.status >= 300) {
    const err = new Error(
      `RevenueCat subscriber ensure failed (${response.status}).`
    );
    err.statusCode = 502;
    throw err;
  }

  return true;
};

const resolveRevenueCatGrantDuration = ({
  expirationDate,
  lifetime = false,
}) => {
  if (lifetime) {
    return { duration: "lifetime", expiresAt: null };
  }

  const expiresAt = toIsoTimestampOrNull(expirationDate);
  if (!expiresAt) {
    const err = new Error(
      "expirationDate is required when lifetime is not requested."
    );
    err.statusCode = 400;
    throw err;
  }

  const diffMs = new Date(expiresAt).getTime() - Date.now();
  if (!Number.isFinite(diffMs) || diffMs <= 0) {
    const err = new Error("expirationDate must be a future timestamp.");
    err.statusCode = 400;
    throw err;
  }

  const durationSeconds = Math.max(60, Math.ceil(diffMs / 1000));
  return { duration: `${durationSeconds}s`, expiresAt };
};

const grantRevenueCatPromotionalEntitlement = async ({
  appUserId,
  entitlementId,
  expirationDate,
  lifetime = false,
  platform = REVENUECAT_WEB_CHECKOUT_PLATFORM,
}) => {
  const normalizedAppUserId = normalizeRevenueCatAppUserId(appUserId);
  const normalizedEntitlementId = normalizeRevenueCatAppUserId(entitlementId);
  if (!normalizedAppUserId) {
    const err = new Error("appUserId is required.");
    err.statusCode = 400;
    throw err;
  }
  if (!normalizedEntitlementId) {
    const err = new Error("entitlementId is required.");
    err.statusCode = 400;
    throw err;
  }
  if (!REVENUECAT_SECRET_API_KEY) {
    const err = new Error("RevenueCat secret key is not configured.");
    err.statusCode = 503;
    throw err;
  }

  const grantWindow = resolveRevenueCatGrantDuration({
    expirationDate,
    lifetime,
  });
  const url = `${REVENUECAT_API_BASE_URL}/subscribers/${encodeURIComponent(
    normalizedAppUserId
  )}/entitlements/${encodeURIComponent(normalizedEntitlementId)}/promotional`;

  let attemptedEnsure = false;
  for (;;) {
    const response = await axios.post(
      url,
      { duration: grantWindow.duration },
      {
        headers: {
          Authorization: `Bearer ${REVENUECAT_SECRET_API_KEY}`,
          "Content-Type": "application/json",
        },
        timeout: REVENUECAT_HTTP_TIMEOUT_MS,
        validateStatus: () => true,
      }
    );

    if (response.status >= 200 && response.status < 300) {
      return {
        granted: true,
        duration: grantWindow.duration,
        expirationDate: grantWindow.expiresAt,
      };
    }

    if (response.status === 404 && !attemptedEnsure) {
      attemptedEnsure = true;
      await ensureRevenueCatSubscriber({
        appUserId: normalizedAppUserId,
        platform,
      });
      continue;
    }

    const err = new Error(
      `RevenueCat promotional grant failed (${response.status}).`
    );
    err.statusCode = 502;
    throw err;
  }
};

const revokeRevenueCatPromotionalEntitlement = async ({
  appUserId,
  entitlementId,
}) => {
  const normalizedAppUserId = normalizeRevenueCatAppUserId(appUserId);
  const normalizedEntitlementId = normalizeRevenueCatAppUserId(entitlementId);
  if (!normalizedAppUserId) {
    const err = new Error("appUserId is required.");
    err.statusCode = 400;
    throw err;
  }
  if (!normalizedEntitlementId) {
    const err = new Error("entitlementId is required.");
    err.statusCode = 400;
    throw err;
  }
  if (!REVENUECAT_SECRET_API_KEY) {
    const err = new Error("RevenueCat secret key is not configured.");
    err.statusCode = 503;
    throw err;
  }

  const url = `${REVENUECAT_API_BASE_URL}/subscribers/${encodeURIComponent(
    normalizedAppUserId
  )}/entitlements/${encodeURIComponent(
    normalizedEntitlementId
  )}/revoke_promotionals`;

  const response = await axios.post(
    url,
    {},
    {
      headers: {
        Authorization: `Bearer ${REVENUECAT_SECRET_API_KEY}`,
        "Content-Type": "application/json",
      },
      timeout: REVENUECAT_HTTP_TIMEOUT_MS,
      validateStatus: () => true,
    }
  );

  if (response.status >= 200 && response.status < 300) {
    return { revoked: true };
  }
  if (response.status === 404) {
    return { revoked: false, reason: "subscriber_not_found" };
  }

  const err = new Error(
    `RevenueCat promotional revoke failed (${response.status}).`
  );
  err.statusCode = 502;
  throw err;
};

const resolveEntitlementStateWithFallback = async ({
  appUserId,
  legacyAppUserId = null,
  legacyAppUserIds = null,
  entitlementId,
  fallbackIsActive,
  fallbackExpirationDate,
  allowFallbackOverride = false,
}) => {
  const primaryVerification = await fetchRevenueCatEntitlementState({
    appUserId,
    entitlementId,
  });
  let verification = primaryVerification;
  const legacyCandidates = [];
  const seenLegacyCandidates = new Set();
  const addLegacyCandidate = (candidate) => {
    const normalized = normalizeRevenueCatAppUserId(candidate);
    if (!normalized || normalized === appUserId || seenLegacyCandidates.has(normalized)) {
      return;
    }
    seenLegacyCandidates.add(normalized);
    legacyCandidates.push(normalized);
  };

  if (Array.isArray(legacyAppUserIds)) {
    for (const candidate of legacyAppUserIds) {
      addLegacyCandidate(candidate);
    }
  } else {
    addLegacyCandidate(legacyAppUserId);
  }

  const shouldTryLegacyLookup =
    legacyCandidates.length > 0 &&
    (!primaryVerification.checked ||
      primaryVerification.reason === "subscriber_not_found" ||
      primaryVerification.reason === "entitlement_not_found" ||
      primaryVerification.isActive !== true);

  if (shouldTryLegacyLookup) {
    const primaryMissing =
      !primaryVerification.checked ||
      primaryVerification.reason === "subscriber_not_found" ||
      primaryVerification.reason === "entitlement_not_found";

    for (const candidate of legacyCandidates) {
      const legacyVerification = await fetchRevenueCatEntitlementState({
        appUserId: candidate,
        entitlementId,
      });
      if (
        legacyVerification.checked &&
        (legacyVerification.isActive === true ||
          (primaryMissing && legacyVerification.isActive !== false))
      ) {
        verification = {
          ...legacyVerification,
          matchedAppUserId: candidate,
          primaryAppUserId: appUserId,
          legacyLookupUsed: true,
          legacyLookupReason: primaryVerification.reason || null,
        };
        break;
      }
    }
  }
  const fallbackProvided = fallbackIsActive !== undefined && fallbackIsActive !== null;
  const fallbackActive = toBool(fallbackIsActive);
  const fallbackExpiry = toIsoTimestampOrNull(fallbackExpirationDate);
  const fallbackEligible =
    fallbackProvided &&
    (allowFallbackOverride ||
      verification.reason === "subscriber_not_found" ||
      verification.reason === "entitlement_not_found");

  if (
    verification.checked &&
    !fallbackEligible
  ) {
    return {
      verification,
      isActive: verification.isActive,
      expirationDate: verification.expirationDate,
      usedFallback: false,
    };
  }

  if (!fallbackProvided) {
    return {
      verification,
      isActive: verification.isActive === true,
      expirationDate: verification.expirationDate || null,
      usedFallback: false,
    };
  }

  return {
    verification,
    isActive: fallbackActive,
    expirationDate: fallbackExpiry,
    usedFallback: true,
  };
};

const isMissingRevenueCatOwnershipLockError = (err) =>
  String(err?.code || "") === "42P01" &&
  String(err?.message || "").toLowerCase().includes("revenuecat_subscription_locks");

const isRevenueCatOwnershipLockUniqueError = (err) =>
  String(err?.code || "") === "23505" &&
  String(err?.message || "")
    .toLowerCase()
    .includes("revenuecat_subscription_locks");

const upsertRevenueCatOwnershipLock = async ({
  client,
  entitlementId,
  userId,
  appUserId,
  originalAppUserId = null,
  productIdentifier = null,
  isActive,
  expirationDate,
}) => {
  const normalizedEntitlementId = normalizeRevenueCatAppUserId(entitlementId);
  const normalizedAppUserId = normalizeRevenueCatAppUserId(appUserId);
  const normalizedOriginalAppUserId = normalizeRevenueCatAppUserId(originalAppUserId);
  const ownershipKey = normalizedOriginalAppUserId || normalizedAppUserId;
  const normalizedProductIdentifier = normalizeRevenueCatAppUserId(productIdentifier);
  if (!normalizedEntitlementId || !normalizedAppUserId || !ownershipKey || !userId) {
    return { mapped: false, reason: "missing_lock_identity" };
  }

  const expiresAt = toIsoTimestampOrNull(expirationDate);
  const nowIso = new Date().toISOString();
  const query = `
    INSERT INTO public.revenuecat_subscription_locks (
      entitlement_id,
      owner_user_id,
      owner_app_user_id,
      owner_original_app_user_id,
      product_identifier,
      is_active,
      expires_at,
      locked_at,
      updated_at,
      last_seen_at
    )
    VALUES (
      $1::text,
      $2::bigint,
      $3::text,
      $4::text,
      $5::text,
      $6::boolean,
      $7::timestamptz,
      COALESCE($8::timestamptz, now()),
      now(),
      now()
    )
    ON CONFLICT ON CONSTRAINT revenuecat_subscription_locks_entitlement_owner_key_uniq DO UPDATE SET
      owner_user_id = EXCLUDED.owner_user_id,
      owner_app_user_id = EXCLUDED.owner_app_user_id,
      owner_original_app_user_id = COALESCE(
        EXCLUDED.owner_original_app_user_id,
        public.revenuecat_subscription_locks.owner_original_app_user_id
      ),
      product_identifier = COALESCE(
        EXCLUDED.product_identifier,
        public.revenuecat_subscription_locks.product_identifier
      ),
      is_active = EXCLUDED.is_active,
      expires_at = EXCLUDED.expires_at,
      updated_at = now(),
      last_seen_at = now()
    WHERE
      public.revenuecat_subscription_locks.owner_user_id = EXCLUDED.owner_user_id
      OR public.revenuecat_subscription_locks.is_active = FALSE
      OR COALESCE(public.revenuecat_subscription_locks.expires_at, 'epoch'::timestamptz) <= now()
    RETURNING
      id::int AS id,
      entitlement_id,
      owner_user_id::int AS owner_user_id,
      owner_app_user_id,
      owner_original_app_user_id,
      product_identifier,
      is_active,
      expires_at,
      locked_at,
      updated_at,
      last_seen_at
  `;

  if (isActive) {
    const sameOwnerRows = await homePostgresQueryWithClient(
      client,
        `
          SELECT
          id::int AS id,
          entitlement_id,
          owner_user_id::int AS owner_user_id,
          owner_app_user_id,
          owner_original_app_user_id,
          product_identifier,
          is_active,
          expires_at,
          locked_at,
          updated_at,
          last_seen_at
        FROM public.revenuecat_subscription_locks
        WHERE entitlement_id = $1::text
          AND owner_user_id = $2::bigint
        ORDER BY updated_at DESC NULLS LAST, id DESC
        LIMIT 1
      `,
      [normalizedEntitlementId, Number(userId)]
    );

    const sameOwner = sameOwnerRows[0] || null;
    if (sameOwner) {
      const updatedSameOwnerRows = await homePostgresQueryWithClient(
        client,
        `
          UPDATE public.revenuecat_subscription_locks
          SET
            entitlement_id = $2::text,
            owner_app_user_id = $3::text,
            owner_original_app_user_id = COALESCE($4::text, owner_original_app_user_id),
            product_identifier = COALESCE($5::text, product_identifier),
            is_active = TRUE,
            expires_at = $6::timestamptz,
            locked_at = now(),
            updated_at = now(),
            last_seen_at = now()
          WHERE id = $1::bigint
          RETURNING
            id::int AS id,
            entitlement_id,
            owner_user_id::int AS owner_user_id,
            owner_app_user_id,
            owner_original_app_user_id,
            product_identifier,
            is_active,
            expires_at,
            locked_at,
            updated_at,
            last_seen_at
        `,
        [
          sameOwner.id,
          normalizedEntitlementId,
          normalizedAppUserId,
          normalizedOriginalAppUserId,
          normalizedProductIdentifier,
          expiresAt,
        ]
      );

      if (updatedSameOwnerRows[0]) {
        await homePostgresQueryWithClient(
          client,
          `
          DELETE FROM public.revenuecat_subscription_locks
          WHERE entitlement_id = $1::text
            AND owner_user_id = $2::bigint
            AND id <> $3::bigint
          `,
          [normalizedEntitlementId, Number(userId), sameOwner.id]
        );

        return {
          mapped: true,
          action: sameOwner.is_active === true ? "updated_same_owner" : "reactivated_same_owner",
          lock: updatedSameOwnerRows[0],
        };
      }
    }
  }

  let rows = [];
  try {
    rows = await homePostgresQueryWithClient(client, query, [
      normalizedEntitlementId,
      userId,
      normalizedAppUserId,
      ownershipKey,
      normalizedProductIdentifier,
      isActive === true,
      expiresAt,
      nowIso,
    ]);
  } catch (err) {
    if (!isRevenueCatOwnershipLockUniqueError(err)) {
      throw err;
    }

    const existingLockRows = await homePostgresQueryWithClient(
      client,
      `
        SELECT
          id::int AS id,
          entitlement_id,
          owner_user_id::int AS owner_user_id,
          owner_app_user_id,
          owner_original_app_user_id,
          product_identifier,
          is_active,
          expires_at,
          locked_at,
          updated_at,
          last_seen_at
        FROM public.revenuecat_subscription_locks
        WHERE entitlement_id = $1::text
          AND (
            owner_original_app_user_id = $2::text
            OR owner_app_user_id = $3::text
            OR owner_user_id = $4::bigint
          )
        ORDER BY updated_at DESC NULLS LAST, id DESC
        LIMIT 1
      `,
      [normalizedEntitlementId, ownershipKey, normalizedAppUserId, Number(userId)]
    );

    const existingLock = existingLockRows[0] || null;
    if (!existingLock) {
      throw err;
    }

    if (Number(existingLock.owner_user_id) !== Number(userId)) {
      return { mapped: false, reason: "locked_to_other_user", entitlementId: normalizedEntitlementId };
    }

    const mergedRows = await homePostgresQueryWithClient(
      client,
      `
        UPDATE public.revenuecat_subscription_locks
        SET
          owner_app_user_id = $2::text,
          owner_original_app_user_id = COALESCE($3::text, owner_original_app_user_id),
          product_identifier = COALESCE($4::text, product_identifier),
          is_active = $5::boolean,
          expires_at = $6::timestamptz,
          updated_at = now(),
          last_seen_at = now()
        WHERE id = $1::bigint
        RETURNING
          id::int AS id,
          entitlement_id,
          owner_user_id::int AS owner_user_id,
          owner_app_user_id,
          owner_original_app_user_id,
          product_identifier,
          is_active,
          expires_at,
          locked_at,
          updated_at,
          last_seen_at
      `,
      [
        existingLock.id,
        normalizedAppUserId,
        normalizedOriginalAppUserId,
        normalizedProductIdentifier,
        isActive === true,
        expiresAt,
      ]
    );

    if (mergedRows[0]) {
      return {
        mapped: true,
        action: "upserted_after_duplicate",
        lock: mergedRows[0],
      };
    }

    return { mapped: false, reason: "duplicate_lock_update_failed" };
  }

  if (rows[0]) {
    return { mapped: true, action: "upserted", lock: rows[0] };
  }

  const existingRows = await homePostgresQueryWithClient(
    client,
    `
      SELECT
        id::int AS id,
        entitlement_id,
        owner_user_id::int AS owner_user_id,
        owner_app_user_id,
        owner_original_app_user_id,
        product_identifier,
        is_active,
        expires_at,
        locked_at,
        updated_at,
        last_seen_at
      FROM public.revenuecat_subscription_locks
      WHERE entitlement_id = $1::text
      ORDER BY updated_at DESC NULLS LAST, id DESC
      LIMIT 1
    `,
    [normalizedEntitlementId]
  );

  const existing = existingRows[0] || null;
  const activeRowExpiry = parseTimestampOrNull(existing?.expires_at);
  const activeRowIsCurrent =
    !!existing &&
    existing.is_active === true &&
    (!activeRowExpiry || activeRowExpiry.getTime() > Date.now());

  if (isActive && activeRowIsCurrent && Number(existing.owner_user_id) !== Number(userId)) {
    const err = new Error("Bu abonelik başka bir hesapta aktif.");
    err.statusCode = 409;
    err.code = "REVENUECAT_ENTITLEMENT_LOCKED";
    err.details = {
      entitlementId: normalizedEntitlementId,
      lockedUserId: Number(existing.owner_user_id),
      lockedAppUserId: existing.owner_app_user_id || null,
      lockedAt: existing.locked_at || null,
      expiresAt: existing.expires_at || null,
    };
    throw err;
  }

  if (isActive) {
    return {
      mapped: false,
      reason: activeRowIsCurrent ? "locked_to_other_user" : "lock_missing",
      entitlementId: normalizedEntitlementId,
    };
  }

  return {
    mapped: true,
    action: existing ? "noop_inactive" : "noop_missing",
    entitlementId: normalizedEntitlementId,
  };
};

const syncRevenueCatAccessByEntitlement = async ({
  userId,
  entitlementId,
  isActive,
  expirationDate,
  appUserId = null,
  originalAppUserId = null,
  productIdentifier = null,
  purchasePlatform = null,
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
  const normalizedPurchasePlatform = normalizePurchasePlatform(purchasePlatform);

  if (mapping.itemType !== "newspaper_subscription" || mapping.itemId !== null) {
    return {
      mapped: false,
      reason: "unsupported_access_mapping",
      entitlementId,
      itemType: mapping.itemType,
    };
  }

  if (revenueCatOwnershipLockSupported) {
    try {
      const lockResult = await withHomePostgresClient((client) =>
        upsertRevenueCatOwnershipLock({
          client,
          entitlementId: mapping.itemType === "newspaper_subscription" ? entitlementKey : entitlementId,
          userId,
          appUserId: appUserId || String(userId),
          originalAppUserId,
          productIdentifier,
          isActive,
          expirationDate,
        })
      );

      if (!lockResult.mapped && lockResult.reason === "locked_to_other_user") {
        const current = await getActiveNewspaperAccessRowFromPostgres({
          userId,
          nowIso,
          client,
          requireCurrent: false,
        });
        if (current?.id && isRevenueCatManagedAccessRow(current, expiresAt || nowIso)) {
          await homePostgresQueryWithClient(
            client,
            `
              UPDATE public.user_content_access
              SET
                is_active = FALSE,
                expires_at = COALESCE(expires_at, now())
              WHERE id = $1
                AND is_active = TRUE
            `,
            [current.id]
          );
        }

        return {
          mapped: false,
          reason: "locked_to_other_user",
          entitlementId,
        };
      }
    } catch (err) {
      if (isMissingRevenueCatOwnershipLockError(err)) {
        revenueCatOwnershipLockSupported = false;
      } else {
        throw err;
      }
    }
  }

  const updateRevenueCatAccess = async (client, userAccessId) => {
    const queryWithBoth = `
      UPDATE public.user_content_access
      SET
        is_active = TRUE,
        expires_at = $2::timestamptz,
        grant_source = $3,
        purchase_platform = $4
      WHERE id = $1
      RETURNING id::int AS id
    `;
    const queryWithGrantSourceOnly = `
      UPDATE public.user_content_access
      SET
        is_active = TRUE,
        expires_at = $2::timestamptz,
        grant_source = $3
      WHERE id = $1
      RETURNING id::int AS id
    `;
    const queryWithPurchasePlatformOnly = `
      UPDATE public.user_content_access
      SET
        is_active = TRUE,
        expires_at = $2::timestamptz,
        purchase_platform = $3
      WHERE id = $1
      RETURNING id::int AS id
    `;
    const queryWithoutMetadata = `
      UPDATE public.user_content_access
      SET
        is_active = TRUE,
        expires_at = $2::timestamptz
      WHERE id = $1
      RETURNING id::int AS id
    `;

    const variants = [];
    if (userContentAccessGrantSourceSupported && userContentAccessPurchasePlatformSupported) {
      variants.push({
        text: queryWithBoth,
        values: [userAccessId, expiresAt, REVENUECAT_ACCESS_SOURCE, normalizedPurchasePlatform],
      });
    }
    if (userContentAccessGrantSourceSupported) {
      variants.push({
        text: queryWithGrantSourceOnly,
        values: [userAccessId, expiresAt, REVENUECAT_ACCESS_SOURCE],
      });
    }
    if (userContentAccessPurchasePlatformSupported) {
      variants.push({
        text: queryWithPurchasePlatformOnly,
        values: [userAccessId, expiresAt, normalizedPurchasePlatform],
      });
    }
    variants.push({
      text: queryWithoutMetadata,
      values: [userAccessId, expiresAt],
    });

    for (const variant of variants) {
      try {
        const rows = await homePostgresQueryWithClient(client, variant.text, variant.values);
        return rows[0] || null;
      } catch (err) {
        const missingGrantSource = isMissingUserContentAccessGrantSourceError(err);
        const missingPurchasePlatform = isMissingUserContentAccessPurchasePlatformError(err);
        if (!missingGrantSource && !missingPurchasePlatform) {
          throw err;
        }
        if (missingGrantSource) {
          userContentAccessGrantSourceSupported = false;
        }
        if (missingPurchasePlatform) {
          userContentAccessPurchasePlatformSupported = false;
        }
      }
    }

    return null;
  };

  const insertRevenueCatAccess = async (client) => {
    const queryWithBoth = `
      INSERT INTO public.user_content_access (
        user_id,
        item_type,
        item_id,
        is_active,
        started_at,
        expires_at,
        grant_source,
        purchase_platform
      )
      VALUES (
        $1,
        'newspaper_subscription'::public.access_item_type,
        NULL,
        TRUE,
        $2::timestamptz,
        $3::timestamptz,
        $4,
        $5
      )
      RETURNING id::int AS id
    `;
    const queryWithGrantSourceOnly = `
      INSERT INTO public.user_content_access (
        user_id,
        item_type,
        item_id,
        is_active,
        started_at,
        expires_at,
        grant_source
      )
      VALUES (
        $1,
        'newspaper_subscription'::public.access_item_type,
        NULL,
        TRUE,
        $2::timestamptz,
        $3::timestamptz,
        $4
      )
      RETURNING id::int AS id
    `;
    const queryWithPurchasePlatformOnly = `
      INSERT INTO public.user_content_access (
        user_id,
        item_type,
        item_id,
        is_active,
        started_at,
        expires_at,
        purchase_platform
      )
      VALUES (
        $1,
        'newspaper_subscription'::public.access_item_type,
        NULL,
        TRUE,
        $2::timestamptz,
        $3::timestamptz,
        $4
      )
      RETURNING id::int AS id
    `;
    const queryWithoutMetadata = `
      INSERT INTO public.user_content_access (
        user_id,
        item_type,
        item_id,
        is_active,
        started_at,
        expires_at
      )
      VALUES (
        $1,
        'newspaper_subscription'::public.access_item_type,
        NULL,
        TRUE,
        $2::timestamptz,
        $3::timestamptz
      )
      RETURNING id::int AS id
    `;

    const variants = [];
    if (userContentAccessGrantSourceSupported && userContentAccessPurchasePlatformSupported) {
      variants.push({
        text: queryWithBoth,
        values: [userId, nowIso, expiresAt, REVENUECAT_ACCESS_SOURCE, normalizedPurchasePlatform],
      });
    }
    if (userContentAccessGrantSourceSupported) {
      variants.push({
        text: queryWithGrantSourceOnly,
        values: [userId, nowIso, expiresAt, REVENUECAT_ACCESS_SOURCE],
      });
    }
    if (userContentAccessPurchasePlatformSupported) {
      variants.push({
        text: queryWithPurchasePlatformOnly,
        values: [userId, nowIso, expiresAt, normalizedPurchasePlatform],
      });
    }
    variants.push({
      text: queryWithoutMetadata,
      values: [userId, nowIso, expiresAt],
    });

    for (const variant of variants) {
      try {
        const rows = await homePostgresQueryWithClient(client, variant.text, variant.values);
        return rows[0] || null;
      } catch (err) {
        const missingGrantSource = isMissingUserContentAccessGrantSourceError(err);
        const missingPurchasePlatform = isMissingUserContentAccessPurchasePlatformError(err);
        if (!missingGrantSource && !missingPurchasePlatform) {
          throw err;
        }
        if (missingGrantSource) {
          userContentAccessGrantSourceSupported = false;
        }
        if (missingPurchasePlatform) {
          userContentAccessPurchasePlatformSupported = false;
        }
      }
    }

    return null;
  };

  if (!isActive) {
    return withHomePostgresClient(async (client) => {
      const current = await getActiveNewspaperAccessRowFromPostgres({
        userId,
        nowIso,
        client,
        requireCurrent: false,
      });

      if (!current) {
        return {
          mapped: true,
          action: "noop_inactive",
          affectedRows: 0,
          itemType: mapping.itemType,
        };
      }

      if (hasManualOverrideExpiry(current, expiresAt || nowIso)) {
        return {
          mapped: true,
          action: "skipped_manual_override",
          affectedRows: 0,
          itemType: mapping.itemType,
          accessId: current.id ?? null,
          expiresAt: current.expires_at || null,
        };
      }

      if (!isRevenueCatManagedAccessRow(current, expiresAt || nowIso)) {
        return {
          mapped: true,
          action: "skipped_manual_override",
          affectedRows: 0,
          itemType: mapping.itemType,
          accessId: current.id ?? null,
          expiresAt: current.expires_at || null,
        };
      }

      const deletedRows = await homePostgresQueryWithClient(
        client,
        `
          DELETE FROM public.user_content_access
          WHERE id = $1
            AND is_active = TRUE
          RETURNING id::int AS id
        `,
        [current.id]
      );

      return {
        mapped: true,
        action: "deleted",
        affectedRows: deletedRows.length,
        itemType: mapping.itemType,
        accessId: deletedRows[0]?.id ?? current.id ?? null,
      };
    });
  }

  return withHomePostgresClient(async (client) => {
    const current = await getActiveNewspaperAccessRowFromPostgres({
      userId,
      nowIso,
      client,
      requireCurrent: false,
    });

    if (current?.id) {
      if (hasManualOverrideExpiry(current, expiresAt)) {
        return {
          mapped: true,
          action: "skipped_manual_override",
          itemType: mapping.itemType,
          accessId: current.id,
          expiresAt: current.expires_at || null,
        };
      }

      await updateRevenueCatAccess(client, current.id);
      return {
        mapped: true,
        action: "updated",
        itemType: mapping.itemType,
        accessId: current.id,
        expiresAt,
      };
    }

    try {
      const inserted = await insertRevenueCatAccess(client);
      return {
        mapped: true,
        action: "inserted",
        itemType: mapping.itemType,
        accessId: inserted?.id ?? null,
        expiresAt,
      };
    } catch (err) {
      if (String(err?.code || "") !== "23505") {
        throw err;
      }

      const recovered = await getActiveNewspaperAccessRowFromPostgres({
        userId,
        nowIso,
        client,
        requireCurrent: false,
      });
      if (!recovered?.id) {
        throw err;
      }

      await updateRevenueCatAccess(client, recovered.id);
      return {
        mapped: true,
        action: "updated_after_conflict",
        itemType: mapping.itemType,
        accessId: recovered.id,
        expiresAt,
      };
    }
  });
};

let revenueCatAuditLogEnabled = true;
const writeRevenueCatAuditLog = async (entry) => {
  if (!revenueCatAuditLogEnabled) return;
  try {
    const rows = await homePostgresQuery(
      `
        INSERT INTO public.revenuecat_sync_logs (
          request_id,
          endpoint,
          source,
          event_type,
          result,
          success,
          auth_mode,
          user_id,
          app_user_id,
          expected_app_user_id,
          identity_payload_matched,
          identity_server_matched,
          identity_effective_matched,
          entitlement_id,
          is_active,
          expiration_date,
          verification_source,
          verification_reason,
          access_action,
          error,
          payload,
          created_at
        ) VALUES (
          $1::text,
          $2::text,
          $3::text,
          $4::text,
          $5::text,
          $6::boolean,
          $7::text,
          $8::bigint,
          $9::text,
          $10::text,
          $11::boolean,
          $12::boolean,
          $13::boolean,
          $14::text,
          $15::boolean,
          $16::timestamptz,
          $17::text,
          $18::text,
          $19::text,
          $20::text,
          $21::jsonb,
          COALESCE($22::timestamptz, NOW())
        )
        RETURNING id
      `,
      [
        entry.request_id || null,
        entry.endpoint || null,
        entry.source || null,
        entry.event_type || null,
        entry.result || null,
        entry.success ?? true,
        entry.auth_mode || null,
        entry.user_id || null,
        entry.app_user_id || null,
        entry.expected_app_user_id || null,
        entry.identity_payload_matched ?? null,
        entry.identity_server_matched ?? null,
        entry.identity_effective_matched ?? null,
        entry.entitlement_id || null,
        entry.is_active ?? null,
        entry.expiration_date || null,
        entry.verification_source || null,
        entry.verification_reason || null,
        entry.access_action || null,
        entry.error || null,
        JSON.stringify(entry.payload ?? {}),
        entry.created_at || null,
      ]
    );
    if (!rows[0]?.id) {
      throw new Error("RevenueCat sync log insert failed.");
    }
  } catch (err) {
    const message = String(err?.message || "");
    if (
      message.includes("insert_revenuecat_sync_logs_one") ||
      message.includes("revenuecat_sync_logs")
    ) {
      revenueCatAuditLogEnabled = false;
    }
    console.warn(
      `[revenuecat][audit-warning] requestId=${entry?.request_id || "-"} msg=${message}`
    );
  }
};

const buildRevenueCatIdentityContext = ({
  expectedAppUserId,
  payloadIdentityMatched,
  resolvedAppUserId,
}) => {
  const normalizedExpected = normalizeRevenueCatAppUserId(expectedAppUserId);
  const normalizedResolved = normalizeRevenueCatAppUserId(resolvedAppUserId);
  const payloadMatched = toNullableBool(payloadIdentityMatched);
  const serverMatched =
    normalizedExpected && normalizedResolved
      ? normalizedExpected === normalizedResolved
      : null;
  const effectiveMatched =
    serverMatched === null
      ? payloadMatched === null
        ? true
        : payloadMatched
      : serverMatched;

  return {
    expectedAppUserId: normalizedExpected,
    payloadIdentityMatched: payloadMatched,
    serverIdentityMatched: serverMatched,
    identityMatched: effectiveMatched,
  };
};

const inferRevenueCatWebhookIsActive = (eventType, expirationDate) => {
  const normalizedType = String(eventType || "")
    .trim()
    .toUpperCase();
  if (REVENUECAT_ACTIVE_EVENT_TYPES.has(normalizedType)) return true;
  if (REVENUECAT_INACTIVE_EVENT_TYPES.has(normalizedType)) return false;
  if (expirationDate) {
    return new Date(expirationDate).getTime() > Date.now();
  }
  return null;
};

const normalizeRevenueCatWebhookEvent = (body) => {
  const root = body && typeof body === "object" ? body : {};
  const event = root.event && typeof root.event === "object" ? root.event : root;
  const eventType =
    normalizeRevenueCatAppUserId(event.type || event.event_type || root.type) || "unknown";
  const appUserId = normalizeRevenueCatAppUserId(
    event.app_user_id ||
      event.appUserId ||
      event.original_app_user_id ||
      event.originalAppUserId
  );
  const entitlementId =
    normalizeRevenueCatAppUserId(
      event.entitlement_id ||
        event.entitlementId ||
        (Array.isArray(event.entitlement_ids) ? event.entitlement_ids[0] : null)
    ) || normalizeRevenueCatAppUserId(REVENUECAT_DEFAULT_ENTITLEMENT_ID);
  const expirationDate =
    toIsoFromMillisOrNull(event.expiration_at_ms || event.expires_date_ms) ||
    toIsoTimestampOrNull(
      event.expiration_at || event.expires_date || event.expiration_date || null
    );
  const inferredIsActive = inferRevenueCatWebhookIsActive(eventType, expirationDate);

  return {
    event,
    eventId: normalizeRevenueCatAppUserId(event.id || event.event_id || root.id),
    eventType,
    appUserId,
    entitlementId,
    expirationDate,
    inferredIsActive,
  };
};

const getRevenueCatReconcileCandidates = async ({
  limit = REVENUECAT_RECONCILE_BATCH_SIZE,
} = {}) => {
  const queryWithGrantSource = `
    SELECT
      uca.id::int AS access_id,
      uca.user_id::int AS user_id,
      uca.started_at,
      uca.expires_at,
      uca.grant_source,
      COALESCE(NULLIF(btrim(u."payUniqe"), ''), uca.user_id::text) AS app_user_id
    FROM public.user_content_access uca
    JOIN public.users u
      ON u.id = uca.user_id
    WHERE uca.item_type = 'newspaper_subscription'::public.access_item_type
      AND uca.item_id IS NULL
      AND uca.is_active = TRUE
    ORDER BY
      CASE WHEN uca.expires_at IS NULL THEN 1 ELSE 0 END,
      uca.expires_at ASC NULLS LAST,
      uca.id ASC
    LIMIT $1
  `;
  const queryWithoutGrantSource = `
    SELECT
      uca.id::int AS access_id,
      uca.user_id::int AS user_id,
      uca.started_at,
      uca.expires_at,
      NULL::text AS grant_source,
      COALESCE(NULLIF(btrim(u."payUniqe"), ''), uca.user_id::text) AS app_user_id
    FROM public.user_content_access uca
    JOIN public.users u
      ON u.id = uca.user_id
    WHERE uca.item_type = 'newspaper_subscription'::public.access_item_type
      AND uca.item_id IS NULL
      AND uca.is_active = TRUE
    ORDER BY
      CASE WHEN uca.expires_at IS NULL THEN 1 ELSE 0 END,
      uca.expires_at ASC NULLS LAST,
      uca.id ASC
    LIMIT $1
  `;

  if (!userContentAccessGrantSourceSupported) {
    return homePostgresQuery(queryWithoutGrantSource, [limit]);
  }

  try {
    return await homePostgresQuery(queryWithGrantSource, [limit]);
  } catch (err) {
    if (!isMissingUserContentAccessGrantSourceError(err)) {
      throw err;
    }
    userContentAccessGrantSourceSupported = false;
    return homePostgresQuery(queryWithoutGrantSource, [limit]);
  }
};

const runRevenueCatReconcileJob = async () => {
  if (revenueCatReconcileRunning) return;
  if (!REVENUECAT_RECONCILE_ENABLED || !REVENUECAT_SECRET_API_KEY) return;

  revenueCatReconcileRunning = true;
  const runId = crypto.randomUUID();
  const stats = {
    total: 0,
    updated: 0,
    inserted: 0,
    deleted: 0,
    skipped: 0,
    errors: 0,
  };

  try {
    const candidates = await getRevenueCatReconcileCandidates();
    stats.total = candidates.length;
    if (!candidates.length) {
      console.log(`[revenuecat][reconcile] id=${runId} total=0 skipped=0 errors=0`);
      return;
    }

    for (const candidate of candidates) {
      const requestId = crypto.randomUUID();
      try {
        const appUserId = normalizeRevenueCatAppUserId(candidate.app_user_id);
        if (!appUserId) {
          stats.skipped += 1;
          await writeRevenueCatAuditLog({
            request_id: requestId,
            endpoint: "/revenuecat/subscription/reconcile-job",
            source: "reconcile_job",
            success: false,
            user_id: candidate.user_id,
            access_action: "skipped_missing_app_user_id",
            error: "Missing payUniqe/appUserId for reconcile candidate.",
          });
          continue;
        }

        const verification = await fetchRevenueCatEntitlementState({
          appUserId,
          entitlementId: REVENUECAT_DEFAULT_ENTITLEMENT_ID,
        });

        if (!verification.checked) {
          stats.skipped += 1;
          await writeRevenueCatAuditLog({
            request_id: requestId,
            endpoint: "/revenuecat/subscription/reconcile-job",
            source: "reconcile_job",
            success: false,
            user_id: candidate.user_id,
            app_user_id: appUserId,
            entitlement_id: REVENUECAT_DEFAULT_ENTITLEMENT_ID,
            access_action: "skipped_unverified",
            verification_source: verification.source || null,
            verification_reason: verification.reason || null,
            error: "RevenueCat verification unavailable during reconcile.",
          });
          continue;
        }

        const accessSync = await syncRevenueCatAccessByEntitlement({
          userId: candidate.user_id,
          entitlementId: REVENUECAT_DEFAULT_ENTITLEMENT_ID,
          isActive: verification.isActive,
          expirationDate: verification.expirationDate,
          appUserId,
          purchasePlatform: verification.purchasePlatform,
        });

        switch (accessSync.action) {
          case "updated":
          case "updated_after_conflict":
            stats.updated += 1;
            break;
          case "inserted":
            stats.inserted += 1;
            break;
          case "deleted":
            stats.deleted += 1;
            break;
          default:
            stats.skipped += 1;
            break;
        }

        await writeRevenueCatAuditLog({
          request_id: requestId,
          endpoint: "/revenuecat/subscription/reconcile-job",
          source: "reconcile_job",
          success: true,
          user_id: candidate.user_id,
          app_user_id: appUserId,
          entitlement_id: REVENUECAT_DEFAULT_ENTITLEMENT_ID,
          is_active: verification.isActive,
          expiration_date: toIsoTimestampOrNull(verification.expirationDate),
          verification_source: verification.source || null,
          verification_reason: verification.reason || null,
          access_action: accessSync.action || accessSync.reason || "none",
        });
      } catch (err) {
        stats.errors += 1;
        await writeRevenueCatAuditLog({
          request_id: requestId,
          endpoint: "/revenuecat/subscription/reconcile-job",
          source: "reconcile_job",
          success: false,
          user_id: candidate.user_id,
          app_user_id: normalizeRevenueCatAppUserId(candidate.app_user_id),
          entitlement_id: REVENUECAT_DEFAULT_ENTITLEMENT_ID,
          error: err.message || "Reconcile failed.",
        });
        console.error(
          `[revenuecat][reconcile][error] id=${requestId} userId=${candidate.user_id} msg=${err.message}`
        );
      }
    }

    console.log(
      `[revenuecat][reconcile] id=${runId} total=${stats.total} updated=${stats.updated} inserted=${stats.inserted} deleted=${stats.deleted} skipped=${stats.skipped} errors=${stats.errors}`
    );
  } catch (err) {
    console.error(`[revenuecat][reconcile][fatal] id=${runId} msg=${err.message}`);
  } finally {
    revenueCatReconcileRunning = false;
  }
};

const startRevenueCatReconcileJob = () => {
  if (!REVENUECAT_RECONCILE_ENABLED) {
    console.log("[revenuecat][reconcile] disabled");
    return;
  }
  if (!REVENUECAT_SECRET_API_KEY) {
    console.log("[revenuecat][reconcile] skipped: missing REVENUECAT_SECRET_API_KEY");
    return;
  }
  if (revenueCatReconcileTimer) {
    clearInterval(revenueCatReconcileTimer);
    revenueCatReconcileTimer = null;
  }

  setTimeout(() => {
    runRevenueCatReconcileJob().catch((err) => {
      console.error(`[revenuecat][reconcile][startup-error] msg=${err.message}`);
    });
  }, REVENUECAT_RECONCILE_STARTUP_DELAY_MS);

  revenueCatReconcileTimer = setInterval(() => {
    runRevenueCatReconcileJob().catch((err) => {
      console.error(`[revenuecat][reconcile][interval-error] msg=${err.message}`);
    });
  }, REVENUECAT_RECONCILE_INTERVAL_MINUTES * 60 * 1000);

  console.log(
    `[revenuecat][reconcile] scheduled interval=${REVENUECAT_RECONCILE_INTERVAL_MINUTES}m batch=${REVENUECAT_RECONCILE_BATCH_SIZE}`
  );
};

const inspectAndRepairRevenueCatSubscriptionForUser = async ({
  userId,
  entitlementId = REVENUECAT_DEFAULT_ENTITLEMENT_ID,
}) => {
  const normalizedUserId = toPositiveIntOrNull(userId);
  const normalizedEntitlementId =
    normalizeRevenueCatAppUserId(entitlementId) ||
    normalizeRevenueCatAppUserId(REVENUECAT_DEFAULT_ENTITLEMENT_ID);
  if (!normalizedUserId) {
    const err = new Error("userId is required.");
    err.statusCode = 400;
    throw err;
  }
  if (!normalizedEntitlementId) {
    const err = new Error("entitlementId is required.");
    err.statusCode = 400;
    throw err;
  }

  const user = await findUserById(normalizedUserId);
  if (!user) {
    const err = new Error("User not found.");
    err.statusCode = 404;
    throw err;
  }

  const activeAccessBefore = await getActiveNewspaperSubscriptionAccess(normalizedUserId);
  const candidates = [];
  const seenCandidates = new Set();
  const addCandidate = (value, source) => {
    const normalized = normalizeRevenueCatAppUserId(value);
    if (!normalized || seenCandidates.has(normalized)) {
      return;
    }
    seenCandidates.add(normalized);
    candidates.push({ appUserId: normalized, source });
  };

  addCandidate(user.payUniqe, "payUniqe");
  addCandidate(String(user.id), "userId");
  addCandidate(
    await getRevenueCatLockFallbackAppUserId(normalizedUserId, normalizedEntitlementId),
    "lockFallback"
  );

  const verifications = [];
  let matchedCandidate = null;
  let matchedVerification = null;

  for (const candidate of candidates) {
    const verification = await fetchRevenueCatEntitlementState({
      appUserId: candidate.appUserId,
      entitlementId: normalizedEntitlementId,
    });
    verifications.push({
      source: candidate.source,
      appUserId: candidate.appUserId,
      checked: verification.checked,
      sourceType: verification.source || null,
      reason: verification.reason || null,
      isActive: verification.isActive === true,
      expirationDate: verification.expirationDate || null,
      purchasePlatform: verification.purchasePlatform || null,
    });

    if (verification.checked && verification.isActive === true) {
      matchedCandidate = candidate;
      matchedVerification = verification;
      break;
    }
  }

  if (!matchedCandidate || !matchedVerification) {
    const healthy = Boolean(activeAccessBefore);
    return {
      ok: true,
      fixed: false,
      healthy,
      activeRevenueCat: false,
      activeAccessBefore: Boolean(activeAccessBefore),
      activeAccessAfter: Boolean(activeAccessBefore),
      payUniqeUpdated: false,
      matchedAppUserId: null,
      matchedSource: null,
      entitlementId: normalizedEntitlementId,
      verifications,
      message: healthy
        ? "Abonelik tarafında kullanıcının sorunu bulunmamaktadır."
        : "RevenueCat'te aktif abonelik bulunamadı.",
    };
  }

  const syncResult = await syncRevenueCatAccessByEntitlement({
    userId: normalizedUserId,
    entitlementId: normalizedEntitlementId,
    isActive: true,
    expirationDate: matchedVerification.expirationDate,
    appUserId: matchedCandidate.appUserId,
    originalAppUserId: matchedCandidate.appUserId,
    productIdentifier: matchedVerification.productIdentifier || null,
    purchasePlatform: matchedVerification.purchasePlatform || null,
  });

  const currentPayUniqe = normalizeRevenueCatAppUserId(user.payUniqe);
  let payUniqeUpdated = false;
  if (currentPayUniqe !== matchedCandidate.appUserId) {
    await setUserPayUniqe(normalizedUserId, matchedCandidate.appUserId);
    payUniqeUpdated = true;
  }

  const activeAccessAfter = await getActiveNewspaperSubscriptionAccess(normalizedUserId);
  const fixed = !activeAccessBefore && Boolean(activeAccessAfter);
  const alreadySynced = Boolean(activeAccessBefore) && !payUniqeUpdated;
  const healthy = Boolean(activeAccessAfter) || Boolean(activeAccessBefore);
  const message = fixed
    ? "Abonelik düzeltildi."
    : payUniqeUpdated
      ? "Abonelik düzeltildi."
      : alreadySynced || healthy
        ? "Abonelik tarafında kullanıcının sorunu bulunmamaktadır."
        : "Abonelik durumu kontrol edildi.";

  return {
    ok: true,
    fixed,
    alreadySynced,
    healthy,
    activeRevenueCat: true,
    activeAccessBefore: Boolean(activeAccessBefore),
    activeAccessAfter: Boolean(activeAccessAfter),
    payUniqeUpdated,
    matchedAppUserId: matchedCandidate.appUserId,
    matchedSource: matchedCandidate.source,
    entitlementId: normalizedEntitlementId,
    verification: {
      ...matchedVerification,
      productIdentifier: matchedVerification.productIdentifier || null,
    },
    verifications,
    syncResult,
    message,
  };
};

app.post("/revenuecat/subscription/sync", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/subscription/sync",
    auth_mode: req.revenueCatAuthMode || "unknown",
  };

  try {
    if (req.revenueCatGuest) {
      return res.status(200).json({
        ok: true,
        skipped: true,
        reason: "guest_noop",
      });
    }

    const body = req.body || {};
    const entitlementId = normalizeRevenueCatAppUserId(body.entitlementId);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const expectedAppUserId = normalizeRevenueCatAppUserId(body.expectedAppUserId);
    const payloadIdentityMatched = toNullableBool(body.identityMatched);
    const customerInfo =
      body.customerInfo && typeof body.customerInfo === "object"
        ? body.customerInfo
        : body.customerInfoRaw && typeof body.customerInfoRaw === "object"
          ? body.customerInfoRaw
          : null;
    const productIdentifier = normalizeRevenueCatAppUserId(
      body.productIdentifier ||
        customerInfo?.entitlement?.productIdentifier ||
        customerInfo?.entitlement?.product_identifier
    );
    const originalAppUserId = normalizeRevenueCatAppUserId(
      customerInfo?.originalAppUserId ||
        customerInfo?.original_app_user_id ||
        body.originalAppUserId ||
        body.original_app_user_id
    );
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const hasJwtBodyMismatch =
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId;
    const resolvedUserIdInput =
      req.revenueCatAuthMode === "jwt" && jwtUserId ? jwtUserId : bodyUserId || jwtUserId;

    if (!entitlementId) {
      return res.status(400).json({ ok: false, error: "entitlementId is required." });
    }
    if (!resolvedUserIdInput && !appUserId) {
      return res.status(400).json({ ok: false, error: "userId or appUserId is required." });
    }
    if (hasJwtBodyMismatch) {
      console.warn(
        `[revenuecat][sync][jwt-mismatch] id=${requestId} bodyUserId=${bodyUserId} jwtUserId=${jwtUserId} mode=jwt_using_token_user_id`
      );
    }

    const resolved = await resolveRevenueCatUser({
      userId: resolvedUserIdInput,
      appUserId,
      allowPayUniqeRelink: req.revenueCatAuthMode === "jwt",
    });

    if (req.revenueCatAuthMode === "jwt" && jwtUserId && resolved.userId !== jwtUserId) {
      return res.status(403).json({ ok: false, error: "User mismatch." });
    }

    const identity = buildRevenueCatIdentityContext({
      expectedAppUserId,
      payloadIdentityMatched,
      resolvedAppUserId: resolved.appUserId,
    });
    if (identity.serverIdentityMatched === false) {
      console.warn(
        `[revenuecat][identity-mismatch] id=${requestId} endpoint=sync userId=${resolved.userId} expected=${identity.expectedAppUserId} resolved=${resolved.appUserId}`
      );
    }

    const lockFallbackAppUserId = await getRevenueCatLockFallbackAppUserId(
      resolved.userId,
      entitlementId
    );
    const state = await resolveEntitlementStateWithFallback({
      appUserId: resolved.appUserId,
      legacyAppUserIds: [
        resolved.user.payUniqe,
        lockFallbackAppUserId,
        originalAppUserId,
      ],
      entitlementId,
      fallbackIsActive: body.isActive,
      fallbackExpirationDate:
        body.expirationDate || customerInfo?.entitlement?.expirationDate || null,
      allowFallbackOverride: false,
    });
    if (!state.verification.checked && body.isActive === undefined) {
      const transientLookupFailure = String(state.verification.reason || "").startsWith(
        "subscriber_lookup_failed"
      );
      if (!transientLookupFailure) {
        return res.status(400).json({
          ok: false,
          error: "isActive is required when RevenueCat verification is unavailable.",
        });
      }
      await writeRevenueCatAuditLog({
        ...baseAudit,
        source: state.verification.source,
        user_id: resolved.userId,
        app_user_id: resolved.appUserId,
        expected_app_user_id: identity.expectedAppUserId,
        identity_payload_matched: identity.payloadIdentityMatched,
        identity_server_matched: identity.serverIdentityMatched,
        identity_effective_matched: identity.identityMatched,
        entitlement_id: entitlementId,
        is_active: false,
        expiration_date: null,
        verification_source: state.verification.source,
        verification_reason: state.verification.reason || null,
        access_action: "skipped_lookup_unavailable",
        success: true,
        payload: body,
      });
      return res.json({
        ok: true,
        requestId,
        skipped: true,
        reason: state.verification.reason || "subscriber_lookup_failed",
        userId: resolved.userId,
        appUserId: resolved.appUserId,
        expectedAppUserId: identity.expectedAppUserId,
        identityMatched: identity.identityMatched,
        identityServerMatched: identity.serverIdentityMatched,
        identityPayloadMatched: identity.payloadIdentityMatched,
        entitlementId,
        isActive: false,
        expirationDate: null,
        verification: state.verification,
        accessSync: {
          mapped: false,
          reason: "subscriber_lookup_unavailable",
          entitlementId,
        },
      });
    }

    const isActive = state.isActive;
    const effectiveExpirationDate = state.expirationDate;
    const accessSync = await syncRevenueCatAccessByEntitlement({
      userId: resolved.userId,
      entitlementId,
      isActive,
      expirationDate: effectiveExpirationDate,
      appUserId: resolved.appUserId,
      originalAppUserId: originalAppUserId || resolved.user.payUniqe || null,
      productIdentifier,
      purchasePlatform:
        state.verification.purchasePlatform ||
        normalizePurchasePlatform(body.purchasePlatform || body.platform),
    });

    await writeRevenueCatAuditLog({
      ...baseAudit,
      source: state.verification.source,
      user_id: resolved.userId,
      app_user_id: resolved.appUserId,
      expected_app_user_id: identity.expectedAppUserId,
      identity_payload_matched: identity.payloadIdentityMatched,
      identity_server_matched: identity.serverIdentityMatched,
      identity_effective_matched: identity.identityMatched,
      entitlement_id: entitlementId,
      is_active: isActive,
      expiration_date: toIsoTimestampOrNull(effectiveExpirationDate),
      verification_source: state.verification.source,
      verification_reason: state.verification.reason || null,
      access_action: accessSync.action || accessSync.reason || "skipped",
      success: true,
      payload: body,
    });

    console.log(
      `[revenuecat][sync] id=${requestId} source=${state.verification.source} userId=${resolved.userId} appUserId=${resolved.appUserId} expected=${identity.expectedAppUserId || "-"} payloadMatched=${boolForLog(identity.payloadIdentityMatched)} serverMatched=${boolForLog(identity.serverIdentityMatched)} entitlement=${entitlementId} active=${isActive} action=${accessSync.action || "skipped"}`
    );

    return res.json({
      ok: true,
      requestId,
      userId: resolved.userId,
      appUserId: resolved.appUserId,
      expectedAppUserId: identity.expectedAppUserId,
      identityMatched: identity.identityMatched,
      identityServerMatched: identity.serverIdentityMatched,
      identityPayloadMatched: identity.payloadIdentityMatched,
      entitlementId,
      isActive,
      expirationDate: effectiveExpirationDate || null,
      verification: state.verification,
      accessSync,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    await writeRevenueCatAuditLog({
      ...baseAudit,
      success: false,
      error: err.message || "Sync failed.",
      payload: req.body || {},
    });
    console.error(`[revenuecat][sync][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Sync failed." });
  }
});

app.post("/revenuecat/subscription/event", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/subscription/event",
    auth_mode: req.revenueCatAuthMode || "unknown",
  };

  try {
    if (req.revenueCatGuest) {
      return res.status(200).json({
        ok: true,
        skipped: true,
        reason: "guest_noop",
      });
    }

    const body = req.body || {};
    const source = normalizeRevenueCatAppUserId(body.source) || "unknown";
    const result = normalizeRevenueCatAppUserId(body.result) || "unknown";
    const success = toBool(body.success);
    const entitlementId = normalizeRevenueCatAppUserId(body.entitlementId);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const expectedAppUserId = normalizeRevenueCatAppUserId(body.expectedAppUserId);
    const originalAppUserId = normalizeRevenueCatAppUserId(
      body.originalAppUserId || body.original_app_user_id
    );
    const payloadIdentityMatched = toNullableBool(body.identityMatched);
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const hasJwtBodyMismatch =
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId;
    const resolvedUserIdInput =
      req.revenueCatAuthMode === "jwt" && jwtUserId ? jwtUserId : bodyUserId || jwtUserId;

    if (hasJwtBodyMismatch) {
      console.warn(
        `[revenuecat][event][jwt-mismatch] id=${requestId} bodyUserId=${bodyUserId} jwtUserId=${jwtUserId} mode=jwt_using_token_user_id`
      );
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

    const identity = buildRevenueCatIdentityContext({
      expectedAppUserId,
      payloadIdentityMatched,
      resolvedAppUserId: resolved?.appUserId || appUserId,
    });
    if (identity.serverIdentityMatched === false && resolved) {
      console.warn(
        `[revenuecat][identity-mismatch] id=${requestId} endpoint=event userId=${resolved.userId} expected=${identity.expectedAppUserId} resolved=${resolved.appUserId}`
      );
    }

    let verification = null;
    let accessSync = null;
    let syncedIsActive = null;
    let syncedExpirationDate = null;
    if (resolved && entitlementId) {
      const lockFallbackAppUserId = await getRevenueCatLockFallbackAppUserId(
        resolved.userId,
        entitlementId
      );
      const state = await resolveEntitlementStateWithFallback({
        appUserId: resolved.appUserId,
        legacyAppUserIds: [
          resolved.user?.payUniqe,
          lockFallbackAppUserId,
          originalAppUserId,
        ],
        entitlementId,
        fallbackIsActive: body.isActive,
        fallbackExpirationDate: body.expirationDate,
        allowFallbackOverride: false,
      });
      verification = state.verification;

      const canSyncFromPayload = body.isActive !== undefined;
      if (state.verification.checked || canSyncFromPayload) {
        syncedIsActive = state.isActive;
        syncedExpirationDate = state.expirationDate;
        accessSync = await syncRevenueCatAccessByEntitlement({
          userId: resolved.userId,
          entitlementId,
          isActive: syncedIsActive,
          expirationDate: syncedExpirationDate,
          appUserId: resolved.appUserId,
          originalAppUserId: resolved.user?.payUniqe || null,
          productIdentifier: body.productIdentifier || null,
          purchasePlatform:
            state.verification.purchasePlatform ||
            normalizePurchasePlatform(body.purchasePlatform || body.platform),
        });
      } else {
        accessSync = {
          mapped: false,
          reason: "missing_is_active_and_no_verification",
          entitlementId,
        };
      }
    }

    await writeRevenueCatAuditLog({
      ...baseAudit,
      source,
      event_type: result,
      result,
      success,
      user_id: resolved?.userId ?? null,
      app_user_id: resolved?.appUserId ?? appUserId ?? null,
      expected_app_user_id: identity.expectedAppUserId,
      identity_payload_matched: identity.payloadIdentityMatched,
      identity_server_matched: identity.serverIdentityMatched,
      identity_effective_matched: identity.identityMatched,
      entitlement_id: entitlementId || null,
      is_active: syncedIsActive,
      expiration_date: toIsoTimestampOrNull(syncedExpirationDate),
      verification_source: verification?.source || null,
      verification_reason: verification?.reason || null,
      access_action: accessSync?.action || accessSync?.reason || "none",
      payload: body,
    });

    console.log(
      `[revenuecat][event] id=${requestId} source=${source} result=${result} success=${success} userId=${resolved?.userId ?? "-"} appUserId=${resolved?.appUserId ?? appUserId ?? "-"} expected=${identity.expectedAppUserId || "-"} payloadMatched=${boolForLog(identity.payloadIdentityMatched)} serverMatched=${boolForLog(identity.serverIdentityMatched)} entitlement=${entitlementId || "-"} action=${accessSync?.action || "none"}`
    );

    return res.json({
      ok: true,
      requestId,
      source,
      result,
      success,
      userId: resolved?.userId ?? null,
      appUserId: resolved?.appUserId ?? appUserId ?? null,
      expectedAppUserId: identity.expectedAppUserId,
      identityMatched: identity.identityMatched,
      identityServerMatched: identity.serverIdentityMatched,
      identityPayloadMatched: identity.payloadIdentityMatched,
      entitlementId: entitlementId || null,
      verification,
      accessSync,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    await writeRevenueCatAuditLog({
      ...baseAudit,
      success: false,
      error: err.message || "Event failed.",
      payload: req.body || {},
    });
    console.error(`[revenuecat][event][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Event failed." });
  }
});

app.post("/revenuecat/subscription/refresh", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/subscription/refresh",
    auth_mode: req.revenueCatAuthMode || "unknown",
  };

  try {
    if (req.revenueCatGuest) {
      return res.status(200).json({
        ok: true,
        skipped: true,
        reason: "guest_noop",
      });
    }

    const body = req.body || {};
    const source = normalizeRevenueCatAppUserId(body.source) || "manual_refresh";
    const entitlementId =
      normalizeRevenueCatAppUserId(body.entitlementId) ||
      normalizeRevenueCatAppUserId(REVENUECAT_DEFAULT_ENTITLEMENT_ID);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const originalAppUserId = normalizeRevenueCatAppUserId(body.originalAppUserId);
    const expectedAppUserId = normalizeRevenueCatAppUserId(body.expectedAppUserId);
    const payloadIdentityMatched = toNullableBool(body.identityMatched);
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const hasJwtBodyMismatch =
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId;
    const resolvedUserIdInput =
      req.revenueCatAuthMode === "jwt" && jwtUserId ? jwtUserId : bodyUserId || jwtUserId;

    if (!entitlementId) {
      return res.status(400).json({ ok: false, error: "entitlementId is required." });
    }
    if (!resolvedUserIdInput && !appUserId) {
      return res.status(400).json({ ok: false, error: "userId or appUserId is required." });
    }
    if (hasJwtBodyMismatch) {
      console.warn(
        `[revenuecat][refresh][jwt-mismatch] id=${requestId} bodyUserId=${bodyUserId} jwtUserId=${jwtUserId} mode=jwt_using_token_user_id`
      );
    }

    const resolved = await resolveRevenueCatUser({
      userId: resolvedUserIdInput,
      appUserId,
      allowPayUniqeRelink: req.revenueCatAuthMode === "jwt",
    });

    if (req.revenueCatAuthMode === "jwt" && jwtUserId && resolved.userId !== jwtUserId) {
      return res.status(403).json({ ok: false, error: "User mismatch." });
    }

    const identity = buildRevenueCatIdentityContext({
      expectedAppUserId,
      payloadIdentityMatched,
      resolvedAppUserId: resolved.appUserId,
    });
    if (identity.serverIdentityMatched === false) {
      console.warn(
        `[revenuecat][identity-mismatch] id=${requestId} endpoint=refresh userId=${resolved.userId} expected=${identity.expectedAppUserId} resolved=${resolved.appUserId}`
      );
    }

    const lockFallbackAppUserId = await getRevenueCatLockFallbackAppUserId(
      resolved.userId,
      entitlementId
    );
    const state = await resolveEntitlementStateWithFallback({
      appUserId: resolved.appUserId,
      legacyAppUserIds: [
        resolved.user?.payUniqe,
        lockFallbackAppUserId,
        originalAppUserId,
      ],
      entitlementId,
      fallbackIsActive: body.isActive,
      fallbackExpirationDate: body.expirationDate,
      allowFallbackOverride: false,
    });
    const accessSync = await syncRevenueCatAccessByEntitlement({
      userId: resolved.userId,
      entitlementId,
      isActive: state.isActive,
      expirationDate: state.expirationDate,
      appUserId: resolved.appUserId,
      originalAppUserId: originalAppUserId || resolved.user?.payUniqe || null,
      productIdentifier: body.productIdentifier || null,
      purchasePlatform:
        state.verification.purchasePlatform ||
        normalizePurchasePlatform(body.purchasePlatform || body.platform),
    });

    await writeRevenueCatAuditLog({
      ...baseAudit,
      source,
      user_id: resolved.userId,
      app_user_id: resolved.appUserId,
      expected_app_user_id: identity.expectedAppUserId,
      identity_payload_matched: identity.payloadIdentityMatched,
      identity_server_matched: identity.serverIdentityMatched,
      identity_effective_matched: identity.identityMatched,
      entitlement_id: entitlementId,
      is_active: state.isActive,
      expiration_date: toIsoTimestampOrNull(state.expirationDate),
      verification_source: state.verification.source || null,
      verification_reason: state.verification.reason || null,
      access_action: accessSync.action || accessSync.reason || "none",
      success: true,
      payload: body,
    });

    console.log(
      `[revenuecat][refresh] id=${requestId} source=${source} userId=${resolved.userId} appUserId=${resolved.appUserId} expected=${identity.expectedAppUserId || "-"} payloadMatched=${boolForLog(identity.payloadIdentityMatched)} serverMatched=${boolForLog(identity.serverIdentityMatched)} entitlement=${entitlementId} active=${state.isActive} action=${accessSync.action || "none"}`
    );

    return res.json({
      ok: true,
      requestId,
      source,
      userId: resolved.userId,
      appUserId: resolved.appUserId,
      expectedAppUserId: identity.expectedAppUserId,
      identityMatched: identity.identityMatched,
      identityServerMatched: identity.serverIdentityMatched,
      identityPayloadMatched: identity.payloadIdentityMatched,
      entitlementId,
      isActive: state.isActive,
      expirationDate: state.expirationDate || null,
      verification: state.verification,
      accessSync,
      usedFallback: state.usedFallback,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    await writeRevenueCatAuditLog({
      ...baseAudit,
      source: normalizeRevenueCatAppUserId(req.body?.source) || "manual_refresh",
      success: false,
      error: err.message || "Refresh failed.",
      payload: req.body || {},
    });
    console.error(`[revenuecat][refresh][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Refresh failed." });
  }
});

app.post("/revenuecat/subscription/grant", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/subscription/grant",
    auth_mode: req.revenueCatAuthMode || "unknown",
  };

  try {
    const body = req.body || {};
    const source = normalizeRevenueCatAppUserId(body.source) || "web_checkout";
    const entitlementId =
      normalizeRevenueCatAppUserId(body.entitlementId) ||
      normalizeRevenueCatAppUserId(REVENUECAT_DEFAULT_ENTITLEMENT_ID);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const expectedAppUserId = normalizeRevenueCatAppUserId(body.expectedAppUserId);
    const payloadIdentityMatched = toNullableBool(body.identityMatched);
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const hasJwtBodyMismatch =
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId;
    const resolvedUserIdInput =
      req.revenueCatAuthMode === "jwt" && jwtUserId ? jwtUserId : bodyUserId || jwtUserId;
    const durationMonths = toPositiveIntOrNull(
      body.durationMonths || body.periodMonths || body.period_months
    );
    const explicitExpirationDate = toIsoTimestampOrNull(body.expirationDate);
    const lifetime = toBool(body.lifetime) || toBool(body.isLifetime);
    let targetExpirationDate = explicitExpirationDate;

    if (!targetExpirationDate && durationMonths) {
      const expiration = new Date();
      expiration.setMonth(expiration.getMonth() + durationMonths);
      targetExpirationDate = expiration.toISOString();
    }

    if (!entitlementId) {
      return res.status(400).json({ ok: false, error: "entitlementId is required." });
    }
    if (!resolvedUserIdInput && !appUserId) {
      return res.status(400).json({ ok: false, error: "userId or appUserId is required." });
    }
    if (!lifetime && !targetExpirationDate) {
      return res.status(400).json({
        ok: false,
        error: "expirationDate, durationMonths or lifetime must be provided.",
      });
    }
    if (hasJwtBodyMismatch) {
      console.warn(
        `[revenuecat][grant][jwt-mismatch] id=${requestId} bodyUserId=${bodyUserId} jwtUserId=${jwtUserId} mode=jwt_using_token_user_id`
      );
    }

    const resolved = await resolveRevenueCatUser({
      userId: resolvedUserIdInput,
      appUserId,
      allowPayUniqeRelink: req.revenueCatAuthMode === "jwt",
    });

    if (req.revenueCatAuthMode === "jwt" && jwtUserId && resolved.userId !== jwtUserId) {
      return res.status(403).json({ ok: false, error: "User mismatch." });
    }

    const identity = buildRevenueCatIdentityContext({
      expectedAppUserId,
      payloadIdentityMatched,
      resolvedAppUserId: resolved.appUserId,
    });
    if (identity.serverIdentityMatched === false) {
      console.warn(
        `[revenuecat][identity-mismatch] id=${requestId} endpoint=grant userId=${resolved.userId} expected=${identity.expectedAppUserId} resolved=${resolved.appUserId}`
      );
    }

    const grant = await grantRevenueCatPromotionalEntitlement({
      appUserId: resolved.appUserId,
      entitlementId,
      expirationDate: targetExpirationDate,
      lifetime,
      platform: normalizeRevenueCatAppUserId(body.platform) || REVENUECAT_WEB_CHECKOUT_PLATFORM,
    });
    const state = await resolveEntitlementStateWithFallback({
      appUserId: resolved.appUserId,
      entitlementId,
      fallbackIsActive: true,
      fallbackExpirationDate: grant.expirationDate ?? targetExpirationDate,
      allowFallbackOverride: true,
    });
    const accessSync = await syncRevenueCatAccessByEntitlement({
      userId: resolved.userId,
      entitlementId,
      isActive: state.isActive,
      expirationDate: state.expirationDate,
      appUserId: resolved.appUserId,
      originalAppUserId: null,
      productIdentifier: body.productIdentifier || null,
      purchasePlatform:
        state.verification.purchasePlatform ||
        normalizePurchasePlatform(body.purchasePlatform || body.platform),
    });

    await writeRevenueCatAuditLog({
      ...baseAudit,
      source,
      event_type: "grant",
      user_id: resolved.userId,
      app_user_id: resolved.appUserId,
      expected_app_user_id: identity.expectedAppUserId,
      identity_payload_matched: identity.payloadIdentityMatched,
      identity_server_matched: identity.serverIdentityMatched,
      identity_effective_matched: identity.identityMatched,
      entitlement_id: entitlementId,
      is_active: state.isActive,
      expiration_date: toIsoTimestampOrNull(state.expirationDate),
      verification_source: state.verification.source || null,
      verification_reason: state.verification.reason || null,
      access_action: accessSync.action || accessSync.reason || "none",
      success: true,
      payload: body,
    });

    console.log(
      `[revenuecat][grant] id=${requestId} source=${source} userId=${resolved.userId} appUserId=${resolved.appUserId} expected=${identity.expectedAppUserId || "-"} payloadMatched=${boolForLog(identity.payloadIdentityMatched)} serverMatched=${boolForLog(identity.serverIdentityMatched)} entitlement=${entitlementId} active=${state.isActive} action=${accessSync.action || "none"}`
    );

    return res.json({
      ok: true,
      requestId,
      source,
      userId: resolved.userId,
      appUserId: resolved.appUserId,
      expectedAppUserId: identity.expectedAppUserId,
      identityMatched: identity.identityMatched,
      identityServerMatched: identity.serverIdentityMatched,
      identityPayloadMatched: identity.payloadIdentityMatched,
      entitlementId,
      isActive: state.isActive,
      expirationDate: state.expirationDate || null,
      verification: state.verification,
      accessSync,
      usedFallback: state.usedFallback,
      grant,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    await writeRevenueCatAuditLog({
      ...baseAudit,
      source: normalizeRevenueCatAppUserId(req.body?.source) || "web_checkout",
      event_type: "grant",
      success: false,
      error: err.message || "Grant failed.",
      payload: req.body || {},
    });
    console.error(`[revenuecat][grant][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Grant failed." });
  }
});

app.post("/revenuecat/subscription/revoke", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/subscription/revoke",
    auth_mode: req.revenueCatAuthMode || "unknown",
  };

  try {
    const body = req.body || {};
    const source = normalizeRevenueCatAppUserId(body.source) || "manual_revoke";
    const entitlementId =
      normalizeRevenueCatAppUserId(body.entitlementId) ||
      normalizeRevenueCatAppUserId(REVENUECAT_DEFAULT_ENTITLEMENT_ID);
    const appUserId = normalizeRevenueCatAppUserId(body.appUserId);
    const expectedAppUserId = normalizeRevenueCatAppUserId(body.expectedAppUserId);
    const payloadIdentityMatched = toNullableBool(body.identityMatched);
    const bodyUserId = toPositiveIntOrNull(body.userId);
    const jwtUserId = extractJwtUserId(req.jwt);
    const hasJwtBodyMismatch =
      req.revenueCatAuthMode === "jwt" &&
      bodyUserId &&
      jwtUserId &&
      bodyUserId !== jwtUserId;
    const resolvedUserIdInput =
      req.revenueCatAuthMode === "jwt" && jwtUserId ? jwtUserId : bodyUserId || jwtUserId;

    if (!entitlementId) {
      return res.status(400).json({ ok: false, error: "entitlementId is required." });
    }
    if (!resolvedUserIdInput && !appUserId) {
      return res.status(400).json({ ok: false, error: "userId or appUserId is required." });
    }
    if (hasJwtBodyMismatch) {
      console.warn(
        `[revenuecat][revoke][jwt-mismatch] id=${requestId} bodyUserId=${bodyUserId} jwtUserId=${jwtUserId} mode=jwt_using_token_user_id`
      );
    }

    const resolved = await resolveRevenueCatUser({
      userId: resolvedUserIdInput,
      appUserId,
      allowPayUniqeRelink: req.revenueCatAuthMode === "jwt",
    });

    if (req.revenueCatAuthMode === "jwt" && jwtUserId && resolved.userId !== jwtUserId) {
      return res.status(403).json({ ok: false, error: "User mismatch." });
    }

    const identity = buildRevenueCatIdentityContext({
      expectedAppUserId,
      payloadIdentityMatched,
      resolvedAppUserId: resolved.appUserId,
    });
    if (identity.serverIdentityMatched === false) {
      console.warn(
        `[revenuecat][identity-mismatch] id=${requestId} endpoint=revoke userId=${resolved.userId} expected=${identity.expectedAppUserId} resolved=${resolved.appUserId}`
      );
    }

    const revoke = await revokeRevenueCatPromotionalEntitlement({
      appUserId: resolved.appUserId,
      entitlementId,
    });
    const fallbackExpirationDate = new Date().toISOString();
    const state = await resolveEntitlementStateWithFallback({
      appUserId: resolved.appUserId,
      entitlementId,
      fallbackIsActive: false,
      fallbackExpirationDate,
      allowFallbackOverride: true,
    });
    const accessSync = await syncRevenueCatAccessByEntitlement({
      userId: resolved.userId,
      entitlementId,
      isActive: state.isActive,
      expirationDate: state.expirationDate,
      appUserId: resolved.appUserId,
      originalAppUserId: null,
      productIdentifier: body.productIdentifier || null,
    });

    await writeRevenueCatAuditLog({
      ...baseAudit,
      source,
      event_type: "revoke",
      user_id: resolved.userId,
      app_user_id: resolved.appUserId,
      expected_app_user_id: identity.expectedAppUserId,
      identity_payload_matched: identity.payloadIdentityMatched,
      identity_server_matched: identity.serverIdentityMatched,
      identity_effective_matched: identity.identityMatched,
      entitlement_id: entitlementId,
      is_active: state.isActive,
      expiration_date: toIsoTimestampOrNull(state.expirationDate),
      verification_source: state.verification.source || null,
      verification_reason: state.verification.reason || null,
      access_action: accessSync.action || accessSync.reason || "none",
      success: true,
      payload: body,
    });

    console.log(
      `[revenuecat][revoke] id=${requestId} source=${source} userId=${resolved.userId} appUserId=${resolved.appUserId} expected=${identity.expectedAppUserId || "-"} payloadMatched=${boolForLog(identity.payloadIdentityMatched)} serverMatched=${boolForLog(identity.serverIdentityMatched)} entitlement=${entitlementId} active=${state.isActive} action=${accessSync.action || "none"}`
    );

    return res.json({
      ok: true,
      requestId,
      source,
      userId: resolved.userId,
      appUserId: resolved.appUserId,
      expectedAppUserId: identity.expectedAppUserId,
      identityMatched: identity.identityMatched,
      identityServerMatched: identity.serverIdentityMatched,
      identityPayloadMatched: identity.payloadIdentityMatched,
      entitlementId,
      isActive: state.isActive,
      expirationDate: state.expirationDate || null,
      verification: state.verification,
      accessSync,
      usedFallback: state.usedFallback,
      revoke,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    await writeRevenueCatAuditLog({
      ...baseAudit,
      source: normalizeRevenueCatAppUserId(req.body?.source) || "manual_revoke",
      event_type: "revoke",
      success: false,
      error: err.message || "Revoke failed.",
      payload: req.body || {},
    });
    console.error(`[revenuecat][revoke][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Revoke failed." });
  }
});

app.post("/revenuecat/webhook", requireRevenueCatWebhookAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/webhook",
    auth_mode: req.revenueCatAuthMode || "webhook",
  };

  try {
    const payload = req.body || {};
    const normalized = normalizeRevenueCatWebhookEvent(payload);
    if (!normalized.appUserId) {
      return res.status(400).json({ ok: false, error: "Webhook app_user_id is required." });
    }
    if (!normalized.entitlementId) {
      return res.status(400).json({ ok: false, error: "Webhook entitlement id is required." });
    }

    const resolved = await resolveRevenueCatUser({
      appUserId: normalized.appUserId,
      allowPayUniqeRelink: false,
    });

    const lockFallbackAppUserId = await getRevenueCatLockFallbackAppUserId(
      resolved.userId,
      normalized.entitlementId
    );
    const state = await resolveEntitlementStateWithFallback({
      appUserId: resolved.appUserId,
      legacyAppUserIds: [
        resolved.user?.payUniqe,
        lockFallbackAppUserId,
        normalized.event?.originalAppUserId,
      ],
      entitlementId: normalized.entitlementId,
      fallbackIsActive: normalized.inferredIsActive,
      fallbackExpirationDate: normalized.expirationDate,
      allowFallbackOverride: false,
    });
    const verification = state.verification;

    if (!verification.checked && normalized.inferredIsActive === null) {
      return res.status(400).json({
        ok: false,
        error: "Unable to infer entitlement state from webhook payload.",
      });
    }

    const isActive = state.isActive;
    const effectiveExpirationDate = state.expirationDate;
    const accessSync = await syncRevenueCatAccessByEntitlement({
      userId: resolved.userId,
      entitlementId: normalized.entitlementId,
      isActive,
      expirationDate: effectiveExpirationDate,
      appUserId: resolved.appUserId,
      originalAppUserId: normalized.event?.originalAppUserId || null,
      productIdentifier:
        normalized.event?.product_id ||
        normalized.event?.productId ||
        normalized.event?.product_identifier ||
        null,
      purchasePlatform: verification.purchasePlatform,
    });

    await writeRevenueCatAuditLog({
      ...baseAudit,
      source: "webhook",
      event_type: normalized.eventType,
      user_id: resolved.userId,
      app_user_id: resolved.appUserId,
      entitlement_id: normalized.entitlementId,
      is_active: isActive,
      expiration_date: toIsoTimestampOrNull(effectiveExpirationDate),
      verification_source: verification.source,
      verification_reason: verification.reason || null,
      access_action: accessSync.action || accessSync.reason || "none",
      success: true,
      payload,
    });

    console.log(
      `[revenuecat][webhook] id=${requestId} eventId=${normalized.eventId || "-"} type=${normalized.eventType} userId=${resolved.userId} appUserId=${resolved.appUserId} entitlement=${normalized.entitlementId} active=${isActive} action=${accessSync.action || "none"}`
    );

    return res.json({
      ok: true,
      requestId,
      eventId: normalized.eventId || null,
      eventType: normalized.eventType,
      userId: resolved.userId,
      appUserId: resolved.appUserId,
      entitlementId: normalized.entitlementId,
      isActive,
      expirationDate: effectiveExpirationDate || null,
      verification,
      accessSync,
    });
  } catch (err) {
    const status = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    await writeRevenueCatAuditLog({
      ...baseAudit,
      source: "webhook",
      success: false,
      error: err.message || "Webhook failed.",
      payload: req.body || {},
    });
    console.error(`[revenuecat][webhook][error] id=${requestId} msg=${err.message}`);
    return res.status(status).json({ ok: false, error: err.message || "Webhook failed." });
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
  if (!safeTokenCompare(signature, expectedSig)) {
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

const uploadToBunny = async (filePath, type, scope, filename) => {
  const url = `/${type}/${scope}/${filename}`;
  try {
    const contentType =
      path.extname(filename || filePath).toLowerCase() === ".pdf"
        ? "application/pdf"
        : "application/octet-stream";
    const response = await bunnyRequest(
      {
        method: "PUT",
        url,
        data: fs.createReadStream(filePath),
        timeout: BUNNY_UPLOAD_TIMEOUT_MS,
        headers: {
          "Content-Type": contentType,
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
      },
      { retries: BUNNY_UPLOAD_RETRIES }
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

const ghostscriptAvailable = (() => {
  let checked = false;
  let available = false;
  return () => {
    if (checked) return available;
    checked = true;
    try {
      const probe = spawnSync("gs", ["--version"], {
        stdio: "ignore",
      });
      available = !probe.error && probe.status === 0;
    } catch (_) {
      available = false;
    }
    return available;
  };
})();

const runGhostscriptCompression = (inputPath, outputPath) =>
  new Promise((resolve) => {
    const args = [
      "-q",
      "-dNOPAUSE",
      "-dBATCH",
      "-dSAFER",
      "-sDEVICE=pdfwrite",
      "-dCompatibilityLevel=1.4",
      `-dPDFSETTINGS=${PDF_UPLOAD_OPTIMIZE_PDFSETTINGS}`,
      "-dDetectDuplicateImages=true",
      "-dCompressFonts=true",
      "-dSubsetFonts=true",
      "-dAutoRotatePages=/None",
      "-dDownsampleColorImages=true",
      "-dColorImageDownsampleType=/Bicubic",
      "-dColorImageResolution=144",
      "-dDownsampleGrayImages=true",
      "-dGrayImageDownsampleType=/Bicubic",
      "-dGrayImageResolution=144",
      "-dDownsampleMonoImages=true",
      "-dMonoImageDownsampleType=/Subsample",
      "-dMonoImageResolution=300",
      `-sOutputFile=${outputPath}`,
      inputPath,
    ];

    const child = spawn("gs", args, {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      resolve({ ok: false, available: false, error });
    });
    child.on("close", (code) => {
      resolve({
        ok: code === 0,
        available: true,
        code,
        stderr: stderr.trim(),
      });
    });
  });

const formatBytes = (bytes) => {
  if (!Number.isFinite(bytes) || bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unitIndex]}`;
};

const maybeOptimizePdfUpload = async (inputPath, originalName) => {
  const ext = path.extname(originalName || inputPath).toLowerCase();
  if (ext !== ".pdf") {
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  let inputStat;
  try {
    inputStat = await fs.promises.stat(inputPath);
  } catch (_) {
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  if (inputStat.size < PDF_UPLOAD_OPTIMIZE_MIN_BYTES) {
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  if (!ghostscriptAvailable()) {
    console.warn(
      `[upload][pdf-optimize] ghostscript not available; skipping optimization for ${path.basename(
        inputPath
      )}`
    );
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  const outputPath = path.join(
    TMP_DIR,
    `${Date.now()}-${crypto.randomUUID()}-optimized.pdf`
  );
  const result = await runGhostscriptCompression(inputPath, outputPath);
  if (!result.ok) {
    await cleanupTempUpload(outputPath);
    console.warn(
      `[upload][pdf-optimize] failed for ${path.basename(inputPath)}: ${result.stderr || result.error?.message || result.code}`
    );
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  let outputStat;
  try {
    outputStat = await fs.promises.stat(outputPath);
  } catch (error) {
    await cleanupTempUpload(outputPath);
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  if (!outputStat || !outputStat.size || outputStat.size >= inputStat.size * PDF_UPLOAD_OPTIMIZE_KEEP_RATIO) {
    await cleanupTempUpload(outputPath);
    console.log(
      `[upload][pdf-optimize] kept original ${path.basename(inputPath)} size=${formatBytes(
        inputStat.size
      )}`
    );
    return { filePath: inputPath, optimized: false, cleanupPath: null };
  }

  console.log(
    `[upload][pdf-optimize] optimized ${path.basename(inputPath)} ${formatBytes(
      inputStat.size
    )} -> ${formatBytes(outputStat.size)} preset=${PDF_UPLOAD_OPTIMIZE_PDFSETTINGS}`
  );
  return { filePath: outputPath, optimized: true, cleanupPath: outputPath };
};

const deleteFromBunny = async (fileReference) => {
  const parsed =
    typeof fileReference === "string" ? parseManagedFileReference(fileReference) : fileReference;
  if (!parsed?.storagePath) {
    throw new Error("Managed CDN file reference is required.");
  }

  try {
    await bunnyRequest(
      {
        method: "DELETE",
        url: parsed.storagePath,
      },
      { retries: 0 }
    );
    return { deleted: true, ...parsed };
  } catch (err) {
    const statusCode = err.response?.status || 500;
    if (statusCode === 404) {
      return { deleted: false, ...parsed };
    }
    const errorMsg = err.response?.data?.Message || err.response?.data || err.message;
    console.error(`[BunnyCDN Delete Error] ${statusCode}: ${JSON.stringify(errorMsg)}`);
    console.error(`[BunnyCDN Delete Details] URL: ${bunnyHttp.defaults.baseURL}${parsed.storagePath}`);
    throw new Error(`BunnyCDN delete failed (${statusCode}): ${JSON.stringify(errorMsg)}`);
  }
};

const cleanupManagedBunnyFile = async (fileReference, { logPrefix = "[bunny][cleanup]" } = {}) => {
  const parsed =
    typeof fileReference === "string" ? parseManagedFileReference(fileReference) : fileReference;
  if (!parsed?.storagePath) {
    return { skipped: true, deleted: false };
  }

  try {
    return await deleteFromBunny(parsed);
  } catch (err) {
    console.warn(`${logPrefix} path=${parsed.storagePath} msg=${err?.message || err}`);
    return { skipped: false, deleted: false, error: err };
  }
};

const cleanupTempUpload = async (filePath) => {
  if (!filePath) return;
  try {
    await fs.promises.unlink(filePath);
  } catch (err) {
    if (err?.code !== "ENOENT") {
      console.warn(`[upload][cleanup-warning] path=${filePath} msg=${err?.message}`);
    }
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
  const tempFilePath = req.file?.path;
  let uploadPath = tempFilePath;
  let optimizedTempPath = null;
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
    const optimized = await maybeOptimizePdfUpload(req.file.path, req.file.originalname);
    uploadPath = optimized.filePath;
    optimizedTempPath = optimized.cleanupPath;
    await uploadToBunny(uploadPath, type, "public", filename);

    return res.json({
      ok: true,
      scope: "public",
      type,
      file: filename,
      url: `https://${BUNNY_SETTINGS.cdnUrl}/${type}/public/${filename}`,
    });
  } catch (err) {
    next(err);
  } finally {
    await cleanupTempUpload(tempFilePath);
    if (optimizedTempPath && optimizedTempPath !== tempFilePath) {
      await cleanupTempUpload(optimizedTempPath);
    }
  }
});

app.post("/upload/private", requireJwt, upload.single("file"), async (req, res, next) => {
  const tempFilePath = req.file?.path;
  let uploadPath = tempFilePath;
  let optimizedTempPath = null;
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
    const optimized = await maybeOptimizePdfUpload(req.file.path, req.file.originalname);
    uploadPath = optimized.filePath;
    optimizedTempPath = optimized.cleanupPath;
    await uploadToBunny(uploadPath, type, "private", filename);

    return res.json({
      ok: true,
      scope: "private",
      type,
      file: filename,
      url: `https://${BUNNY_SETTINGS.cdnUrl}/${type}/private/${filename}`,
    });
  } catch (err) {
    next(err);
  } finally {
    await cleanupTempUpload(tempFilePath);
    if (optimizedTempPath && optimizedTempPath !== tempFilePath) {
      await cleanupTempUpload(optimizedTempPath);
    }
  }
});

app.post("/upload/delete", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();

  try {
    await ensureAdminJwtActor(req);
    const parsed = parseManagedFileReference(req.body?.url || req.body?.path);
    if (!parsed) {
      return res.status(400).json({
        ok: false,
        error: "Managed CDN url/path is required.",
        requestId,
      });
    }

    const result = await deleteFromBunny(parsed);
    return res.json({
      ok: true,
      deleted: result.deleted,
      type: parsed.type,
      scope: parsed.scope,
      path: parsed.storagePath,
      requestId,
    });
  } catch (err) {
    const statusCode = err?.statusCode || 502;
    console.error(`[upload][delete][error] id=${requestId} msg=${err?.message || err}`);
    return res.status(statusCode).json({
      ok: false,
      error: statusCode === 403 ? "Admin privileges required." : "Delete failed.",
      requestId,
    });
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

const buildPrivatePdfHeaders = (filename, options = {}) => {
  const headers = {
    "Content-Type": "application/pdf",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    Pragma: "no-cache",
    "X-Content-Type-Options": "nosniff",
  };

  if (filename) {
    headers["Content-Disposition"] = `inline; filename="${sanitizeFilename(path.basename(String(filename)))}"`;
  }

  if (options.withFrameAncestors) {
    headers["Content-Security-Policy"] = `frame-ancestors ${FRAME_ANCESTORS_DIRECTIVE}`;
  }

  return headers;
};

const streamPrivatePdfFromPath = async ({
  req,
  res,
  route,
  action,
  rawPath,
  headers,
  successMessage,
}) => {
  const parsed = parsePrivatePath(rawPath);
  if (!parsed) {
    logPdfRequest({
      req,
      scope: "private",
      route,
      action,
      filename: rawPath,
      status: 400,
      outcome: "error",
      message: "Invalid path format.",
    });
    res.status(400).json({
      ok: false,
      error: "path must be like /private/<type>/<file.pdf>",
    });
    return;
  }

  const logBase = {
    req,
    scope: "private",
    route,
    action,
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
      headers,
      successMessage,
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
};

app.get("/private/:type/:filename", requireJwtOrServiceAuth, async (req, res) => {
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

app.post("/private/view", requireJwtOrServiceAuth, async (req, res) => {
  const rawPath = req.body?.path || req.body?.pdf || req.body?.file;
  await streamPrivatePdfFromPath({
    req,
    res,
    route: "/private/view",
    action: "view-inline",
    rawPath,
    headers: buildPrivatePdfHeaders(rawPath, { withFrameAncestors: true }),
    successMessage: "Inline PDF served from BunnyCDN.",
  });
});

app.post("/private/view-file", requireJwtOrServiceAuth, async (req, res) => {
  const rawPath = req.body?.path || req.body?.pdf || req.body?.file;
  await streamPrivatePdfFromPath({
    req,
    res,
    route: "/private/view-file",
    action: "view-file-raw",
    rawPath,
    headers: buildPrivatePdfHeaders(rawPath),
    successMessage: "Raw PDF served from BunnyCDN.",
  });
});

app.get("/private/view-file", requireJwtOrServiceAuth, async (req, res) => {
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
    const bunnyResponse = await fetchStreamFromBunny(parsed.type, "private", parsed.filename);
    await pipeBunnyStreamToResponse({
      req,
      res,
      bunnyResponse,
      logBase,
      headers: {
        ...corsHeaders,
        ...buildPrivatePdfHeaders(parsed.filename, { withFrameAncestors: true }),
      },
      successMessage: "Secure PDF delivered from BunnyCDN.",
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

app.post("/payment/session", requireJwt, async (req, res, next) => {
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
    const returnUrl = pick("RETURNURL", "returnUrl") || PARATIKA_RETURNURL;
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

app.post("/payment/query-card", requireJwt, async (req, res, next) => {
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
    const customer = await resolvePaymentCustomerId({
      customer: pick("CUSTOMER", "customer"),
      jwt: req.jwt,
    });

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
    const parsedResponse = normalizeParatikaJsonPayload(response.data);
    if (parsedResponse && typeof parsedResponse === "object") {
      const normalized = normalizeQueryCardResponse(parsedResponse);
      return res.status(status).json(normalized);
    }

    if (response.data && typeof response.data === "object") {
      return res.status(status).json(normalizeQueryCardResponse(response.data));
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

app.post("/payment/delete-card", requireJwt, async (req, res, next) => {
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

async function resolvePaymentCustomerId({ customer, jwt }) {
  const directCustomer = String(customer || "").trim();
  if (directCustomer) return directCustomer;

  const jwtUserId = extractJwtUserId(jwt);
  if (!jwtUserId) return null;

  const user = await findUserById(jwtUserId);
  if (!user) return null;

  const payUniqe = String(user.payUniqe || "").trim();
  if (payUniqe) return payUniqe;

  return `Customer-${user.id}`;
}

function normalizeParatikaJsonPayload(data) {
  if (!data) return null;
  if (typeof data === "object") return data;
  if (typeof data !== "string") return null;
  const trimmed = data.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  try {
    return JSON.parse(trimmed);
  } catch (_) {
    return null;
  }
}

function normalizeQueryCardResponse(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return payload;
  }

  const cardList = Array.isArray(payload.cardList) ? payload.cardList : [];
  const responseCode = String(
    payload.responseCode ?? payload.responsecode ?? "",
  ).trim();
  const responseMsg = String(
    payload.responseMsg ?? payload.responsemsg ?? payload.message ?? "",
  ).trim();

  const emptyCardMarkers = [
    "kart bulunamadı",
    "kayıtlı kart bulunamadı",
    "kayıtlı kart yok",
    "no card",
    "no cards",
    "card not found",
    "customer not found",
    "no record",
    "no records",
    "not found",
    "empty",
  ];
  const combined = `${String(payload.errorMsg ?? "")} ${responseMsg}`.toLowerCase();
  if (cardList.length > 0) {
    return {
      ...payload,
      responseCode: "00",
      responseMsg: responseMsg || "Kayıtlı kartlar alındı.",
      errorMsg: "",
      cardList,
    };
  }

  const looksEmpty =
    cardList.length === 0 &&
    (emptyCardMarkers.some((marker) => combined.includes(marker)) ||
      responseCode === "" ||
      responseCode === "99" ||
      responseCode === "404" ||
      responseCode === "204");

  if (!looksEmpty) {
    return payload;
  }

  return {
    ...payload,
    responseCode: "00",
    responseMsg: responseMsg || "Kayıtlı kart bulunamadı.",
    errorMsg: "",
    cardList: [],
  };
}

app.post("/payment/pay", requireJwt, async (req, res, next) => {
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

app.post("/payment/pay/redirect", requireJwt, async (req, res, next) => {
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

app.all("/payment/return", async (req, res) => {
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
    errorCode: normalized.errorCode || "",
    errorMsg: normalized.errorMsg || "",
  });

  const requestedAppReturnOrigin =
    payload.appReturnOrigin || payload.appreturnorigin || null;

  const resolveAppReturnBase = () => {
    const candidate = requestedAppReturnOrigin || PAYMENT_RETURN_REDIRECT_URL || "";
    if (!candidate) return null;
    try {
      const parsed = new URL(String(candidate));
      const origin = parsed.origin;
      const host = parsed.hostname.toLowerCase();
      const isLocalhost =
        host === "localhost" || host === "127.0.0.1" || host === "::1";
      const isTrustedHost =
        host === "yeniasyadijital.com" ||
        host === "www.yeniasyadijital.com" ||
        host === "cdn.yeniasyadijital.com";
      if (!isLocalhost && !isTrustedHost) {
        return null;
      }
      return origin;
    } catch (err) {
      return null;
    }
  };

  const redirectPath = isApproved ? "/payment/pay/success" : "/payment/pay/error";
  const appReturnBase = resolveAppReturnBase();
  const redirectTarget = appReturnBase
    ? new URL(`${redirectPath}?${params.toString()}`, `${appReturnBase}/`).toString()
    : `${redirectPath}?${params.toString()}`;

  if (isApproved) {
    await settleApprovedPaymentOrder({
      merchantPaymentId: normalized.merchantPaymentId,
      paymentSessionToken: normalized.sessionToken,
      responseCode: normalized.responseCode || "00",
      responseMsg: normalized.responseMsg || "Approved",
      errorCode: normalized.errorCode || null,
      errorMsg: normalized.errorMsg || null,
    }).catch((err) => {
      console.error(
        `[payment][settle][error] merchantPaymentId=${normalized.merchantPaymentId || "-"} pgOrderId=${normalized.pgOrderId || "-"} msg=${err.message}`
      );
    });
  }

  return res.redirect(redirectTarget);
});

app.post("/payment/test-session", requireJwt, async (req, res, next) => {
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

app.post("/admin/users/purge", requireJwtOrServiceAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    if (req.hasuraAuthMode === "jwt") {
      await ensureAdminJwtActor(req);
    }

    const userId = toPositiveIntOrNull(req.body?.userId);
    const email = normalizeEmail(req.body?.email);
    const phone = req.body?.phone ? String(req.body.phone).trim() : null;

    if (userId && (email || phone)) {
      return res.status(400).json({
        ok: false,
        error: "userId ile email/phone aynı anda gönderilemez.",
      });
    }
    if (!userId && !email && !phone) {
      return res.status(400).json({
        ok: false,
        error: "userId veya email/phone zorunludur.",
      });
    }

    let purgeResult;
    if (userId) {
      const user = await getInactiveUserIdentityById(userId);
      if (!user) {
        return res.status(404).json({
          ok: false,
          error: "Kullanıcı bulunamadı.",
        });
      }
      if (user.is_active === true) {
        return res.status(409).json({
          ok: false,
          error: "Kalıcı silme yalnızca pasif kullanıcılar için kullanılabilir.",
        });
      }
      const hasIdentity =
        Boolean(normalizeEmail(user.email)) ||
        Boolean(String(user.phone || "").trim());
      purgeResult = hasIdentity
        ? await purgeInactiveUsersForAuthIdentity({
            email: user.email,
            phone: user.phone,
          })
        : await purgeUsersByIdsFromPostgres([userId]);
    } else {
      purgeResult = await purgeInactiveUsersForAuthIdentity({ email, phone });
    }

    console.log(
      `[admin][users][purge][success] id=${requestId} mode=${userId ? "userId" : "identity"} userId=${userId || "-"} email=${email || "-"} phone=${phone || "-"} deletedUserIds=${purgeResult.deletedUserIds.join(",")}`
    );
    return res.json({
      ok: true,
      ...purgeResult,
    });
  } catch (err) {
    console.error(
      `[admin][users][purge][error] id=${requestId} msg=${err.message}`
    );
    return res.status(err.statusCode || 500).json({
      ok: false,
      error: err.message || "Kullanıcı silinemedi.",
    });
  }
});

app.post("/admin/users/revenuecat/reconcile", requireJwtOrServiceAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    const actor = req.hasuraAuthMode === "jwt" ? await ensureAdminJwtActor(req) : null;
    const userId = toPositiveIntOrNull(req.body?.userId);
    const entitlementId =
      normalizeRevenueCatAppUserId(req.body?.entitlementId) ||
      REVENUECAT_DEFAULT_ENTITLEMENT_ID;

    if (!userId) {
      return res.status(400).json({
        ok: false,
        error: "userId zorunludur.",
      });
    }

    const result = await inspectAndRepairRevenueCatSubscriptionForUser({
      userId,
      entitlementId,
    });

    console.log(
      `[admin][users][revenuecat][reconcile][success] id=${requestId} actor=${actor?.id || "-"} userId=${userId} entitlement=${entitlementId} fixed=${result.fixed} activeRevenueCat=${result.activeRevenueCat} payUniqeUpdated=${result.payUniqeUpdated}`
    );
    return res.json({
      ok: true,
      requestId,
      actorUserId: actor?.id || null,
      userId,
      ...result,
    });
  } catch (err) {
    console.error(
      `[admin][users][revenuecat][reconcile][error] id=${requestId} msg=${err.message}`
    );
    return res.status(err.statusCode || 500).json({
      ok: false,
      error: err.message || "Abonelik incelenemedi.",
    });
  }
});

app.post("/admin/notifications/send", requireJwtOrServiceAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    await ensureNotificationAdminActor(req);

    const title = String(req.body?.title || "").trim();
    const body = String(req.body?.body || "").trim();
    const userId = toPositiveIntOrNull(req.body?.userId);
    const userIds = Array.isArray(req.body?.userIds)
      ? req.body.userIds.map((id) => toPositiveIntOrNull(id)).filter(Boolean)
      : [];
    const persist = req.body?.persist === undefined ? true : toBool(req.body.persist);
    const dryRun = toBool(req.body?.dryRun);
    const data = normalizeFcmDataPayload(req.body?.data);

    if (!title || !body) {
      return res
        .status(400)
        .json({ ok: false, error: "title and body are required." });
    }
    if (userId && userIds.length > 0) {
      return res.status(400).json({
        ok: false,
        error: "Provide either userId or userIds, not both.",
      });
    }

    const targets = await fetchUsersWithFirebaseTokens({
      userId: userId || null,
      userIds: userIds.length ? userIds : null,
    });
    if (!targets.length) {
      if (userId) {
        const existingUser = await getUserByIdForAuth(userId);
        if (!existingUser) {
          return res.status(404).json({
            ok: false,
            error: "Kullanıcı bulunamadı.",
          });
        }
        return res.status(404).json({
          ok: false,
          error: "Bu kullanıcıda kayıtlı FCM token bulunamadı.",
        });
      }
      return res.status(404).json({
        ok: false,
        error: "Bu hedef için kayıtlı FCM token bulunamadı.",
      });
    }

    const tokenMap = new Map();
    for (const target of targets) {
      const token = String(target.firebase_token || "").trim();
      const uid = toPositiveIntOrNull(target.id);
      if (!token || !uid) continue;
      const existing = tokenMap.get(token) || [];
      existing.push(uid);
      tokenMap.set(token, existing);
    }

    if (!tokenMap.size) {
      return res.status(404).json({
        ok: false,
        error: "Geçerli FCM token kaydı bulunamadı.",
      });
    }

    let sentCount = 0;
    let failedCount = 0;
    const successfulUserIds = new Set();
    const invalidTokenUserIds = new Set();
    const failedResults = [];

    for (const [token, linkedUserIds] of tokenMap.entries()) {
      // eslint-disable-next-line no-await-in-loop
      const result = await sendFirebaseMessageToToken({
        token,
        title,
        body,
        data,
        dryRun,
      });

      if (result.ok) {
        sentCount += 1;
        for (const uid of linkedUserIds) {
          successfulUserIds.add(uid);
        }
        continue;
      }

      failedCount += 1;
      if (FCM_INVALID_TOKEN_CODES.has(String(result.errorCode || "").toUpperCase())) {
        for (const uid of linkedUserIds) {
          invalidTokenUserIds.add(uid);
        }
      }

      failedResults.push({
        token: maskDeviceToken(token),
        userIds: linkedUserIds,
        statusCode: result.statusCode,
        errorCode: result.errorCode || null,
        errorMessage: result.errorMessage || "Unknown FCM error.",
      });
    }

    let persistedCount = 0;
    if (persist && !dryRun && successfulUserIds.size) {
      persistedCount = await persistNotifications({
        title,
        body,
        userIds: [...successfulUserIds],
      });
    }

    let clearedTokenCount = 0;
    if (invalidTokenUserIds.size) {
      clearedTokenCount = await clearUsersFirebaseTokens([...invalidTokenUserIds]);
    }

    console.log(
      `[notifications][send] id=${requestId} targets=${tokenMap.size} sent=${sentCount} failed=${failedCount} persist=${persistedCount} cleared=${clearedTokenCount} dryRun=${dryRun}`
    );

    return res.json({
      ok: true,
      summary: {
        requestId,
        targetUsers: targets.length,
        targetTokens: tokenMap.size,
        sent: sentCount,
        failed: failedCount,
        persisted: persistedCount,
        clearedInvalidTokens: clearedTokenCount,
        dryRun,
      },
      failed: failedResults.slice(0, 100),
    });
  } catch (err) {
    const statusCode = Number.isInteger(err?.statusCode) ? err.statusCode : 500;
    console.error(`[notifications][send][error] id=${requestId}:`, err?.message || err);
    return res.status(statusCode).json({
      ok: false,
      error: err?.message || "Notification send failed.",
      requestId,
    });
  }
});

app.post("/mail/order-summary", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  try {
    const orderId = String(req.body?.orderId || "").trim();
    const totalRaw = Number(req.body?.total);
    const items = Array.isArray(req.body?.items) ? req.body.items : [];

    if (!orderId) {
      return res.status(400).json({ ok: false, error: "orderId is required." });
    }
    if (!Number.isFinite(totalRaw) || totalRaw < 0) {
      return res.status(400).json({ ok: false, error: "total must be a valid number." });
    }
    if (!items.length) {
      return res.status(400).json({ ok: false, error: "items are required." });
    }

    const user = await getUserMailProfile(userId);
    if (!user) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    const email = normalizeEmail(user.email);
    if (!email) {
      return res.status(400).json({ ok: false, error: "User email is missing." });
    }
    const name = String(user.name || "").trim() || email.split("@")[0];

    const rowsHtml = items
      .slice(0, 200)
      .map((item) => {
        const title = escapeHtml(item?.title || "-");
        const qty = Math.max(1, toPositiveIntOrNull(item?.quantity) || 1);
        const price = formatCurrencyTry(item?.line_total);
        return `<tr><td>${title}</td><td align='center'>${qty}</td><td align='right'>₺${price}</td></tr>`;
      })
      .join("");

    const html = buildOrderSummaryMailHtml({
      name,
      orderId,
      total: totalRaw,
      rowsHtml,
    });
    const text = `Merhaba ${name}, sipariş #${orderId} alındı. Toplam: ₺${formatCurrencyTry(totalRaw)}.`;

    const info = await mailTransporter.sendMail({
      from: MAIL_SETTINGS.from,
      to: email,
      subject: `Sipariş #${orderId} alındı`,
      text,
      html,
    });

    return res.json({
      ok: true,
      sent: true,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      requestId,
    });
  } catch (err) {
    console.error(
      `[mail][order-summary][error] id=${requestId} userId=${userId} msg=${err?.message || err}`
    );
    return res.status(500).json({
      ok: false,
      error: "Order summary mail send failed.",
      requestId,
    });
  }
});

app.post("/mail/welcome", requireJwt, async (req, res) => {
  const requestId = crypto.randomUUID();
  const userId = extractJwtUserId(req.jwt);
  if (!userId) {
    return res.status(401).json({ ok: false, error: "Invalid user token." });
  }

  const claimedAt = new Date().toISOString();
  try {
    const claim = await claimWelcomeMailSend(userId, claimedAt);
    if (Number(claim?.affected_rows || 0) === 0) {
      const userState = await getUserWelcomeMailState(userId);
      if (!userState) {
        return res.status(404).json({ ok: false, error: "User not found." });
      }
      return res.json({
        ok: true,
        skipped: true,
        reason: "already_sent",
        welcomeMailSentAt: userState.welcome_mail_sent_at,
      });
    }

    const user = claim?.returning?.[0];
    const email = normalizeEmail(user?.email);
    if (!email) {
      await rollbackWelcomeMailClaim(userId, claimedAt);
      return res.status(400).json({ ok: false, error: "User email is missing." });
    }
    const name = String(user?.name || "").trim() || email.split("@")[0];

    const subject = `Yeni Asya’ya hoş geldiniz, ${name}`;
    const html = buildWelcomeMailHtml(name);
    const text = `Merhaba ${name}, aramıza katıldığınız için teşekkürler. Keyifli okumalar!`;

    const info = await mailTransporter.sendMail({
      from: MAIL_SETTINGS.from,
      to: email,
      subject,
      text,
      html,
    });

    return res.json({
      ok: true,
      sent: true,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      welcomeMailSentAt: claimedAt,
      requestId,
    });
  } catch (err) {
    try {
      await rollbackWelcomeMailClaim(userId, claimedAt);
    } catch (rollbackErr) {
      console.error(
        `[mail][welcome][rollback-failed] id=${requestId} userId=${userId} msg=${rollbackErr?.message || rollbackErr}`
      );
    }
    console.error(
      `[mail][welcome][error] id=${requestId} userId=${userId} msg=${err?.message || err}`
    );
    return res.status(500).json({
      ok: false,
      error: "Welcome mail send failed.",
      requestId,
    });
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

app.use(async (err, req, res, next) => {
  // Multer and manual errors land here
  await cleanupTempUpload(req?.file?.path);
  console.error(err);
  res.status(400).json({ ok: false, error: err.message || "Upload failed." });
});

app.listen(PORT, () => {
  console.log(`File API listening on http://localhost:${PORT}`);
  startRevenueCatReconcileJob();
});
