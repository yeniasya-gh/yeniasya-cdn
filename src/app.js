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
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1d";
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
  const response = await hasuraHttp.post(
    HASURA_ENDPOINT,
    { query, variables },
    {
      timeout: options.timeout || HASURA_HTTP_TIMEOUT_MS,
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

const proxyHasuraRequest = async (req, res) => {
  try {
    const { query, variables, operationName } = req.body || {};
    if (!query) {
      return res.status(400).json({ ok: false, error: "query is required." });
    }

    const response = await hasuraHttp.post(
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
    await hasuraRequest(
      `
        mutation LogServerHomeError($input: app_error_logs_insert_input!) {
          insert_app_error_logs_one(object: $input) { id }
        }
      `,
      {
        input: {
          service: serviceLabel,
          operation: section,
          message: payload.message,
          stack_trace: err?.stack || null,
          payload,
        },
      }
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
    ? value.map((item) =>
        item && typeof item === "object" && !Array.isArray(item) ? { ...item } : item
      )
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
    EXTRACT(YEAR FROM added_at)::int AS publish_year
  FROM public.magazine_issue
  WHERE magazine_id = $1
    AND COALESCE(is_published, TRUE) = TRUE
  ORDER BY issue_number DESC NULLS LAST, added_at DESC NULLS LAST, id DESC
`;

const loadPublicMagazineIssuesFromHasura = async (magazineId) => {
  const data = await hasuraRequest(
    `
      query GetPublicMagazineIssues($magazine_id: Int!) {
        magazine_issue(
          where: {
            magazine_id: {_eq: $magazine_id}
            is_published: {_eq: true}
          }
          order_by: {issue_number: desc}
        ) {
          id
          magazine_id
          issue_number
          photo_url
          price
          description
          added_at
        }
      }
    `,
    { magazine_id: magazineId },
    { timeout: HOME_BOOTSTRAP_HASURA_TIMEOUT_MS }
  );
  return cloneMagazinePublicIssues(data?.magazine_issue);
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
    itemTypeWhere = ` AND item_type = $${values.length}`;
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

const getUserOrderDetailFromPostgres = async ({ userId, orderId }) => {
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
          WHERE id = $1
            AND user_id = $2
          LIMIT 1
        `,
        [orderId, userId]
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
          WHERE id = $1
            AND user_id = $2
          LIMIT 1
        `,
        [orderId, userId]
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

  const tokenSessionId = extractJwtSessionId(payload);
  const activeSessionId = normalizeAuthSessionId(user.auth_session_id);
  if (activeSessionId && tokenSessionId !== activeSessionId) {
    return {
      ok: false,
      statusCode: 401,
      code: "SESSION_REVOKED",
      error: "Oturumunuz sonlandırıldı. Lütfen tekrar giriş yapın.",
    };
  }

  return {
    ok: true,
    userId,
    user,
    tokenSessionId,
    activeSessionId,
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
    const data = await hasuraRequest(
      `
        query GetUserToken($id: bigint!) {
          users_by_pk(id: $id) {
            id
            firebase_token
          }
        }
      `,
      { id: userId }
    );
    const user = data?.users_by_pk;
    if (!user || !String(user.firebase_token || "").trim()) return [];
    return [{ id: user.id, firebase_token: String(user.firebase_token).trim() }];
  }

  if (Array.isArray(userIds) && userIds.length) {
    const data = await hasuraRequest(
      `
        query GetUserTokensByIds($ids: [bigint!]!) {
          users(
            where: {
              id: {_in: $ids}
              firebase_token: {_is_null: false, _neq: ""}
            }
          ) {
            id
            firebase_token
          }
        }
      `,
      { ids: userIds }
    );
    return (data?.users || [])
      .map((u) => ({
        id: u.id,
        firebase_token: String(u.firebase_token || "").trim(),
      }))
      .filter((u) => !!u.firebase_token);
  }

  const data = await hasuraRequest(
    `
      query GetAllUserTokens {
        users(
          where: {firebase_token: {_is_null: false, _neq: ""}}
          order_by: {firebase_token_updated_at: desc}
        ) {
          id
          firebase_token
        }
      }
    `
  );
  return (data?.users || [])
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
  const objects = uniqueIds.map((id) => ({ title, body, user_id: id }));
  const data = await hasuraRequest(
    `
      mutation InsertNotifications($objects: [notifications_insert_input!]!) {
        insert_notifications(objects: $objects) {
          affected_rows
        }
      }
    `,
    { objects }
  );
  return Number(data?.insert_notifications?.affected_rows || 0);
};

const clearUsersFirebaseTokens = async (userIds) => {
  const uniqueIds = [...new Set((userIds || []).map((id) => toPositiveIntOrNull(id)).filter(Boolean))];
  if (!uniqueIds.length) return 0;
  const data = await hasuraRequest(
    `
      mutation ClearFirebaseTokens($ids: [bigint!]!) {
        update_users(
          where: {id: {_in: $ids}},
          _set: {firebase_token: null, firebase_token_updated_at: null}
        ) {
          affected_rows
        }
      }
    `,
    { ids: uniqueIds }
  );
  return Number(data?.update_users?.affected_rows || 0);
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
  const data = await hasuraRequest(
    `
      query GetUserMailProfile($id: bigint!) {
        users_by_pk(id: $id) {
          id
          name
          email
        }
      }
    `,
    { id: userId }
  );
  return data?.users_by_pk || null;
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
  const data = await hasuraRequest(
    `
      query GetUserByEmailForAuth($email: String!) {
        users(
          where: {
            _or: [
              {email: {_eq: $email}},
              {email: {_ilike: $email}}
            ],
            is_active: {_eq: true}
          },
          order_by: [{email_verified_at: desc_nulls_last}, {id: asc}],
          limit: 1
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          auth_session_id
          role_id
          password
          is_active
          email_verified_at
        }
      }
    `,
    { email }
  );
  return data?.users?.[0] || null;
};

const getInactiveUserByEmailForAuth = async (email) => {
  const data = await hasuraRequest(
    `
      query GetInactiveUserByEmailForAuth($email: String!) {
        users(
          where: {
            _or: [
              {email: {_eq: $email}},
              {email: {_ilike: $email}}
            ],
            is_active: {_eq: false}
          },
          order_by: [{email_verified_at: desc_nulls_last}, {id: asc}],
          limit: 1
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          auth_session_id
          role_id
          password
          is_active
          email_verified_at
          deactivated_at
        }
      }
    `,
    { email }
  );
  return data?.users?.[0] || null;
};

const getUserByPhoneForAuth = async (phone) => {
  const data = await hasuraRequest(
    `
      query GetUserByPhoneForAuth($phone: String!) {
        users(
          where: {
            phone: { _eq: $phone },
            is_active: { _eq: true }
          }
          order_by: [{email_verified_at: desc_nulls_last}, {id: asc}]
          limit: 1
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          auth_session_id
          role_id
          password
          is_active
          email_verified_at
        }
      }
    `,
    { phone }
  );
  return data?.users?.[0] || null;
};

const getInactiveUserByPhoneForAuth = async (phone) => {
  const data = await hasuraRequest(
    `
      query GetInactiveUserByPhoneForAuth($phone: String!) {
        users(
          where: {
            phone: { _eq: $phone },
            is_active: { _eq: false }
          }
          order_by: [{email_verified_at: desc_nulls_last}, {id: asc}]
          limit: 1
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          auth_session_id
          role_id
          password
          is_active
          email_verified_at
          deactivated_at
        }
      }
    `,
    { phone }
  );
  return data?.users?.[0] || null;
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
      SELECT to_regclass($1) IS NOT NULL AS exists
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
          AND table_name = $1
          AND column_name = $2
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
  const data = await hasuraRequest(
    `
      query GetUserByIdForAuth($id: bigint!) {
        users_by_pk(id: $id) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          auth_session_id
          role_id
          email_verified_at
          is_active
        }
      }
    `,
    { id }
  );
  return data?.users_by_pk || null;
};

const getUserByIdForPasswordChange = async (id) => {
  const data = await hasuraRequest(
    `
      query GetUserByIdForPasswordChange($id: bigint!) {
        users_by_pk(id: $id) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          role_id
          password
          auth_session_id
          is_active
          email_verified_at
        }
      }
    `,
    { id }
  );
  return data?.users_by_pk || null;
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
    const data = await hasuraRequest(
      `
        mutation IssueUserAuthSession($id: bigint!, $sessionId: String!) {
          update_users_by_pk(
            pk_columns: {id: $id},
            _set: {auth_session_id: $sessionId}
          ) {
            id
            auth_session_id
          }
        }
      `,
      { id: userId, sessionId }
    );
    return data?.update_users_by_pk || null;
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
  const data = await hasuraRequest(
    `
      mutation UpdateUserProfileFields(
        $id: bigint!,
        $name: String!,
        $phone: String
      ) {
        update_users_by_pk(
          pk_columns: {id: $id},
          _set: {
            name: $name,
            phone: $phone
          }
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          role_id
          email_verified_at
          is_active
        }
      }
    `,
    { id: userId, name, phone }
  );
  return data?.update_users_by_pk || null;
};

const updateUserAvatarUrl = async ({ userId, avatarUrl }) => {
  const data = await hasuraRequest(
    `
      mutation UpdateUserAvatarUrl($id: bigint!, $avatarUrl: String) {
        update_users_by_pk(
          pk_columns: {id: $id},
          _set: {avatar_url: $avatarUrl}
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          role_id
          email_verified_at
          is_active
        }
      }
    `,
    { id: userId, avatarUrl }
  );
  return data?.update_users_by_pk || null;
};

const getActiveUserByEmail = async (email) => {
  const data = await hasuraRequest(
    `
      query GetActiveUserByEmail($email: String!) {
        users(
          where: {
            email: {_eq: $email},
            is_active: {_eq: true}
          },
          limit: 1
        ) {
          id
          name
          email
          email_verified_at
        }
      }
    `,
    { email }
  );
  return data?.users?.[0] || null;
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
  const data = await hasuraRequest(
    `
      mutation InvalidatePasswordResetTokens($userId: bigint!, $usedAt: timestamptz!) {
        update_password_reset_tokens(
          where: {
            user_id: {_eq: $userId},
            used_at: {_is_null: true}
          },
          _set: {used_at: $usedAt}
        ) {
          affected_rows
        }
      }
    `,
    { userId, usedAt }
  );
  return Number(data?.update_password_reset_tokens?.affected_rows || 0);
};

const createPasswordResetTokenRecord = async ({
  userId,
  tokenHash,
  expiresAt,
  requestedIp,
  userAgent,
}) => {
  const data = await hasuraRequest(
    `
      mutation CreatePasswordResetToken($object: password_reset_tokens_insert_input!) {
        insert_password_reset_tokens_one(object: $object) {
          id
          user_id
          token_hash
          expires_at
          used_at
        }
      }
    `,
    {
      object: {
        user_id: userId,
        token_hash: tokenHash,
        expires_at: expiresAt,
        requested_ip: requestedIp || null,
        user_agent: userAgent || null,
      },
    }
  );
  return data?.insert_password_reset_tokens_one || null;
};

const getPasswordResetTokenStateByHash = async (tokenHash) => {
  const data = await hasuraRequest(
    `
      query GetPasswordResetTokenStateByHash($tokenHash: String!) {
        password_reset_tokens(
          where: {token_hash: {_eq: $tokenHash}},
          order_by: {created_at: desc},
          limit: 1
        ) {
          id
          user_id
          expires_at
          used_at
        }
      }
    `,
    { tokenHash }
  );
  return data?.password_reset_tokens?.[0] || null;
};

const markPasswordResetTokenUsed = async (tokenId, usedAt) => {
  const data = await hasuraRequest(
    `
      mutation MarkPasswordResetTokenUsed($id: bigint!, $usedAt: timestamptz!) {
        update_password_reset_tokens_by_pk(
          pk_columns: {id: $id},
          _set: {used_at: $usedAt}
        ) {
          id
          used_at
        }
      }
    `,
    { id: tokenId, usedAt }
  );
  return data?.update_password_reset_tokens_by_pk || null;
};

const invalidateEmailVerificationTokensForUser = async (userId, usedAt) => {
  const data = await hasuraRequest(
    `
      mutation InvalidateEmailVerificationTokens($userId: bigint!, $usedAt: timestamptz!) {
        update_email_verification_tokens(
          where: {
            user_id: {_eq: $userId},
            used_at: {_is_null: true}
          },
          _set: {used_at: $usedAt}
        ) {
          affected_rows
        }
      }
    `,
    { userId, usedAt }
  );
  return Number(data?.update_email_verification_tokens?.affected_rows || 0);
};

const createEmailVerificationTokenRecord = async ({
  userId,
  tokenHash,
  expiresAt,
  requestedIp,
  userAgent,
}) => {
  const data = await hasuraRequest(
    `
      mutation CreateEmailVerificationToken($object: email_verification_tokens_insert_input!) {
        insert_email_verification_tokens_one(object: $object) {
          id
          user_id
          token_hash
          expires_at
          used_at
        }
      }
    `,
    {
      object: {
        user_id: userId,
        token_hash: tokenHash,
        expires_at: expiresAt,
        requested_ip: requestedIp || null,
        user_agent: userAgent || null,
      },
    }
  );
  return data?.insert_email_verification_tokens_one || null;
};

const getEmailVerificationTokenStateByHash = async (tokenHash) => {
  const data = await hasuraRequest(
    `
      query GetEmailVerificationTokenStateByHash($tokenHash: String!) {
        email_verification_tokens(
          where: {token_hash: {_eq: $tokenHash}},
          order_by: {created_at: desc},
          limit: 1
        ) {
          id
          user_id
          expires_at
          used_at
        }
      }
    `,
    { tokenHash }
  );
  return data?.email_verification_tokens?.[0] || null;
};

const markEmailVerificationTokenUsed = async (tokenId, usedAt) => {
  const data = await hasuraRequest(
    `
      mutation MarkEmailVerificationTokenUsed($id: bigint!, $usedAt: timestamptz!) {
        update_email_verification_tokens_by_pk(
          pk_columns: {id: $id},
          _set: {used_at: $usedAt}
        ) {
          id
          used_at
        }
      }
    `,
    { id: tokenId, usedAt }
  );
  return data?.update_email_verification_tokens_by_pk || null;
};

const markUserEmailVerified = async (userId, verifiedAt) => {
  const data = await hasuraRequest(
    `
      mutation MarkUserEmailVerified($id: bigint!, $verifiedAt: timestamptz!) {
        update_users_by_pk(
          pk_columns: {id: $id},
          _set: {email_verified_at: $verifiedAt}
        ) {
          id
          name
          email
          phone
          avatar_url
          payUniqe
          role_id
          email_verified_at
        }
      }
    `,
    { id: userId, verifiedAt }
  );
  return data?.update_users_by_pk || null;
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

  const data = await hasuraRequest(
    `
      query GetActiveNewspaperSubscriptionAccess(
        $user_id: Int!
        $item_type: access_item_type!
        $now: timestamptz!
      ) {
        user_content_access(
          where: {
            user_id: {_eq: $user_id}
            item_type: {_eq: $item_type}
            is_active: {_eq: true}
            _or: [{expires_at: {_is_null: true}}, {expires_at: {_gt: $now}}]
          }
          order_by: {expires_at: desc_nulls_last}
          limit: 1
        ) {
          id
          expires_at
        }
      }
    `,
    {
      user_id: userId,
      item_type: "newspaper_subscription",
      now: nowIso,
    }
  );
  return data?.user_content_access?.[0] || null;
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
    // Fallback to Hasura if home postgres is unavailable.
  }

  const data = await hasuraRequest(
    `
      query GetNewspaperByPublishDate($publishDate: date!) {
        newspaper(
          where: {publish_date: {_eq: $publishDate}}
          order_by: {id: desc}
          limit: 1
        ) {
          id
          publish_date
          file_url
        }
      }
    `,
    { publishDate }
  );
  return data?.newspaper?.[0] || null;
};

const getUserWelcomeMailState = async (userId) => {
  const data = await hasuraRequest(
    `
      query GetUserWelcomeMailState($id: bigint!) {
        users_by_pk(id: $id) {
          id
          name
          email
          welcome_mail_sent_at
        }
      }
    `,
    { id: userId }
  );
  return data?.users_by_pk || null;
};

const claimWelcomeMailSend = async (userId, claimedAt) => {
  const data = await hasuraRequest(
    `
      mutation ClaimWelcomeMailSend($id: bigint!, $claimedAt: timestamptz!) {
        update_users(
          where: {id: {_eq: $id}, welcome_mail_sent_at: {_is_null: true}},
          _set: {welcome_mail_sent_at: $claimedAt}
        ) {
          affected_rows
          returning {
            id
            name
            email
            welcome_mail_sent_at
          }
        }
      }
    `,
    { id: userId, claimedAt }
  );
  return data?.update_users || { affected_rows: 0, returning: [] };
};

const rollbackWelcomeMailClaim = async (userId, claimedAt) => {
  const data = await hasuraRequest(
    `
      mutation RollbackWelcomeMailSend($id: bigint!, $claimedAt: timestamptz!) {
        update_users(
          where: {id: {_eq: $id}, welcome_mail_sent_at: {_eq: $claimedAt}},
          _set: {welcome_mail_sent_at: null}
        ) {
          affected_rows
        }
      }
    `,
    { id: userId, claimedAt }
  );
  return Number(data?.update_users?.affected_rows || 0);
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
  const headers = {};

  if (req?.hasuraAuthMode === "service") {
    headers["x-hasura-admin-secret"] = HASURA_ADMIN_SECRET;
    return headers;
  }

  if (req?.hasuraAuthMode === "jwt" && req?.jwtToken) {
    if (hasAdminRoleInBearerToken(req.jwtToken)) {
      headers["x-hasura-admin-secret"] = HASURA_ADMIN_SECRET;
      return headers;
    }
    headers.Authorization = `Bearer ${req.jwtToken}`;
  }

  return headers;
};

const setUserPasswordHash = async (userId, passwordHash) => {
  await hasuraRequest(
    `
      mutation UpdateUserPassword($id: bigint!, $password: String!) {
        update_users_by_pk(pk_columns: {id: $id}, _set: {password: $password}) {
          id
        }
      }
    `,
    { id: userId, password: passwordHash }
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

    const createUser = async () =>
      hasuraRequest(
        `
          mutation CreateUser($object: users_insert_input!) {
            insert_users_one(object: $object) {
              id
              name
              email
              phone
              avatar_url
              payUniqe
              role_id
            }
          }
        `,
        {
          object: createPayload,
        }
      );

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
      const created = await hasuraRequest(
        `
          mutation CreateSocialLoginUser($object: users_insert_input!) {
            insert_users_one(object: $object) {
              id
              name
              email
              phone
              avatar_url
              payUniqe
              role_id
              email_verified_at
            }
          }
        `,
        {
          object: {
            name: socialName,
            email,
            phone,
            password: passwordHash,
            payUniqe,
            email_verified_at: verifiedAt,
          },
        }
      );
      user = created?.insert_users_one;
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
    const createSocialUser = async () =>
      hasuraRequest(
        `
          mutation CreateSocialUser($object: users_insert_input!) {
            insert_users_one(object: $object) {
              id
              name
              email
              phone
              avatar_url
              payUniqe
              role_id
              email_verified_at
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
            email_verified_at: verifiedAt,
          },
        }
      );

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
  const data = await hasuraRequest(
    `
      query GetUserById($id: bigint!) {
        users_by_pk(id: $id) {
          id
          name
          email
          phone
          avatar_url
          role_id
          payUniqe
        }
      }
    `,
    { id: userId }
  );
  return data?.users_by_pk || null;
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

  const runLookupByPayUniqe = async (value, gqlType) => {
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

  const byPayUniqe = await runLookupByPayUniqe(normalizedValue, "String!");
  if (byPayUniqe) return byPayUniqe;

  const asBigint = toPositiveIntOrNull(normalizedValue);
  if (!asBigint) return null;

  const byId = await hasuraRequest(
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
    { id: asBigint }
  );
  return byId?.users_by_pk || null;
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
  const purchasePlatform = purchasePlatformFromRevenueCatStore(
    entitlement.store || entitlement.store_name || entitlement.storeName
  );

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
    const err = new Error(
      "RevenueCat verification unavailable and no fallback entitlement state was provided."
    );
    err.statusCode = 503;
    throw err;
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

  const rows = await homePostgresQueryWithClient(client, query, [
    normalizedEntitlementId,
    userId,
    normalizedAppUserId,
    ownershipKey,
    normalizedProductIdentifier,
    isActive === true,
    expiresAt,
    nowIso,
  ]);

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
    const ownerState = await getRevenueCatLockOwnerTransferState(
      client,
      existing.owner_user_id
    );
    const ownerCanTransfer =
      !ownerState ||
      ownerState.is_active !== true ||
      ownerState.has_active_revenuecat_access !== true;

    if (ownerCanTransfer) {
      const transferredRows = await homePostgresQueryWithClient(
        client,
        `
          UPDATE public.revenuecat_subscription_locks
          SET
            owner_user_id = $2::bigint,
            owner_app_user_id = $3::text,
            owner_original_app_user_id = COALESCE($4::text, owner_original_app_user_id),
            product_identifier = COALESCE($5::text, product_identifier),
            is_active = TRUE,
            expires_at = $6::timestamptz,
            locked_at = now(),
            updated_at = now(),
            last_seen_at = now()
          WHERE entitlement_id = $1::text
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
          normalizedEntitlementId,
          Number(userId),
          normalizedAppUserId,
          normalizedOriginalAppUserId,
          normalizedProductIdentifier,
          expiresAt,
        ]
      );

      if (transferredRows[0]) {
        console.log(
          `[revenuecat][lock-transfer] entitlement=${normalizedEntitlementId} fromUserId=${existing.owner_user_id} toUserId=${userId} reason=${
            ownerState?.is_active === true ? "owner_without_active_access" : "owner_inactive"
          }`
        );
        return {
          mapped: true,
          action: "transferred",
          reason:
            ownerState?.is_active === true
              ? "owner_without_active_access"
              : "owner_inactive",
          lock: transferredRows[0],
        };
      }
    }

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

const getRevenueCatLockOwnerTransferState = async (client, ownerUserId) => {
  const rows = await homePostgresQueryWithClient(
    client,
    `
      SELECT
        u.id::int AS user_id,
        u.is_active AS is_active,
        EXISTS(
          SELECT 1
          FROM public.user_content_access uca
          WHERE uca.user_id = u.id
            AND uca.item_type = 'newspaper_subscription'::public.access_item_type
            AND uca.item_id IS NULL
            AND uca.is_active = TRUE
            AND COALESCE(uca.expires_at, 'epoch'::timestamptz) > now()
            AND COALESCE(NULLIF(btrim(uca.grant_source), ''), 'revenuecat') = 'revenuecat'
        ) AS has_active_revenuecat_access
      FROM public.users u
      WHERE u.id = $1::bigint
      LIMIT 1
    `,
    [ownerUserId]
  );
  return rows[0] || null;
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

  const logSyncStage = (stage, details = "") => {
    console.log(
      `[revenuecat][sync-access][stage] userId=${userId} entitlement=${entitlementId} active=${boolForLog(isActive)} stage=${stage}${details ? ` ${details}` : ""}`
    );
  };

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
      logSyncStage("lock-upsert:start");
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
      logSyncStage("lock-upsert:done", `mapped=${boolForLog(lockResult.mapped)} reason=${lockResult.reason || "-"}`);

      if (!lockResult.mapped && lockResult.reason === "locked_to_other_user") {
        logSyncStage("locked-to-other-user");
        const current = await getActiveNewspaperAccessRowFromPostgres({
          userId,
          nowIso,
          client,
          requireCurrent: false,
        });
        if (current?.id && isRevenueCatManagedAccessRow(current, expiresAt || nowIso)) {
          logSyncStage("locked-to-other-user:deactivate-current", `accessId=${current.id}`);
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
      logSyncStage("inactive:lookup-current");
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

      logSyncStage("inactive:deleted-current", `accessId=${deletedRows[0]?.id ?? current.id ?? "-"}`);
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
    logSyncStage("active:lookup-current");
    const current = await getActiveNewspaperAccessRowFromPostgres({
      userId,
      nowIso,
      client,
      requireCurrent: false,
    });

    if (current?.id) {
      if (hasManualOverrideExpiry(current, expiresAt)) {
        logSyncStage("active:skip-manual-override", `accessId=${current.id}`);
        return {
          mapped: true,
          action: "skipped_manual_override",
          itemType: mapping.itemType,
          accessId: current.id,
          expiresAt: current.expires_at || null,
        };
      }

      logSyncStage("active:update-current", `accessId=${current.id}`);
      await updateRevenueCatAccess(client, current.id);
      logSyncStage("active:update-current:done", `accessId=${current.id}`);
      return {
        mapped: true,
        action: "updated",
        itemType: mapping.itemType,
        accessId: current.id,
        expiresAt,
      };
    }

    try {
      logSyncStage("active:insert-current");
      const inserted = await insertRevenueCatAccess(client);
      logSyncStage("active:insert-current:done", `accessId=${inserted?.id ?? "-"}`);
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

      logSyncStage("active:recovered-after-conflict", `accessId=${recovered.id}`);
      await updateRevenueCatAccess(client, recovered.id);
      logSyncStage("active:recovered-after-conflict:done", `accessId=${recovered.id}`);
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
  const object = Object.fromEntries(
    Object.entries(entry || {}).filter(([, value]) => value !== undefined)
  );
  try {
    await hasuraRequest(
      `
        mutation InsertRevenueCatSyncLog($object: revenuecat_sync_logs_insert_input!) {
          insert_revenuecat_sync_logs_one(object: $object) {
            id
          }
        }
      `,
      { object }
    );
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

app.post("/revenuecat/subscription/sync", requireRevenueCatAuth, async (req, res) => {
  const requestId = crypto.randomUUID();
  const baseAudit = {
    request_id: requestId,
    endpoint: "/revenuecat/subscription/sync",
    auth_mode: req.revenueCatAuthMode || "unknown",
  };

  try {
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
      return res.status(400).json({
        ok: false,
        error: "isActive is required when RevenueCat verification is unavailable.",
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
    const body = req.body || {};
    const source = normalizeRevenueCatAppUserId(body.source) || "unknown";
    const result = normalizeRevenueCatAppUserId(body.result) || "unknown";
    const success = toBool(body.success);
    const entitlementId = normalizeRevenueCatAppUserId(body.entitlementId);
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
    const response = await bunnyRequest(
      {
        method: "PUT",
        url,
        data: fs.createReadStream(filePath),
        timeout: BUNNY_UPLOAD_TIMEOUT_MS,
        headers: {
          "Content-Type": "application/octet-stream",
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
    await uploadToBunny(req.file.path, type, "public", filename);

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
  }
});

app.post("/upload/private", requireJwt, upload.single("file"), async (req, res, next) => {
  const tempFilePath = req.file?.path;
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
    await uploadToBunny(req.file.path, type, "private", filename);

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
      return res.status(404).json({
        ok: false,
        error: "No users with firebase tokens were found for this target.",
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
        error: "No valid firebase token entries found.",
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
