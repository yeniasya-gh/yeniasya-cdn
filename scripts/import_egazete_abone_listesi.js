#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const axios = require("axios");
const dotenv = require("dotenv");

const ROOT = path.resolve(__dirname, "..");
dotenv.config({ path: path.join(ROOT, ".env") });

const XLSX_PATH =
  process.argv[2] || "/Users/ayktbyz/Downloads/E-gazete-Abone-Listesi.xlsx";
const PARSER_PATH = path.join(__dirname, "extract_egazete_abone_listesi.py");
const HASURA_ENDPOINT = String(process.env.HASURA_ENDPOINT || "")
  .trim()
  .replace(/\/+$/, "");
const HASURA_ADMIN_SECRET = String(process.env.HASURA_ADMIN_SECRET || "").trim();
const HASURA_METADATA_URL = HASURA_ENDPOINT.replace(/\/v1\/graphql$/i, "/v1/metadata");
const HASURA_QUERY_URL = HASURA_ENDPOINT.replace(/\/v1\/graphql$/i, "/v2/query");
const HASURA_SOURCE_NAME = String(process.env.HASURA_SOURCE_NAME || "").trim();

if (!HASURA_ENDPOINT || !HASURA_ADMIN_SECRET) {
  console.error(
    "HASURA_ENDPOINT / HASURA_ADMIN_SECRET env değerleri eksik. .env dosyasını kontrol edin."
  );
  process.exit(1);
}

const passwordHash = crypto
  .createHash("sha256")
  .update("Abonelik")
  .digest("hex");

const sqlQuote = (value) => `'${String(value).replace(/'/g, "''")}'`;

const runMetadata = async (body) => {
  const resp = await axios.post(HASURA_METADATA_URL, body, {
    headers: {
      "content-type": "application/json",
      "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
    },
    timeout: 120000,
    validateStatus: () => true,
  });
  if (resp.status < 200 || resp.status >= 300) {
    throw new Error(
      `Hasura metadata request failed (${resp.status}): ${JSON.stringify(resp.data)}`
    );
  }
  if (resp.data?.error) {
    throw new Error(`Hasura metadata error: ${JSON.stringify(resp.data.error)}`);
  }
  return resp.data;
};

const detectSourceName = async () => {
  if (HASURA_SOURCE_NAME) {
    return HASURA_SOURCE_NAME;
  }

  const metadata = await runMetadata({
    type: "export_metadata",
    args: {},
  });

  const sourceName = metadata?.sources?.[0]?.name;
  if (!sourceName) {
    throw new Error("Hasura source name could not be detected from metadata.");
  }
  return sourceName;
};

const runQuery = async (body) => {
  const resp = await axios.post(HASURA_QUERY_URL, body, {
    headers: {
      "content-type": "application/json",
      "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
    },
    timeout: 120000,
    validateStatus: () => true,
  });
  if (resp.status < 200 || resp.status >= 300) {
    throw new Error(
      `Hasura query request failed (${resp.status}): ${JSON.stringify(resp.data)}`
    );
  }
  if (resp.data?.error) {
    throw new Error(`Hasura query error: ${JSON.stringify(resp.data.error)}`);
  }
  return resp.data;
};

const parseWorkbook = () => {
  const result = spawnSync("python3", [PARSER_PATH, XLSX_PATH], {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    throw new Error(`Workbook parse failed: ${stderr || result.stdout || "unknown error"}`);
  }

  return JSON.parse(result.stdout);
};

const buildSql = (rows) => {
  const values = rows
    .map((row) => {
      const name = sqlQuote(row.name);
      const email = sqlQuote(row.email);
      const startsAt = sqlQuote(`${row.starts_at} 00:00:00+03:00`);
      const endsAt = sqlQuote(`${row.ends_at} 23:59:59+03:00`);
      const payUniqe = sqlQuote(crypto.randomUUID());
      return `(${name}, ${email}, ${startsAt}, ${endsAt}, ${payUniqe})`;
    })
    .join(",\n");

  return `
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'manual_newspaper_users'
      AND column_name = 'status'
  ) THEN
    ALTER TABLE public.manual_newspaper_users ADD COLUMN status text;
  END IF;
END $$;

UPDATE public.manual_newspaper_users
SET status = 'new'
WHERE status IS NULL OR btrim(status) = '';

ALTER TABLE public.manual_newspaper_users
  ALTER COLUMN status SET DEFAULT 'new';

ALTER TABLE public.manual_newspaper_users
  ALTER COLUMN status SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'manual_newspaper_users_status_check'
  ) THEN
    ALTER TABLE public.manual_newspaper_users
      ADD CONSTRAINT manual_newspaper_users_status_check
      CHECK (status IN ('old', 'new'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS manual_newspaper_users_status_active_idx
  ON public.manual_newspaper_users (status, is_active, ends_at DESC);

CREATE TEMP TABLE tmp_egazete_import (
  name text NOT NULL,
  email text NOT NULL,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  pay_uniqe text NOT NULL
) ON COMMIT DROP;

INSERT INTO tmp_egazete_import (name, email, starts_at, ends_at, pay_uniqe)
VALUES
${values};

WITH upserted_users AS (
  INSERT INTO public.users AS u (
    name,
    email,
    password,
    "payUniqe",
    email_verified_at,
    is_active,
    deactivated_at
  )
  SELECT
    t.name,
    lower(t.email),
    ${sqlQuote(passwordHash)},
    t.pay_uniqe,
    now(),
    TRUE,
    NULL
  FROM tmp_egazete_import t
  ON CONFLICT ((lower(email))) DO UPDATE
    SET name = EXCLUDED.name,
        password = EXCLUDED.password,
        "payUniqe" = COALESCE(u."payUniqe", EXCLUDED."payUniqe"),
        email_verified_at = EXCLUDED.email_verified_at,
        is_active = TRUE,
        deactivated_at = NULL
  RETURNING id, email
)
INSERT INTO public.manual_newspaper_users AS m (
  user_id,
  starts_at,
  ends_at,
  is_active,
  status,
  note
)
SELECT
  u.id,
  t.starts_at,
  t.ends_at,
  TRUE,
  'old',
  NULL
FROM upserted_users u
JOIN tmp_egazete_import t
  ON lower(t.email) = u.email
ON CONFLICT (user_id) DO UPDATE
  SET starts_at = EXCLUDED.starts_at,
      ends_at = EXCLUDED.ends_at,
      is_active = TRUE,
      status = EXCLUDED.status,
      note = EXCLUDED.note;

COMMIT;
`;
};

const main = async () => {
  const parsed = parseWorkbook();
  const rows = Array.isArray(parsed.rows) ? parsed.rows : [];

  if (rows.length === 0) {
    console.log("Aktif kayıt bulunamadı.");
    return;
  }

  console.log(`Aktif kayıt sayısı: ${rows.length}`);
  console.log("Import hazırlanıyor...");

  const sql = buildSql(rows);
  const sourceName = await detectSourceName();
  await runQuery({
    type: "run_sql",
    args: {
      source: sourceName,
      sql,
      cascade: false,
      read_only: false,
    },
  });

  await runMetadata({
    type: "reload_metadata",
    args: {
      reload_sources: true,
    },
  });

  const summary = await runQuery({
    type: "run_sql",
    args: {
      source: sourceName,
      sql: `
        SELECT
          (SELECT count(*) FROM public.users) AS users,
          (SELECT count(*) FROM public.manual_newspaper_users) AS manual_newspaper_users;
      `,
      cascade: false,
      read_only: true,
    },
  });

  const result = summary?.result;
  const counts = Array.isArray(result) && Array.isArray(result[1]) ? result[1] : null;
  if (counts) {
    const [users, manualNewspaperUsers] = counts;
    console.log(`Toplam kullanıcı: ${users}`);
    console.log(`Toplam manuel e-gazete kaydı: ${manualNewspaperUsers}`);
  }

  console.log("Import tamamlandı.");
};

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
